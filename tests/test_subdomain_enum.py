"""Tests for modules/subdomain_enum — multi-source orchestrator."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from modules.subdomain_enum import (
    SubdomainReport,
    enumerate_subdomains,
)


pytestmark = pytest.mark.unit


def _http_response(payload, status_code: int = 200):
    """Build a duck-typed httpx-style response."""
    return SimpleNamespace(
        status_code=status_code,
        json=lambda: payload,
    )


# ── crt.sh / CertSpotter parsing ─────────────────────────────────────────────


def test_crtsh_source_parses_name_value_and_filters_wildcards():
    """crt.sh's ``name_value`` is newline-separated; wildcards must collapse."""
    payload = [
        {"name_value": "*.example.com\nstaging.example.com"},
        {"name_value": "api.example.com\nout-of-scope.other.com"},
    ]
    http_get = MagicMock(return_value=_http_response(payload))

    report = enumerate_subdomains(
        "example.com",
        sources=("crtsh",),
        http_get=http_get,
    )
    assert report.per_source["crtsh"] == frozenset(
        {"staging.example.com", "api.example.com", "example.com" * 0 + "example.com"}
        - {"example.com"}
    )
    # Wildcard stripped, out-of-scope dropped.
    assert "out-of-scope.other.com" not in report.subdomains


def test_certspotter_source_uses_dns_names_field():
    payload = [
        {"dns_names": ["a.example.com", "*.b.example.com", "c.unrelated.org"]},
    ]
    http_get = MagicMock(return_value=_http_response(payload))

    report = enumerate_subdomains(
        "example.com",
        sources=("certspotter",),
        http_get=http_get,
    )
    assert report.per_source["certspotter"] == frozenset(
        {"a.example.com", "b.example.com"}
    )


def test_api_error_status_is_absorbed_into_empty_set():
    http_get = MagicMock(return_value=_http_response(None, status_code=500))
    report = enumerate_subdomains(
        "example.com",
        sources=("crtsh", "certspotter"),
        http_get=http_get,
    )
    assert report.subdomains == frozenset()
    assert report.per_source["crtsh"] == frozenset()
    assert report.per_source["certspotter"] == frozenset()


def test_http_get_raising_records_error_does_not_crash():
    def boom(*_a, **_kw):
        raise RuntimeError("network down")

    report = enumerate_subdomains(
        "example.com",
        sources=("crtsh",),
        http_get=boom,
    )
    assert "crtsh" in report.source_errors
    assert "RuntimeError" in report.source_errors["crtsh"]


# ── Binary-tool integration ──────────────────────────────────────────────────


def test_subfinder_source_unions_into_report():
    from utils.recon_tools import ReconToolResult

    http_get = MagicMock(return_value=_http_response([]))
    fake_result = ReconToolResult(
        tool="subfinder",
        subdomains=frozenset({"sf1.example.com", "sf2.example.com"}),
        succeeded=True,
    )
    with patch("utils.recon_tools.run_subfinder", return_value=fake_result):
        report = enumerate_subdomains(
            "example.com",
            sources=("crtsh", "subfinder"),
            http_get=http_get,
        )
    assert "sf1.example.com" in report.subdomains
    assert "sf2.example.com" in report.subdomains
    assert report.per_source["subfinder"] == fake_result.subdomains


def test_missing_binary_records_error_and_empty_set():
    from utils.recon_tools import ReconToolResult

    http_get = MagicMock(return_value=_http_response([]))
    fake_result = ReconToolResult(
        tool="subfinder", error="binary not on PATH", succeeded=False
    )
    with patch("utils.recon_tools.run_subfinder", return_value=fake_result):
        report = enumerate_subdomains(
            "example.com",
            sources=("subfinder",),
            http_get=http_get,
        )
    assert report.per_source["subfinder"] == frozenset()
    assert "binary" in report.source_errors["subfinder"]


# ── DNS brute ────────────────────────────────────────────────────────────────


def test_dns_brute_uses_injected_resolver():
    resolved = {"api.example.com", "dev.example.com"}

    def resolve_one(name):
        return name in resolved

    http_get = MagicMock(return_value=_http_response([]))
    report = enumerate_subdomains(
        "example.com",
        sources=(),  # no passive sources — isolate brute
        http_get=http_get,
        brute_wordlist=["api", "dev", "ghost", "missing"],
        resolve_one=resolve_one,
    )
    assert report.per_source["dns_brute"] == frozenset(
        {"api.example.com", "dev.example.com"}
    )


# ── Live-resolve filter ──────────────────────────────────────────────────────


def test_live_resolve_filters_to_resolving_names():
    payload = [{"name_value": "a.example.com\nb.example.com"}]
    http_get = MagicMock(return_value=_http_response(payload))
    resolved = {"a.example.com"}

    report = enumerate_subdomains(
        "example.com",
        sources=("crtsh",),
        http_get=http_get,
        resolve_one=lambda n: n in resolved,
        live_resolve=True,
    )
    assert report.subdomains == frozenset({"a.example.com", "b.example.com"})
    assert report.live_resolved == frozenset({"a.example.com"})


# ── Domain validation ────────────────────────────────────────────────────────


def test_ip_target_short_circuits():
    report = enumerate_subdomains("1.2.3.4", sources=("crtsh",), http_get=MagicMock())
    assert report.subdomains == frozenset()


def test_empty_target_short_circuits():
    report = enumerate_subdomains("", sources=("crtsh",), http_get=MagicMock())
    assert report.subdomains == frozenset()


# ── SubdomainReport helpers ─────────────────────────────────────────────────


def test_union_in_merges_into_set():
    report = SubdomainReport(domain="x")
    report.union_in("a", {"x.example.com"})
    report.union_in("b", {"y.example.com"})
    assert report.subdomains == frozenset({"x.example.com", "y.example.com"})
    assert report.per_source["a"] == frozenset({"x.example.com"})
