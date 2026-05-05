"""Tests for utils.asset_search — multi-provider asset search.

All providers are mocked. No live API calls.
"""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest


pytestmark = pytest.mark.unit


def _resp(status_code=200, body=None):
    r = MagicMock()
    r.status_code = status_code
    if isinstance(body, (dict, list)):
        r.json = MagicMock(return_value=body)
        r.text = json.dumps(body)
    else:
        r.json = MagicMock(side_effect=ValueError("not json"))
        r.text = body or ""
    return r


class TestNormalizeTarget:
    def test_strips_scheme_and_path(self):
        from utils.asset_search import _normalize_target

        assert _normalize_target("https://example.com/path?q=1") == "example.com"
        assert _normalize_target("http://1.2.3.4:8080/a") == "1.2.3.4"

    def test_passes_bare_host_through(self):
        from utils.asset_search import _normalize_target

        assert _normalize_target("example.com") == "example.com"
        assert _normalize_target("1.2.3.4") == "1.2.3.4"


class TestProvidersWithoutKeys:
    """Without env keys, providers should silently return empty results."""

    @pytest.mark.parametrize(
        "provider_fn,env_keys",
        [
            ("censys_lookup", ["CENSYS_API_ID", "CENSYS_API_SECRET"]),
            ("zoomeye_lookup", ["ZOOMEYE_API_KEY"]),
            ("fofa_lookup", ["FOFA_EMAIL", "FOFA_API_KEY"]),
            ("onyphe_lookup", ["ONYPHE_API_KEY"]),
            ("netlas_lookup", ["NETLAS_API_KEY"]),
            ("fullhunt_lookup", ["FULLHUNT_API_KEY"]),
        ],
    )
    def test_returns_empty_when_keys_missing(self, provider_fn, env_keys, monkeypatch):
        from utils import asset_search

        for key in env_keys:
            monkeypatch.delenv(key, raising=False)

        fn = getattr(asset_search, provider_fn)
        result = fn("example.com")
        assert result["ports"] == []
        assert result["raw"] == {}


class TestCensysParser:
    def test_extracts_ports_and_services(self, monkeypatch):
        from utils import asset_search

        monkeypatch.setenv("CENSYS_API_ID", "id")
        monkeypatch.setenv("CENSYS_API_SECRET", "secret")

        body = {
            "result": {
                "ip": "1.2.3.4",
                "services": [
                    {"port": 80, "service_name": "HTTP", "transport_protocol": "TCP"},
                    {"port": 443, "service_name": "HTTPS", "transport_protocol": "TCP"},
                ],
                "autonomous_system": {"name": "ASN-EX"},
                "location": {"country": "US"},
                "dns": {"names": ["a.example.com"]},
            }
        }
        with patch("utils.asset_search.smart_request", return_value=_resp(200, body)):
            r = asset_search.censys_lookup("1.2.3.4")
        assert r["ip"] == "1.2.3.4"
        assert r["ports"] == [80, 443]
        assert r["asn"] == "ASN-EX"
        assert r["country"] == "US"
        assert r["hostnames"] == ["a.example.com"]


class TestLeakIXParser:
    def test_parses_public_endpoint(self, monkeypatch):
        from utils import asset_search

        monkeypatch.delenv("LEAKIX_API_KEY", raising=False)
        body = {
            "Services": [
                {"port": 22, "protocol": "tcp", "transport": ["tcp"],
                 "service": {"name": "ssh"}},
                {"port": 443, "protocol": "tcp", "transport": ["tcp"],
                 "service": {"name": "https"}},
            ],
            "Leaks": [{"event_source": "GitConfigHttpPlugin"}],
        }
        with patch("utils.asset_search.smart_request", return_value=_resp(200, body)):
            r = asset_search.leakix_lookup("example.com")
        assert r["ports"] == [22, 443]
        assert r["vulns"] == ["GitConfigHttpPlugin"]


class TestOnypheParser:
    def test_collects_cves_and_tags(self, monkeypatch):
        from utils import asset_search

        monkeypatch.setenv("ONYPHE_API_KEY", "k")
        body = {
            "status": "ok",
            "results": [
                {"port": 80, "cve": ["CVE-2020-1"], "hostname": ["a.example.com"],
                 "tag": ["webserver"], "asn": "AS1", "country": "DE", "ip": "9.9.9.9"},
                {"port": 443, "cve": ["CVE-2021-2"], "tag": ["tls"]},
            ],
        }
        with patch("utils.asset_search.smart_request", return_value=_resp(200, body)):
            r = asset_search.onyphe_lookup("example.com")
        assert r["ports"] == [80, 443]
        assert r["vulns"] == ["CVE-2020-1", "CVE-2021-2"]
        assert "webserver" in r["tags"] and "tls" in r["tags"]
        assert r["asn"] == "AS1"
        assert r["ip"] == "9.9.9.9"


class TestMergeResults:
    def test_unions_across_providers(self):
        from utils.asset_search import merge_results

        results = [
            {"provider": "censys", "ip": "1.2.3.4", "ports": [80, 443],
             "vulns": [], "hostnames": ["a.example.com"], "tags": [], "services": []},
            {"provider": "leakix", "ip": "1.2.3.4", "ports": [443, 22],
             "vulns": ["GitLeak"], "hostnames": [], "tags": ["tcp"], "services": []},
        ]
        merged = merge_results(results)
        assert merged["providers"] == ["censys", "leakix"]
        assert merged["ports"] == [22, 80, 443]
        assert merged["vulns"] == ["GitLeak"]
        assert merged["hostnames"] == ["a.example.com"]
        assert merged["ips"] == ["1.2.3.4"]
        assert "censys" in merged["by_provider"] and "leakix" in merged["by_provider"]


class TestLookupAllProviders:
    def test_skips_providers_without_keys_and_runs_leakix(self, monkeypatch):
        from utils import asset_search

        for key in [
            "CENSYS_API_ID", "CENSYS_API_SECRET", "ZOOMEYE_API_KEY",
            "FOFA_EMAIL", "FOFA_API_KEY", "ONYPHE_API_KEY",
            "NETLAS_API_KEY", "FULLHUNT_API_KEY",
        ]:
            monkeypatch.delenv(key, raising=False)
        monkeypatch.delenv("LEAKIX_API_KEY", raising=False)

        body = {"Services": [{"port": 80}], "Leaks": []}
        with patch("utils.asset_search.smart_request", return_value=_resp(200, body)):
            results = asset_search.lookup_all_providers("example.com")
        # only leakix returns non-empty since it has no key requirement
        assert len(results) == 1
        assert results[0]["provider"] == "leakix"
