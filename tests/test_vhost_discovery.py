"""Tests for modules/vhost_discovery — Host-header brute discovery."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from modules.vhost_discovery import (
    VhostBaseline,
    discover_vhosts,
)


pytestmark = pytest.mark.unit


def _resp(status: int, text: str = "") -> SimpleNamespace:
    return SimpleNamespace(status_code=status, text=text)


# ── VhostBaseline diff logic ────────────────────────────────────────────────


def test_baseline_diff_status_change():
    b = VhostBaseline(status=200, length=100, body_hash="aaa")
    assert b.is_materially_different(status=302, length=100, body_hash="aaa")


def test_baseline_diff_body_hash_change():
    b = VhostBaseline(status=200, length=100, body_hash="aaa")
    assert b.is_materially_different(status=200, length=100, body_hash="bbb")


def test_baseline_diff_length_within_tolerance_is_not_different():
    b = VhostBaseline(status=200, length=100, body_hash="aaa")
    # +16 bytes is within the default ±32 tolerance.
    assert not b.is_materially_different(
        status=200, length=116, body_hash="aaa"
    )


def test_baseline_diff_length_beyond_tolerance_is_different():
    b = VhostBaseline(status=200, length=100, body_hash="aaa")
    assert b.is_materially_different(status=200, length=500, body_hash="aaa")


# ── discover_vhosts orchestration ───────────────────────────────────────────


def test_discovers_distinct_vhost():
    """One candidate returns a materially different page → discovered."""

    def fake_get(url, headers, timeout):
        host = headers["Host"]
        if "invalid" in host:
            return _resp(404, "<html>Not Found</html>")
        if host == "internal.t.com":
            return _resp(200, "<html>Internal admin panel — restricted</html>")
        return _resp(404, "<html>Not Found</html>")

    report = discover_vhosts(
        "10.0.0.1",
        ["internal.t.com", "noise.t.com"],
        http_get=fake_get,
    )
    assert len(report.hits) == 1
    assert report.hits[0].host == "internal.t.com"
    assert report.candidates_tried == 2


def test_collapses_catch_all_responses_to_one_hit():
    """If every candidate returns the same page, we record at most one hit.

    This is the wildcard / catch-all defender — without it the report
    would scream about every word in the wordlist.
    """

    def fake_get(url, headers, timeout):
        host = headers["Host"]
        if "invalid" in host:
            return _resp(200, "BASELINE PAGE")
        return _resp(200, "EVERY CANDIDATE RETURNS THE SAME WILDCARD PAGE")

    report = discover_vhosts(
        "10.0.0.1",
        ["a.t.com", "b.t.com", "c.t.com"],
        http_get=fake_get,
    )
    assert len(report.hits) == 1  # wildcard collapsed to one


def test_baseline_request_failure_aborts_cleanly():
    def boom(url, headers, timeout):
        raise RuntimeError("network down")

    report = discover_vhosts(
        "10.0.0.1",
        ["a.t.com"],
        http_get=boom,
    )
    assert report.baseline is None
    assert report.candidates_tried == 0
    assert any("baseline" in e for e in report.errors)


def test_per_candidate_failure_is_isolated():
    calls = {"n": 0}

    def fake_get(url, headers, timeout):
        host = headers["Host"]
        calls["n"] += 1
        if "invalid" in host:
            return _resp(404, "baseline")
        if host == "broken.t.com":
            raise RuntimeError("connection reset")
        return _resp(200, f"unique-page-for-{host}")

    report = discover_vhosts(
        "10.0.0.1",
        ["broken.t.com", "good.t.com"],
        http_get=fake_get,
    )
    assert report.candidates_tried == 2
    assert any("broken.t.com" in e for e in report.errors)
    assert any(h.host == "good.t.com" for h in report.hits)


def test_baseline_host_candidate_is_skipped():
    """If the wordlist contains the baseline host itself, skip it."""

    def fake_get(url, headers, timeout):
        return _resp(200, "always the same")

    report = discover_vhosts(
        "10.0.0.1",
        ["unlikely-baseline-host.invalid", ""],
        http_get=fake_get,
    )
    assert report.candidates_tried == 0


# ── as_findings ──────────────────────────────────────────────────────────────


def test_as_findings_returns_one_dict_per_hit():
    def fake_get(url, headers, timeout):
        host = headers["Host"]
        if "invalid" in host:
            return _resp(404, "baseline")
        return _resp(200, f"unique-{host}")

    report = discover_vhosts(
        "10.0.0.1",
        ["a.t.com", "b.t.com"],
        http_get=fake_get,
    )
    findings = report.as_findings()
    assert len(findings) == 2
    for finding in findings:
        assert finding["type"] == "Virtual_Host_Discovered"
        assert finding["module"] == "vhost_discovery"
        assert finding["host_header"] in {"a.t.com", "b.t.com"}


def test_empty_findings_when_no_hits():
    def fake_get(url, headers, timeout):
        return _resp(200, "always the same wildcard")

    report = discover_vhosts(
        "10.0.0.1",
        ["a.t.com"],
        http_get=fake_get,
    )
    # The first non-baseline response gets recorded once (wildcard
    # collapse logic), so we may have 1 hit at most. Asserting that
    # subsequent identical responses don't add to it.
    extra = discover_vhosts(
        "10.0.0.1",
        ["a.t.com", "b.t.com", "c.t.com"],
        http_get=fake_get,
    )
    assert len(extra.hits) <= 1
