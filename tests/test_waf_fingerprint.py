"""Tests for modules/waf_fingerprint — active probe-based WAF detection."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from modules.waf_fingerprint import (
    WAF_BLOCK_SIGNATURES,
    _identify_waf,
    _match_signature,
    active_fingerprint,
)


pytestmark = pytest.mark.unit


def _resp(status: int, body: str = "", headers: dict | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        status_code=status, text=body, headers=dict(headers or {})
    )


# ── Signature catalogue sanity ───────────────────────────────────────────────


def test_signature_db_is_non_trivial():
    # Project requirement: cover materially more WAFs than the 20 in
    # utils/waf.py. Asserting >=20 ensures regressions don't quietly
    # collapse coverage.
    assert len(WAF_BLOCK_SIGNATURES) >= 20


@pytest.mark.parametrize("waf", list(WAF_BLOCK_SIGNATURES.keys()))
def test_every_signature_has_at_least_one_strong_fingerprint(waf):
    sig = WAF_BLOCK_SIGNATURES[waf]
    # A strong fingerprint must exist in either headers or body — status
    # alone is insufficient (corroboration requirement enforced by
    # _match_signature). Catches typos and accidentally-empty entries.
    assert sig.get("headers") or sig.get("body"), waf


# ── _match_signature semantics ───────────────────────────────────────────────


def test_status_alone_is_insufficient_to_match():
    # A naive WAF guess based solely on a 403 would false-positive any
    # 403 page. Require a header or body fingerprint to corroborate.
    sig = WAF_BLOCK_SIGNATURES["Cloudflare"]
    reasons = _match_signature(
        status=403, body="generic forbidden", headers={}, signature=sig
    )
    assert reasons == []


def test_body_fingerprint_match_passes_corroboration():
    sig = WAF_BLOCK_SIGNATURES["Cloudflare"]
    reasons = _match_signature(
        status=403,
        body="Attention Required! | Cloudflare",
        headers={},
        signature=sig,
    )
    assert any("body~=" in r for r in reasons)


def test_header_fingerprint_match_passes_corroboration():
    sig = WAF_BLOCK_SIGNATURES["AWS WAF"]
    reasons = _match_signature(
        status=403,
        body="",
        headers={"x-amzn-errortype": "AccessDenied"},
        signature=sig,
    )
    assert any("header~=" in r for r in reasons)


# ── _identify_waf precedence ────────────────────────────────────────────────


def test_identify_waf_returns_first_strong_match():
    waf, reasons = _identify_waf(
        status=403,
        body="Attention required! | Cloudflare cf-ray: abc",
        headers={"cf-ray": "abc"},
    )
    assert waf == "Cloudflare"
    assert reasons


def test_identify_waf_none_on_generic_403():
    waf, _ = _identify_waf(status=403, body="<h1>403 Forbidden</h1>", headers={})
    assert waf is None


# ── active_fingerprint orchestration ────────────────────────────────────────


def test_active_fingerprint_records_baseline_and_probes():
    responses = {
        "https://t/": _resp(200, "<html>welcome</html>", {}),
    }

    def fake_get(url, timeout):
        if "wafprobe" in url:
            return _resp(
                403,
                "Attention Required! | Cloudflare",
                {"cf-ray": "12345-DFW"},
            )
        return responses.get(url, _resp(404, ""))

    report = active_fingerprint(
        "https://t/", http_get=fake_get, probes=(("xss", "<script>"),)
    )
    assert report.baseline_status == 200
    assert "Cloudflare" in report.detected_wafs
    assert len(report.probe_outcomes) == 1
    assert report.probe_outcomes[0].matched_waf == "Cloudflare"


def test_active_fingerprint_detects_multiple_wafs_across_probes():
    """Some misconfigured stacks layer multiple WAFs — we surface all of them."""

    def fake_get(url, timeout):
        if "XSSMARKER" in url:
            return _resp(
                403, "Request blocked", {"x-amzn-errortype": "AccessDenied"}
            )
        if "SQLIMARKER" in url:
            return _resp(403, "Incident ID: powered by incapsula", {})
        return _resp(200, "ok")

    report = active_fingerprint(
        "https://t/",
        http_get=fake_get,
        probes=(("xss", "XSSMARKER"), ("sqli", "SQLIMARKER")),
    )
    assert set(report.detected_wafs) >= {"AWS WAF", "Imperva / Incapsula"}


def test_active_fingerprint_handles_network_errors():
    def boom(url, timeout):
        raise RuntimeError("connect timeout")

    report = active_fingerprint(
        "https://t/", http_get=boom, probes=(("xss", "x"),)
    )
    assert report.detected_wafs == []
    assert any("baseline" in e for e in report.errors)
    # Probe error is recorded but doesn't crash the run.
    assert any("probe xss" in e for e in report.errors)


def test_no_detection_emits_empty_findings():
    def benign(url, timeout):
        return _resp(200, "ok")

    report = active_fingerprint(
        "https://t/", http_get=benign, probes=(("xss", "x"),)
    )
    assert report.as_findings() == []


def test_detected_waf_becomes_finding_dict():
    def fake_get(url, timeout):
        if "wafprobe" in url:
            return _resp(403, "Attention Required! | Cloudflare", {"cf-ray": "1"})
        return _resp(200, "")

    report = active_fingerprint(
        "https://t/", http_get=fake_get, probes=(("xss", "x"),)
    )
    findings = report.as_findings()
    assert findings and findings[0]["type"] == "WAF_Detected"
    assert findings[0]["module"] == "waf_fingerprint"
    assert "Cloudflare" in findings[0]["evidence"]
    assert findings[0]["waf"] == ["Cloudflare"]


def test_query_separator_chosen_correctly():
    captured: list[str] = []

    def capturing(url, timeout):
        captured.append(url)
        return _resp(200, "")

    # URL with no query string → use ?
    active_fingerprint("https://t/", http_get=capturing, probes=(("xss", "x"),))
    # URL with existing query string → use &
    active_fingerprint(
        "https://t/?a=1", http_get=capturing, probes=(("xss", "x"),)
    )
    no_query = [u for u in captured if u.startswith("https://t/?")]
    with_query = [u for u in captured if u.startswith("https://t/?a=1&")]
    assert any("wafprobe=" in u for u in no_query)
    assert any("wafprobe=" in u for u in with_query)
