"""Tests for utils.finding.spa_filter.

The filter must drop content-dependent findings whose response body matches
the homepage template baseline, but never touch Missing_Security_Header or
findings that have no captured response body.
"""

from __future__ import annotations

import pytest

from utils.finding.spa_filter import filter_template_mirror_findings
from utils.response_fingerprint import compute_baseline_set

pytestmark = pytest.mark.unit


HOMEPAGE = """<!doctype html><html><head><title>Site</title></head>
<body><nav>home about</nav><main>welcome</main><footer>f</footer></body></html>"""

REAL_LEAK = "OPENAI_API_KEY=sk-proj-abc123def456\nDATABASE_URL=postgres://x:y@h/d\n"


def _baseline():
    return compute_baseline_set([(HOMEPAGE, {})])


class TestFiltering:
    def test_drops_spa_fallback_sensitive_info(self):
        findings = [
            {"type": "Sensitive_Information_Exposure", "url": "http://x/.env", "response_body": HOMEPAGE},
        ]
        out = filter_template_mirror_findings(findings, _baseline())
        assert out == []

    def test_drops_spa_fallback_secret_leak(self):
        findings = [
            {"type": "Secret_Leak", "url": "http://x/.env", "response_body": HOMEPAGE},
        ]
        out = filter_template_mirror_findings(findings, _baseline())
        assert out == []

    def test_keeps_real_secret_leak(self):
        findings = [
            {"type": "Secret_Leak", "url": "http://x/.env", "response_body": REAL_LEAK},
        ]
        out = filter_template_mirror_findings(findings, _baseline())
        assert len(out) == 1
        assert out[0]["url"] == "http://x/.env"

    def test_never_drops_missing_security_header(self):
        findings = [
            {"type": "Missing_Security_Header", "url": "http://x/", "param": "CSP", "response_body": HOMEPAGE},
        ]
        out = filter_template_mirror_findings(findings, _baseline())
        assert len(out) == 1

    def test_keeps_findings_without_response_body(self):
        findings = [
            {"type": "Secret_Leak", "url": "http://x/.env"},  # no body captured
        ]
        out = filter_template_mirror_findings(findings, _baseline())
        assert len(out) == 1

    def test_no_baseline_is_passthrough(self):
        findings = [
            {"type": "Sensitive_Information_Exposure", "url": "http://x/", "response_body": HOMEPAGE},
        ]
        out = filter_template_mirror_findings(findings, None)
        assert out == findings


class TestRealismScenario:
    def test_narinkaucuk_style_batch(self):
        """Replays the actual narinkaucuk.com.tr pattern: many SPA-fallback
        hits + one real .env leak + several missing headers."""
        findings = [
            # 5 SPA-fallback "unknown vulnerability" hits (false positives)
            {"type": "Sensitive_Information_Exposure", "url": "http://x/api-docs", "response_body": HOMEPAGE},
            {"type": "Sensitive_Information_Exposure", "url": "http://x/wp-admin/", "response_body": HOMEPAGE},
            {"type": "Sensitive_Information_Exposure", "url": "http://x/swagger.json", "response_body": HOMEPAGE},
            {"type": "Debug_Info", "url": "http://x/debug", "response_body": HOMEPAGE},
            {"type": "Secret_Leak", "url": "http://x/package.json", "response_body": HOMEPAGE},
            # 1 real .env leak
            {"type": "Secret_Leak", "url": "http://x/.env", "response_body": REAL_LEAK},
            # 3 valid header findings (must always survive)
            {"type": "Missing_Security_Header", "url": "http://x/", "param": "Content-Security-Policy"},
            {"type": "Missing_Security_Header", "url": "http://x/", "param": "Strict-Transport-Security"},
            {"type": "Missing_Security_Header", "url": "http://x/", "param": "X-Frame-Options"},
        ]
        out = filter_template_mirror_findings(findings, _baseline())
        # 5 SPA fallbacks dropped, real leak + 3 headers kept = 4
        assert len(out) == 4
        types = {f["type"] for f in out}
        assert "Sensitive_Information_Exposure" not in types
        assert "Debug_Info" not in types
        assert "Secret_Leak" in types
        assert "Missing_Security_Header" in types
