"""Tests for the Scan Intelligence Engine (RAG-Lite Knowledge Loop)."""
import pytest
from utils.scan_intelligence import ScanIntelligence


@pytest.fixture
def intel(tmp_path):
    db_path = str(tmp_path / "test_intel.db")
    return ScanIntelligence(db_path=db_path)


class TestScanIntelligence:
    def test_record_and_query(self, intel):
        intel.record_scan_result(
            target="https://example.com", vuln_type="XSS",
            payload="<script>alert(1)</script>", success=True,
            waf_name="Cloudflare", module="xss_scanner", scan_id="scan1"
        )
        report = intel.query_intelligence("https://example.com")
        assert report.past_scans >= 1
        assert len(report.recommended_payloads) >= 1
        assert report.recommended_payloads[0].vuln_type == "XSS"

    def test_negative_result(self, intel):
        intel.record_negative_result("https://example.com", module="lfi_scanner", scan_id="scan1")
        intel.record_negative_result("https://example.com", module="lfi_scanner", scan_id="scan2")
        report = intel.query_intelligence("https://example.com")
        assert "lfi_scanner" in report.modules_to_skip

    def test_defence_recording(self, intel):
        intel.record_defence("https://example.com", "waf", "Cloudflare")
        profile = intel.get_target_profile("https://example.com")
        assert len(profile.defences) == 1
        assert profile.defences[0].defence_type == "waf"
        assert profile.defences[0].detail == "Cloudflare"

    def test_payload_effectiveness(self, intel):
        payload = "<img src=x onerror=alert(1)>"
        intel.record_scan_result(target="https://a.com", vuln_type="XSS", payload=payload, success=True)
        intel.record_scan_result(target="https://b.com", vuln_type="XSS", payload=payload, success=True)
        intel.record_scan_result(target="https://c.com", vuln_type="XSS", payload=payload, success=False)
        payloads = intel.get_effective_payloads("XSS")
        assert len(payloads) >= 1
        assert payloads[0].success_count == 2
        assert payloads[0].fail_count == 1

    def test_batch_record(self, intel):
        findings = [
            {"type": "SQLi", "payload": "' OR 1=1--", "module": "sqli"},
            {"type": "XSS", "payload": "<script>", "module": "xss"},
        ]
        intel.record_batch("https://example.com", findings, scan_id="batch1")
        profile = intel.get_target_profile("https://example.com")
        assert profile.total_findings == 2

    def test_search(self, intel):
        intel.record_scan_result(target="https://a.com", vuln_type="SQLi", payload="' UNION SELECT", success=True)
        results = intel.search("UNION")
        assert len(results) >= 1

    def test_stats(self, intel):
        intel.record_scan_result(target="https://a.com", vuln_type="XSS", success=True, scan_id="s1")
        stats = intel.get_stats()
        assert stats["total_records"] >= 1
        assert stats["successful_payloads"] >= 1

    def test_target_profile(self, intel):
        intel.record_scan_result(target="https://example.com", vuln_type="XSS", success=True, scan_id="s1", tech_stack='["PHP","Apache"]', waf_name="ModSecurity")
        intel.record_defence("https://example.com", "waf", "ModSecurity")
        profile = intel.get_target_profile("https://example.com")
        assert profile.domain == "example.com"
        assert profile.total_findings >= 1
        assert profile.waf_name != ""
        assert len(profile.defences) >= 1

    def test_intel_report_context_string(self, intel):
        intel.record_scan_result(target="https://x.com", vuln_type="XSS", payload="test", success=True, scan_id="s1")
        intel.record_defence("https://x.com", "waf", "Cloudflare")
        report = intel.query_intelligence("https://x.com")
        ctx = report.to_context_string()
        assert "x.com" in ctx
        assert "WAF" in ctx or "waf" in ctx.lower()

    def test_ai_decision_recording(self, intel):
        intel.record_ai_decision("https://example.com", "xss", "Found a reflected parameter", "Testing payloads")
        # Query the database directly to verify
        with intel._conn() as conn:
            row = conn.execute("SELECT * FROM ai_decisions WHERE target=?", ("https://example.com",)).fetchone()
            assert row is not None
            assert row["module"] == "xss"
            assert row["reasoning"] == "Found a reflected parameter"
            assert row["action"] == "Testing payloads"
