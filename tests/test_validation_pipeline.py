"""Tests for the Finding Validation Pipeline."""
import pytest
from utils.validation_pipeline import ValidationPipeline, STAGE_ORDER


@pytest.fixture
def pipeline():
    return ValidationPipeline(verify_replay=False)


class TestValidationPipeline:
    def test_finding_with_evidence_passes_gate0(self, pipeline):
        finding = {
            "type": "XSS", "severity": "high", "payload": "<script>alert(1)</script>",
            "url": "https://example.com/search?q=test",
            "response_snippet": "Result: <script>alert(1)</script>",
        }
        result = pipeline.validate_finding(finding)
        assert result["validation_stage"] in ("verified", "confirmed", "exploitable")
        assert result["validation_gates"]["gate_0_evidence"]["passed"] is True

    def test_finding_without_evidence_stays_suspected(self, pipeline):
        finding = {
            "type": "SQLi", "severity": "high",
            "url": "https://example.com/login",
            "description": "Potential SQL injection",
        }
        result = pipeline.validate_finding(finding)
        assert result["validation_stage"] == "suspected"

    def test_info_finding_auto_passes(self, pipeline):
        finding = {
            "type": "Missing_Header", "severity": "info",
            "url": "https://example.com",
            "description": "Missing X-Content-Type-Options header",
        }
        result = pipeline.validate_finding(finding)
        assert result["validation_stage"] in ("verified", "confirmed")

    def test_waf_block_fails_gate2(self, pipeline):
        finding = {
            "type": "XSS", "severity": "high",
            "payload": "<script>alert(1)</script>",
            "url": "https://example.com/search",
            "evidence": "Access Denied by Cloudflare WAF",
            "description": "Request was blocked by Cloudflare",
        }
        result = pipeline.validate_finding(finding)
        g2 = result["validation_gates"].get("gate_2_exploitable", {})
        assert g2.get("passed") is False or result["validation_stage"] in ("suspected", "evidence_confirmed")

    def test_static_asset_fp_gate3(self, pipeline):
        finding = {
            "type": "XSS", "severity": "high",
            "payload": "<script>", "evidence": "found",
            "url": "https://example.com/styles/main.css",
        }
        result = pipeline.validate_finding(finding)
        g3 = result["validation_gates"].get("gate_3_no_false_positive", {})
        assert g3.get("passed") is False

    def test_injection_without_payload_is_fp(self, pipeline):
        finding = {
            "type": "SQLi", "severity": "high",
            "url": "https://example.com/page",
            "evidence": "error detected",
            "description": "Possible SQL injection",
        }
        result = pipeline.validate_finding(finding)
        # Should be caught by gate 3 as FP (injection type without payload)
        g3 = result.get("validation_gates", {}).get("gate_3_no_false_positive", {})
        if g3:
            assert g3.get("passed") is False

    def test_validate_batch(self, pipeline):
        findings = [
            {"type": "XSS", "severity": "high", "payload": "<script>", "evidence": "reflected",
             "url": "https://a.com", "response_snippet": "<script>"},
            {"type": "SQLi", "severity": "high", "url": "https://b.com",
             "description": "maybe sqli"},
        ]
        validated, suspected = pipeline.validate_batch(findings)
        assert len(validated) + len(suspected) == 2

    def test_promote(self):
        finding = {"validation_stage": "suspected"}
        result = ValidationPipeline.promote(finding, reason="manual review")
        assert result["validation_stage"] == "evidence_confirmed"
        assert len(result["validation_history"]) == 1

    def test_demote(self):
        finding = {"validation_stage": "confirmed"}
        result = ValidationPipeline.demote(finding, reason="false positive")
        assert result["validation_stage"] == "suspected"
        assert result["demote_reason"] == "false positive"

    def test_validation_history_tracking(self, pipeline):
        finding = {
            "type": "Missing_Header", "severity": "info",
            "url": "https://example.com", "description": "Missing CSP",
        }
        result = pipeline.validate_finding(finding)
        assert "validation_history" in result
        assert len(result["validation_history"]) >= 1

    def test_ai_verified_passes_gate3(self, pipeline):
        finding = {
            "type": "XSS", "severity": "high",
            "payload": "<script>alert(1)</script>",
            "evidence": "payload reflected",
            "url": "https://example.com/search",
            "ai_verified": True,
        }
        result = pipeline.validate_finding(finding)
        g3 = result["validation_gates"].get("gate_3_no_false_positive", {})
        assert g3.get("passed") is True
