"""
Tests for utils/finding.py and modules/passive.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.finding import (
    AttackPath,
    Finding,
    Observation,
    build_scan_artifacts,
    normalize_vuln,
    normalize_all,
    generate_sarif,
    VULN_REGISTRY,
)
from modules.passive import scan_passive, SECURITY_HEADERS, SECRET_PATTERNS


class TestFinding:
    """Tests for Finding dataclass."""

    def test_finding_creation(self):
        f = Finding(
            title="Test XSS",
            severity="high",
            cvss=6.1,
            cwe="CWE-79",
            url="https://example.com",
            module="XSS_Param",
        )
        assert f.title == "Test XSS"
        assert f.severity == "high"
        assert f.cvss == 6.1
        assert f.cwe == "CWE-79"

    def test_finding_to_dict(self):
        f = Finding(
            title="Test",
            severity="high",
            cvss=6.1,
            cwe="CWE-79",
            url="https://example.com",
            module="XSS_Param",
            id="finding_1",
            asset_id="asset_1",
            surface="web",
            verification_state="verified",
            exploitability="medium",
        )
        d = f.to_dict()
        assert "title" in d
        assert "url" in d
        assert d["type"] == "XSS_Param"
        assert d["verification_state"] == "verified"
        assert d["exploitability"] == "medium"
        # None values should be excluded
        assert "context" not in d
        assert "source" not in d

    def test_finding_to_sarif_result(self):
        f = Finding(
            title="SQL Injection",
            severity="critical",
            cvss=9.8,
            cwe="CWE-89",
            url="https://example.com/login",
            module="SQLi_Param",
            param="id",
            payload="' OR 1=1--",
        )
        sarif = f.to_sarif_result()
        assert sarif["ruleId"] == "CWE-89"
        assert sarif["level"] == "error"
        assert (
            sarif["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            == "https://example.com/login"
        )


class TestVulnRegistry:
    """Tests for CVSS/CWE registry."""

    def test_registry_has_xss(self):
        assert "XSS_Param" in VULN_REGISTRY
        assert VULN_REGISTRY["XSS_Param"]["cwe"] == "CWE-79"

    def test_registry_has_sqli(self):
        assert "SQLi_Param" in VULN_REGISTRY
        assert VULN_REGISTRY["SQLi_Param"]["cvss"] == 9.8

    def test_registry_has_cmdi(self):
        assert "CMDi_Param" in VULN_REGISTRY
        assert VULN_REGISTRY["CMDi_Param"]["cwe"] == "CWE-78"

    def test_all_entries_have_required_fields(self):
        for vuln_type, info in VULN_REGISTRY.items():
            assert "severity" in info, f"{vuln_type} missing severity"
            assert "cvss" in info, f"{vuln_type} missing cvss"
            assert "cwe" in info, f"{vuln_type} missing cwe"
            assert "title" in info, f"{vuln_type} missing title"
            assert "remediation" in info, f"{vuln_type} missing remediation"

    def test_cvss_range(self):
        for vuln_type, info in VULN_REGISTRY.items():
            assert 0.0 <= info["cvss"] <= 10.0, f"{vuln_type} CVSS out of range"

    def test_minimum_registry_size(self):
        assert len(VULN_REGISTRY) >= 35


class TestNormalizeVuln:
    """Tests for normalize_vuln."""

    def test_known_type(self):
        vuln = {
            "type": "XSS_Param",
            "url": "https://x.com",
            "param": "q",
            "payload": "<script>",
        }
        f = normalize_vuln(vuln)
        assert f.severity == "high"
        assert f.cvss == 6.1
        assert f.cwe == "CWE-79"
        assert f.param == "q"

    def test_unknown_type(self):
        vuln = {"type": "SomethingNew", "url": "https://x.com"}
        f = normalize_vuln(vuln)
        assert f.cwe == "CWE-0"
        assert f.cvss == 5.0

    def test_severity_override(self):
        """If the module provides a severity, it should be used."""
        vuln = {"type": "CORS_Misconfig", "url": "https://x.com", "severity": "HIGH"}
        f = normalize_vuln(vuln)
        assert f.severity == "high"

    def test_normalize_all(self):
        vulns = [
            {"type": "XSS_Param", "url": "https://x.com"},
            {"type": "SQLi_Form", "url": "https://y.com"},
        ]
        findings = normalize_all(vulns)
        assert len(findings) == 2
        assert findings[0].cwe == "CWE-79"
        assert findings[1].cwe == "CWE-89"

    def test_normalize_preserves_request_and_response_context(self):
        finding = normalize_vuln(
            {
                "type": "API_Unauth_Access",
                "url": "https://api.example.com/private",
                "description": "Protected endpoint accessible without auth.",
                "request_method": "GET",
                "response_snippet": '{"id":1}',
                "repro_steps": ["GET /private without auth"],
            }
        )

        assert finding.finding_type == "API_Unauth_Access"
        assert finding.request == {"method": "GET"}
        assert finding.response_snippet == '{"id":1}'
        assert finding.repro_steps == ["GET /private without auth"]

    def test_normalize_assigns_reasoning_fields(self):
        finding = normalize_vuln(
            {
                "type": "SQLi_Param",
                "url": "https://app.example.com/item?id=1",
                "param": "id",
                "payload": "' OR 1=1--",
                "evidence": "SQL syntax error returned by server",
            }
        )

        assert finding.id.startswith("finding_")
        assert finding.asset_id.startswith("asset_")
        assert finding.surface == "web"
        assert finding.verification_state == "verified"
        assert finding.exploitability == "medium"
        assert finding.observation_refs
        assert finding.replay_recipe["url"] == "https://app.example.com/item?id=1"

    def test_build_scan_artifacts_returns_observations_and_attack_paths(self):
        artifacts = build_scan_artifacts(
            [
                {
                    "type": "SSRF_Param",
                    "url": "https://app.example.com/proxy",
                    "param": "url",
                    "payload": "http://169.254.169.254/latest/meta-data/",
                }
            ]
        )

        assert len(artifacts["observations"]) == 1
        assert isinstance(artifacts["observations"][0], Observation)
        assert len(artifacts["findings"]) == 1
        assert artifacts["findings"][0].attack_path_refs
        assert artifacts["attack_paths"]
        assert isinstance(artifacts["attack_paths"][0], AttackPath)


class TestSARIF:
    """Tests for SARIF output generation."""

    def test_sarif_structure(self):
        findings = [
            Finding(
                title="XSS",
                severity="high",
                cvss=6.1,
                cwe="CWE-79",
                url="https://x.com",
                module="XSS_Param",
            ),
        ]
        sarif = generate_sarif(findings)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "cyberm4fia-scanner"
        assert len(sarif["runs"][0]["results"]) == 1

    def test_sarif_multiple_findings(self):
        findings = [
            Finding(
                title="XSS",
                severity="high",
                cvss=6.1,
                cwe="CWE-79",
                url="https://x.com",
                module="XSS_Param",
            ),
            Finding(
                title="SQLi",
                severity="critical",
                cvss=9.8,
                cwe="CWE-89",
                url="https://y.com",
                module="SQLi_Param",
            ),
        ]
        sarif = generate_sarif(findings)
        assert len(sarif["runs"][0]["results"]) == 2
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 2


class TestPassiveScanner:
    """Tests for passive scanning module."""

    def test_missing_security_headers(self):
        findings = scan_passive("https://example.com", headers={}, body="<html></html>")
        header_findings = [
            f for f in findings if f["type"] == "Missing_Security_Header"
        ]
        assert len(header_findings) == len(SECURITY_HEADERS)

    def test_no_missing_headers_when_all_present(self):
        headers = {h: "some-value" for h in SECURITY_HEADERS}
        findings = scan_passive(
            "https://example.com", headers=headers, body="<html></html>"
        )
        header_findings = [
            f for f in findings if f["type"] == "Missing_Security_Header"
        ]
        assert len(header_findings) == 0

    def test_detect_aws_key(self):
        body = 'var key = "AKIAIOSFODNN7EXAMPLE";'
        findings = scan_passive("https://example.com", headers={}, body=body)
        secret_findings = [f for f in findings if f["type"] == "Secret_Leak"]
        assert len(secret_findings) >= 1
        assert any("AWS" in f["param"] for f in secret_findings)

    def test_detect_github_token(self):
        body = 'token: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
        findings = scan_passive("https://example.com", headers={}, body=body)
        secret_findings = [f for f in findings if f["type"] == "Secret_Leak"]
        assert len(secret_findings) >= 1

    def test_detect_python_traceback(self):
        body = "Traceback (most recent call last):\n  File 'app.py', line 42"
        findings = scan_passive("https://example.com", headers={}, body=body)
        debug_findings = [f for f in findings if f["type"] == "Debug_Info"]
        assert len(debug_findings) >= 1

    def test_detect_internal_ip(self):
        body = "Server at 192.168.1.100:8080"
        findings = scan_passive("https://example.com", headers={}, body=body)
        ip_findings = [f for f in findings if f["type"] == "Internal_IP_Leak"]
        assert len(ip_findings) >= 1

    def test_detect_server_version(self):
        headers = {"Server": "Apache/2.4.51"}
        findings = scan_passive("https://example.com", headers=headers, body="")
        debug_findings = [f for f in findings if f["type"] == "Debug_Info"]
        assert len(debug_findings) >= 1

    def test_detect_x_powered_by(self):
        headers = {"X-Powered-By": "PHP/7.4.3"}
        findings = scan_passive("https://example.com", headers=headers, body="")
        debug_findings = [f for f in findings if f["type"] == "Debug_Info"]
        assert len(debug_findings) >= 1

    def test_clean_response(self):
        headers = {h: "val" for h in SECURITY_HEADERS}
        headers["Server"] = "nginx"
        findings = scan_passive(
            "https://example.com", headers=headers, body="<html>Clean page</html>"
        )
        assert len(findings) == 0

    def test_secret_patterns_count(self):
        assert len(SECRET_PATTERNS) >= 14
