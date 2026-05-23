"""Tests for concrete external-tool wrappers: arjun, sslyze, wpscan.

Each wrapper is tested for (1) command construction and (2) defensive parsing
of representative tool output into structured data + findings.
"""

from __future__ import annotations

import json

import pytest

from utils.external_tools.arjun import ArjunTool
from utils.external_tools.sslyze import SslyzeTool
from utils.external_tools.wpscan import WpscanTool

pytestmark = pytest.mark.unit


# ─── arjun: HTTP parameter discovery ──────────────────────────────────────────


class TestArjunTool:
    def test_command_targets_url_and_emits_json(self):
        cmd = ArjunTool().get_command("https://t/api")
        assert "https://t/api" in cmd
        assert "-u" in cmd
        assert "-oJ" in cmd  # JSON output

    def test_parses_discovered_params(self):
        out = json.dumps({"https://t/api": ["id", "user", "debug"]})
        parsed = ArjunTool().parse_output(out, "", 0)
        assert parsed["count"] == 3
        assert set(parsed["params"]["https://t/api"]) == {"id", "user", "debug"}

    def test_parse_tolerates_log_noise_before_json(self):
        out = "[*] Scanning...\n[+] done\n" + json.dumps({"https://t/": ["q"]})
        parsed = ArjunTool().parse_output(out, "", 0)
        assert parsed["count"] == 1

    def test_to_findings_emits_param_discovery_per_endpoint(self):
        parsed = {"params": {"https://t/api": ["id", "user"]}, "count": 2}
        findings = ArjunTool().to_findings(parsed)
        assert len(findings) == 1
        assert findings[0]["url"] == "https://t/api"
        assert "id" in findings[0]["evidence"]


# ─── sslyze: TLS configuration audit ──────────────────────────────────────────


def _sslyze_json(*, ssl2=False, ssl3=False, tls10=False, tls11=False):
    def block(accepted):
        return {"result": {"accepted_cipher_suites":
                           [{"cipher_suite": {"name": "X"}}] if accepted else []}}
    return json.dumps({
        "server_scan_results": [{
            "scan_result": {
                "ssl_2_0_cipher_suites": block(ssl2),
                "ssl_3_0_cipher_suites": block(ssl3),
                "tls_1_0_cipher_suites": block(tls10),
                "tls_1_1_cipher_suites": block(tls11),
                "tls_1_2_cipher_suites": block(True),
            }
        }]
    })


class TestSslyzeTool:
    def test_command_emits_json_to_stdout(self):
        cmd = SslyzeTool().get_command("t.example:443")
        assert "t.example:443" in cmd
        assert any("json" in part for part in cmd)

    def test_flags_weak_protocols_only(self):
        parsed = SslyzeTool().parse_output(_sslyze_json(ssl3=True, tls10=True), "", 0)
        assert set(parsed["weak_protocols"]) == {"SSLv3", "TLS 1.0"}

    def test_clean_config_has_no_weak_protocols(self):
        parsed = SslyzeTool().parse_output(_sslyze_json(), "", 0)
        assert parsed["weak_protocols"] == []

    def test_to_findings_severity_reflects_protocol(self):
        parsed = {"weak_protocols": ["SSLv2", "TLS 1.0"]}
        findings = SslyzeTool().to_findings(parsed, target="t.example")
        sev = {f["title"]: f["severity"] for f in findings}
        assert sev["SSLv2 enabled"] == "critical"
        assert sev["TLS 1.0 enabled"] == "medium"


# ─── wpscan: WordPress vulnerability scan ─────────────────────────────────────


class TestWpscanTool:
    def test_command_targets_url_json_no_banner(self):
        cmd = WpscanTool().get_command("https://wp.test")
        assert "https://wp.test" in cmd
        assert "--url" in cmd
        assert "--format" in cmd and "json" in cmd

    def test_collects_version_and_plugin_vulnerabilities(self):
        out = json.dumps({
            "version": {"number": "5.0",
                        "vulnerabilities": [{"title": "Core XSS"}]},
            "plugins": {"contact-form": {
                "vulnerabilities": [{"title": "CF SQLi"}]}},
        })
        parsed = WpscanTool().parse_output(out, "", 0)
        assert parsed["count"] == 2
        titles = {v["title"] for v in parsed["vulnerabilities"]}
        assert titles == {"Core XSS", "CF SQLi"}

    def test_no_vulnerabilities_yields_empty(self):
        out = json.dumps({"version": {"number": "6.0"}, "plugins": {}})
        parsed = WpscanTool().parse_output(out, "", 0)
        assert parsed["count"] == 0

    def test_to_findings_tags_source(self):
        parsed = {"vulnerabilities": [
            {"title": "CF SQLi", "source": "plugin:contact-form"}], "count": 1}
        findings = WpscanTool().to_findings(parsed, target="https://wp.test")
        assert findings[0]["type"] == "WordPress_Vuln"
        assert "CF SQLi" in findings[0]["title"]
