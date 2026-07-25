"""Tests for concrete external-tool wrappers: arjun, sslyze, wpscan.

Each wrapper is tested for (1) command construction and (2) defensive parsing
of representative tool output into structured data + findings.
"""

from __future__ import annotations

import json

import pytest

from utils.external_tools.arjun import ArjunTool
from utils.external_tools.cloudhunter import CloudHunterTool
from utils.external_tools.gitleaks import GitleaksTool
from utils.external_tools.gowitness import GowitnessTool
from utils.external_tools.kube_hunter import KubeHunterTool
from utils.external_tools.smbmap import SmbmapTool
from utils.external_tools.sslyze import SslyzeTool
from utils.external_tools.testssl import TestsslTool
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


# ─── testssl.sh: deep TLS auditor ─────────────────────────────────────────────


class TestTestsslTool:
    def test_command_emits_json_to_stdout(self):
        cmd = TestsslTool().get_command("t.example:443")
        assert "t.example:443" in cmd
        # /dev/stdout is the Linux-portable way to direct file output to stdout
        assert any("/dev/stdout" in part for part in cmd)

    def test_parses_actionable_vulnerabilities(self):
        out = json.dumps([
            {"id": "heartbleed", "ip": "1.2.3.4", "port": "443",
             "severity": "CRITICAL", "finding": "VULNERABLE - Heartbleed"},
            {"id": "ROBOT", "severity": "HIGH", "finding": "VULNERABLE"},
            {"id": "scanProblem", "severity": "INFO", "finding": "scan started"},
            {"id": "cert_notBefore", "severity": "OK", "finding": "valid"},
        ])
        parsed = TestsslTool().parse_output(out, "", 0)
        ids = {v["id"] for v in parsed["vulnerabilities"]}
        # INFO / OK should be filtered out.
        assert ids == {"heartbleed", "ROBOT"}

    def test_to_findings_carries_severity(self):
        parsed = {"vulnerabilities": [
            {"id": "heartbleed", "severity": "CRITICAL",
             "finding": "VULNERABLE - Heartbleed"},
        ]}
        findings = TestsslTool().to_findings(parsed, target="t.example:443")
        assert findings[0]["type"] == "TLS_Vulnerability"
        assert findings[0]["severity"] == "critical"
        assert "heartbleed" in findings[0]["title"].lower()


# ─── smbmap: SMB share enumeration ────────────────────────────────────────────


_SMBMAP_OUT = """[+] IP: 192.0.2.10:445  Name: HOST01
        Disk                                                  Permissions
        ----                                                  -----------
        ADMIN$                                                NO ACCESS
        C$                                                    NO ACCESS
        IPC$                                                  READ ONLY
        Users                                                 READ, WRITE
"""


class TestSmbmapTool:
    def test_command_targets_host(self):
        cmd = SmbmapTool().get_command("192.0.2.10")
        assert "192.0.2.10" in cmd
        assert "-H" in cmd

    def test_parses_share_permissions(self):
        parsed = SmbmapTool().parse_output(_SMBMAP_OUT, "", 0)
        shares = {s["share"]: s["permission"] for s in parsed["shares"]}
        assert shares["IPC$"] == "READ ONLY"
        assert shares["Users"] == "READ, WRITE"
        assert shares["C$"] == "NO ACCESS"

    def test_to_findings_only_for_accessible_shares(self):
        parsed = {"shares": [
            {"share": "Users", "permission": "READ, WRITE"},
            {"share": "IPC$", "permission": "READ ONLY"},
            {"share": "C$", "permission": "NO ACCESS"},
        ]}
        findings = SmbmapTool().to_findings(parsed, target="192.0.2.10")
        # NO ACCESS shares must not be surfaced as findings. Match the share
        # name as the title's quoted token to avoid IPC$ matching "C$".
        titles = [f["title"] for f in findings]
        assert any("'Users'" in t for t in titles)
        assert not any("'C$'" in t for t in titles)
        writable = next(f for f in findings if "'Users'" in f["title"])
        assert writable["severity"] == "high"   # writable share is high-impact


# ─── kube-hunter: Kubernetes cluster scanner ──────────────────────────────────


class TestKubeHunterTool:
    def test_command_passes_remote_and_json(self):
        cmd = KubeHunterTool().get_command("https://kube.test:6443")
        assert "https://kube.test:6443" in cmd
        assert "--remote" in cmd
        assert "--report" in cmd and "json" in cmd

    def test_parses_vulnerabilities(self):
        out = json.dumps({
            "vulnerabilities": [
                {"vulnerability": "Anonymous Authentication",
                 "description": "API server allows anonymous",
                 "severity": "high", "category": "Access Risk"},
                {"vulnerability": "K8s Version Disclosure",
                 "severity": "low", "category": "Information Disclosure"},
            ]
        })
        parsed = KubeHunterTool().parse_output(out, "", 0)
        assert parsed["count"] == 2

    def test_to_findings_normalizes_severity(self):
        parsed = {"vulnerabilities": [
            {"vulnerability": "Anonymous Authentication", "severity": "high"},
        ]}
        findings = KubeHunterTool().to_findings(parsed, target="https://kube.test:6443")
        assert findings[0]["type"] == "Kubernetes_Vuln"
        assert findings[0]["severity"] == "high"


# ─── gowitness: visual recon (HTTP screenshots) ───────────────────────────────


class TestGowitnessTool:
    def test_command_uses_scan_single_with_url(self):
        cmd = GowitnessTool().get_command("https://t.example/")
        assert "scan" in cmd and "single" in cmd
        assert "https://t.example/" in cmd
        # v3 writes JSON to stdout via --write-stdout
        assert "--write-stdout" in cmd

    def test_parses_capture_metadata(self):
        out = json.dumps({
            "url": "https://t.example/",
            "final_url": "https://t.example/login",
            "title": "Welcome",
            "status_code": 200,
            "screenshot_path": "/tmp/shots/t.png",
        })
        parsed = GowitnessTool().parse_output(out, "", 0)
        assert parsed["count"] == 1
        cap = parsed["captures"][0]
        assert cap["title"] == "Welcome"
        assert cap["status"] == 200
        assert cap["screenshot"] == "/tmp/shots/t.png"

    def test_to_findings_info_level(self):
        parsed = {"captures": [
            {"url": "https://t.example/", "title": "Welcome",
             "status": 200, "screenshot": "/tmp/shots/t.png"},
        ]}
        findings = GowitnessTool().to_findings(parsed, target="https://t.example/")
        assert findings[0]["type"] == "Visual_Capture"
        assert findings[0]["severity"] == "info"
        assert "Welcome" in findings[0]["evidence"]


# ─── gitleaks: secrets detection on a local source path ───────────────────────


class TestGitleaksTool:
    def test_command_targets_source_path_with_json_stdout(self):
        cmd = GitleaksTool().get_command("/path/to/repo")
        assert "/path/to/repo" in cmd
        assert "detect" in cmd
        assert "--report-format" in cmd and "json" in cmd
        assert "--report-path" in cmd and "/dev/stdout" in cmd

    def test_parses_leak_records(self):
        out = json.dumps([
            {"RuleID": "aws-access-key", "Description": "AWS Access Key",
             "File": "config/aws.env", "StartLine": 4,
             "Secret": "AKIA....", "Match": "AKIA...."},
            {"RuleID": "github-pat", "Description": "GitHub PAT",
             "File": "scripts/deploy.sh", "StartLine": 12,
             "Secret": "ghp_xxx", "Match": "ghp_xxx"},
        ])
        parsed = GitleaksTool().parse_output(out, "", 1)   # gitleaks exits 1 when leaks found
        assert parsed["count"] == 2
        rules = {leak["rule"] for leak in parsed["leaks"]}
        assert rules == {"aws-access-key", "github-pat"}

    def test_to_findings_marks_high_severity(self):
        parsed = {"leaks": [
            {"rule": "aws-access-key", "description": "AWS Access Key",
             "file": "config/aws.env", "line": 4},
        ]}
        findings = GitleaksTool().to_findings(parsed, target="/path/to/repo")
        assert findings[0]["type"] == "Secret_Leak"
        assert findings[0]["severity"] == "high"
        assert "aws-access-key" in findings[0]["title"]


# ─── CloudHunter: multi-cloud bucket enumeration ──────────────────────────────


class TestCloudHunterTool:
    def test_command_targets_domain(self):
        cmd = CloudHunterTool().get_command("example.com")
        assert "example.com" in cmd

    def test_parses_found_buckets_with_cloud_and_acl(self):
        out = (
            "[*] Scanning example.com\n"
            "[FOUND] aws example-prod (public-read)\n"
            "[FOUND] gcp example-stg (private)\n"
            "[FOUND] azure example-bak (PublicRead)\n"
            "[*] Done\n"
        )
        parsed = CloudHunterTool().parse_output(out, "", 0)
        assert parsed["count"] == 3
        clouds = {b["cloud"] for b in parsed["buckets"]}
        assert clouds == {"aws", "gcp", "azure"}

    def test_to_findings_escalates_public_buckets(self):
        parsed = {"buckets": [
            {"cloud": "aws", "name": "example-prod", "acl": "public-read"},
            {"cloud": "gcp", "name": "example-stg", "acl": "private"},
        ]}
        findings = CloudHunterTool().to_findings(parsed, target="example.com")
        sev = {f["title"]: f["severity"] for f in findings}
        # Public bucket = high; private discovery = info recon entry.
        public_title = next(t for t in sev if "example-prod" in t)
        private_title = next(t for t in sev if "example-stg" in t)
        assert sev[public_title] == "high"
        assert sev[private_title] == "info"
