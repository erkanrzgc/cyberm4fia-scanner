"""Tests for the 6 new vulnerability modules added in the wapiti gap-fill.

All HTTP traffic is mocked — no live network calls. Each module gets a
small focused test that verifies the happy-path detection and at least
one negative case so we don't drown in false positives.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


pytestmark = pytest.mark.unit


# ─── Test helpers ────────────────────────────────────────────────────────────


def _resp(status_code: int = 200, text: str = "", headers: dict | None = None):
    r = MagicMock()
    r.status_code = status_code
    r.text = text
    r.headers = headers or {}
    return r


# ─── CRLF Injection ──────────────────────────────────────────────────────────


class TestCRLF:
    def test_detects_injected_sentinel_header(self):
        from modules.crlf import SENTINEL_HEADER_NAME, SENTINEL_HEADER_VALUE, scan_crlf

        # Server reflects the sentinel — vulnerable.
        vulnerable = _resp(
            status_code=200, text="ok",
            headers={SENTINEL_HEADER_NAME: SENTINEL_HEADER_VALUE},
        )

        with patch("modules.crlf.smart_request", return_value=vulnerable):
            findings = scan_crlf("http://t/?q=1", threads=1)

        assert len(findings) == 1
        f = findings[0]
        assert f["type"] == "CRLF_Injection"
        assert f["param"] == "q"
        assert f["severity"] == "High"

    def test_no_finding_when_sentinel_not_reflected(self):
        from modules.crlf import scan_crlf

        # Server returns a clean response — no header reflection.
        with patch("modules.crlf.smart_request", return_value=_resp(text="ok")):
            findings = scan_crlf("http://t/?q=1", threads=1)
        assert findings == []

    def test_skips_when_no_query_params(self):
        from modules.crlf import scan_crlf
        with patch("modules.crlf.smart_request") as m:
            findings = scan_crlf("http://t/", threads=1)
        assert findings == []
        m.assert_not_called()


# ─── LDAP Injection ──────────────────────────────────────────────────────────


class TestLDAP:
    def test_detects_ldap_error_in_response(self):
        from modules.ldap import scan_ldap_injection

        baseline = _resp(text="welcome")
        # First probe → server emits a JNDI/LDAP error.
        vuln_resp = _resp(
            status_code=500,
            text="javax.naming.directory.InvalidSearchFilterException: Bad search filter",
        )

        # First call is the baseline (clean), subsequent calls are probes.
        responses = [baseline] + [vuln_resp] * 20

        with patch("modules.ldap.smart_request", side_effect=responses):
            findings = scan_ldap_injection("http://t/?user=bob", threads=1)

        assert findings
        f = findings[0]
        assert f["type"] == "LDAP_Injection"
        assert f["param"] == "user"
        assert f["severity"] == "High"

    def test_skips_if_baseline_already_dirty(self):
        from modules.ldap import scan_ldap_injection

        # Baseline already contains an LDAP error → can't distinguish injection.
        dirty = _resp(text="LDAPException occurred earlier")

        with patch("modules.ldap.smart_request", return_value=dirty):
            findings = scan_ldap_injection("http://t/?user=bob", threads=1)
        assert findings == []


# ─── Log4Shell ───────────────────────────────────────────────────────────────


class TestLog4Shell:
    def test_emits_probe_finding_per_vector(self):
        from modules.log4shell import scan_log4shell

        with patch("modules.log4shell.smart_request", return_value=_resp(text="ok")):
            findings = scan_log4shell("http://t/?q=1", threads=2)

        # 8 header vectors + 1 param vector = 9 probes.
        assert len(findings) == 9
        types = {f["type"] for f in findings}
        assert types == {"Log4Shell_Probe"}
        # Every finding must have an OOB token.
        for f in findings:
            assert f["oob_token"]
            assert f["validation_state"] == "probe_sent"
            assert "${jndi:ldap://" in f["payload"]

    def test_uses_oob_server_env_var(self, monkeypatch):
        from modules import log4shell

        monkeypatch.setenv("OOB_SERVER", "custom-collab.example")
        with patch("modules.log4shell.smart_request", return_value=_resp()):
            findings = log4shell.scan_log4shell("http://t/", threads=1)

        assert all("custom-collab.example" in f["payload"] for f in findings)


# ─── Shellshock ──────────────────────────────────────────────────────────────


class TestShellshock:
    def test_detects_token_reflection(self):
        from modules.shellshock import scan_shellshock

        # Build a response that contains *any* token reflection. Since the
        # token is generated per-call, we let the function generate it and
        # then return that exact token in the body.
        captured_tokens: list[str] = []

        def fake_request(method, url, **kwargs):
            payload = kwargs["headers"][next(iter(kwargs["headers"]))]
            # Token is the last hex chunk in our payload echo
            import re
            m = re.search(r"echo '([0-9a-f]+)'", payload)
            if m:
                captured_tokens.append(m.group(1))
                return _resp(text=f"<html>{m.group(1)} reflected</html>")
            return _resp(text="ok")

        with patch("modules.shellshock.smart_request", side_effect=fake_request):
            findings = scan_shellshock("http://t/", paths=["/cgi-bin/test.cgi"])

        assert findings
        assert findings[0]["type"] == "Shellshock"
        assert findings[0]["cve"] == "CVE-2014-6271"
        assert findings[0]["severity"] == "Critical"

    def test_no_finding_on_clean_response(self):
        from modules.shellshock import scan_shellshock
        with patch("modules.shellshock.smart_request", return_value=_resp(text="hello world")):
            findings = scan_shellshock("http://t/", paths=["/"])
        assert findings == []


# ─── HTTP Method Abuse ───────────────────────────────────────────────────────


class TestHttpMethods:
    def test_flags_advertised_dangerous_methods(self):
        from modules.http_methods import scan_http_methods

        # OPTIONS returns Allow: GET, PUT, DELETE
        opts = _resp(headers={"Allow": "GET, PUT, DELETE"})

        # All other methods → 405 except GET (200) so the active probe
        # also flags PUT/DELETE as accepted.
        def fake(method, url, **kwargs):
            method = method.upper()
            if method == "OPTIONS":
                return opts
            if method in ("PUT", "DELETE"):
                return _resp(status_code=200)
            return _resp(status_code=405)

        with patch("modules.http_methods.smart_request", side_effect=fake):
            findings = scan_http_methods("http://t/")

        types = {f["type"] for f in findings}
        assert "HTTP_Method_Advertised" in types
        assert "HTTP_Method_Accepted" in types

    def test_detects_trace_xst(self):
        from modules.http_methods import scan_http_methods

        def fake(method, url, **kwargs):
            method = method.upper()
            if method == "OPTIONS":
                return _resp(headers={})
            if method == "TRACE":
                return _resp(status_code=200)
            return _resp(status_code=405)

        with patch("modules.http_methods.smart_request", side_effect=fake):
            findings = scan_http_methods("http://t/")
        types = {f["type"] for f in findings}
        assert "HTTP_TRACE_Enabled" in types

    def test_clean_server_no_findings(self):
        from modules.http_methods import scan_http_methods

        with patch("modules.http_methods.smart_request",
                   return_value=_resp(status_code=405, headers={})):
            findings = scan_http_methods("http://t/")
        assert findings == []


# ─── CMS Enumeration ─────────────────────────────────────────────────────────


class TestCMSEnum:
    def test_detects_wordpress_via_login_page(self):
        from modules.cms_enum import scan_cms_enum

        def fake(method, url, **kwargs):
            if "/wp-login.php" in url:
                return _resp(text="<form id='loginform'>Powered by WordPress</form>")
            if "/readme.html" in url:
                return _resp(text="WordPress 6.4.2 readme")
            if "/wp-json/" in url:
                return _resp(text='{"namespace":"wp/v2","routes":{}}')
            # Generic GET to base — generator meta
            return _resp(text='<meta name="generator" content="WordPress 6.4.2"/>')

        with patch("modules.cms_enum.smart_request", side_effect=fake):
            findings = scan_cms_enum("http://target.test/")

        assert findings
        wp = next(f for f in findings if f["cms"] == "WordPress")
        assert wp["version"] == "6.4.2"
        assert wp["confidence"] == 90

    def test_detects_drupal_via_x_generator_header(self):
        from modules.cms_enum import scan_cms_enum

        def fake(method, url, **kwargs):
            if url.endswith("/"):
                return _resp(headers={"X-Generator": "Drupal 9.5.11 (https://www.drupal.org)"},
                             text="")
            if "CHANGELOG.txt" in url:
                return _resp(text="Drupal 9.5.11, 2024-01-15")
            return _resp(status_code=404)

        with patch("modules.cms_enum.smart_request", side_effect=fake):
            findings = scan_cms_enum("http://target.test/")

        drupal = next(f for f in findings if f["cms"] == "Drupal")
        assert drupal["version"] == "9.5.11"

    def test_clean_target_no_findings(self):
        from modules.cms_enum import scan_cms_enum
        with patch("modules.cms_enum.smart_request",
                   return_value=_resp(status_code=404, text="")):
            findings = scan_cms_enum("http://target.test/")
        assert findings == []
