"""Tests for modules/forbidden_bypass.py — 403/401 bypass detection.

All HTTP traffic is mocked. Focus is on the bypass-403 gap-fill payloads
(X-Forwarded-For variants, wildcard suffix, POST + Content-Length: 0)
plus baseline filtering and regression guards on the payload tables.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from modules.forbidden_bypass import (
    BYPASS_HEADERS_IP,
    PATH_MUTATIONS,
    _test_header_bypass,
    _test_method_bypass,
    scan_forbidden_bypass,
)


pytestmark = pytest.mark.unit


def _resp(status_code: int = 200, text: str = "", headers: dict | None = None):
    r = MagicMock()
    r.status_code = status_code
    r.text = text
    r.headers = headers or {}
    return r


class TestPayloadRegression:
    """Guard that the bypass-403 gap-fill payloads stay in the tables."""

    def test_xff_scheme_prefixed_present(self):
        assert ("X-Forwarded-For", "http://127.0.0.1") in BYPASS_HEADERS_IP

    def test_xff_port_suffixed_present(self):
        assert ("X-Forwarded-For", "127.0.0.1:80") in BYPASS_HEADERS_IP

    def test_wildcard_suffix_present(self):
        assert "{path}/*" in PATH_MUTATIONS


class TestHeaderBypass:
    def test_finds_bypass_via_xff_scheme_variant(self):
        # Default 403, but 200 when X-Forwarded-For: http://127.0.0.1 is sent.
        def fake_request(method, url, **kwargs):
            headers = kwargs.get("headers") or {}
            if headers.get("X-Forwarded-For") == "http://127.0.0.1":
                return _resp(status_code=200)
            return _resp(status_code=403)

        with patch("modules.forbidden_bypass.smart_request", side_effect=fake_request):
            findings = _test_header_bypass("http://t/admin", "/admin")

        assert findings
        assert findings[0]["vuln"] == "Header IP Spoofing"
        assert "X-Forwarded-For: http://127.0.0.1" in findings[0]["header"]

    def test_no_finding_when_all_headers_blocked(self):
        with patch(
            "modules.forbidden_bypass.smart_request",
            return_value=_resp(status_code=403),
        ):
            findings = _test_header_bypass("http://t/admin", "/admin")
        assert findings == []


class TestMethodBypass:
    def test_finds_bypass_via_post_content_length_zero(self):
        # Every method 403 EXCEPT POST + Content-Length: 0 → 200.
        def fake_request(method, url, **kwargs):
            headers = kwargs.get("headers") or {}
            if method == "post" and headers.get("Content-Length") == "0":
                return _resp(status_code=200)
            return _resp(status_code=403)

        with patch("modules.forbidden_bypass.smart_request", side_effect=fake_request):
            findings = _test_method_bypass("http://t/admin")

        assert findings
        assert findings[0]["payload"] == "POST + Content-Length: 0"

    def test_finds_bypass_via_method_switch(self):
        # PUT bypasses; everything else 403.
        def fake_request(method, url, **kwargs):
            if method == "put":
                return _resp(status_code=200)
            return _resp(status_code=403)

        with patch("modules.forbidden_bypass.smart_request", side_effect=fake_request):
            findings = _test_method_bypass("http://t/admin")

        assert findings
        assert findings[0]["payload"] == "PUT"


class TestScanForbiddenBypass:
    def test_skips_when_baseline_is_200(self):
        # Baseline 200 → not forbidden → nothing to bypass test.
        with patch(
            "modules.forbidden_bypass.smart_request",
            return_value=_resp(status_code=200),
        ):
            findings = scan_forbidden_bypass("http://t/")
        assert findings == []

    def test_runs_when_baseline_is_403(self):
        # Baseline 403, header bypass succeeds → at least one finding.
        call_count = {"n": 0}

        def fake_request(method, url, **kwargs):
            call_count["n"] += 1
            headers = kwargs.get("headers") or {}
            # First call = baseline check, must be 403 to enter bypass loop.
            if call_count["n"] == 1:
                return _resp(status_code=403)
            # Subsequent: bypass when X-Forwarded-For is set.
            if "X-Forwarded-For" in headers:
                return _resp(status_code=200)
            return _resp(status_code=403)

        with patch("modules.forbidden_bypass.smart_request", side_effect=fake_request):
            findings = scan_forbidden_bypass("http://t/admin")

        assert findings
        assert findings[0]["type"] == "403 Bypass"
