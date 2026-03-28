"""
Tests for modules/ssti.py — SSTI detection logic and scanning.
"""

from unittest.mock import patch, MagicMock

from modules.ssti import (
    inject_payload,
    scan_ssti,
    SSTI_PAYLOADS,
    SSTI_RCE_PAYLOADS,
)


class TestSSTIPayloads:
    """Validate payload structure."""

    def test_payloads_have_required_keys(self):
        for entry in SSTI_PAYLOADS:
            assert "payload" in entry
            assert "expect" in entry
            assert "engine" in entry

    def test_rce_payloads_exist(self):
        assert len(SSTI_RCE_PAYLOADS) > 0
        for engine, payloads in SSTI_RCE_PAYLOADS.items():
            assert len(payloads) > 0


class TestInjectPayload:
    """Tests for inject_payload() with mocked HTTP."""

    @patch("modules.ssti.smart_request")
    def test_inject_get_method(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.text = "Result: 49"
        mock_resp.status_code = 200
        mock_req.return_value = mock_resp

        body, status = inject_payload(
            "http://example.com/page?name=test", "name", "{{7*7}}", delay=0
        )
        assert body == "Result: 49"
        assert status == 200
        mock_req.assert_called_once()
        call_args = mock_req.call_args
        assert call_args[0][0] == "get"

    @patch("modules.ssti.smart_request")
    def test_inject_post_method(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.text = "Result: 49"
        mock_resp.status_code = 200
        mock_req.return_value = mock_resp

        body, status = inject_payload(
            "http://example.com/page?name=test", "name", "{{7*7}}", delay=0, method="post"
        )
        assert body == "Result: 49"
        assert status == 200
        call_args = mock_req.call_args
        assert call_args[0][0] == "post"

    @patch("modules.ssti.smart_request")
    def test_inject_handles_exception(self, mock_req):
        mock_req.side_effect = OSError("Connection refused")

        body, status = inject_payload(
            "http://example.com/page?name=test", "name", "{{7*7}}", delay=0
        )
        assert body is None
        assert status is None

    @patch("modules.ssti.smart_request")
    def test_inject_adds_param_if_missing(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.text = "49"
        mock_resp.status_code = 200
        mock_req.return_value = mock_resp

        body, status = inject_payload(
            "http://example.com/page", "name", "{{7*7}}", delay=0
        )
        assert body == "49"
        call_url = mock_req.call_args[0][1]
        assert "name=%7B%7B7%2A7%7D%7D" in call_url or "name={{7*7}}" in call_url


class TestScanSSTI:
    """Tests for scan_ssti() with mocked HTTP."""

    @patch("modules.ssti.smart_request")
    def test_no_params_returns_empty(self, mock_req):
        result = scan_ssti("http://example.com/page", delay=0)
        assert result == []

    @patch("modules.ssti.smart_request")
    def test_detects_jinja2_ssti(self, mock_req):
        call_count = [0]

        def mock_response(*args, **kwargs):
            call_count[0] += 1
            resp = MagicMock()
            resp.status_code = 200
            url = args[1] if len(args) > 1 else kwargs.get("url", "")

            if "harmless_test_string" in str(url) or "harmless_test_string" in str(kwargs.get("data", "")):
                resp.text = "Normal page without math results"
            elif "%7B%7B7%2A7%7D%7D" in str(url) or "{{7*7}}" in str(url):
                resp.text = "Your input: 49"
            else:
                resp.text = "Normal page"
            return resp

        mock_req.side_effect = mock_response

        result = scan_ssti("http://example.com/page?name=test", delay=0)
        assert len(result) >= 1
        assert result[0]["type"] == "SSTI"
        assert result[0]["field"] == "name"
        assert result[0]["severity"] == "CRITICAL"

    @patch("modules.ssti.smart_request")
    def test_no_vuln_returns_empty(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.text = "Normal safe page"
        mock_resp.status_code = 200
        mock_req.return_value = mock_resp

        result = scan_ssti("http://example.com/page?name=test", delay=0)
        assert result == []

    @patch("modules.ssti.smart_request")
    def test_ignores_expected_value_in_baseline(self, mock_req):
        """If '49' already appears on the clean page, it's not SSTI."""
        mock_resp = MagicMock()
        mock_resp.text = "You have 49 items in your cart"
        mock_resp.status_code = 200
        mock_req.return_value = mock_resp

        result = scan_ssti("http://example.com/page?q=test", delay=0)
        assert result == []

    @patch("modules.ssti.smart_request")
    def test_waf_block_tracked(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.text = "Blocked"
        mock_resp.status_code = 403
        mock_req.return_value = mock_resp

        result = scan_ssti("http://example.com/page?q=test", delay=0)
        assert result == []
