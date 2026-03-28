"""
Tests for modules/xxe.py — XXE detection logic and scanning.
"""

from unittest.mock import patch, MagicMock

from modules.xxe import (
    detect_xml_endpoints,
    test_xxe_payload as xxe_test_payload,
    scan_xxe,
    XXE_FILE_READ,
    XXE_FILE_READ_WIN,
    XXE_SSRF,
    XXE_XINCLUDE,
    LINUX_SIGNATURES,
    WINDOWS_SIGNATURES,
    AWS_SIGNATURES,
)


class TestXXEPayloads:
    """Validate XXE payload structure."""

    def test_linux_payload_has_entity(self):
        assert "<!ENTITY" in XXE_FILE_READ
        assert "file:///etc/passwd" in XXE_FILE_READ

    def test_windows_payload_has_entity(self):
        assert "<!ENTITY" in XXE_FILE_READ_WIN
        assert "win.ini" in XXE_FILE_READ_WIN

    def test_ssrf_payload_targets_metadata(self):
        assert "169.254.169.254" in XXE_SSRF

    def test_xinclude_payload(self):
        assert "xi:include" in XXE_XINCLUDE

    def test_signatures_not_empty(self):
        assert len(LINUX_SIGNATURES) > 0
        assert len(WINDOWS_SIGNATURES) > 0
        assert len(AWS_SIGNATURES) > 0


class TestTestXXEPayload:
    """Tests for test_xxe_payload() with mocked HTTP."""

    @patch("modules.xxe.smart_request")
    def test_returns_body_and_status(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.text = "root:x:0:0:root"
        mock_resp.status_code = 200
        mock_req.return_value = mock_resp

        body, status = xxe_test_payload("http://example.com/api/xml", XXE_FILE_READ)
        assert body == "root:x:0:0:root"
        assert status == 200

    @patch("modules.xxe.smart_request")
    def test_sends_xml_content_type(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.text = ""
        mock_resp.status_code = 200
        mock_req.return_value = mock_resp

        xxe_test_payload("http://example.com/api/xml", XXE_FILE_READ)
        call_kwargs = mock_req.call_args
        headers = call_kwargs[1].get("headers", {}) if call_kwargs[1] else {}
        assert headers.get("Content-Type") == "application/xml"

    @patch("modules.xxe.smart_request")
    def test_handles_exception(self, mock_req):
        mock_req.side_effect = OSError("Connection refused")

        body, status = xxe_test_payload("http://example.com/api/xml", XXE_FILE_READ)
        assert body is None
        assert status is None


class TestDetectXMLEndpoints:
    """Tests for detect_xml_endpoints() with mocked HTTP."""

    @patch("modules.xxe.smart_request")
    def test_discovers_xml_endpoint(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "application/xml"}
        mock_req.return_value = mock_resp

        endpoints = detect_xml_endpoints("http://example.com")
        assert len(endpoints) > 0

    @patch("modules.xxe.smart_request")
    def test_skips_404_endpoints(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.headers = {}
        mock_req.return_value = mock_resp

        endpoints = detect_xml_endpoints("http://example.com")
        assert len(endpoints) == 0

    @patch("modules.xxe.smart_request")
    def test_handles_connection_errors(self, mock_req):
        mock_req.side_effect = OSError("Connection refused")

        endpoints = detect_xml_endpoints("http://example.com")
        assert endpoints == []


class TestScanXXE:
    """Tests for scan_xxe() with mocked HTTP."""

    @patch("modules.xxe.smart_request")
    def test_detects_linux_file_read(self, mock_req):
        call_count = [0]

        def mock_response(*args, **kwargs):
            call_count[0] += 1
            resp = MagicMock()
            resp.headers = {"content-type": "text/html"}
            data = kwargs.get("data", "")

            if "file:///etc/passwd" in str(data) and "ENTITY" in str(data):
                resp.text = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"
                resp.status_code = 200
            else:
                resp.text = "OK"
                resp.status_code = 200
            return resp

        mock_req.side_effect = mock_response

        result = scan_xxe("http://example.com/api/xml")
        xxe_findings = [f for f in result if f["type"] == "XXE"]
        assert len(xxe_findings) >= 1
        assert xxe_findings[0]["severity"] == "CRITICAL"

    @patch("modules.xxe.smart_request")
    def test_detects_xml_parser_errors(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.text = "Error: XMLSyntaxError at line 3"
        mock_resp.status_code = 500
        mock_resp.headers = {"content-type": "text/html"}
        mock_req.return_value = mock_resp

        result = scan_xxe("http://example.com/api")
        potential = [f for f in result if f["type"] == "XXE-Potential"]
        assert len(potential) >= 1
        assert potential[0]["severity"] == "MEDIUM"

    @patch("modules.xxe.smart_request")
    def test_no_vuln_returns_empty(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.text = "Normal response"
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "text/html"}
        mock_req.return_value = mock_resp

        result = scan_xxe("http://example.com/page")
        assert result == []
