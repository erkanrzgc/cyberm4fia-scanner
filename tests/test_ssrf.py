"""
Tests for modules/ssrf.py — SSRF detection logic and scanning.
"""

from unittest.mock import patch, MagicMock

from modules.ssrf import (
    detect_ssrf,
    scan_ssrf,
    SSRF_PARAM_NAMES,
)


class TestDetectSSRF:
    """Tests for the detect_ssrf() detection function."""

    def test_no_match_on_normal_page(self):
        category, sig = detect_ssrf("Welcome to our website!", "http://127.0.0.1")
        assert category is None
        assert sig is None

    def test_detects_aws_metadata(self):
        response = "Here is: ami-id i-12345 instance-id"
        category, sig = detect_ssrf(response, "http://169.254.169.254")
        assert category == "aws_metadata"
        assert sig == "ami-id"

    def test_detects_cloud_metadata(self):
        response = "computeMetadata response data"
        category, sig = detect_ssrf(response, "http://metadata.google.internal")
        assert category == "cloud_metadata"
        assert sig == "computeMetadata"

    def test_detects_internal_service_ssh(self):
        response = "SSH-2.0-OpenSSH_8.9"
        category, sig = detect_ssrf(response, "http://127.0.0.1:22")
        assert category == "internal_service"
        assert sig in ("openssh", "ssh-2.0")

    def test_detects_internal_service_redis(self):
        response = "redis_version:7.0.0\nredis_mode:standalone"
        category, sig = detect_ssrf(response, "dict://127.0.0.1:6379")
        assert category == "internal_service"
        assert sig == "redis_version"

    def test_detects_file_read_etc_passwd(self):
        response = "root:x:0:0:root:/root:/bin/bash"
        category, sig = detect_ssrf(response, "file:///etc/passwd")
        assert category == "file_read"
        assert sig == "root:x:0:0:"

    def test_detects_file_read_windows(self):
        response = "for 16-bit app support\n[fonts]\n[extensions]"
        category, sig = detect_ssrf(response, "file:///c:/windows/win.ini")
        assert category == "file_read"
        assert sig == "for 16-bit app"

    def test_detects_internal_error(self):
        response = "Error: connection refused to host"
        category, sig = detect_ssrf(response, "http://10.0.0.1")
        assert category == "internal_error"
        assert sig == "connection refused"

    def test_ignores_signature_present_in_baseline(self):
        baseline = "root:x:0:0:root:/root:/bin/bash"
        response = "root:x:0:0:root:/root:/bin/bash"
        category, sig = detect_ssrf(response, "file:///etc/passwd", baseline, len(baseline))
        assert category is None

    def test_new_signature_not_in_baseline(self):
        baseline = "Welcome to the homepage"
        response = "redis_version:7.0.0"
        category, sig = detect_ssrf(response, "dict://127.0.0.1:6379", baseline, len(baseline))
        assert category == "internal_service"

    def test_significant_content_change_with_internal_indicator(self):
        baseline = "A" * 100
        response = "Welcome to nginx default page. Server at localhost port 80. " + "B" * 200
        category, sig = detect_ssrf(response, "http://127.0.0.1", baseline, len(baseline))
        assert category == "internal_page"

    def test_no_false_positive_on_small_change(self):
        baseline = "Hello world! " * 10
        response = "Hello world! " * 11
        category, sig = detect_ssrf(response, "http://127.0.0.1", baseline, len(baseline))
        assert category is None

    def test_empty_response(self):
        category, sig = detect_ssrf("", "http://127.0.0.1")
        assert category is None


class TestSSRFParamNames:
    """Tests for SSRF parameter name heuristics."""

    def test_common_url_params_present(self):
        expected = ["url", "uri", "redirect", "callback", "src", "dest"]
        for param in expected:
            assert param in SSRF_PARAM_NAMES

    def test_not_empty(self):
        assert len(SSRF_PARAM_NAMES) > 10


class TestScanSSRF:
    """Tests for scan_ssrf() with mocked HTTP."""

    @patch("modules.ssrf.smart_request")
    @patch("modules.ssrf.get_oob_client", return_value=None)
    @patch("modules.ssrf.get_thread_count", return_value=1)
    def test_no_params_no_forms_returns_empty(self, mock_threads, mock_oob, mock_req):
        mock_resp = MagicMock()
        mock_resp.text = "Normal page"
        mock_req.return_value = mock_resp

        result = scan_ssrf("http://example.com/", forms=[], delay=0, threads=1)
        assert result == []

    @patch("modules.ssrf.smart_request")
    @patch("modules.ssrf.get_oob_client", return_value=None)
    @patch("modules.ssrf.get_thread_count", return_value=1)
    def test_detects_ssrf_in_url_param(self, mock_threads, mock_oob, mock_req):
        baseline_resp = MagicMock()
        baseline_resp.text = "Normal page content"

        vuln_resp = MagicMock()
        vuln_resp.text = "root:x:0:0:root:/root:/bin/bash"

        mock_req.side_effect = [baseline_resp, vuln_resp]

        result = scan_ssrf(
            "http://example.com/fetch?url=http://safe.com",
            forms=[],
            delay=0,
            threads=1,
        )
        assert len(result) >= 1
        assert result[0]["type"] == "SSRF_Param"
        assert result[0]["param"] == "url"

    @patch("modules.ssrf.smart_request")
    @patch("modules.ssrf.get_oob_client", return_value=None)
    @patch("modules.ssrf.get_thread_count", return_value=1)
    def test_no_vuln_returns_empty(self, mock_threads, mock_oob, mock_req):
        mock_resp = MagicMock()
        mock_resp.text = "Normal safe response without any indicators"
        mock_req.return_value = mock_resp

        result = scan_ssrf(
            "http://example.com/page?q=hello",
            forms=[],
            delay=0,
            threads=1,
        )
        assert result == []
