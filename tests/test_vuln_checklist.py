# -*- coding: utf-8 -*-
"""Tests for new vulnerability checklist modules."""

from unittest.mock import patch, MagicMock


class TestForbiddenBypass:
    """Tests for the 403/401 bypass scanner module."""

    def test_bypass_headers_defined(self):
        from modules.forbidden_bypass import BYPASS_HEADERS_IP, BYPASS_HEADERS_URL
        assert len(BYPASS_HEADERS_IP) >= 20
        assert len(BYPASS_HEADERS_URL) >= 5

    def test_path_mutations_defined(self):
        from modules.forbidden_bypass import PATH_MUTATIONS
        assert len(PATH_MUTATIONS) >= 20

    def test_scan_returns_list(self):
        with patch("modules.forbidden_bypass.smart_request") as mock_req:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = "OK"
            mock_req.return_value = mock_resp

            from modules.forbidden_bypass import scan_forbidden_bypass
            result = scan_forbidden_bypass("http://test.com/", delay=0)
            assert isinstance(result, list)

    def test_method_bypass_detection(self):
        from modules.forbidden_bypass import HTTP_METHODS
        assert "GET" in HTTP_METHODS
        assert "POST" in HTTP_METHODS
        assert "DELETE" in HTTP_METHODS


class TestFileUpload:
    """Tests for the file upload vulnerability scanner module."""

    def test_php_extensions_defined(self):
        from modules.file_upload import PHP_EXTENSIONS
        assert len(PHP_EXTENSIONS) >= 10
        assert ".php" in PHP_EXTENSIONS
        assert ".phtml" in PHP_EXTENSIONS

    def test_content_type_bypass_pairs(self):
        from modules.file_upload import CONTENT_TYPE_BYPASS
        assert len(CONTENT_TYPE_BYPASS) >= 5

    def test_magic_bytes_defined(self):
        from modules.file_upload import MAGIC_BYTES
        assert "gif" in MAGIC_BYTES
        assert MAGIC_BYTES["gif"] == b"GIF89a;"

    def test_whitelist_bypass_names(self):
        from modules.file_upload import WHITELIST_BYPASS_NAMES
        assert len(WHITELIST_BYPASS_NAMES) >= 8

    def test_scan_returns_list(self):
        from modules.file_upload import scan_file_upload
        result = scan_file_upload("http://test.com/", forms=[], delay=0)
        assert isinstance(result, list)


class TestAccountTakeover:
    """Tests for the account takeover scanner module."""

    def test_host_header_payloads(self):
        from modules.account_takeover import HOST_HEADER_PAYLOADS
        assert "evil.com" in HOST_HEADER_PAYLOADS
        assert "localhost" in HOST_HEADER_PAYLOADS

    def test_email_injection_payloads(self):
        from modules.account_takeover import EMAIL_PARAM_PAYLOADS
        assert len(EMAIL_PARAM_PAYLOADS) >= 6

    def test_oauth_redirect_payloads(self):
        from modules.account_takeover import OAUTH_REDIRECT_PAYLOADS
        assert any("evil.com" in p for p in OAUTH_REDIRECT_PAYLOADS)

    def test_duplicate_email_tricks(self):
        from modules.account_takeover import DUPLICATE_EMAIL_TRICKS
        assert len(DUPLICATE_EMAIL_TRICKS) >= 5

    def test_scan_returns_list(self):
        with patch("modules.account_takeover.smart_request") as mock_req:
            mock_resp = MagicMock()
            mock_resp.status_code = 404
            mock_resp.text = "Not Found"
            mock_req.return_value = mock_resp

            from modules.account_takeover import scan_account_takeover
            result = scan_account_takeover("http://test.com/", delay=0)
            assert isinstance(result, list)


class TestAuthBypass:
    """Tests for the 2FA & authentication bypass scanner module."""

    def test_otp_bypass_values(self):
        from modules.auth_bypass import OTP_BYPASS_VALUES
        assert "" in OTP_BYPASS_VALUES
        assert "000000" in OTP_BYPASS_VALUES
        assert "null" in OTP_BYPASS_VALUES

    def test_default_credentials(self):
        from modules.auth_bypass import DEFAULT_CREDS
        assert len(DEFAULT_CREDS) >= 15
        assert ("admin", "admin") in DEFAULT_CREDS

    def test_login_sqli_payloads(self):
        from modules.auth_bypass import LOGIN_SQLI_PAYLOADS
        assert len(LOGIN_SQLI_PAYLOADS) >= 5

    def test_response_manipulation_indicators(self):
        from modules.auth_bypass import RESPONSE_MANIPULATION_INDICATORS
        assert any("success" in i for i in RESPONSE_MANIPULATION_INDICATORS)

    def test_scan_returns_list(self):
        with patch("modules.auth_bypass.smart_request") as mock_req:
            mock_resp = MagicMock()
            mock_resp.status_code = 404
            mock_resp.text = "Not Found"
            mock_req.return_value = mock_resp

            from modules.auth_bypass import scan_auth_bypass
            result = scan_auth_bypass("http://test.com/", delay=0)
            assert isinstance(result, list)


class TestBusinessLogicEnhancements:
    """Tests for enhanced business logic module."""

    def test_idor_methods_defined(self):
        from modules.business_logic import IDOR_METHODS
        assert len(IDOR_METHODS) >= 5
        assert "PUT" in IDOR_METHODS

    def test_mass_assignment_payloads(self):
        from modules.business_logic import MASS_ASSIGNMENT_PAYLOADS
        assert len(MASS_ASSIGNMENT_PAYLOADS) >= 15

    def test_extended_id_params(self):
        from modules.business_logic import ID_PARAMS
        assert "order_id" in ID_PARAMS
        assert "comment_id" in ID_PARAMS

    def test_extended_role_params(self):
        from modules.business_logic import ROLE_PARAMS
        assert "isadmin" in ROLE_PARAMS
        assert "user_priv" in ROLE_PARAMS


class TestRegistryIntegration:
    """Verify new modules appear in the registry."""

    def test_new_modules_registered(self):
        from core.module_registry import PHASE_MODULES
        module_ids = {m.id for m in PHASE_MODULES}
        assert "forbidden_bypass" in module_ids
        assert "file_upload" in module_ids
        assert "ato" in module_ids
        assert "auth_bypass" in module_ids

    def test_new_modules_are_post_scan(self):
        from core.module_registry import PHASE_MODULES
        new_ids = {"forbidden_bypass", "file_upload", "ato", "auth_bypass"}
        for m in PHASE_MODULES:
            if m.id in new_ids:
                assert m.phase == "post_scan"
                assert m.collect_results is True
