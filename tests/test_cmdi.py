"""
Tests for modules/cmdi.py — Command Injection detection logic.
"""


from modules.cmdi import (
    detect_cmdi,
    _match_standalone_output_line,
)
from modules.payloads import CMDI_PAYLOADS, CMDI_SIGNATURES


class TestMatchStandaloneOutputLine:
    """Tests for _match_standalone_output_line()."""

    def test_matches_exact_line(self):
        text = "some header\nwww-data\nsome footer"
        result = _match_standalone_output_line(text, ["www-data", "root", "apache"])
        assert result == "www-data"

    def test_ignores_html_lines(self):
        text = "<div>www-data</div>"
        result = _match_standalone_output_line(text, ["www-data"])
        assert result is None

    def test_no_match(self):
        text = "Hello world\nNormal output"
        result = _match_standalone_output_line(text, ["root", "www-data"])
        assert result is None

    def test_case_insensitive(self):
        text = "some line\nROOT\nanother line"
        result = _match_standalone_output_line(text, ["root"])
        assert result == "root"

    def test_handles_whitespace(self):
        text = "  www-data  \n"
        result = _match_standalone_output_line(text, ["www-data"])
        assert result == "www-data"

    def test_empty_text(self):
        result = _match_standalone_output_line("", ["root"])
        assert result is None


class TestDetectCMDi:
    """Tests for detect_cmdi() detection function."""

    def test_detects_linux_id_output(self):
        response = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
        cmd_type, sig = detect_cmdi(response)
        assert cmd_type == "linux_id"

    def test_detects_windows_dir_output(self):
        text = "Volume Serial Number is ABCD-1234\n Directory of C:\\Windows"
        cmd_type, sig = detect_cmdi(text)
        assert cmd_type == "windows_dir"

    def test_detects_whoami_standalone(self):
        text = "some header\nwww-data\nsome footer"
        cmd_type, sig = detect_cmdi(text)
        # Should match if www-data is in CMDI_SIGNATURES["linux_whoami"]
        if "www-data" in CMDI_SIGNATURES.get("linux_whoami", []):
            assert cmd_type == "linux_whoami"
        else:
            assert cmd_type is None

    def test_no_match_on_normal_page(self):
        response = "Welcome to our website! This is a normal page."
        cmd_type, sig = detect_cmdi(response)
        assert cmd_type is None
        assert sig is None

    def test_empty_response(self):
        cmd_type, sig = detect_cmdi("")
        assert cmd_type is None
        assert sig is None

    def test_detects_id_in_mixed_content(self):
        response = "<html><body>Result: uid=0(root) gid=0(root)</body></html>"
        cmd_type, sig = detect_cmdi(response)
        assert cmd_type == "linux_id"


class TestCMDiPayloads:
    """Validate CMDi payload and signature structure."""

    def test_payloads_not_empty(self):
        assert len(CMDI_PAYLOADS) > 10

    def test_payloads_include_whoami(self):
        whoami_payloads = [p for p in CMDI_PAYLOADS if "whoami" in p]
        assert len(whoami_payloads) > 0

    def test_payloads_include_id(self):
        id_payloads = [p for p in CMDI_PAYLOADS if " id" in p or ";id" in p or "|id" in p]
        assert len(id_payloads) > 0

    def test_payloads_include_sleep(self):
        sleep_payloads = [p for p in CMDI_PAYLOADS if "sleep" in p]
        assert len(sleep_payloads) > 0

    def test_signatures_have_required_categories(self):
        assert "linux_id" in CMDI_SIGNATURES
        assert "windows_dir" in CMDI_SIGNATURES
        assert len(CMDI_SIGNATURES["linux_id"]) > 0
        assert len(CMDI_SIGNATURES["windows_dir"]) > 0

    def test_payloads_include_separator_variants(self):
        separators = [";", "|", "||", "&&", "`", "$("]
        for sep in separators:
            matching = [p for p in CMDI_PAYLOADS if sep in p]
            assert len(matching) > 0, f"No payload with separator '{sep}'"
