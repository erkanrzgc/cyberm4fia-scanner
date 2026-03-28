"""
Tests for modules/lfi.py — LFI detection logic and scanning.
"""

import base64

from modules.lfi import (
    detect_lfi,
    _detect_php_wrapper_output,
)
from modules.payloads import LFI_PAYLOADS, LFI_SIGNATURES


class TestDetectLFI:
    """Tests for the detect_lfi() detection function."""

    def test_detects_linux_passwd(self):
        response = "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:"
        os_type, sig = detect_lfi(response)
        assert os_type == "linux"
        assert "root:x:0:0:" in sig

    def test_detects_linux_shadow(self):
        response = "root:$6$somehash:18000:0:99999:7:::"
        os_type, sig = detect_lfi(response)
        assert os_type == "linux_shadow"

    def test_detects_windows_system_ini(self):
        response = "[drivers]\ntimer=timer.drv\n[extensions]\n"
        os_type, sig = detect_lfi(response)
        assert os_type == "windows"
        assert sig == "[drivers]"

    def test_detects_windows_boot_loader(self):
        response = "[boot loader]\ntimeout=30\ndefault=multi(0)disk(0)"
        os_type, sig = detect_lfi(response)
        assert os_type == "windows"
        assert sig == "[boot loader]"

    def test_detects_php_source(self):
        response = "PD9waHA= some more data <?php echo 'hello'; ?>"
        os_type, sig = detect_lfi(response)
        assert os_type == "php_source"

    def test_detects_config_leak(self):
        response = "DB_PASSWORD=secret123\nDB_HOST=dbserver.internal"
        os_type, sig = detect_lfi(response)
        assert os_type == "config"

    def test_no_match_on_normal_page(self):
        response = "Welcome to our website! This is a normal page."
        os_type, sig = detect_lfi(response)
        assert os_type is None
        assert sig is None

    def test_ignores_signature_in_baseline(self):
        baseline = "root:x:0:0:root:/root:/bin/bash"
        response = "root:x:0:0:root:/root:/bin/bash"
        os_type, sig = detect_lfi(response, baseline_text=baseline)
        assert os_type is None

    def test_new_signature_not_in_baseline(self):
        baseline = "Welcome to our website"
        response = "root:x:0:0:root:/root:/bin/bash"
        os_type, sig = detect_lfi(response, baseline_text=baseline)
        assert os_type == "linux"

    def test_empty_response(self):
        os_type, sig = detect_lfi("")
        assert os_type is None

    def test_case_insensitive_detection(self):
        response = "/bin/Bash is a shell"
        os_type, sig = detect_lfi(response)
        assert os_type == "linux"


class TestDetectPHPWrapperOutput:
    """Tests for _detect_php_wrapper_output()."""

    def test_detects_base64_php_source(self):
        php_code = "<?php echo 'hello'; require 'config.php'; ?>"
        encoded = base64.b64encode(php_code.encode()).decode()
        response = f"Some prefix {encoded} some suffix"
        result = _detect_php_wrapper_output(response, "php://filter/convert.base64-encode/resource=index.php")
        assert result is not None
        assert "<?php" in result

    def test_ignores_non_php_filter_payload(self):
        php_code = "<?php echo 'hello'; ?>"
        encoded = base64.b64encode(php_code.encode()).decode()
        response = f"Some prefix {encoded}"
        result = _detect_php_wrapper_output(response, "../../../etc/passwd")
        assert result is None

    def test_ignores_short_base64(self):
        response = "Some short text abc123"
        result = _detect_php_wrapper_output(response, "php://filter/convert.base64-encode/resource=x")
        assert result is None

    def test_ignores_non_code_base64(self):
        random_data = "This is just random text without any code markers whatsoever nothing interesting"
        encoded = base64.b64encode(random_data.encode()).decode()
        response = f"Data: {encoded}"
        result = _detect_php_wrapper_output(response, "php://filter/convert.base64-encode/resource=x")
        assert result is None


class TestLFIPayloads:
    """Validate LFI payload and signature structure."""

    def test_payloads_not_empty(self):
        assert len(LFI_PAYLOADS) > 10

    def test_payloads_include_traversal(self):
        traversal_payloads = [p for p in LFI_PAYLOADS if "../" in p]
        assert len(traversal_payloads) > 0

    def test_payloads_include_php_wrappers(self):
        wrapper_payloads = [p for p in LFI_PAYLOADS if "php://" in p]
        assert len(wrapper_payloads) > 0

    def test_payloads_include_windows(self):
        win_payloads = [p for p in LFI_PAYLOADS if "windows" in p.lower() or "win.ini" in p.lower()]
        assert len(win_payloads) > 0

    def test_signatures_cover_linux_and_windows(self):
        assert "linux" in LFI_SIGNATURES
        assert "windows" in LFI_SIGNATURES
        assert len(LFI_SIGNATURES["linux"]) > 0
        assert len(LFI_SIGNATURES["windows"]) > 0
