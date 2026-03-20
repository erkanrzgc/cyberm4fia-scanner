"""
cyberm4fia-scanner – API Security Scanner
Uses api_spec_parser.py for OpenAPI/Swagger parsing.
"""
from utils.request import ScanExceptions

import re
import json
from urllib.parse import urljoin

from utils.colors import log_info, log_success, log_warning
from utils.request import smart_request
from utils.auth import auth_manager

# Import all spec-parsing helpers from the extracted module
from modules.api_spec_parser import (  # noqa: F401
    API_ENDPOINTS,
    IDOR_PATTERNS,
    _is_openapi_spec,
    _parse_api_spec_text,
    _resolve_ref,
    _first_example_value,
    _guess_schema_value,
    _guess_parameter_value,
    _pick_media_type,
    _extract_request_body,
    _extract_auth_schemes,
    _describe_auth_scheme,
    _build_auth_placeholders,
    _flatten_form_payload,
    _merge_request_body,
    _build_request_body_kwargs,
    collect_auth_findings,
    _render_path_template,
    _normalize_server_url,
    _build_endpoint_url,
    load_api_spec,
    fetch_openapi_spec,
    extract_openapi_endpoints,
)

def _dedupe_api_endpoints(endpoints):
    """Deduplicate endpoints by HTTP method and URL."""
    deduped = []
    seen = set()

    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue
        method = endpoint.get("method", "GET").upper()
        url = endpoint.get("url")
        if not url:
            continue
        key = (method, url)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(endpoint)

    return deduped

def _coerce_target(target):
    """Normalize an endpoint target into (url, method)."""
    if isinstance(target, dict):
        return target.get("url", ""), target.get("method", "GET").upper()
    return target, "GET"

def _build_api_finding(
    finding_type,
    target,
    severity,
    description,
    evidence="",
    confidence="high",
    **extra,
):
    """Build a finding dict that already matches the normalized reporting schema."""
    url, method = _coerce_target(target)
    request = extra.pop("request", None) or {"method": method, "url": url}
    repro_steps = extra.pop("repro_steps", None) or [f"{method} {url}"]
    finding = {
        "type": finding_type,
        "url": url,
        "severity": severity,
        "description": description,
        "evidence": evidence or description,
        "confidence": confidence,
        "request": request,
        "repro_steps": repro_steps,
    }
    finding.update(extra)
    return finding

def _build_endpoint_request_kwargs(target):
    """Build a representative request for an API endpoint."""
    if not isinstance(target, dict):
        return {}

    method = str(target.get("method", "GET")).upper()
    if method not in {"POST", "PUT", "PATCH"}:
        return {}

    sample_body = target.get("request_body")
    if sample_body is None:
        return {}
    return _build_request_body_kwargs(target, {})

def _collect_json_paths(value, prefix=""):
    """Flatten JSON keys into comparable dotted paths."""
    if isinstance(value, dict):
        paths = set()
        for key, sub_value in value.items():
            new_prefix = f"{prefix}.{key}" if prefix else str(key)
            paths.add(new_prefix)
            paths.update(_collect_json_paths(sub_value, new_prefix))
        return paths

    if isinstance(value, list):
        paths = set()
        if value:
            sample = value[0]
            array_prefix = f"{prefix}[]" if prefix else "[]"
            paths.add(array_prefix)
            paths.update(_collect_json_paths(sample, array_prefix))
        return paths

    return set()

def _response_signature(resp):
    """Summarize a response for auth/unauth diff comparisons."""
    signature = {
        "status_code": getattr(resp, "status_code", 0),
        "content_type": getattr(resp, "headers", {}).get("content-type", "").lower(),
        "length": len(getattr(resp, "text", "") or ""),
        "snippet": (getattr(resp, "text", "") or "")[:180],
        "json_paths": set(),
    }

    try:
        signature["json_paths"] = _collect_json_paths(resp.json())
    except ScanExceptions:
        pass

    return signature

def _responses_look_equivalent(left, right):
    """Return True when two response signatures appear materially the same."""
    if not left or not right:
        return False
    if left["status_code"] != right["status_code"]:
        return False

    if left["json_paths"] or right["json_paths"]:
        return left["json_paths"] == right["json_paths"]

    max_length = max(left["length"], right["length"], 1)
    return abs(left["length"] - right["length"]) <= max(24, int(max_length * 0.2))

def _request_api_target(target, delay=0):
    """Execute a representative request for an API endpoint target."""
    url, method = _coerce_target(target)
    request_kwargs = _build_endpoint_request_kwargs(target)
    return smart_request(
        method.lower(),
        url,
        delay=delay,
        timeout=5,
        **request_kwargs,
    )

def test_auth_response_diff(target, delay=0):
    """Compare unauthenticated and authenticated behavior for protected endpoints."""
    if not isinstance(target, dict):
        return []

    if not (target.get("auth_schemes") or target.get("auth_placeholders")):
        return []

    url, method = _coerce_target(target)
    findings = []

    try:
        with auth_manager.without_auth():
            unauth_resp = _request_api_target(target, delay=delay)
    except ScanExceptions:
        unauth_resp = None

    placeholders = target.get("auth_placeholders") or {}
    try:
        with auth_manager.using_placeholders(placeholders):
            auth_resp = _request_api_target(target, delay=delay)
    except ScanExceptions:
        auth_resp = None

    if unauth_resp is None and auth_resp is None:
        return findings

    unauth_sig = _response_signature(unauth_resp) if unauth_resp is not None else None
    auth_sig = _response_signature(auth_resp) if auth_resp is not None else None
    protected_write = method in {"POST", "PUT", "PATCH", "DELETE"}

    if unauth_resp is not None and unauth_resp.status_code in (200, 201, 202, 204):
        finding_type = "API_BFLA" if protected_write else "API_Unauth_Access"
        auth_summary = (
            f"auth status {auth_resp.status_code}"
            if auth_resp is not None
            else "no authenticated baseline available"
        )
        findings.append(
            _build_api_finding(
                finding_type,
                target,
                "CRITICAL",
                (
                    f"OpenAPI declared authentication for {method} {url}, but the "
                    f"unauthenticated request still succeeded with HTTP {unauth_resp.status_code}."
                ),
                evidence=(
                    f"Unauthenticated request returned {unauth_resp.status_code}; "
                    f"{auth_summary}."
                ),
                confidence="confirmed",
                response_snippet=(unauth_sig or {}).get("snippet"),
                unauth_status=unauth_resp.status_code,
                auth_status=auth_resp.status_code if auth_resp is not None else None,
            )
        )
        return findings

    if (
        unauth_resp is not None
        and auth_resp is not None
        and auth_resp.status_code in (200, 201, 202, 204)
        and unauth_resp.status_code in (401, 403, 404)
    ):
        auth_only_paths = sorted(auth_sig["json_paths"] - unauth_sig["json_paths"])
        if auth_only_paths or not _responses_look_equivalent(unauth_sig, auth_sig):
            findings.append(
                _build_api_finding(
                    "API_Auth_Response_Diff",
                    target,
                    "INFO",
                    (
                        f"Authenticated and unauthenticated responses differed for "
                        f"{method} {url}."
                    ),
                    evidence=(
                        f"Unauthenticated status {unauth_resp.status_code}; "
                        f"authenticated status {auth_resp.status_code}; "
                        f"auth-only fields: {', '.join(auth_only_paths[:8]) or 'n/a'}."
                    ),
                    confidence="high",
                    response_snippet=auth_sig.get("snippet"),
                    unauth_status=unauth_resp.status_code,
                    auth_status=auth_resp.status_code,
                    auth_only_fields=auth_only_paths[:12],
                )
            )

    return findings

def discover_api_endpoints(url, delay=0, spec_path=None):
    """Discover available API endpoints."""
    log_info("Discovering API endpoints...")
    discovered = []

    for endpoint in API_ENDPOINTS:
        try:
            test_url = urljoin(url, endpoint)
            resp = smart_request("get", test_url, delay=delay, timeout=5)

            if resp.status_code in (200, 201, 401, 403):
                content_type = resp.headers.get("content-type", "").lower()
                is_api = (
                    "json" in content_type
                    or "xml" in content_type
                    or endpoint.endswith(".json")
                )

                discovered.append(
                    {
                        "url": test_url,
                        "method": "GET",
                        "status": resp.status_code,
                        "content_type": content_type,
                        "is_api": is_api,
                        "body_preview": resp.text[:200],
                        "request_body": None,
                        "request_body_content_type": "",
                        "auth_schemes": [],
                        "auth_placeholders": {},
                    }
                )

                if is_api:
                    log_success(f"API endpoint found: {test_url} [{resp.status_code}]")
                elif resp.status_code in (401, 403):
                    log_info(f"Protected endpoint: {test_url} [{resp.status_code}]")

        except ScanExceptions:
            pass

    local_spec = load_api_spec(spec_path)
    if local_spec:
        discovered.extend(
            extract_openapi_endpoints(local_spec, url, source=f"file:{spec_path}")
        )
    else:
        remote_spec, spec_url = fetch_openapi_spec(url, delay=delay)
        if remote_spec:
            discovered.extend(
                extract_openapi_endpoints(remote_spec, url, source=spec_url)
            )

    discovered = _dedupe_api_endpoints(discovered)
    spec_count = len([e for e in discovered if e.get("source")])
    if spec_count:
        log_info(f"Loaded {spec_count} API operation(s) from OpenAPI/Swagger spec")

    return discovered

def test_bola(target, delay=0):
    """
    API1: Broken Object Level Authorization (BOLA/IDOR)
    Try accessing other users' data by manipulating IDs.
    """
    findings = []

    url, _ = _coerce_target(target)

    for pattern, param_name in IDOR_PATTERNS:
        match = re.search(pattern, url)
        if match:
            original_id = match.group(1)
            # Try other IDs
            test_ids = ["1", "2", "0", "100", "999", str(int(original_id) + 1)]

            for test_id in test_ids:
                if test_id == original_id:
                    continue
                test_url = url[: match.start(1)] + test_id + url[match.end(1) :]
                try:
                    resp = smart_request("get", test_url, delay=delay, timeout=5)
                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            if data and isinstance(data, dict):
                                findings.append(
                                    {
                                        "type": "API_BOLA",
                                        "vuln": "BOLA (Broken Object Level Authorization)",
                                        "severity": "CRITICAL",
                                        "url": test_url,
                                        "param": param_name,
                                        "original_id": original_id,
                                        "tested_id": test_id,
                                        "description": (
                                            f"Accessed {param_name}={test_id} data without "
                                            f"authorization. IDOR vulnerability confirmed."
                                        ),
                                    }
                                )
                                break
                        except json.JSONDecodeError:
                            pass
                except ScanExceptions:
                    pass

    return findings

def test_rate_limiting(target, delay=0):
    """
    API4: Unrestricted Resource Consumption
    Check if API has rate limiting.
    """
    findings = []
    url, method = _coerce_target(target)

    try:
        success_count = 0
        for i in range(30):
            resp = smart_request(method.lower(), url, delay=0, timeout=3)
            if resp.status_code == 200:
                success_count += 1
            elif resp.status_code == 429:
                log_info(f"Rate limiting detected after {i + 1} requests")
                return findings

        if success_count >= 28:
            findings.append(
                {
                    "type": "API_Rate_Limit",
                    "vuln": "No Rate Limiting",
                    "severity": "MEDIUM",
                    "url": url,
                    "description": (
                        f"API endpoint accepted {success_count}/30 rapid requests "
                        f"without rate limiting. Vulnerable to brute force and DoS."
                    ),
                }
            )
    except ScanExceptions:
        pass

    return findings

def test_mass_assignment(target, delay=0):
    """
    API6: Mass Assignment
    Try adding admin/role fields to POST/PUT requests.
    """
    findings = []
    url, method = _coerce_target(target)
    if isinstance(target, dict) and method not in {"POST", "PUT", "PATCH"}:
        return findings

    injection_fields = {
        "role": "admin",
        "is_admin": True,
        "admin": True,
        "isAdmin": True,
        "user_type": "administrator",
        "permissions": ["admin", "write", "delete"],
        "verified": True,
        "is_staff": True,
        "privilege": "root",
    }

    try:
        request_kwargs = _build_request_body_kwargs(target, injection_fields)
        resp = smart_request(
            method.lower() if method in {"POST", "PUT", "PATCH"} else "post",
            url,
            delay=delay,
            timeout=5,
            **request_kwargs,
        )

        if resp.status_code in (200, 201):
            try:
                data = resp.json()
                # Check if any injection fields were reflected back
                for field, value in injection_fields.items():
                    if field in str(data):
                        findings.append(
                            {
                                "type": "API_Mass_Assignment",
                                "vuln": "Mass Assignment",
                                "severity": "HIGH",
                                "url": url,
                                "field": field,
                                "description": (
                                    f"API reflected injected field '{field}' in response. "
                                    f"Potential mass assignment vulnerability."
                                ),
                            }
                        )
                        break
            except json.JSONDecodeError:
                pass
    except ScanExceptions:
        pass

    return findings

def test_graphql_introspection(url, delay=0):
    """Check if GraphQL introspection is enabled (information disclosure)."""
    findings = []
    graphql_urls = [
        urljoin(url, "/graphql"),
        urljoin(url, "/graphiql"),
        urljoin(url, "/api/graphql"),
    ]

    introspection_query = {"query": "{ __schema { types { name fields { name } } } }"}

    for gql_url in graphql_urls:
        try:
            resp = smart_request(
                "post",
                gql_url,
                json=introspection_query,
                delay=delay,
                timeout=5,
            )

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if "data" in data and "__schema" in data.get("data", {}):
                        types = data["data"]["__schema"].get("types", [])
                        findings.append(
                            {
                                "type": "API_GraphQL_Introspection",
                                "vuln": "GraphQL Introspection Enabled",
                                "severity": "MEDIUM",
                                "url": gql_url,
                                "types_count": len(types),
                                "description": (
                                    f"GraphQL introspection is enabled, exposing "
                                    f"{len(types)} types. Attackers can map the "
                                    f"entire API schema."
                                ),
                            }
                        )
                        log_warning(
                            f"GraphQL introspection enabled at {gql_url} "
                            f"({len(types)} types exposed)"
                        )
                except json.JSONDecodeError:
                    pass
        except ScanExceptions:
            pass

    return findings

def test_verb_tampering(url, delay=0):
    """Test HTTP verb tampering — can bypassed authn by PATCH/DELETE/PUT."""
    findings = []
    methods = ["PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"]

    for method in methods:
        try:
            resp = smart_request(method.lower(), url, delay=delay, timeout=5)
            if resp.status_code in (200, 201, 204):
                findings.append(
                    {
                        "type": "API_Verb_Tampering",
                        "vuln": "HTTP Verb Tampering",
                        "severity": "MEDIUM",
                        "url": url,
                        "method": method,
                        "description": (
                            f"API responds to {method} method with {resp.status_code}. "
                            f"Possible authentication or access control bypass."
                        ),
                    }
                )
        except ScanExceptions:
            pass

    return findings

def test_jwt_issues(url, resp_headers, delay=0):
    """Check for JWT algorithm confusion and weak token issues."""
    findings = []

    auth_header = resp_headers.get("authorization", "")
    set_cookie = resp_headers.get("set-cookie", "")

    # Look for JWT patterns
    jwt_pattern = r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    jwt_locations = [auth_header, set_cookie]

    for location in jwt_locations:
        match = re.search(jwt_pattern, location)
        if match:
            token = match.group(0)
            try:
                import base64

                # Decode header (first part)
                header_b64 = token.split(".")[0]
                # Add padding
                header_b64 += "=" * (4 - len(header_b64) % 4)
                header = json.loads(base64.urlsafe_b64decode(header_b64))

                alg = header.get("alg", "UNKNOWN")

                if alg == "none" or alg == "None":
                    findings.append(
                        {
                            "type": "JWT_None_Alg",
                            "vuln": "JWT Algorithm None",
                            "severity": "CRITICAL",
                            "url": url,
                            "description": "JWT uses 'none' algorithm — signatures are not verified!",
                        }
                    )
                elif alg.startswith("HS"):
                    findings.append(
                        {
                            "type": "JWT_Weak_Secret",
                            "vuln": "JWT HMAC Symmetric Key",
                            "severity": "LOW",
                            "url": url,
                            "description": (
                                f"JWT uses symmetric algorithm ({alg}). "
                                f"If the secret key is weak, tokens can be forged."
                            ),
                        }
                    )
            except ScanExceptions:
                pass

    return findings

def scan_api(url, delay=0, threads=5, spec_path=None):
    """Main entry point for API security scanning."""
    log_info("Starting API Security Scanner (OWASP API Top 10)...")

    all_findings = []

    # Step 1: Discover endpoints
    endpoints = discover_api_endpoints(url, delay, spec_path=spec_path)
    api_endpoints = [e for e in endpoints if e.get("is_api")]

    if not api_endpoints:
        log_info("No API endpoints discovered. Scanning target URL directly.")
        api_endpoints = [{"url": url, "status": 200, "method": "GET"}]

    auth_findings = collect_auth_findings(api_endpoints)
    for finding in auth_findings:
        all_findings.append(finding)
        log_info(f"[INFO] Auth Scheme: {finding['evidence']}")

    # Step 2: Run tests on discovered endpoints
    for ep in api_endpoints:
        ep_url = ep["url"]
        method = ep.get("method", "GET").upper()
        log_info(f"Testing API endpoint: {method} {ep_url}")
        placeholders = ep.get("auth_placeholders") or {}
        if placeholders:
            log_info(f"Using auth placeholders for endpoint: {placeholders}")

        auth_diff_results = test_auth_response_diff(ep, delay)
        for result in auth_diff_results:
            all_findings.append(result)
            if result["type"] in {"API_Unauth_Access", "API_BFLA"}:
                log_success(f"[CRITICAL] Auth bypass signal: {result['url']}")
            else:
                log_info(f"[INFO] Auth response diff: {result['url']}")

        with auth_manager.using_placeholders(placeholders):
            # BOLA (IDOR)
            bola_results = test_bola(ep, delay)
            for r in bola_results:
                all_findings.append(r)
                log_success(f"[CRITICAL] BOLA/IDOR: {r['url']}")

            # Rate Limiting
            rate_results = test_rate_limiting(ep, delay)
            for r in rate_results:
                all_findings.append(r)
                log_warning(f"[MEDIUM] No Rate Limiting: {r['url']}")

            # Mass Assignment
            mass_results = test_mass_assignment(ep, delay)
            for r in mass_results:
                all_findings.append(r)
                log_warning(f"[HIGH] Mass Assignment: {r['url']}")

            # Verb Tampering
            verb_results = test_verb_tampering(ep_url, delay)
            for r in verb_results:
                all_findings.append(r)
                log_info(f"[MEDIUM] Verb Tampering ({r['method']}): {r['url']}")

    # Step 3: GraphQL introspection (global test)
    gql_results = test_graphql_introspection(url, delay)
    all_findings.extend(gql_results)

    # Step 4: JWT analysis on main page
    try:
        main_resp = smart_request("get", url, delay=delay, timeout=5)
        headers = {k.lower(): v for k, v in main_resp.headers.items()}
        jwt_results = test_jwt_issues(url, headers, delay)
        all_findings.extend(jwt_results)
    except ScanExceptions:
        pass

    log_success(f"API scan complete. Found {len(all_findings)} issue(s).")
    return all_findings
