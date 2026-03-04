"""
cyberm4fia-scanner - API Security Scanner
Tests REST/GraphQL endpoints for OWASP API Top 10 vulnerabilities
"""

import sys
import os
import re
import json
from urllib.parse import urljoin

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.colors import log_info, log_success, log_warning
from utils.request import smart_request

# ─────────────────────────────────────────────────────
# Common API paths to discover
# ─────────────────────────────────────────────────────
API_ENDPOINTS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/rest",
    "/rest/v1",
    "/rest/v2",
    "/graphql",
    "/graphiql",
    "/playground",
    "/api-docs",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/openapi/v3/api-docs",
    "/v1",
    "/v2",
    "/v3",
    "/.well-known/openid-configuration",
    "/api/health",
    "/api/status",
    "/api/info",
    "/api/users",
    "/api/user",
    "/api/me",
    "/api/admin",
    "/api/config",
    "/api/settings",
    "/api/debug",
    "/api/test",
    "/api/docs",
    "/api/graphql",
    "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/posts",
]

# IDOR test patterns
IDOR_PATTERNS = [
    (r"/api/v\d+/users/(\d+)", "user_id"),
    (r"/api/v\d+/orders/(\d+)", "order_id"),
    (r"/api/v\d+/accounts/(\d+)", "account_id"),
    (r"/api/v\d+/profiles/(\d+)", "profile_id"),
    (r"/users/(\d+)", "user_id"),
    (r"/orders/(\d+)", "order_id"),
]


def discover_api_endpoints(url, delay=0):
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
                        "status": resp.status_code,
                        "content_type": content_type,
                        "is_api": is_api,
                        "body_preview": resp.text[:200],
                    }
                )

                if is_api:
                    log_success(f"API endpoint found: {test_url} [{resp.status_code}]")
                elif resp.status_code in (401, 403):
                    log_info(f"Protected endpoint: {test_url} [{resp.status_code}]")

        except Exception:
            pass

    return discovered


def test_bola(url, delay=0):
    """
    API1: Broken Object Level Authorization (BOLA/IDOR)
    Try accessing other users' data by manipulating IDs.
    """
    findings = []

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
                                        "type": "api_vulnerability",
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
                except Exception:
                    pass

    return findings


def test_rate_limiting(url, delay=0):
    """
    API4: Unrestricted Resource Consumption
    Check if API has rate limiting.
    """
    findings = []

    try:
        success_count = 0
        for i in range(30):
            resp = smart_request("get", url, delay=0, timeout=3)
            if resp.status_code == 200:
                success_count += 1
            elif resp.status_code == 429:
                log_info(f"Rate limiting detected after {i + 1} requests")
                return findings

        if success_count >= 28:
            findings.append(
                {
                    "type": "api_vulnerability",
                    "vuln": "No Rate Limiting",
                    "severity": "MEDIUM",
                    "url": url,
                    "description": (
                        f"API endpoint accepted {success_count}/30 rapid requests "
                        f"without rate limiting. Vulnerable to brute force and DoS."
                    ),
                }
            )
    except Exception:
        pass

    return findings


def test_mass_assignment(url, delay=0):
    """
    API6: Mass Assignment
    Try adding admin/role fields to POST/PUT requests.
    """
    findings = []
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
        # Try POST with injected fields
        resp = smart_request(
            "post",
            url,
            json=injection_fields,
            delay=delay,
            timeout=5,
        )

        if resp.status_code in (200, 201):
            try:
                data = resp.json()
                # Check if any injection fields were reflected back
                for field, value in injection_fields.items():
                    if field in str(data):
                        findings.append(
                            {
                                "type": "api_vulnerability",
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
    except Exception:
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
                                "type": "api_vulnerability",
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
        except Exception:
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
                        "type": "api_vulnerability",
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
        except Exception:
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
                            "type": "api_vulnerability",
                            "vuln": "JWT Algorithm None",
                            "severity": "CRITICAL",
                            "url": url,
                            "description": "JWT uses 'none' algorithm — signatures are not verified!",
                        }
                    )
                elif alg.startswith("HS"):
                    findings.append(
                        {
                            "type": "api_vulnerability",
                            "vuln": "JWT HMAC Symmetric Key",
                            "severity": "LOW",
                            "url": url,
                            "description": (
                                f"JWT uses symmetric algorithm ({alg}). "
                                f"If the secret key is weak, tokens can be forged."
                            ),
                        }
                    )
            except Exception:
                pass

    return findings


def scan_api(url, delay=0, threads=5):
    """Main entry point for API security scanning."""
    log_info("Starting API Security Scanner (OWASP API Top 10)...")

    all_findings = []

    # Step 1: Discover endpoints
    endpoints = discover_api_endpoints(url, delay)
    api_endpoints = [e for e in endpoints if e.get("is_api")]

    if not api_endpoints:
        log_info("No API endpoints discovered. Scanning target URL directly.")
        api_endpoints = [{"url": url, "status": 200}]

    # Step 2: Run tests on discovered endpoints
    for ep in api_endpoints:
        ep_url = ep["url"]
        log_info(f"Testing API endpoint: {ep_url}")

        # BOLA (IDOR)
        bola_results = test_bola(ep_url, delay)
        for r in bola_results:
            all_findings.append(r)
            log_success(f"[CRITICAL] BOLA/IDOR: {r['url']}")

        # Rate Limiting
        rate_results = test_rate_limiting(ep_url, delay)
        for r in rate_results:
            all_findings.append(r)
            log_warning(f"[MEDIUM] No Rate Limiting: {r['url']}")

        # Mass Assignment
        mass_results = test_mass_assignment(ep_url, delay)
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
    except Exception:
        pass

    log_success(f"API scan complete. Found {len(all_findings)} issue(s).")
    return all_findings
