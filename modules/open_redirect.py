"""
cyberm4fia-scanner - Open Redirect Scanner
Detects URL redirect vulnerabilities for phishing and auth bypass
"""

import sys
import os
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.colors import log_info, log_success, log_warning, log_error
from utils.request import smart_request

# ─────────────────────────────────────────────────────
# Open Redirect Payloads
# ─────────────────────────────────────────────────────
REDIRECT_PAYLOADS = [
    # Standard
    "https://evil.com",
    "http://evil.com",
    "//evil.com",
    # Protocol-relative
    "///evil.com",
    "////evil.com",
    # Encoded
    "https:%2F%2Fevil.com",
    "http:%2F%2Fevil.com",
    "%2F%2Fevil.com",
    # Backslash tricks
    "https:\\\\evil.com",
    "/\\evil.com",
    "\\evil.com",
    # JavaScript (for DOM-based)
    "javascript:alert(1)",
    # Data URI
    "data:text/html,<script>alert(1)</script>",
    # CRLF + redirect
    "%0d%0aLocation:%20https://evil.com",
    # Null byte
    "https://evil.com%00.target.com",
    # @ trick
    "https://target.com@evil.com",
    "https://target.com%40evil.com",
    # Dot tricks
    "https://evil.com/.target.com",
    "https://evil.com%23.target.com",
    # Unicode
    "https://evil.com%E3%80%82target.com",
]

# Common parameter names used for redirects
REDIRECT_PARAMS = [
    "url",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "next",
    "next_url",
    "return",
    "return_url",
    "returnTo",
    "redir",
    "rurl",
    "dest",
    "destination",
    "go",
    "goto",
    "target",
    "link",
    "out",
    "view",
    "ref",
    "callback",
    "continue",
    "forward",
    "path",
    "to",
    "u",
    "r",
    "ReturnUrl",
    "redirect_to",
    "login_url",
]

# Common paths that have redirect functionality
REDIRECT_PATHS = [
    "/login?redirect=",
    "/login?next=",
    "/login?return=",
    "/logout?redirect=",
    "/logout?next=",
    "/auth/callback?redirect=",
    "/sso?return=",
    "/sso?redirect=",
    "/oauth/authorize?redirect_uri=",
    "/redirect?url=",
]

CANARY_DOMAIN = "evil.com"


def test_redirect(url, param, payload, delay):
    """Test a single redirect payload."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    test_url = urlunparse(parsed._replace(query=new_query))

    try:
        resp = smart_request(
            "get", test_url, delay=delay, timeout=8, allow_redirects=False
        )

        # Check for redirect in response
        location = resp.headers.get("location", "").lower()
        status = resp.status_code

        # Confirmed open redirect
        if status in (301, 302, 303, 307, 308):
            if CANARY_DOMAIN in location:
                return {
                    "type": "Open Redirect",
                    "url": url,
                    "field": param,
                    "payload": payload,
                    "redirect_to": resp.headers.get("location", ""),
                    "status": status,
                    "severity": "MEDIUM",
                    "description": (
                        f"Open Redirect via '{param}' parameter. "
                        f"Redirects to: {resp.headers.get('location', '')}"
                    ),
                }

        # Check for meta refresh redirect in body
        if status == 200:
            body = resp.text[:5000].lower()
            if CANARY_DOMAIN in body:
                # Check for meta refresh or JS redirect
                if "meta http-equiv" in body or "window.location" in body:
                    return {
                        "type": "Open Redirect (DOM)",
                        "url": url,
                        "field": param,
                        "payload": payload,
                        "severity": "MEDIUM",
                        "description": (
                            f"DOM-based redirect via '{param}'. "
                            f"Redirect target reflected in page."
                        ),
                    }

    except Exception:
        pass
    return None


def scan_open_redirect(url, delay=0):
    """Main Open Redirect scanner entry point."""
    log_info(f"Starting Open Redirect scan on {url}")
    findings = []

    parsed = urlparse(url)
    existing_params = list(parse_qs(parsed.query, keep_blank_values=True).keys())

    # Combine existing params with common redirect param names
    params_to_test = list(set(existing_params + REDIRECT_PARAMS))

    for param in params_to_test:
        for payload in REDIRECT_PAYLOADS:
            result = test_redirect(url, param, payload, delay)
            if result:
                findings.append(result)
                log_success(
                    f"[REDIRECT] {result['type']} via '{param}' → "
                    f"{result.get('redirect_to', result['payload'])}"
                )
                break  # One finding per param is enough

    # Also test common redirect paths
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    for path in REDIRECT_PATHS:
        test_url = base_url + path + "https://evil.com"
        try:
            resp = smart_request(
                "get", test_url, delay=delay, timeout=5, allow_redirects=False
            )
            location = resp.headers.get("location", "").lower()
            if (
                resp.status_code in (301, 302, 303, 307, 308)
                and CANARY_DOMAIN in location
            ):
                findings.append(
                    {
                        "type": "Open Redirect",
                        "url": test_url,
                        "field": "path",
                        "payload": path,
                        "redirect_to": resp.headers.get("location", ""),
                        "severity": "MEDIUM",
                        "description": f"Open Redirect at {path}",
                    }
                )
                log_success(f"[REDIRECT] at path {path}")
        except Exception:
            pass

    log_success(f"Open Redirect scan complete. Found {len(findings)} redirect(s).")
    return findings
