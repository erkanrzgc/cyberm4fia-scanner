"""
cyberm4fia-scanner — Cookie & HSTS Security Audit Module

Deep analyzes Set-Cookie attributes and HSTS configuration
to identify session hijacking and SSL stripping vulnerabilities.

Detects:
  - Missing Secure flag (HTTP MITM cookie theft)
  - Missing HttpOnly flag (XSS document.cookie theft)
  - Missing/weak SameSite (CSRF attacks)
  - Overly broad Domain scope
  - Weak HSTS max-age
  - Missing includeSubDomains / preload
  - SSL Strip window (HTTPS redirect without HSTS)
"""

import re
from urllib.parse import urlparse


from utils.colors import log_info, log_warning, log_success, log_vuln
from utils.request import increment_vulnerability_count
from utils.request import ScanExceptions


# Known session cookie names (case-insensitive matching)
SESSION_COOKIE_NAMES = {
    "phpsessid",
    "jsessionid",
    "asp.net_sessionid",
    "aspsessionid",
    "connect.sid",
    "sessionid",
    "session_id",
    "sid",
    "ssid",
    "laravel_session",
    "ci_session",
    "wordpress_logged_in",
    "_session_id",
    "rack.session",
    "express.sid",
    "token",
    "access_token",
    "auth_token",
    "jwt",
}

# Minimum recommended HSTS max-age (1 year in seconds)
MIN_HSTS_MAX_AGE = 31536000


def _parse_set_cookies(headers: dict) -> list:
    """Extract and parse all Set-Cookie headers into structured dicts."""
    cookies = []

    # httpx returns headers as httpx.Headers which can have multiple values
    raw_cookies = []
    if hasattr(headers, "get_list"):
        raw_cookies = headers.get_list("set-cookie")
    else:
        # Fallback: single header value with possible comma-separation
        # But cookies use ; separation, so we handle individual header
        sc = headers.get("set-cookie", "")
        if sc:
            raw_cookies = [sc]

    for raw in raw_cookies:
        if not raw:
            continue

        cookie = {"raw": raw, "flags": set(), "attributes": {}}

        parts = raw.split(";")
        if parts:
            # First part is name=value
            name_val = parts[0].strip()
            if "=" in name_val:
                cookie["name"] = name_val.split("=", 1)[0].strip()
                cookie["value"] = name_val.split("=", 1)[1].strip()
            else:
                cookie["name"] = name_val
                cookie["value"] = ""

        # Parse remaining attributes
        for part in parts[1:]:
            part = part.strip()
            if not part:
                continue

            part_lower = part.lower()

            if part_lower == "secure":
                cookie["flags"].add("secure")
            elif part_lower == "httponly":
                cookie["flags"].add("httponly")
            elif part_lower.startswith("samesite"):
                if "=" in part:
                    val = part.split("=", 1)[1].strip().lower()
                    cookie["attributes"]["samesite"] = val
                    cookie["flags"].add("samesite")
                else:
                    cookie["flags"].add("samesite")
                    cookie["attributes"]["samesite"] = "lax"  # default
            elif part_lower.startswith("domain"):
                if "=" in part:
                    cookie["attributes"]["domain"] = part.split("=", 1)[1].strip()
            elif part_lower.startswith("path"):
                if "=" in part:
                    cookie["attributes"]["path"] = part.split("=", 1)[1].strip()
            elif part_lower.startswith("max-age"):
                if "=" in part:
                    try:
                        cookie["attributes"]["max-age"] = int(
                            part.split("=", 1)[1].strip()
                        )
                    except ValueError:
                        pass
            elif part_lower.startswith("expires"):
                if "=" in part:
                    cookie["attributes"]["expires"] = part.split("=", 1)[1].strip()

        cookies.append(cookie)

    return cookies


def _is_session_cookie(name: str) -> bool:
    """Check if a cookie name looks like a session identifier."""
    name_lower = name.lower()
    # Direct match
    if name_lower in SESSION_COOKIE_NAMES:
        return True
    # Pattern match
    for pattern in ["sess", "session", "token", "auth", "login", "user_id", "sid"]:
        if pattern in name_lower:
            return True
    return False


def _analyze_cookie(cookie: dict, url: str, is_https: bool) -> list:
    """Analyze a single cookie for security issues."""
    findings = []
    name = cookie.get("name", "unknown")
    is_session = _is_session_cookie(name)

    missing_flags = []

    # Check Secure flag
    if "secure" not in cookie["flags"]:
        missing_flags.append("Secure")
        findings.append(
            {
                "type": "Insecure_Cookie",
                "severity": "high" if is_session else "medium",
                "cookie_name": name,
                "missing_flag": "Secure",
                "is_session_cookie": is_session,
                "description": f"Cookie '{name}' missing Secure flag — transmittable over HTTP (MITM theft)",
                "exploit_scenario": "Attacker on same network can sniff HTTP traffic and steal this cookie",
                "url": url,
            }
        )

    # Check HttpOnly flag
    if "httponly" not in cookie["flags"]:
        missing_flags.append("HttpOnly")
        findings.append(
            {
                "type": "Insecure_Cookie",
                "severity": "high" if is_session else "medium",
                "cookie_name": name,
                "missing_flag": "HttpOnly",
                "is_session_cookie": is_session,
                "description": f"Cookie '{name}' missing HttpOnly flag — accessible via document.cookie (XSS theft)",
                "exploit_scenario": "XSS payload can read this cookie: document.cookie → attacker steals session",
                "url": url,
            }
        )

    # Check SameSite
    if "samesite" not in cookie["flags"]:
        missing_flags.append("SameSite")
        findings.append(
            {
                "type": "Insecure_Cookie",
                "severity": "medium" if is_session else "low",
                "cookie_name": name,
                "missing_flag": "SameSite",
                "is_session_cookie": is_session,
                "description": f"Cookie '{name}' missing SameSite attribute — vulnerable to CSRF",
                "exploit_scenario": "Cross-site form/fetch can send this cookie automatically",
                "url": url,
            }
        )
    elif cookie["attributes"].get("samesite") == "none":
        findings.append(
            {
                "type": "Insecure_Cookie",
                "severity": "medium" if is_session else "low",
                "cookie_name": name,
                "missing_flag": "SameSite=None",
                "is_session_cookie": is_session,
                "description": f"Cookie '{name}' has SameSite=None — cross-site requests always send it",
                "exploit_scenario": "Any website can trigger authenticated requests with this cookie",
                "url": url,
            }
        )

    # Check overly broad domain
    domain = cookie["attributes"].get("domain", "")
    if domain:
        parsed = urlparse(url)
        host_parts = parsed.hostname.split(".") if parsed.hostname else []
        domain_parts = domain.lstrip(".").split(".")

        # If domain is broader (fewer parts) than actual host, it's overly permissive
        if len(domain_parts) < len(host_parts) and len(domain_parts) <= 2:
            findings.append(
                {
                    "type": "Insecure_Cookie",
                    "severity": "medium",
                    "cookie_name": name,
                    "missing_flag": "Overly_Broad_Domain",
                    "is_session_cookie": is_session,
                    "description": f"Cookie '{name}' domain '{domain}' is overly broad — accessible from subdomains",
                    "exploit_scenario": f"Any subdomain of {domain} can read/overwrite this cookie",
                    "url": url,
                }
            )

    # Predictable Session ID Detection
    if is_session:
        value = cookie.get("value", "")
        if value:
            findings.extend(_check_predictable_session(name, value, url))

    return findings


def _check_predictable_session(name: str, value: str, url: str) -> list:
    """Detect predictable/weak session IDs via entropy and pattern analysis."""
    findings = []
    import math

    # Check 1: Very short session ID (< 16 chars)
    if len(value) < 16:
        findings.append({
            "type": "Insecure_Cookie",
            "severity": "high",
            "cookie_name": name,
            "missing_flag": "Weak_Session_ID",
            "is_session_cookie": True,
            "description": f"Session cookie '{name}' has very short value ({len(value)} chars) — easily brute-forced",
            "exploit_scenario": f"Short session ID ({len(value)} chars) can be guessed or brute-forced",
            "url": url,
        })

    # Check 2: Purely numeric session ID
    if value.isdigit():
        findings.append({
            "type": "Insecure_Cookie",
            "severity": "high",
            "cookie_name": name,
            "missing_flag": "Numeric_Session_ID",
            "is_session_cookie": True,
            "description": f"Session cookie '{name}' is purely numeric ({value[:8]}...) — sequential/predictable",
            "exploit_scenario": "Numeric session IDs are often sequential and can be enumerated",
            "url": url,
        })

    # Check 3: Low entropy (Shannon entropy)
    if len(value) >= 8:
        char_freq = {}
        for c in value:
            char_freq[c] = char_freq.get(c, 0) + 1
        entropy = 0.0
        for count in char_freq.values():
            p = count / len(value)
            if p > 0:
                entropy -= p * math.log2(p)
        if entropy < 2.5:
            findings.append({
                "type": "Insecure_Cookie",
                "severity": "medium",
                "cookie_name": name,
                "missing_flag": "Low_Entropy_Session",
                "is_session_cookie": True,
                "description": f"Session cookie '{name}' has low entropy ({entropy:.1f} bits) — potentially predictable",
                "exploit_scenario": f"Low entropy ({entropy:.1f}) suggests the session ID may follow a pattern",
                "url": url,
            })

    return findings


def _analyze_hsts(headers: dict, url: str) -> list:
    """Analyze HSTS (Strict-Transport-Security) configuration."""
    findings = []
    parsed = urlparse(url)
    is_https = parsed.scheme == "https"

    hsts_value = None
    for key, value in headers.items():
        if key.lower() == "strict-transport-security":
            hsts_value = value
            break

    if not hsts_value:
        if is_https:
            findings.append(
                {
                    "type": "Weak_HSTS",
                    "severity": "medium",
                    "description": "No HSTS header on HTTPS site — first request vulnerable to SSL strip",
                    "detail": "Without HSTS, an attacker can intercept the initial HTTP→HTTPS redirect",
                    "exploit_scenario": "SSLStrip attack: MITM downgrades HTTPS to HTTP on first visit",
                    "url": url,
                }
            )
        return findings

    # Parse HSTS directives
    hsts_lower = hsts_value.lower()

    # Check max-age
    max_age_match = re.search(r"max-age\s*=\s*(\d+)", hsts_lower)
    if max_age_match:
        max_age = int(max_age_match.group(1))
        if max_age < MIN_HSTS_MAX_AGE:
            days = max_age // 86400
            findings.append(
                {
                    "type": "Weak_HSTS",
                    "severity": "low",
                    "description": f"HSTS max-age too short: {days} days (recommended: 365+ days)",
                    "detail": f"max-age={max_age} ({days} days) — should be at least {MIN_HSTS_MAX_AGE}",
                    "exploit_scenario": "Short HSTS window increases chances of SSL strip after expiry",
                    "url": url,
                }
            )
        if max_age == 0:
            findings.append(
                {
                    "type": "Weak_HSTS",
                    "severity": "high",
                    "description": "HSTS max-age=0 effectively disables HSTS protection!",
                    "detail": "Setting max-age=0 tells browsers to remove HSTS policy",
                    "exploit_scenario": "HSTS is completely disabled despite header being present",
                    "url": url,
                }
            )

    # Check includeSubDomains
    if "includesubdomains" not in hsts_lower:
        findings.append(
            {
                "type": "Weak_HSTS",
                "severity": "low",
                "description": "HSTS missing 'includeSubDomains' — subdomains not protected",
                "detail": "Subdomains can still be accessed over HTTP",
                "exploit_scenario": "Attacker MITM targets subdomain (e.g. api.example.com) via HTTP",
                "url": url,
            }
        )

    # Check preload
    if "preload" not in hsts_lower:
        findings.append(
            {
                "type": "Weak_HSTS",
                "severity": "info",
                "description": "HSTS missing 'preload' — not in browser preload list",
                "detail": "First-ever visit is still vulnerable to SSL strip",
                "exploit_scenario": "Without preload, very first connection can be intercepted",
                "url": url,
            }
        )

    return findings


def scan_cookie_hsts(url: str, response=None) -> list:
    """Main Cookie & HSTS audit scanner.

    Args:
        url: Target URL
        response: httpx Response object (optional)

    Returns:
        list of vulnerability dicts
    """
    log_info("🍪 Auditing Cookies & HSTS Security...")

    if response and hasattr(response, "headers"):
        headers = response.headers
    else:
        from utils.request import smart_request

        try:
            resp = smart_request("get", url)
            headers = resp.headers
        except ScanExceptions:
            log_warning("Failed to fetch target for Cookie/HSTS audit")
            return []

    parsed = urlparse(url)
    is_https = parsed.scheme == "https"
    all_findings = []

    # ── Cookie Analysis ──
    cookies = _parse_set_cookies(headers)

    if cookies:
        log_info(f"Found {len(cookies)} cookie(s) to analyze")
        for cookie in cookies:
            cookie_findings = _analyze_cookie(cookie, url, is_https)
            all_findings.extend(cookie_findings)
    else:
        log_info("No Set-Cookie headers found")

    # ── HSTS Analysis ──
    hsts_findings = _analyze_hsts(headers, url)
    all_findings.extend(hsts_findings)

    # Log results
    session_issues = [f for f in all_findings if f.get("is_session_cookie")]
    high_findings = [f for f in all_findings if f.get("severity") == "high"]

    if session_issues:
        log_vuln(f"🔴 Found {len(session_issues)} session cookie security issue(s)!")

    if high_findings:
        for f in high_findings:
            increment_vulnerability_count()
            log_vuln(f"Cookie/HSTS: {f['description']}")
    elif all_findings:
        for f in all_findings:
            if f.get("severity") in ("medium", "high"):
                increment_vulnerability_count()
            log_warning(f"Cookie/HSTS: {f['description']}")
    else:
        log_success("Cookie & HSTS configuration appears secure ✅")

    return all_findings
