"""
cyberm4fia-scanner — Passive Scanner Module

Analyzes HTTP responses WITHOUT sending additional requests.
Detects:
  - Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
  - Secret/API key leaks in response body
  - Debug information exposure (stack traces, error messages)
  - Internal IP address disclosure
  - Server version disclosure
"""

import re

from utils.colors import log_info, log_warning, log_success
from utils.request import ScanExceptions


# ──────────────────────────────────────────────
#  Security Headers to Check
# ──────────────────────────────────────────────
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "Prevents XSS and data injection attacks",
        "severity": "medium",
    },
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections",
        "severity": "medium",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing",
        "severity": "low",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "severity": "medium",
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (still useful for old browsers)",
        "severity": "low",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information leakage",
        "severity": "low",
    },
    "Permissions-Policy": {
        "description": "Controls browser feature access (camera, mic, geolocation)",
        "severity": "low",
    },
}

# ──────────────────────────────────────────────
#  Secret Patterns (regex)
# ──────────────────────────────────────────────
SECRET_PATTERNS = [
    # API Keys
    (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?", "API Key"),
    (
        r"(?i)(secret[_-]?key|secretkey)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?",
        "Secret Key",
    ),
    (
        r"(?i)(access[_-]?token|accesstoken)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?",
        "Access Token",
    ),
    # AWS
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (
        r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{40})['\"]?",
        "AWS Secret Key",
    ),
    # Google
    (r"AIza[0-9A-Za-z\\-_]{35}", "Google API Key"),
    # GitHub
    (r"gh[ps]_[A-Za-z0-9_]{36,}", "GitHub Token"),
    (r"github_pat_[A-Za-z0-9_]{22,}", "GitHub PAT"),
    # Slack
    (r"xox[baprs]-[0-9A-Za-z\-]{10,}", "Slack Token"),
    # Stripe
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Secret Key"),
    (r"pk_live_[0-9a-zA-Z]{24,}", "Stripe Publishable Key"),
    # JWT
    (r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JWT Token"),
    # Generic password patterns
    (
        r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']',
        "Hardcoded Password",
    ),
    # Database connection strings
    (r"(?i)(mongodb|mysql|postgres|redis)://[^\s<>\"']+", "Database Connection String"),
    # Private keys
    (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "Private Key"),
]

# ──────────────────────────────────────────────
#  Debug / Error Patterns
# ──────────────────────────────────────────────
DEBUG_PATTERNS = [
    (r"(?i)Traceback \(most recent call last\)", "Python Stack Trace"),
    (r"(?i)Fatal error:.+in\s+/.+on line\s+\d+", "PHP Fatal Error"),
    (r"(?i)Warning:.+in\s+/.+on line\s+\d+", "PHP Warning"),
    (r"(?i)at\s+[\w\.$]+\([\w]+\.java:\d+\)", "Java Stack Trace"),
    (r"(?i)Microsoft .NET Framework.+Version:", ".NET Framework Error"),
    (r"(?i)ASP\.NET.+Error", "ASP.NET Error"),
    (r"(?i)django\.core\.exceptions", "Django Debug Info"),
    (r"(?i)DEBUG\s*=\s*True", "Debug Mode Enabled"),
    (r"(?i)DJANGO_SETTINGS_MODULE", "Django Settings Exposed"),
    (r"(?i)phpinfo\(\)", "phpinfo() Detected"),
    (r"(?i)var_dump\(|print_r\(", "PHP Debug Output"),
    (r"(?i)console\.(log|debug|warn|error)\(", "JavaScript Console Debug"),
    (r"(?i)\.env\.local|\.env\.development", "Environment File Reference"),
]

# Internal IP patterns
INTERNAL_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b"
)

# Server version disclosure
SERVER_VERSION_RE = re.compile(
    r"(?i)(?:apache|nginx|iis|lighttpd|tomcat|jetty|openresty|caddy)"
    r"[/ ]+[\d]+\.[\d]+(?:\.[\d]+)?"
)


def scan_passive(url: str, response=None, headers=None, body=None, delay=0):
    """
    Analyze a response for passive findings.

    Args:
        url: The URL that was requested
        response: httpx/requests Response object (optional)
        headers: dict of response headers (used if response is None)
        body: response body text (used if response is None)
        delay: unused (kept for API compatibility with other modules)

    Returns:
        list of vulnerability dicts
    """
    findings = []

    # Extract headers and body from response object if provided
    if response is not None:
        headers = dict(response.headers) if hasattr(response, "headers") else {}
        try:
            body = response.text if hasattr(response, "text") else str(response.content)
        except ScanExceptions:
            body = ""
    else:
        headers = headers or {}
        body = body or ""

    # Normalize header keys to title case for consistent checking
    headers_normalized = {k.title(): v for k, v in headers.items()}

    # ── 1. Missing Security Headers ──
    missing = _check_security_headers(url, headers_normalized)
    findings.extend(missing)

    # ── 2. Secret Leaks ──
    secrets = _check_secrets(url, body)
    findings.extend(secrets)

    # ── 3. Debug Info ──
    debug = _check_debug_info(url, body)
    findings.extend(debug)

    # ── 4. Internal IP Disclosure ──
    ips = _check_internal_ips(url, body, headers)
    findings.extend(ips)

    # ── 5. Server Version Disclosure ──
    versions = _check_server_version(url, headers)
    findings.extend(versions)

    if findings:
        log_warning(f"[Passive] {len(findings)} issue(s) found on {url}")
    else:
        log_info(f"[Passive] No passive issues on {url}")

    return findings


def _check_security_headers(url, headers):
    """Check for missing security headers."""
    findings = []
    for header, info in SECURITY_HEADERS.items():
        if header.title() not in headers:
            findings.append(
                {
                    "type": "Missing_Security_Header",
                    "url": url,
                    "param": header,
                    "severity": info["severity"].upper(),
                    "evidence": f"Missing header: {header}",
                    "payload": info["description"],
                }
            )
    return findings


def _check_secrets(url, body):
    """Scan response body for leaked secrets."""
    findings = []
    seen = set()

    for pattern, name in SECRET_PATTERNS:
        matches = re.finditer(pattern, body)
        for match in matches:
            # Avoid AWS Pre-signed URL false positives
            if name == "AWS Access Key ID":
                start_idx = max(0, match.start() - 40)
                if "amz-credential" in body[start_idx : match.start()].lower():
                    continue

            secret_preview = match.group(0)[:60]  # Truncate for safety
            if secret_preview in seen:
                continue
            seen.add(secret_preview)

            log_success(f"[Passive] Secret found: {name} on {url}")
            findings.append(
                {
                    "type": "Secret_Leak",
                    "url": url,
                    "param": name,
                    "severity": "HIGH",
                    "evidence": f"{name}: {secret_preview}...",
                    "payload": match.group(0)[:100],
                }
            )

    return findings


def _check_debug_info(url, body):
    """Check for debug information exposure."""
    findings = []
    seen = set()

    for pattern, name in DEBUG_PATTERNS:
        if re.search(pattern, body):
            if name in seen:
                continue
            seen.add(name)

            log_warning(f"[Passive] Debug info: {name} on {url}")
            findings.append(
                {
                    "type": "Debug_Info",
                    "url": url,
                    "param": name,
                    "severity": "MEDIUM",
                    "evidence": f"Detected: {name}",
                }
            )

    return findings


def _check_internal_ips(url, body, headers):
    """Check for internal IP address disclosure."""
    findings = []
    seen = set()

    # Check body
    for match in INTERNAL_IP_RE.finditer(body):
        ip = match.group(0)
        if ip not in seen:
            seen.add(ip)

    # Check headers
    for header_val in headers.values():
        for match in INTERNAL_IP_RE.finditer(str(header_val)):
            ip = match.group(0)
            if ip not in seen:
                seen.add(ip)

    for ip in seen:
        findings.append(
            {
                "type": "Internal_IP_Leak",
                "url": url,
                "param": "Internal IP",
                "severity": "LOW",
                "evidence": f"Internal IP disclosed: {ip}",
                "payload": ip,
            }
        )

    return findings


def _check_server_version(url, headers):
    """Check for server version disclosure in headers."""
    findings = []
    server = headers.get("server", headers.get("Server", ""))

    if server and SERVER_VERSION_RE.search(server):
        findings.append(
            {
                "type": "Debug_Info",
                "url": url,
                "param": "Server Version",
                "severity": "LOW",
                "evidence": f"Server header: {server}",
                "payload": server,
            }
        )

    # X-Powered-By
    powered_by = headers.get("x-powered-by", headers.get("X-Powered-By", ""))
    if powered_by:
        findings.append(
            {
                "type": "Debug_Info",
                "url": url,
                "param": "X-Powered-By",
                "severity": "LOW",
                "evidence": f"X-Powered-By: {powered_by}",
                "payload": powered_by,
            }
        )

    return findings
