"""
cyberm4fia-scanner - Technology Fingerprinter
Wappalyzer-style detection of frameworks, CMS, servers, and libraries
"""

import sys
import os
import re
from urllib.parse import urljoin

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.colors import log_info, log_success, log_warning, log_error
from utils.request import smart_request

# ─────────────────────────────────────────────────────
# Technology Fingerprint Database
# ─────────────────────────────────────────────────────
TECHNOLOGIES = [
    # ── Web Servers ──
    {
        "name": "Nginx",
        "category": "Web Server",
        "headers": {"server": r"nginx/?(\S+)?"},
    },
    {
        "name": "Apache",
        "category": "Web Server",
        "headers": {"server": r"Apache/?(\S+)?"},
    },
    {
        "name": "IIS",
        "category": "Web Server",
        "headers": {"server": r"Microsoft-IIS/?(\S+)?"},
    },
    {
        "name": "LiteSpeed",
        "category": "Web Server",
        "headers": {"server": r"LiteSpeed"},
    },
    {
        "name": "Caddy",
        "category": "Web Server",
        "headers": {"server": r"Caddy"},
    },
    {
        "name": "Cloudflare",
        "category": "CDN/WAF",
        "headers": {"server": r"cloudflare", "cf-ray": r".*"},
    },
    {
        "name": "Vercel",
        "category": "PaaS",
        "headers": {"x-vercel-id": r".*", "server": r"Vercel"},
    },
    {
        "name": "Netlify",
        "category": "PaaS",
        "headers": {"server": r"Netlify", "x-nf-request-id": r".*"},
    },
    # ── Programming Languages ──
    {
        "name": "PHP",
        "category": "Language",
        "headers": {"x-powered-by": r"PHP/?(\S+)?"},
    },
    {
        "name": "ASP.NET",
        "category": "Language",
        "headers": {"x-aspnet-version": r"(\S+)", "x-powered-by": r"ASP\.NET"},
    },
    {
        "name": "Python",
        "category": "Language",
        "headers": {"x-powered-by": r"(Python|Flask|Django|Gunicorn)"},
    },
    {
        "name": "Express.js",
        "category": "Framework",
        "headers": {"x-powered-by": r"Express"},
    },
    # ── CMS ──
    {
        "name": "WordPress",
        "category": "CMS",
        "body_patterns": [
            r"/wp-content/",
            r"/wp-includes/",
            r'<meta name="generator" content="WordPress\s*([\d.]+)?"',
        ],
        "paths": ["/wp-login.php", "/wp-admin/", "/xmlrpc.php"],
    },
    {
        "name": "Joomla",
        "category": "CMS",
        "body_patterns": [
            r"/media/jui/",
            r"/components/com_",
            r'<meta name="generator" content="Joomla',
        ],
        "paths": ["/administrator/"],
    },
    {
        "name": "Drupal",
        "category": "CMS",
        "body_patterns": [
            r"Drupal\.settings",
            r"/sites/default/files/",
            r'<meta name="Generator" content="Drupal',
        ],
        "paths": ["/user/login", "/core/misc/drupal.js"],
    },
    {
        "name": "Magento",
        "category": "CMS",
        "body_patterns": [r"/skin/frontend/", r"Mage\.Cookies"],
    },
    # ── JavaScript Frameworks ──
    {
        "name": "React",
        "category": "JS Framework",
        "body_patterns": [
            r"data-reactroot",
            r"__NEXT_DATA__",
            r"react\.production\.min\.js",
            r'"react-dom"',
        ],
    },
    {
        "name": "Next.js",
        "category": "JS Framework",
        "body_patterns": [r"__NEXT_DATA__", r"/_next/static/"],
        "headers": {"x-powered-by": r"Next\.js"},
    },
    {
        "name": "Vue.js",
        "category": "JS Framework",
        "body_patterns": [r"vue\.runtime", r"data-v-[a-f0-9]", r"__vue__"],
    },
    {
        "name": "Nuxt.js",
        "category": "JS Framework",
        "body_patterns": [r"__NUXT__", r"/_nuxt/"],
    },
    {
        "name": "Angular",
        "category": "JS Framework",
        "body_patterns": [r"ng-version", r"ng-app", r"angular\.min\.js"],
    },
    {
        "name": "Svelte",
        "category": "JS Framework",
        "body_patterns": [r"__svelte", r"svelte-"],
    },
    {
        "name": "jQuery",
        "category": "JS Library",
        "body_patterns": [r"jquery[.-](\d[\d.]+)\.min\.js", r"jquery\.min\.js"],
    },
    # ── Security / Auth ──
    {
        "name": "Firebase",
        "category": "Backend",
        "body_patterns": [r"firebaseapp\.com", r"firebase\.js"],
    },
    {
        "name": "Supabase",
        "category": "Backend",
        "body_patterns": [r"supabase\.co", r"supabase"],
    },
    # ── Analytics ──
    {
        "name": "Google Analytics",
        "category": "Analytics",
        "body_patterns": [
            r"google-analytics\.com/analytics\.js",
            r"gtag\('config'",
            r"googletagmanager\.com",
        ],
    },
    {
        "name": "Hotjar",
        "category": "Analytics",
        "body_patterns": [r"static\.hotjar\.com"],
    },
    # ── Security Headers ──
    {
        "name": "HSTS",
        "category": "Security",
        "headers": {"strict-transport-security": r".*"},
    },
    {
        "name": "CSP",
        "category": "Security",
        "headers": {"content-security-policy": r".*"},
    },
    {
        "name": "X-Frame-Options",
        "category": "Security",
        "headers": {"x-frame-options": r".*"},
    },
]


def fingerprint_headers(headers, tech):
    """Check response headers against technology fingerprints."""
    results = {}
    tech_headers = tech.get("headers", {})

    for header_name, pattern in tech_headers.items():
        header_value = headers.get(header_name, "")
        if header_value:
            match = re.search(pattern, header_value, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex else None
                results["matched"] = True
                results["version"] = version
                return results

    return results


def fingerprint_body(body, tech):
    """Check response body against technology fingerprints."""
    patterns = tech.get("body_patterns", [])
    for pattern in patterns:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            version = match.group(1) if match.lastindex else None
            return {"matched": True, "version": version}
    return {}


def check_paths(url, tech, delay):
    """Check specific paths that indicate a technology."""
    paths = tech.get("paths", [])
    for path in paths:
        try:
            check_url = urljoin(url, path)
            resp = smart_request("get", check_url, delay=delay, timeout=5)
            if resp.status_code == 200:
                return {"matched": True, "evidence": path}
        except Exception:
            pass
    return {}


def check_security_posture(headers):
    """Analyze missing security headers."""
    issues = []
    critical_headers = {
        "strict-transport-security": "No HSTS — vulnerable to SSL stripping",
        "content-security-policy": "No CSP — vulnerable to XSS",
        "x-frame-options": "No X-Frame-Options — vulnerable to clickjacking",
        "x-content-type-options": "No X-Content-Type-Options — MIME sniffing possible",
        "x-xss-protection": "No X-XSS-Protection header",
        "referrer-policy": "No Referrer-Policy — information leakage risk",
        "permissions-policy": "No Permissions-Policy — feature access not restricted",
    }

    for header, message in critical_headers.items():
        if header not in headers:
            issues.append({"header": header, "issue": message, "severity": "MEDIUM"})

    # Check for information disclosure
    dangerous_headers = ["server", "x-powered-by", "x-aspnet-version"]
    for h in dangerous_headers:
        if h in headers:
            issues.append(
                {
                    "header": h,
                    "issue": f"Information disclosure via {h}: {headers[h]}",
                    "severity": "LOW",
                }
            )

    return issues


def scan_technology(url, delay=0):
    """Main entry point for technology fingerprinting."""
    log_info(f"Starting Technology Fingerprinting on {url}...")

    detected = []

    try:
        resp = smart_request("get", url, delay=delay, timeout=10)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text[:50000]  # Limit body analysis to first 50KB

        for tech in TECHNOLOGIES:
            result = {}

            # Check headers
            if "headers" in tech:
                header_result = fingerprint_headers(headers, tech)
                if header_result.get("matched"):
                    result = header_result

            # Check body patterns
            if not result.get("matched") and "body_patterns" in tech:
                body_result = fingerprint_body(body, tech)
                if body_result.get("matched"):
                    result = body_result

            # Check specific paths
            if not result.get("matched") and "paths" in tech:
                path_result = check_paths(url, tech, delay)
                if path_result.get("matched"):
                    result = path_result

            if result.get("matched"):
                version = result.get("version", "")
                evidence = result.get("evidence", "")
                version_str = f" v{version}" if version else ""

                detected.append(
                    {
                        "type": "technology",
                        "name": tech["name"],
                        "category": tech["category"],
                        "version": version,
                        "evidence": evidence,
                    }
                )

                log_success(f"[{tech['category']}] {tech['name']}{version_str}")

        # Security posture analysis
        security_issues = check_security_posture(headers)
        for issue in security_issues:
            detected.append(
                {
                    "type": "security_header",
                    "name": issue["header"],
                    "category": "Security",
                    "issue": issue["issue"],
                    "severity": issue["severity"],
                }
            )

    except Exception as e:
        log_error(f"Technology fingerprinting failed: {e}")

    log_success(f"Tech detection complete. {len(detected)} item(s) identified.")
    return detected
