"""
cyberm4fia-scanner — CSP Bypass Engine

Parses Content-Security-Policy headers to identify weak directives,
then uses Playwright headless browser to verify exploitable XSS bypasses.

Detects:
  - unsafe-inline / unsafe-eval in script-src
  - Wildcard (*) sources
  - data: / blob: scheme allowances
  - Known CDN JSONP endpoints (cdnjs, jsdelivr, googleapis)
  - Missing script-src (falls back to default-src)
  - Nonce extraction from DOM
  - Complete absence of CSP
"""

import re
from urllib.parse import urlparse

from utils.colors import log_info, log_warning, log_success, log_vuln
from utils.request import increment_vulnerability_count
from utils.request import ScanExceptions

# File extensions that are binary/non-HTML — never navigate to these
_SKIP_EXTENSIONS = re.compile(
    r"\.(wasm|zip|tar|gz|bz2|xz|rar|7z|exe|dll|so|bin|dat|iso|img|"
    r"pdf|doc|docx|xls|xlsx|ppt|pptx|mp3|mp4|avi|mkv|mov|flv|wmv|"
    r"jpg|jpeg|png|gif|bmp|svg|ico|webp|tiff|woff|woff2|ttf|eot|otf)$",
    re.IGNORECASE,
)


def _is_navigable_url(url: str) -> bool:
    """Check if a URL is safe for Playwright navigation (not a binary download)."""
    path = urlparse(url).path
    return not bool(_SKIP_EXTENSIONS.search(path))


# ──────────────────────────────────────────────
#  Known CDN JSONP / Angular endpoints for CSP bypass
# ──────────────────────────────────────────────
KNOWN_BYPASS_CDNS = [
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "ajax.googleapis.com",
    "unpkg.com",
    "accounts.google.com",
    "www.google.com",
    "*.googleapis.com",
]

# ──────────────────────────────────────────────
#  CSP Weakness Definitions
# ──────────────────────────────────────────────
CSP_WEAKNESSES = {
    "unsafe-inline": {
        "severity": "high",
        "description": "Allows inline <script> tags — direct XSS possible",
        "payload": "<script>alert('CSP-Bypass-Inline')</script>",
    },
    "unsafe-eval": {
        "severity": "high",
        "description": "Allows eval()/setTimeout(string) — JS code injection",
        "payload": None,  # Browser verify not needed for eval
    },
    "wildcard": {
        "severity": "high",
        "description": "Wildcard (*) in script-src allows loading scripts from any domain",
        "payload": None,
    },
    "data_scheme": {
        "severity": "high",
        "description": "data: URI scheme allowed — inline script via data: URL",
        "payload": None,
    },
    "cdn_jsonp": {
        "severity": "medium",
        "description": "Whitelisted CDN with known JSONP endpoints",
        "payload": None,
    },
    "missing_csp": {
        "severity": "medium",
        "description": "No Content-Security-Policy header — no XSS mitigation",
        "payload": "<img src=x onerror=alert('No-CSP')>",
    },
    "nonce_leak": {
        "severity": "high",
        "description": "CSP nonce value found in DOM — can be reused for XSS",
        "payload": None,
    },
}


def parse_csp(csp_header: str) -> dict:
    """Parse a CSP header string into a directive map.

    Returns:
        dict mapping directive names to their source lists
        e.g. {"script-src": ["'self'", "'unsafe-inline'"], "default-src": ["'self'"]}
    """
    directives = {}
    if not csp_header:
        return directives

    for part in csp_header.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directive_name = tokens[0].lower()
            directives[directive_name] = [t.lower() for t in tokens[1:]]

    return directives


def analyze_csp_weaknesses(directives: dict, url: str) -> list:
    """Analyze parsed CSP directives for exploitable weaknesses."""
    weaknesses = []

    # Get the effective script source list
    script_sources = directives.get("script-src", directives.get("default-src", []))

    if not directives:
        weaknesses.append(
            {
                "type": "CSP_Bypass",
                "weakness": "missing_csp",
                "detail": "No CSP directives found",
                **CSP_WEAKNESSES["missing_csp"],
                "url": url,
                "verified": False,
            }
        )
        return weaknesses

    # Check for unsafe-inline
    if "'unsafe-inline'" in script_sources:
        weaknesses.append(
            {
                "type": "CSP_Bypass",
                "weakness": "unsafe-inline",
                "detail": f"script-src contains 'unsafe-inline': {' '.join(script_sources)}",
                **CSP_WEAKNESSES["unsafe-inline"],
                "url": url,
                "verified": False,
            }
        )

    # Check for unsafe-eval
    if "'unsafe-eval'" in script_sources:
        weaknesses.append(
            {
                "type": "CSP_Bypass",
                "weakness": "unsafe-eval",
                "detail": f"script-src contains 'unsafe-eval': {' '.join(script_sources)}",
                **CSP_WEAKNESSES["unsafe-eval"],
                "url": url,
                "verified": False,
            }
        )

    # Check for wildcard
    if "*" in script_sources:
        weaknesses.append(
            {
                "type": "CSP_Bypass",
                "weakness": "wildcard",
                "detail": "script-src contains wildcard (*)",
                **CSP_WEAKNESSES["wildcard"],
                "url": url,
                "verified": False,
            }
        )

    # Check for data: scheme
    if "data:" in script_sources:
        weaknesses.append(
            {
                "type": "CSP_Bypass",
                "weakness": "data_scheme",
                "detail": "script-src allows data: URIs",
                **CSP_WEAKNESSES["data_scheme"],
                "url": url,
                "verified": False,
            }
        )

    # Check for known bypass CDNs
    for source in script_sources:
        source_clean = source.strip("'\"")
        for cdn in KNOWN_BYPASS_CDNS:
            if cdn in source_clean or source_clean.endswith(cdn):
                weaknesses.append(
                    {
                        "type": "CSP_Bypass",
                        "weakness": "cdn_jsonp",
                        "detail": f"CDN with known JSONP endpoints whitelisted: {source_clean}",
                        **CSP_WEAKNESSES["cdn_jsonp"],
                        "url": url,
                        "verified": False,
                    }
                )
                break

    return weaknesses


def _verify_with_playwright(url: str, weaknesses: list) -> list:
    """Use Playwright to verify CSP bypass by attempting actual XSS execution."""
    if not _is_navigable_url(url):
        log_info(f"Skipping Playwright CSP verify — non-HTML resource: {url}")
        return weaknesses

    try:
        from playwright.sync_api import (
            sync_playwright,
            TimeoutError as PlaywrightTimeoutError,
        )
    except ImportError:
        log_warning("Playwright not installed — CSP bypass verification skipped")
        return weaknesses

    verifiable = [w for w in weaknesses if w.get("payload")]
    if not verifiable:
        return weaknesses

    log_info("🔬 Verifying CSP bypasses with Playwright...")

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            context = browser.new_context(viewport={"width": 1920, "height": 1080})
        except ScanExceptions as e:
            log_warning(f"Playwright launch failed: {e}")
            return weaknesses

        try:
            for weakness in verifiable:
                payload = weakness["payload"]
                test_url = f"{url}#"

                page = context.new_page()
                alert_triggered = [False]

                def handle_dialog(dialog):
                    if "CSP" in dialog.message or "No-CSP" in dialog.message:
                        alert_triggered[0] = True
                    dialog.accept()

                page.on("dialog", handle_dialog)

                try:
                    page.goto(test_url, timeout=8000, wait_until="load")
                    # Inject the payload directly into the DOM
                    page.evaluate(f"""
                        (() => {{
                            const div = document.createElement('div');
                            div.innerHTML = `{payload}`;
                            document.body.appendChild(div);
                        }})()
                    """)
                    page.wait_for_timeout(1500)
                except PlaywrightTimeoutError:
                    pass
                except Exception:  # noqa: BLE001 — catch download, nav, and other Playwright errors
                    pass

                if alert_triggered[0]:
                    weakness["verified"] = True
                    log_success(f"✅ CSP Bypass VERIFIED: {weakness['weakness']}")

                page.close()
        finally:
            browser.close()

    return weaknesses


def _check_nonce_leak(url: str) -> dict | None:
    """Check if CSP nonce values are leaked in the page DOM."""
    if not _is_navigable_url(url):
        return None

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            page = browser.new_page()
            page.goto(url, timeout=8000, wait_until="load")

            # Search for nonce attributes in script tags
            nonces = page.evaluate("""
                () => {
                    const scripts = document.querySelectorAll('script[nonce]');
                    return Array.from(scripts).map(s => s.getAttribute('nonce')).filter(Boolean);
                }
            """)

            browser.close()

            if nonces:
                return {
                    "type": "CSP_Bypass",
                    "weakness": "nonce_leak",
                    "detail": f"Found {len(nonces)} nonce(s) exposed in DOM: {nonces[0][:16]}...",
                    **CSP_WEAKNESSES["nonce_leak"],
                    "url": url,
                    "verified": True,
                    "nonces": nonces,
                }
        except Exception:  # noqa: BLE001 — Playwright nav errors
            pass

    return None


def scan_csp_bypass(url: str, response=None) -> list:
    """Main CSP Bypass scanner — analyzes CSP header and verifies exploitability.

    Args:
        url: Target URL
        response: httpx Response object (optional, will fetch if not provided)

    Returns:
        list of CSP bypass vulnerability dicts
    """
    log_info("🛡️ Analyzing Content-Security-Policy...")

    # Get CSP header
    if response and hasattr(response, "headers"):
        headers = {k.lower(): v for k, v in response.headers.items()}
    else:
        from utils.request import smart_request

        try:
            resp = smart_request("get", url)
            headers = {k.lower(): v for k, v in resp.headers.items()}
        except ScanExceptions:
            log_warning("Failed to fetch target for CSP analysis")
            return []

    csp_header = headers.get("content-security-policy", "")
    csp_report_only = headers.get("content-security-policy-report-only", "")

    # Parse & analyze
    directives = parse_csp(csp_header)
    weaknesses = analyze_csp_weaknesses(directives, url)

    # If CSP-Report-Only is present instead, it's effectively no enforcement
    if not csp_header and csp_report_only:
        weaknesses.append(
            {
                "type": "CSP_Bypass",
                "weakness": "report_only",
                "severity": "medium",
                "description": "CSP is in report-only mode — not enforced",
                "detail": "Content-Security-Policy-Report-Only found instead of enforcing CSP",
                "url": url,
                "verified": False,
                "payload": None,
            }
        )

    if not weaknesses:
        log_info("CSP appears properly configured — no obvious bypasses found")
        return []

    # Log findings
    for w in weaknesses:
        log_warning(f"CSP Weakness: {w['weakness']} — {w['description']}")

    # Attempt Playwright verification for exploitable weaknesses
    weaknesses = _verify_with_playwright(url, weaknesses)

    # Check for nonce leaks
    nonce_finding = _check_nonce_leak(url)
    if nonce_finding:
        weaknesses.append(nonce_finding)

    # Count verified vulns
    for w in weaknesses:
        increment_vulnerability_count()
        source = "🔬 Verified" if w.get("verified") else "📋 Detected"
        log_vuln(f"CSP Bypass [{source}]: {w['weakness']}")

    return weaknesses
