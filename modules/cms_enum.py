"""
cyberm4fia-scanner - CMS Enumeration Scanner

Fingerprints the major CMS platforms (WordPress, Drupal, Joomla) and
extracts their version where possible. Version-pinning enables follow-up
CVE matching by other modules (osv_scanner, cve_feed).

Independent reimplementation; the URL paths and meta-tag patterns are
public CMS conventions, not copyrightable expression.

Coverage
--------
* WordPress  → /wp-login.php, /readme.html, generator meta tag, /wp-json/
* Drupal     → /CHANGELOG.txt, X-Generator header, /core/CHANGELOG.txt
* Joomla     → /administrator/, /language/en-GB/en-GB.xml, generator meta
* Magento    → /magento_version, /static/version, X-Magento-Vary header
* Generic    → <meta name="generator"> for any CMS not above
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

from utils.colors import log_info, log_success
from utils.request import BlockedTargetPath, ScanExceptions, smart_request


# Compiled once at import.
_GENERATOR_META_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_WP_VERSION_RE = re.compile(r"WordPress\s+(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
_DRUPAL_VERSION_RE = re.compile(r"Drupal\s+(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
_JOOMLA_VERSION_RE = re.compile(r"Joomla[!\s]+(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)


def _safe_get(url: str, delay: float):
    try:
        return smart_request("get", url, delay=delay, allow_redirects=True)
    except (ScanExceptions, BlockedTargetPath):
        return None


def _detect_generator(html: str) -> str:
    if not html:
        return ""
    m = _GENERATOR_META_RE.search(html)
    return m.group(1).strip() if m else ""


def _check_wordpress(base: str, delay: float) -> dict | None:
    home = _safe_get(base, delay)
    home_html = getattr(home, "text", "") or ""

    indicators: list[str] = []
    version = ""

    # generator meta
    gen = _detect_generator(home_html)
    if "WordPress" in gen:
        indicators.append(f"generator meta: '{gen}'")
        m = _WP_VERSION_RE.search(gen)
        if m:
            version = m.group(1)

    # readme.html — leaks version on default installs
    readme = _safe_get(urljoin(base, "/readme.html"), delay)
    readme_text = getattr(readme, "text", "") or ""
    m = _WP_VERSION_RE.search(readme_text)
    if m:
        indicators.append(f"/readme.html exposes version {m.group(1)}")
        version = version or m.group(1)

    # /wp-login.php — most reliable WordPress fingerprint
    login = _safe_get(urljoin(base, "/wp-login.php"), delay)
    if login is not None and getattr(login, "status_code", 0) == 200:
        body = getattr(login, "text", "") or ""
        if "wp-login" in body or "WordPress" in body:
            indicators.append("/wp-login.php returns WP login page")

    # /wp-json/ — REST API
    api = _safe_get(urljoin(base, "/wp-json/"), delay)
    if api is not None and getattr(api, "status_code", 0) == 200:
        body = getattr(api, "text", "") or ""
        if '"namespace"' in body or '"routes"' in body:
            indicators.append("/wp-json/ REST API exposed")

    if not indicators:
        return None
    return {
        "type": "CMS_Identified",
        "cms": "WordPress",
        "url": base,
        "version": version,
        "evidence": "; ".join(indicators[:4]),
        "severity": "Info" if not version else "Low",
        "confidence": 90,
        "module": "cms_enum",
    }


def _check_drupal(base: str, delay: float) -> dict | None:
    home = _safe_get(base, delay)
    home_html = getattr(home, "text", "") or ""
    headers = getattr(home, "headers", {}) or {}

    indicators: list[str] = []
    version = ""

    if "X-Generator" in headers and "Drupal" in str(headers["X-Generator"]):
        indicators.append(f"X-Generator: {headers['X-Generator']}")
        m = _DRUPAL_VERSION_RE.search(str(headers["X-Generator"]))
        if m:
            version = m.group(1)

    gen = _detect_generator(home_html)
    if "Drupal" in gen:
        indicators.append(f"generator meta: '{gen}'")
        m = _DRUPAL_VERSION_RE.search(gen)
        if m:
            version = version or m.group(1)

    for changelog_path in ("/CHANGELOG.txt", "/core/CHANGELOG.txt"):
        changelog = _safe_get(urljoin(base, changelog_path), delay)
        if changelog is None:
            continue
        body = getattr(changelog, "text", "") or ""
        m = _DRUPAL_VERSION_RE.search(body)
        if m:
            indicators.append(f"{changelog_path} → {m.group(0)}")
            version = version or m.group(1)
            break

    if not indicators:
        return None
    return {
        "type": "CMS_Identified",
        "cms": "Drupal",
        "url": base,
        "version": version,
        "evidence": "; ".join(indicators[:4]),
        "severity": "Info" if not version else "Low",
        "confidence": 85,
        "module": "cms_enum",
    }


def _check_joomla(base: str, delay: float) -> dict | None:
    home = _safe_get(base, delay)
    home_html = getattr(home, "text", "") or ""

    indicators: list[str] = []
    version = ""

    gen = _detect_generator(home_html)
    if "Joomla" in gen:
        indicators.append(f"generator meta: '{gen}'")
        m = _JOOMLA_VERSION_RE.search(gen)
        if m:
            version = m.group(1)

    admin = _safe_get(urljoin(base, "/administrator/"), delay)
    if admin is not None and getattr(admin, "status_code", 0) in (200, 303, 301):
        body = getattr(admin, "text", "") or ""
        if "Joomla" in body or "joomla" in body:
            indicators.append("/administrator/ returns Joomla login")

    xml = _safe_get(urljoin(base, "/language/en-GB/en-GB.xml"), delay)
    if xml is not None and getattr(xml, "status_code", 0) == 200:
        body = getattr(xml, "text", "") or ""
        m = re.search(r"<version>(\d+\.\d+(?:\.\d+)?)</version>", body)
        if m:
            indicators.append(f"language file → {m.group(1)}")
            version = version or m.group(1)

    if not indicators:
        return None
    return {
        "type": "CMS_Identified",
        "cms": "Joomla",
        "url": base,
        "version": version,
        "evidence": "; ".join(indicators[:4]),
        "severity": "Info" if not version else "Low",
        "confidence": 85,
        "module": "cms_enum",
    }


def _check_magento(base: str, delay: float) -> dict | None:
    home = _safe_get(base, delay)
    if home is None:
        return None
    headers = getattr(home, "headers", {}) or {}
    body = getattr(home, "text", "") or ""

    indicators: list[str] = []

    if any(h.lower().startswith("x-magento") for h in headers):
        indicators.append("X-Magento-* response header present")

    ver = _safe_get(urljoin(base, "/magento_version"), delay)
    if ver is not None and getattr(ver, "status_code", 0) == 200:
        text = (getattr(ver, "text", "") or "").strip()
        if text and len(text) < 200:
            indicators.append(f"/magento_version → {text}")

    if "Mage.Cookies" in body or "var BASE_URL" in body:
        indicators.append("Magento JS globals visible")

    if not indicators:
        return None
    return {
        "type": "CMS_Identified",
        "cms": "Magento",
        "url": base,
        "version": "",
        "evidence": "; ".join(indicators[:4]),
        "severity": "Info",
        "confidence": 75,
        "module": "cms_enum",
    }


def _check_generic_generator(base: str, delay: float) -> dict | None:
    home = _safe_get(base, delay)
    home_html = getattr(home, "text", "") or ""
    gen = _detect_generator(home_html)
    if not gen:
        return None
    # Skip the ones already covered above.
    for name in ("WordPress", "Drupal", "Joomla", "Magento"):
        if name in gen:
            return None
    return {
        "type": "CMS_Identified",
        "cms": gen.split()[0] if gen else "Unknown",
        "url": base,
        "version": "",
        "evidence": f"generator meta: '{gen}'",
        "severity": "Info",
        "confidence": 60,
        "module": "cms_enum",
    }


def scan_cms_enum(url: str, *, delay: float = 0.0) -> list[dict]:
    """Identify the CMS powering a target. Returns at most a few findings."""
    log_info(f"📜 CMS-Enum: fingerprinting {url[:60]}")

    results: list[dict] = []
    for checker in (_check_wordpress, _check_drupal, _check_joomla, _check_magento):
        finding = checker(url, delay)
        if finding:
            results.append(finding)
            log_success(f"  ✅ {finding['cms']}"
                        + (f" v{finding['version']}" if finding["version"] else ""))

    if not results:
        generic = _check_generic_generator(url, delay)
        if generic:
            results.append(generic)
            log_success(f"  ✅ {generic['cms']} (generic)")

    return results
