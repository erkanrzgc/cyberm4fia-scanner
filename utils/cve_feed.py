"""
cyberm4fia-scanner — SiberAdar CVE Threat Intel Feed

Fetches real-time CVE data from SiberAdar (siberadar.com) API
and enriches technology fingerprint results with known vulnerabilities.

Usage:
    from utils.cve_feed import enrich_with_cves
    cve_findings = enrich_with_cves(tech_detect_results)
"""

import httpx
from utils.colors import log_info, log_success, log_warning
from utils.request import ScanExceptions

SIBERADAR_API = "https://www.siberadar.com/api/cves"

# Map tech_detect names → SiberAdar vendor_products search terms
TECH_TO_VENDOR = {
    "Nginx": "nginx",
    "Apache": "apache",
    "IIS": "iis",
    "PHP": "php",
    "ASP.NET": "asp.net",
    "Python": "python",
    "Express.js": "nodejs",
    "Node.js": "nodejs",
    "WordPress": "wordpress",
    "Joomla": "joomla",
    "Drupal": "drupal",
    "Magento": "magento",
    "React": "react",
    "Angular": "angular",
    "Vue.js": "vue",
    "jQuery": "jquery",
    "Bootstrap": "bootstrap",
    "Laravel": "laravel",
    "Django": "django",
    "Flask": "flask",
    "Spring": "spring",
    "Tomcat": "tomcat",
    "MySQL": "mysql",
    "PostgreSQL": "postgresql",
    "MongoDB": "mongodb",
    "Redis": "redis",
    "Cloudflare": "cloudflare",
    "Firebase": "firebase",
    "Supabase": "supabase",
}

# In-memory cache to avoid duplicate queries in same scan
_cache: dict[str, list] = {}

def fetch_cves(tech_name: str, max_results: int = 10) -> list[dict]:
    """
    Fetch CVEs for a technology from SiberAdar API.

    Args:
        tech_name: Technology name (e.g. 'php', 'nginx')
        max_results: Maximum CVEs to return

    Returns:
        List of CVE dicts with cve_id, score, severity, description, etc.
    """
    cache_key = tech_name.lower()
    if cache_key in _cache:
        return _cache[cache_key]

    try:
        with httpx.Client(timeout=10, follow_redirects=True) as client:
            resp = client.get(
                SIBERADAR_API,
                params={"vendor_products": cache_key},
            )
            resp.raise_for_status()
            data = resp.json()

        cves = data.get("cves", [])

        # Filter: only HIGH/CRITICAL with actual scores
        filtered = []
        for cve in cves:
            severity = (cve.get("severity") or "").upper()
            if severity in ("CRITICAL", "HIGH"):
                filtered.append(cve)
            if len(filtered) >= max_results:
                break

        _cache[cache_key] = filtered
        return filtered

    except httpx.HTTPStatusError as e:
        log_warning(
            f"SiberAdar API error for '{tech_name}': HTTP {e.response.status_code}"
        )
        return []
    except httpx.RequestError as e:
        log_warning(f"SiberAdar API unreachable: {e}")
        return []
    except ScanExceptions as e:
        log_warning(f"CVE feed error: {e}")
        return []

def enrich_with_cves(tech_results: list[dict]) -> list[dict]:
    """
    Take tech_detect results and fetch relevant CVEs from SiberAdar.

    Args:
        tech_results: Output from scan_technology() — list of dicts with
                      'name', 'category', 'version' keys.

    Returns:
        List of vulnerability dicts (type='CVE_Intel') ready for all_vulns.
    """
    if not tech_results:
        return []

    # Get unique technology names that have vendor mappings
    techs_to_query = set()
    for tech in tech_results:
        if tech.get("type") != "technology":
            continue
        name = tech.get("name", "")
        if name in TECH_TO_VENDOR:
            techs_to_query.add(name)

    if not techs_to_query:
        return []

    log_info(
        f"🔍 Fetching CVE intel from SiberAdar for {len(techs_to_query)} technologies..."
    )

    findings = []

    for tech_name in sorted(techs_to_query):
        vendor_key = TECH_TO_VENDOR[tech_name]
        cves = fetch_cves(vendor_key)

        if not cves:
            continue

        # Get version from tech_results for this tech
        detected_version = ""
        for tech in tech_results:
            if tech.get("name") == tech_name:
                detected_version = tech.get("version", "")
                break

        kev_count = sum(1 for c in cves if c.get("in_kev"))
        exploit_count = sum(1 for c in cves if c.get("has_exploit"))

        log_success(
            f"  {tech_name}: {len(cves)} CVE(s) "
            f"({'🔥 ' + str(exploit_count) + ' exploitable' if exploit_count else ''}"
            f"{', ⚠️ ' + str(kev_count) + ' in KEV' if kev_count else ''})"
        )

        for cve in cves:
            cve_id = cve.get("cve_id", "N/A")
            score = cve.get("score") or 0
            severity = (cve.get("severity") or "unknown").lower()
            epss = cve.get("epss_score", 0)
            in_kev = cve.get("in_kev", False)
            has_exploit = cve.get("has_exploit", 0)
            desc = cve.get("description_tr") or cve.get("description", "")
            cwe = cve.get("cwe_ids", "")
            tags = cve.get("tags", "")

            # Build risk labels
            risk_labels = []
            if in_kev:
                risk_labels.append("⚠️ CISA KEV")
            if has_exploit:
                risk_labels.append("🔥 Exploit Available")
            if epss and epss > 0.5:
                risk_labels.append(f"📊 EPSS: {epss:.1%}")

            finding = {
                "type": "CVE_Intel",
                "url": f"https://www.siberadar.com/cve/{cve_id}",
                "param": tech_name,
                "payload": cve_id,
                "evidence": desc[:200] if desc else "",
                "severity": severity,
                "cvss": score,
                "cwe": cwe.split(",")[0] if cwe else "",
                "tags": tags,
                "risk_labels": ", ".join(risk_labels) if risk_labels else "",
                "tech_version": detected_version,
                "epss_score": epss,
                "in_kev": in_kev,
                "has_exploit": bool(has_exploit),
            }
            findings.append(finding)

    if findings:
        log_success(f"🛡️ CVE Intel: {len(findings)} relevant CVE(s) from SiberAdar")

        # ── Public Exploit Search ──
        # For CVEs that have known exploits, search for actual PoC code
        try:
            from utils.exploit_finder import find_exploits, build_exploit_context

            exploit_cves = [f for f in findings if f.get("has_exploit")]
            if exploit_cves:
                log_info(f"🔍 Searching public exploit databases for {len(exploit_cves)} exploitable CVE(s)...")

                for finding in exploit_cves[:5]:  # limit to top 5 to avoid slowdown
                    cve_id = finding.get("payload", "")
                    if not cve_id or not cve_id.startswith("CVE-"):
                        continue

                    search_result = find_exploits(cve_id)
                    if search_result.has_exploits:
                        best = search_result.best_exploit
                        finding["public_exploit_url"] = best.url if best else ""
                        finding["public_exploit_source"] = best.source if best else ""
                        finding["public_exploit_count"] = search_result.total_found
                        finding["exploit_context"] = build_exploit_context(search_result)

                        if best and best.verified:
                            log_warning(
                                f"  ⚡ {cve_id}: VERIFIED exploit on {best.source} → {best.url}"
                            )
                        elif best:
                            log_success(
                                f"  💀 {cve_id}: PoC found on {best.source} → {best.url}"
                            )
        except ImportError:
            pass

    else:
        log_info("No relevant CVEs found for detected technologies.")

    return findings

def clear_cache():
    """Clear in-memory CVE cache (useful between scans)."""
    _cache.clear()
