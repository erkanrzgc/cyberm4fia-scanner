"""Pre-scan recon + discovery / fuzzer / crawler phase runners."""

from __future__ import annotations

import os

from utils.request import ScanExceptions  # noqa: F401  (used by some imports)


# ── Discovery / Recon runners ───────────────────────────────────────────────

def _run_cloud_storage(state):
    from modules.cloud_enum import scan_cloud_storage

    return scan_cloud_storage(state["url"], delay=state["delay"])


def _run_recon(state):
    from modules.recon import run_recon

    state["recon_data"] = run_recon(
        state["url"],
        deep=bool(state["options"].get("recon")),
    )
    return []


def _run_osint(state):
    from utils.shodan_lookup import scan_osint

    shodan_key = os.environ.get("SHODAN_API_KEY", "")
    state["osint_data"] = scan_osint(state["url"], shodan_api_key=shodan_key or None, delay=state["delay"])
    return []


def _run_tech_intel(state):
    from modules.tech_detect import scan_technology
    from utils.colors import log_warning

    state["tech_results"] = scan_technology(state["url"], delay=state["delay"])
    
    # Convert tech_results list into a category→name dict that PayloadFilter expects
    # e.g. [{"category": "Language", "name": "PHP"}, ...] → {"lang": "php", "os": "linux"}
    if "options" in state:
        _category_map = {
            "Language": "lang",
            "Web Server": "server",
            "Database": "db",
            "OS": "os",
            "Framework": "framework",
        }
        tech_context = {}
        for item in (state["tech_results"] or []):
            if item.get("type") != "technology":
                continue
            key = _category_map.get(item.get("category", ""), "")
            if key and item.get("name"):
                tech_context[key] = item["name"].lower()
        state["options"]["target_context"] = tech_context

    try:
        from utils.cve_feed import enrich_with_cves

        state["cve_intel"] = enrich_with_cves(state["tech_results"])
    except ScanExceptions as exc:
        log_warning(f"CVE feed unavailable: {exc}")
        state["cve_intel"] = []

    return state["cve_intel"]


def _run_sploitus_search(state):
    from utils.sploitus_search import get_sploitus
    tech_stack = state.get("tech_results", {})
    if tech_stack:
        sploitus = get_sploitus()
        enrichments = sploitus.enrich_findings([], tech_stack=tech_stack)
        if enrichments:
            sploitus.print_results(enrichments)
    return []


def _run_google_dorker(state):
    from modules.google_dorker import scan_google_dorks

    tech_stack = state.get("tech_results")
    result = scan_google_dorks(
        state["url"],
        delay=state["delay"],
        tech_stack=tech_stack,
    )
    state["dorking_data"] = result

    # Feed discovered URLs into the scan pipeline
    discovered = result.get("discovered_urls", [])
    if discovered:
        from core.module_registry import canonicalize_scan_urls
        from utils.colors import log_success

        existing = state.get("urls_to_scan", [state["url"]])
        state["urls_to_scan"] = canonicalize_scan_urls(existing + discovered)
        log_success(f"Dorking added {len(discovered)} URL(s) to scan queue")

    return []


def _run_osint_identity(state):
    from modules.osint_identity import scan_identity_fabric

    subdomains = state.get("recon_data", {}).get("subdomains", [])
    result = scan_identity_fabric(
        state["url"],
        subdomains=subdomains,
        delay=state["delay"],
    )
    state["osint_identity_data"] = result
    return result


def _run_osint_breach(state):
    from modules.osint_breach import scan_breach_intel

    emails = state.get("recon_data", {}).get("emails", [])
    hibp_key = os.environ.get("HIBP_API_KEY", "")
    result = scan_breach_intel(
        state["url"],
        emails=emails,
        hibp_api_key=hibp_key or None,
        delay=state["delay"],
    )
    state["osint_breach_data"] = result
    return result


def _run_osint_sector(state):
    from modules.osint_sector import scan_sector_osint

    result = scan_sector_osint(state["url"], delay=state["delay"])
    state["osint_sector_data"] = result
    return []


def _run_container_registry(state):
    from modules.cloud_enum import scan_container_registries

    result = scan_container_registries(state["url"], delay=state["delay"])
    state["container_registry_data"] = result
    return result


def _run_cicd_exposure(state):
    from modules.cloud_enum import scan_cicd_exposure

    result = scan_cicd_exposure(state["url"], delay=state["delay"])
    state["cicd_exposure_data"] = result
    return result


def _run_wayback_harvester(state):
    from modules.wayback_harvester import scan_wayback

    result = scan_wayback(state["url"], delay=state["delay"])
    state["wayback_data"] = result

    # Feed interesting URLs into the scan pipeline
    interesting = result.get("interesting", {})
    # Prioritize API, admin, auth, and param endpoints
    priority_urls = []
    for cat in ["api", "admin", "auth", "param_endpoints", "upload", "debug"]:
        priority_urls.extend(interesting.get(cat, []))

    if priority_urls:
        from core.module_registry import canonicalize_scan_urls
        from utils.colors import log_success

        existing = state.get("urls_to_scan", [state["url"]])
        # Limit wayback additions to avoid scan explosion
        state["urls_to_scan"] = canonicalize_scan_urls(
            existing + priority_urls[:50]
        )
        log_success(f"Wayback added {min(len(priority_urls), 50)} URL(s) to scan queue")

    # Feed discovered parameters into param_discovery context
    params = result.get("parameters", set())
    if params:
        if "options" in state:
            existing_params = state["options"].get("wayback_params", set())
            state["options"]["wayback_params"] = existing_params | params

    return []


def _run_urlscan_passive(state):
    from modules.urlscan_passive import scan_urlscan

    result = scan_urlscan(state["url"], delay=state["delay"])
    state["urlscan_data"] = result

    # Feed discovered URLs into the scan pipeline
    discovered = result.get("discovered_urls", [])
    if discovered:
        from core.module_registry import canonicalize_scan_urls
        from utils.colors import log_success

        existing = state.get("urls_to_scan", [state["url"]])
        state["urls_to_scan"] = canonicalize_scan_urls(existing + discovered)
        log_success(f"URLScan added {len(discovered)} URL(s) to scan queue")

    # Merge URLScan technology detections into tech_results
    urlscan_techs = result.get("technologies", [])
    if urlscan_techs and "tech_results" in state:
        existing_names = {t.get("name") for t in (state["tech_results"] or [])}
        for tech in urlscan_techs:
            if tech.get("name") and tech["name"] not in existing_names:
                state["tech_results"].append({
                    "type": "technology",
                    "name": tech["name"],
                    "category": ", ".join(tech.get("categories", [])),
                    "version": tech.get("version", ""),
                    "evidence": "URLScan.io",
                })

    return []


def _run_brute_force(state):
    from modules.brute_force import BruteForcer
    from urllib.parse import urlparse
    
    host = urlparse(state["url"]).netloc.split(":")[0]
    
    # Basic port detection logic (fallback if no osint)
    # Shodan OSINT data from _run_osint might contain ports
    open_ports = None
    if "osint_data" in state and isinstance(state["osint_data"], dict):
        open_ports = state["osint_data"].get("ports")
        
    bruter = BruteForcer()
    results = bruter.auto_brute(host, open_ports=open_ports)
    return bruter.results_to_findings(results)

def _run_subdomain_takeover(state):
    from modules.subdomain_takeover import scan_subdomain_takeover

    return scan_subdomain_takeover(state["url"], delay=state["delay"])


def _run_api_scan(state):
    from modules.api_scanner import scan_api

    return scan_api(
        state["url"],
        delay=state["delay"],
        spec_path=state["options"].get("api_spec") or None,
    )


def _run_subdomain_scan(state):
    from modules.recon import scan_subdomains

    scan_subdomains(state["target_host"])
    return []


def _run_cors(state):
    from modules.cors import scan_cors

    return scan_cors(state["url"])


def _run_header_inject(state):
    from modules.header_inject import scan_header_inject

    return scan_header_inject(state["url"], state["delay"])


# ── Discovery expansion runners ─────────────────────────────────────────────

def _run_fuzzer_discovery(state):
    from modules.endpoint_fuzzer import scan_fuzzer_async
    from core.module_registry import canonicalize_scan_urls

    endpoints = scan_fuzzer_async(
        state["url"],
        state["wordlist_file"],
        threads=state["options"].get("threads", 50),
        delay=state["delay"],
    )
    if endpoints:
        state["urls_to_scan"].extend(
            [
                endpoint["url"]
                for endpoint in endpoints
                if endpoint["status"] in [200, 301, 302, 307, 308]
            ]
        )
        state["urls_to_scan"] = canonicalize_scan_urls(state["urls_to_scan"])
    return []


def _run_headless_discovery(state):
    from modules.dynamic_crawler import run_dynamic_spider
    from utils.colors import log_info, log_success
    from core.module_registry import canonicalize_scan_urls

    har_output = None
    if state["options"].get("har_output"):
        har_output = state["scan_dir"]

    log_info("Using dynamic Playwright crawler for SPA...")
    crawl_result = run_dynamic_spider(
        state["url"], delay=state["delay"], har_output=har_output
    )

    found_links = crawl_result.get("links", [])
    state["urls_to_scan"] = canonicalize_scan_urls(
        state.get("urls_to_scan", [state["url"]]) + found_links
    )
    state["crawled_forms"] = crawl_result.get("forms", [])

    endpoints = crawl_result.get("endpoints", [])
    if endpoints:
        log_success(f"Discovered {len(endpoints)} background API endpoints")
        for method, endpoint_url in endpoints:
            if method.upper() == "GET":
                state["urls_to_scan"].append(endpoint_url)

    har_path = crawl_result.get("har_path")
    if har_path:
        state["har_path"] = har_path
        log_success(f"HAR recording saved: {har_path}")

    state["urls_to_scan"] = canonicalize_scan_urls(state["urls_to_scan"])[:30]
    return []


def _run_crawl_discovery(state):
    from modules.crawler import crawl_site
    from core.module_registry import canonicalize_scan_urls

    if state["options"].get("headless"):
        return []

    crawl_result = crawl_site(state["url"], max_pages=30)
    if isinstance(crawl_result, dict):
        state["urls_to_scan"] = canonicalize_scan_urls(
            crawl_result.get("urls", [state["url"]])
        )
        state["crawled_forms"] = crawl_result.get("forms", [])
    else:
        state["urls_to_scan"] = canonicalize_scan_urls(crawl_result)
    return []


