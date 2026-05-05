"""
cyberm4fia-scanner - URLScan.io Passive Reconnaissance
Passive intelligence gathering using URLScan.io's free API.

Submits targets for scanning and retrieves:
- Page screenshots, DOM content, and embedded links
- JavaScript analysis and external resource mapping
- Technology detection and certificate information
- Threat/malicious indicators
"""

import os
import time
from urllib.parse import urlparse

from utils.colors import Colors, log_info, log_success, log_warning, log_error
from utils.request import smart_request, ScanExceptions


URLSCAN_API = "https://urlscan.io/api/v1"
URLSCAN_RESULT_WAIT = 15  # seconds to wait for scan to complete


def _get_api_key():
    """Get URLScan.io API key from environment."""
    return os.environ.get("URLSCAN_API_KEY", "")


def search_existing(domain, limit=5):
    """
    Search URLScan.io for existing scans of a domain.
    This does NOT submit a new scan — just queries past results.
    No API key needed for search.

    Args:
        domain: Target domain to search
        limit: Max results to return

    Returns:
        List of scan result dicts
    """
    log_info(f"Searching URLScan.io for existing scans of {domain}...")

    try:
        resp = smart_request(
            "get",
            f"{URLSCAN_API}/search/",
            params={"q": f"domain:{domain}", "size": limit},
            timeout=10,
            delay=0,
        )
        if resp.status_code == 200:
            data = resp.json()
            results = data.get("results", [])
            if results:
                log_success(f"Found {len(results)} existing scan(s)")
            else:
                log_info("No existing scans found")
            return results
        elif resp.status_code == 429:
            log_warning("URLScan.io rate limit reached")
        else:
            log_warning(f"URLScan.io search returned {resp.status_code}")
    except ScanExceptions as e:
        log_warning(f"URLScan.io search failed: {e}")

    return []


def submit_scan(url, visibility="public"):
    """
    Submit a new scan to URLScan.io.
    Requires API key.

    Args:
        url: URL to scan
        visibility: Scan visibility ('public', 'unlisted', 'private')

    Returns:
        Scan UUID string if successful, None otherwise
    """
    api_key = _get_api_key()
    if not api_key:
        log_info("No URLSCAN_API_KEY — using search-only mode")
        return None

    try:
        resp = smart_request(
            "post",
            f"{URLSCAN_API}/scan/",
            headers={
                "API-Key": api_key,
                "Content-Type": "application/json",
            },
            json={"url": url, "visibility": visibility},
            timeout=10,
            delay=0,
        )
        if resp.status_code == 200:
            data = resp.json()
            uuid = data.get("uuid")
            if uuid:
                log_success(f"Scan submitted: {data.get('result', '')}")
                return uuid
        elif resp.status_code == 429:
            log_warning("URLScan.io rate limit reached")
        else:
            log_warning(f"URLScan.io submit returned {resp.status_code}")
    except ScanExceptions as e:
        log_warning(f"URLScan.io submit failed: {e}")

    return None


def get_scan_result(uuid, wait=True):
    """
    Get results of a URLScan.io scan by UUID.

    Args:
        uuid: Scan UUID
        wait: If True, wait for scan to complete (up to 30s)

    Returns:
        Full result dict or None
    """
    if wait:
        log_info(f"Waiting {URLSCAN_RESULT_WAIT}s for scan to complete...")
        time.sleep(URLSCAN_RESULT_WAIT)

    max_retries = 3
    for attempt in range(max_retries):
        try:
            resp = smart_request(
                "get",
                f"{URLSCAN_API}/result/{uuid}/",
                timeout=10,
                delay=0,
            )
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                if attempt < max_retries - 1:
                    log_info("Scan not ready yet, waiting...")
                    time.sleep(10)
                continue
        except ScanExceptions:
            if attempt < max_retries - 1:
                time.sleep(5)

    return None


def extract_intel(result):
    """
    Extract actionable intelligence from a URLScan.io result.

    Returns:
        dict with categories: links, js_files, apis, technologies,
        certificates, ip_info, threats
    """
    intel = {
        "links": [],
        "js_files": [],
        "apis": [],
        "technologies": [],
        "certificates": [],
        "ip_info": {},
        "threats": [],
        "cookies": [],
        "headers": {},
        "console_messages": [],
        "global_variables": [],
    }

    if not result:
        return intel

    # ── Page Data ──
    page = result.get("page", {})
    intel["page_title"] = page.get("title", "")
    intel["page_ip"] = page.get("ip", "")
    intel["page_server"] = page.get("server", "")
    intel["page_status"] = page.get("status", 0)

    # ── Links ──
    lists_data = result.get("lists", {})
    intel["links"] = lists_data.get("urls", [])

    # ── IP addresses ──
    intel["ip_addresses"] = lists_data.get("ips", [])

    # ── Domains contacted ──
    intel["domains"] = lists_data.get("domains", [])

    # ── Certificates ──
    intel["certificates"] = lists_data.get("certificates", [])

    # ── Hashes ──
    intel["hashes"] = lists_data.get("hashes", [])

    # ── Data from detailed analysis ──
    data_section = result.get("data", {})

    # Requests made during scan — extract JS files and API calls
    requests = data_section.get("requests", [])
    for req in requests:
        req_url = req.get("request", {}).get("request", {}).get("url", "")
        mime_type = req.get("response", {}).get("response", {}).get("mimeType", "")

        if req_url:
            if "javascript" in mime_type or req_url.endswith(".js"):
                intel["js_files"].append(req_url)
            if "/api/" in req_url or "/rest/" in req_url or "/graphql" in req_url:
                intel["apis"].append(req_url)

    # Cookies
    cookies = data_section.get("cookies", [])
    intel["cookies"] = [
        {
            "name": c.get("name", ""),
            "domain": c.get("domain", ""),
            "secure": c.get("secure", False),
            "httpOnly": c.get("httpOnly", False),
            "sameSite": c.get("sameSite", ""),
        }
        for c in cookies
    ]

    # Console messages (error messages leak info)
    console_msgs = data_section.get("console", [])
    intel["console_messages"] = [
        m.get("message", {}).get("text", "")
        for m in console_msgs
        if m.get("message", {}).get("level") in ("error", "warning")
    ]

    # Global JavaScript variables (potential secrets)
    globals_list = data_section.get("globals", [])
    if isinstance(globals_list, list):
        # Filter for interesting variable names
        sensitive_patterns = [
            "api", "key", "token", "secret", "auth", "password",
            "firebase", "aws", "config", "endpoint", "base_url",
        ]
        for g in globals_list:
            prop = g.get("prop", "").lower() if isinstance(g, dict) else str(g).lower()
            if any(pat in prop for pat in sensitive_patterns):
                intel["global_variables"].append(
                    g.get("prop") if isinstance(g, dict) else str(g)
                )

    # Technologies (from Wappalyzer data)
    meta = result.get("meta", {})
    processors = meta.get("processors", {})
    wappalyzer = processors.get("wappa", {})
    for tech in wappalyzer.get("data", []):
        intel["technologies"].append({
            "name": tech.get("app", ""),
            "categories": [c.get("name", "") for c in tech.get("categories", [])],
            "version": tech.get("version", ""),
        })

    # Threat verdicts
    verdicts = result.get("verdicts", {})
    overall = verdicts.get("overall", {})
    if overall.get("malicious"):
        intel["threats"].append({
            "verdict": "MALICIOUS",
            "score": overall.get("score", 0),
            "tags": overall.get("tags", []),
        })
    engines = verdicts.get("engines", {})
    if engines.get("malicious"):
        intel["threats"].append({
            "verdict": "ENGINE_MALICIOUS",
            "score": engines.get("score", 0),
            "categories": engines.get("categories", []),
        })

    return intel


def scan_urlscan(url, delay=0.5):
    """
    Main entry point: Perform passive recon via URLScan.io.

    Strategy:
    1. Search for existing scans (no API key needed)
    2. If API key available, submit a new scan
    3. Extract and categorize intelligence

    Args:
        url: Target URL
        delay: Request delay (mostly unused for API calls)

    Returns:
        dict with intel categories and discovered URLs
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    parts = hostname.split(".")
    domain = ".".join(parts[-2:]) if len(parts) > 2 else hostname

    print(
        f"\n{Colors.BOLD}{Colors.CYAN}"
        f"──── URLSCAN.IO PASSIVE RECON ────{Colors.END}"
    )

    all_intel = {
        "domain": domain,
        "scans_analyzed": 0,
        "links": [],
        "js_files": [],
        "apis": [],
        "technologies": [],
        "cookies": [],
        "threats": [],
        "global_variables": [],
        "console_messages": [],
        "discovered_urls": [],
    }

    # Step 1: Search existing scans
    existing = search_existing(domain, limit=3)

    # Step 2: If API key exists, submit new scan
    scan_uuid = submit_scan(url)
    if scan_uuid:
        result = get_scan_result(scan_uuid)
        if result:
            intel = extract_intel(result)
            _merge_intel(all_intel, intel)
            all_intel["scans_analyzed"] += 1

    # Step 3: Analyze existing scans
    for scan in existing[:3]:
        task = scan.get("task", {})
        scan_uuid = scan.get("_id") or task.get("uuid")
        if scan_uuid:
            result = get_scan_result(scan_uuid, wait=False)
            if result:
                intel = extract_intel(result)
                _merge_intel(all_intel, intel)
                all_intel["scans_analyzed"] += 1

    # ── Print Results ──
    print(f"\n{Colors.BOLD}[*] URLScan.io Intelligence Summary{Colors.END}")
    log_info(f"  Scans analyzed: {all_intel['scans_analyzed']}")

    if all_intel["technologies"]:
        log_success(f"  Technologies detected: {len(all_intel['technologies'])}")
        for tech in all_intel["technologies"][:10]:
            cats = ", ".join(tech.get("categories", []))
            version = f" v{tech['version']}" if tech.get("version") else ""
            print(f"    {Colors.GREEN}→ {tech['name']}{version} [{cats}]{Colors.END}")

    if all_intel["js_files"]:
        log_success(f"  JS files discovered: {len(all_intel['js_files'])}")
        for js in all_intel["js_files"][:5]:
            print(f"    {Colors.GREY}→ {js[:80]}{Colors.END}")
        if len(all_intel["js_files"]) > 5:
            print(f"    {Colors.DIM}... +{len(all_intel['js_files']) - 5} more{Colors.END}")

    if all_intel["apis"]:
        log_success(f"  API endpoints found: {len(all_intel['apis'])}")
        for api in all_intel["apis"][:5]:
            print(f"    {Colors.CYAN}→ {api[:80]}{Colors.END}")

    if all_intel["cookies"]:
        insecure = [c for c in all_intel["cookies"] if not c.get("secure")]
        no_httponly = [c for c in all_intel["cookies"] if not c.get("httpOnly")]
        log_info(f"  Cookies: {len(all_intel['cookies'])} total")
        if insecure:
            log_warning(f"    ⚠ {len(insecure)} cookie(s) without Secure flag")
        if no_httponly:
            log_warning(f"    ⚠ {len(no_httponly)} cookie(s) without HttpOnly flag")

    if all_intel["global_variables"]:
        log_warning(f"  Suspicious JS globals: {len(all_intel['global_variables'])}")
        for g in all_intel["global_variables"][:5]:
            print(f"    {Colors.YELLOW}→ {g}{Colors.END}")

    if all_intel["console_messages"]:
        log_warning(f"  Console errors/warnings: {len(all_intel['console_messages'])}")
        for msg in all_intel["console_messages"][:3]:
            print(f"    {Colors.GREY}{msg[:100]}{Colors.END}")

    if all_intel["threats"]:
        for threat in all_intel["threats"]:
            log_error(f"  🚨 THREAT: {threat['verdict']} (score: {threat.get('score', 'N/A')})")

    # Build discovered URLs list (unique, in-scope)
    discovered = set()
    for link in all_intel["links"]:
        if isinstance(link, str) and domain in link:
            discovered.add(link)
    for api in all_intel["apis"]:
        if isinstance(api, str) and domain in api:
            discovered.add(api)
    all_intel["discovered_urls"] = list(discovered)

    if discovered:
        log_success(f"  Total discovered URLs: {len(discovered)}")

    print(
        f"\n{Colors.BOLD}{Colors.CYAN}"
        f"──── URLSCAN.IO RECON COMPLETE ────{Colors.END}\n"
    )

    return all_intel


def _merge_intel(target, source):
    """Merge a source intel dict into target, deduplicating lists."""
    list_keys = [
        "links", "js_files", "apis", "technologies",
        "cookies", "threats", "global_variables", "console_messages",
    ]
    for key in list_keys:
        existing = {str(item) for item in target.get(key, [])}
        for item in source.get(key, []):
            item_str = str(item)
            if item_str not in existing:
                target[key].append(item)
                existing.add(item_str)
