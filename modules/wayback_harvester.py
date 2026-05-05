"""
cyberm4fia-scanner - Wayback Machine URL Harvester
Discovers historical endpoints, removed pages, and hidden API paths
from the Wayback Machine (web.archive.org) archive.
"""

import re
from urllib.parse import urlparse, parse_qs

from utils.colors import Colors, log_info, log_success, log_warning, log_error
from utils.request import smart_request, ScanExceptions


# Interesting URL patterns to prioritize from Wayback results
INTERESTING_PATTERNS = {
    "api": re.compile(r"/api[/\?]", re.IGNORECASE),
    "admin": re.compile(r"/(admin|dashboard|manage|panel|cpanel|backend)", re.IGNORECASE),
    "auth": re.compile(r"/(login|signin|signup|register|auth|oauth|sso|forgot|reset)", re.IGNORECASE),
    "upload": re.compile(r"/(upload|file|import|attachment|media)", re.IGNORECASE),
    "config": re.compile(r"/\.(env|config|ini|yml|yaml|conf|cfg|xml|json|bak|backup|old|orig|swp)", re.IGNORECASE),
    "debug": re.compile(r"/(debug|test|staging|dev|phpinfo|info\.php|status|health)", re.IGNORECASE),
    "data": re.compile(r"/(export|download|dump|backup|db|database|sql|csv)", re.IGNORECASE),
    "vcs": re.compile(r"/\.(git|svn|hg|bzr)/", re.IGNORECASE),
    "sensitive_ext": re.compile(r"\.(sql|bak|log|env|conf|ini|key|pem|crt|csr|p12|pfx|jks)$", re.IGNORECASE),
    "source_code": re.compile(r"\.(php|asp|aspx|jsp|py|rb|pl|cgi)$", re.IGNORECASE),
    "param_endpoints": re.compile(r"\?[a-zA-Z]+=", re.IGNORECASE),
}

# URL patterns to skip (noise, assets, etc.)
SKIP_PATTERNS = re.compile(
    r"\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|mp4|mp3|avi|mov|mkv|webm|webp)$",
    re.IGNORECASE,
)

SKIP_DOMAINS = {
    "fonts.googleapis.com",
    "ajax.googleapis.com",
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "maxcdn.bootstrapcdn.com",
    "unpkg.com",
    "stackpath.bootstrapcdn.com",
}


def fetch_wayback_urls(domain, no_subs=True, timeout=30):
    """
    Fetch URLs from the Wayback Machine's CDX API.

    Args:
        domain: Target domain (e.g. example.com)
        no_subs: If True, exclude subdomains
        timeout: Request timeout

    Returns:
        List of unique URL strings
    """
    log_info(f"Querying Wayback Machine for {domain}...")

    urls = set()
    cdx_url = "https://web.archive.org/cdx/search/cdx"
    params = {
        "url": f"*.{domain}/*" if not no_subs else f"{domain}/*",
        "output": "text",
        "fl": "original",
        "collapse": "urlkey",
        "limit": "5000",
    }

    try:
        resp = smart_request("get", cdx_url, params=params, timeout=timeout, delay=0)
        if resp.status_code == 200 and resp.text.strip():
            for line in resp.text.strip().split("\n"):
                url = line.strip()
                if url and url.startswith("http"):
                    urls.add(url)
            log_success(f"Wayback CDX returned {len(urls)} URLs")
        else:
            log_warning(f"Wayback CDX returned status {resp.status_code}")
    except ScanExceptions as e:
        log_warning(f"Wayback CDX query failed: {e}")

    # Fallback: Also try web.archive.org's text API
    if not urls:
        try:
            resp = smart_request(
                "get",
                f"https://web.archive.org/web/timemap/link/{domain}",
                timeout=15,
                delay=0,
            )
            if resp.status_code == 200:
                for match in re.findall(r'<(https?://[^>]+)>', resp.text):
                    urls.add(match)
                if urls:
                    log_success(f"Wayback timemap returned {len(urls)} URLs")
        except ScanExceptions:
            pass

    return list(urls)


def classify_url(url):
    """
    Classify a URL by its security relevance.

    Returns:
        List of category strings that match, or empty list.
    """
    categories = []
    for category, pattern in INTERESTING_PATTERNS.items():
        if pattern.search(url):
            categories.append(category)
    return categories


def filter_urls(urls, domain):
    """
    Filter and deduplicate Wayback URLs.

    Removes:
    - Static assets (CSS, JS, images)
    - CDN domains
    - Duplicate paths (ignoring fragments)

    Returns:
        Filtered list of unique, interesting URLs
    """
    seen_paths = set()
    filtered = []

    for url in urls:
        # Skip static assets
        if SKIP_PATTERNS.search(url):
            continue

        # Skip CDN domains
        parsed = urlparse(url)
        if parsed.netloc in SKIP_DOMAINS:
            continue

        # Must belong to target domain
        if domain not in parsed.netloc:
            continue

        # Deduplicate by path (ignore query params for dedup)
        path_key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if path_key in seen_paths:
            continue
        seen_paths.add(path_key)

        filtered.append(url)

    return filtered


def extract_parameters(urls):
    """
    Extract unique parameter names from URLs for later injection testing.

    Returns:
        Set of parameter name strings
    """
    params = set()
    for url in urls:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        params.update(qs.keys())
    return params


def scan_wayback(url, delay=0.5, no_subs=True):
    """
    Main entry point: Harvest historical URLs from the Wayback Machine.

    Args:
        url: Target URL (e.g. https://example.com)
        delay: Not used for Wayback (archive API), but kept for consistency
        no_subs: If True, only query exact domain (no subdomains)

    Returns:
        dict with keys:
        - domain: Target domain
        - total_urls: Total raw URLs found
        - filtered_urls: Cleaned, deduplicated URLs
        - interesting: Dict of {category: [urls]}
        - parameters: Set of unique parameter names
        - endpoints: List of discovered endpoint paths
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    parts = hostname.split(".")
    domain = ".".join(parts[-2:]) if len(parts) > 2 else hostname

    print(
        f"\n{Colors.BOLD}{Colors.CYAN}"
        f"──── WAYBACK MACHINE HARVESTER ────{Colors.END}"
    )

    # Fetch URLs
    raw_urls = fetch_wayback_urls(domain, no_subs=no_subs)

    if not raw_urls:
        log_warning("No Wayback data found for this domain")
        print(
            f"{Colors.BOLD}{Colors.CYAN}"
            f"──── WAYBACK HARVESTER COMPLETE ────{Colors.END}\n"
        )
        return {
            "domain": domain,
            "total_urls": 0,
            "filtered_urls": [],
            "interesting": {},
            "parameters": set(),
            "endpoints": [],
        }

    # Filter and classify
    filtered = filter_urls(raw_urls, domain)
    log_info(f"After filtering: {len(filtered)} unique endpoints (from {len(raw_urls)} raw)")

    # Classify interesting URLs
    interesting = {}
    for furl in filtered:
        categories = classify_url(furl)
        for cat in categories:
            if cat not in interesting:
                interesting[cat] = []
            interesting[cat].append(furl)

    # Extract parameters
    params = extract_parameters(filtered)

    # Extract unique paths as endpoints
    endpoints = set()
    for furl in filtered:
        p = urlparse(furl)
        endpoints.add(p.path)

    # ── Print Results ──
    print(f"\n{Colors.BOLD}[*] Wayback Machine Results{Colors.END}")
    log_info(f"  Raw URLs: {len(raw_urls)}")
    log_info(f"  Filtered (unique): {len(filtered)}")
    log_success(f"  Unique endpoints: {len(endpoints)}")

    if params:
        log_success(f"  Unique parameters: {len(params)}")
        param_preview = ", ".join(sorted(params)[:15])
        print(f"    {Colors.GREY}{param_preview}{Colors.END}")
        if len(params) > 15:
            print(f"    {Colors.DIM}... +{len(params) - 15} more{Colors.END}")

    if interesting:
        print(f"\n{Colors.BOLD}[*] Interesting URLs by Category{Colors.END}")
        for cat, cat_urls in sorted(interesting.items()):
            icon = {
                "api": "🔌",
                "admin": "🔐",
                "auth": "🔑",
                "upload": "📤",
                "config": "⚙️",
                "debug": "🐛",
                "data": "💾",
                "vcs": "📦",
                "sensitive_ext": "🔥",
                "source_code": "📜",
                "param_endpoints": "🎯",
            }.get(cat, "📌")
            print(f"\n  {icon} {Colors.CYAN}{Colors.BOLD}{cat.upper()}{Colors.END} ({len(cat_urls)})")
            for u in cat_urls[:5]:
                print(f"    {Colors.GREEN}→ {u}{Colors.END}")
            if len(cat_urls) > 5:
                print(f"    {Colors.DIM}... +{len(cat_urls) - 5} more{Colors.END}")

    print(
        f"\n{Colors.BOLD}{Colors.CYAN}"
        f"──── WAYBACK HARVESTER COMPLETE ────{Colors.END}\n"
    )

    return {
        "domain": domain,
        "total_urls": len(raw_urls),
        "filtered_urls": filtered,
        "interesting": interesting,
        "parameters": params,
        "endpoints": list(endpoints),
    }
