"""
cyberm4fia-scanner - Google Dorking Engine
Automated Google Dork generation & search for target reconnaissance.

Generates context-aware dorks based on target domain and detected technology
stack, then queries search APIs for results to seed the discovery pipeline.
"""

import re
import time
from urllib.parse import urlparse, quote_plus

from utils.colors import Colors, log_info, log_success, log_warning, log_error
from utils.request import smart_request, ScanExceptions


# ─────────────────────────────────────────────────────
# Dork Templates — grouped by attack surface category
# ─────────────────────────────────────────────────────

DORK_TEMPLATES = {
    "sensitive_files": [
        'site:{domain} filetype:sql',
        'site:{domain} filetype:env',
        'site:{domain} filetype:log',
        'site:{domain} filetype:bak',
        'site:{domain} filetype:conf',
        'site:{domain} filetype:cfg',
        'site:{domain} filetype:ini',
        'site:{domain} filetype:yml',
        'site:{domain} filetype:yaml',
        'site:{domain} filetype:json "password"',
        'site:{domain} filetype:xml "password"',
        'site:{domain} filetype:csv',
        'site:{domain} filetype:xlsx',
        'site:{domain} filetype:doc',
        'site:{domain} filetype:pdf "confidential"',
    ],
    "admin_panels": [
        'site:{domain} inurl:admin',
        'site:{domain} inurl:login',
        'site:{domain} inurl:dashboard',
        'site:{domain} inurl:panel',
        'site:{domain} inurl:cpanel',
        'site:{domain} inurl:phpmyadmin',
        'site:{domain} inurl:wp-admin',
        'site:{domain} inurl:administrator',
        'site:{domain} inurl:manage',
        'site:{domain} inurl:console',
    ],
    "api_endpoints": [
        'site:{domain} inurl:api',
        'site:{domain} inurl:api/v1',
        'site:{domain} inurl:api/v2',
        'site:{domain} inurl:graphql',
        'site:{domain} inurl:swagger',
        'site:{domain} inurl:api-docs',
        'site:{domain} inurl:openapi',
        'site:{domain} filetype:json "swagger"',
        'site:{domain} inurl:rest',
        'site:{domain} inurl:webhook',
    ],
    "credentials_exposure": [
        'site:{domain} intext:password',
        'site:{domain} intext:"api_key"',
        'site:{domain} intext:"secret_key"',
        'site:{domain} intext:"access_token"',
        'site:{domain} intext:"aws_access_key_id"',
        'site:{domain} intext:"private_key"',
        'site:{domain} filetype:env "DB_PASSWORD"',
        'site:{domain} filetype:env "SECRET"',
        '"{domain}" password filetype:txt',
        '"{domain}" "BEGIN RSA PRIVATE KEY"',
    ],
    "source_code": [
        'site:{domain} filetype:php',
        'site:{domain} filetype:asp',
        'site:{domain} filetype:aspx',
        'site:{domain} filetype:jsp',
        'site:{domain} filetype:py',
        'site:{domain} filetype:rb',
        'site:{domain} filetype:js intext:"apiKey"',
        'site:{domain} ext:js "firebase"',
    ],
    "backup_debug": [
        'site:{domain} inurl:backup',
        'site:{domain} inurl:debug',
        'site:{domain} inurl:test',
        'site:{domain} inurl:staging',
        'site:{domain} inurl:dev',
        'site:{domain} inurl:.git',
        'site:{domain} inurl:.svn',
        'site:{domain} inurl:.env',
        'site:{domain} intitle:"index of"',
        'site:{domain} intitle:"directory listing"',
    ],
    "error_pages": [
        'site:{domain} intext:"sql syntax"',
        'site:{domain} intext:"mysql_fetch"',
        'site:{domain} intext:"Warning: pg_"',
        'site:{domain} intext:"ORA-"',
        'site:{domain} intext:"Stack Trace"',
        'site:{domain} intext:"Traceback (most recent call last)"',
        'site:{domain} intext:"Fatal error"',
        'site:{domain} intitle:"500 Internal Server Error"',
    ],
    "subdomains": [
        'site:*.{domain} -www',
        'site:*.{domain} inurl:dev',
        'site:*.{domain} inurl:staging',
        'site:*.{domain} inurl:test',
        'site:*.{domain} inurl:api',
        'site:*.{domain} inurl:beta',
    ],
    "cloud_ci_shadow_it": [
        'site:s3.amazonaws.com "{domain}"',
        'site:storage.googleapis.com "{domain}"',
        'site:blob.core.windows.net "{domain}"',
        'site:digitaloceanspaces.com "{domain}"',
        'site:trello.com "{domain}"',
        'site:*.atlassian.net "{domain}"',
        'site:dev.azure.com "{domain}"',
        'site:bitbucket.org "{domain}"',
        'site:firebaseio.com "{domain}"',
        'site:herokuapp.com "{domain}"',
    ],
    "docs_intel": [
        'site:{domain} filetype:pdf (confidential OR internal OR restricted)',
        'site:{domain} filetype:xlsx OR filetype:csv',
        'site:{domain} filetype:docx',
        'site:{domain} filetype:pptx OR filetype:ppt',
        'site:scribd.com "{company}"',
        '"{company}" filetype:pdf (salary OR payroll OR "organization chart")',
        'site:slideshare.net "{company}"',
    ],
    "vuln_indicators": [
        'site:{domain} intext:"sql syntax" OR intext:"you have an error in your sql"',
        'site:{domain} intext:"Warning: mysql_"',
        'site:{domain} intext:"Fatal error:" intext:"on line"',
        'site:{domain} intext:"stack trace" OR intext:"Traceback (most recent call last)"',
        '"Apache/2.4.49" site:{domain}',
        '"Server: nginx/1.14" site:{domain}',
        'site:{domain} inurl:wp-content OR inurl:wp-includes',
    ],
    "internal_tools": [
        'site:{domain} intitle:"Splunk"',
        'site:{domain} intitle:"Grafana"',
        'site:{domain} intitle:"Kibana"',
        'site:{domain} intitle:"Prometheus Time Series"',
        'site:{domain} intitle:"Jaeger UI"',
        'site:{domain} intitle:"AlertManager"',
        'site:{domain} intitle:"Argo CD"',
        'site:{domain} intitle:"Sonarqube"',
        'site:{domain} intitle:"Sentry"',
        'site:{domain} intitle:"Confluence"',
        'site:{domain} intitle:"Jira"',
        'site:{domain} intitle:"GitLab"',
        'site:{domain} intitle:"Gitea"',
        'site:{domain} intitle:"Drone CI"',
        'site:{domain} inurl:"/jenkins/"',
    ],
    "backup_dump_files": [
        'site:{domain} ext:bak OR ext:backup OR ext:old OR ext:orig OR ext:save OR ext:swp',
        'site:{domain} ext:tar OR ext:tar.gz OR ext:tgz OR ext:zip OR ext:rar OR ext:7z',
        'site:{domain} ext:db OR ext:sqlite OR ext:sqlite3 OR ext:mdb',
        'site:{domain} ext:dump OR ext:rdb OR ext:bson',
        'site:{domain} (intext:"-- MySQL dump" OR intext:"PostgreSQL database dump")',
        'site:{domain} ext:pcap OR ext:pcapng OR ext:cap',
        'site:{domain} ext:core OR ext:hprof OR ext:dmp',
    ],
    "paste_sites": [
        'site:pastebin.com "{domain}"',
        'site:ghostbin.com "{domain}"',
        'site:rentry.co "{domain}"',
        'site:gist.github.com "{domain}"',
        'site:hastebin.com "{domain}"',
        'site:justpaste.it "{domain}"',
        'site:paste.ee "{domain}"',
    ],
    "saas_collaboration": [
        'site:notion.site "{domain}"',
        'site:notion.so "{domain}"',
        'site:atlassian.net "{domain}"',
        'site:trello.com "{domain}"',
        'site:miro.com "{domain}"',
        'site:lucid.app "{domain}"',
        'site:figma.com "{domain}"',
        'site:asana.com "{domain}"',
        'site:gitbook.io "{domain}"',
        'site:readthedocs.io "{domain}"',
    ],
}

# Technology-specific dorks
TECH_DORKS = {
    "WordPress": [
        'site:{domain} inurl:wp-content/uploads',
        'site:{domain} inurl:wp-json',
        'site:{domain} inurl:xmlrpc.php',
        'site:{domain} inurl:wp-includes',
        'site:{domain} filetype:sql "wp_users"',
    ],
    "Joomla": [
        'site:{domain} inurl:administrator',
        'site:{domain} inurl:components/com_',
        'site:{domain} inurl:configuration.php',
    ],
    "Drupal": [
        'site:{domain} inurl:sites/default/files',
        'site:{domain} inurl:user/login',
        'site:{domain} inurl:node/',
    ],
    "Laravel": [
        'site:{domain} inurl:storage/logs',
        'site:{domain} inurl:.env "APP_KEY"',
        'site:{domain} intext:"Whoops! There was an error"',
    ],
    "Django": [
        'site:{domain} inurl:admin/',
        'site:{domain} intext:"DisallowedHost"',
        'site:{domain} intitle:"Django" "DEBUG"',
    ],
    "PHP": [
        'site:{domain} inurl:phpinfo',
        'site:{domain} ext:php inurl:config',
        'site:{domain} ext:php inurl:include',
    ],
    "ASP.NET": [
        'site:{domain} inurl:web.config',
        'site:{domain} inurl:elmah.axd',
        'site:{domain} ext:aspx',
    ],
    "Kubernetes": [
        'site:{domain} inurl:".kube/config"',
        'site:{domain} inurl:"kubeconfig"',
        'site:{domain} inurl:"helm" inurl:"values"',
    ],
}

# GitHub dorks for target organization
GITHUB_DORKS = [
    '"{domain}" password',
    '"{domain}" api_key',
    '"{domain}" secret',
    '"{domain}" token',
    '"{domain}" AWS_SECRET',
    '"{domain}" PRIVATE_KEY',
    '"{domain}" ".env"',
    '"{domain}" jdbc:',
    '"{domain}" mongodb+srv',
]


def generate_dorks(domain, categories=None, tech_stack=None):
    """
    Generate context-aware Google Dorks for a target domain.

    Args:
        domain: Target domain (e.g. example.com)
        categories: Optional list of dork categories to use.
                     If None, uses all categories.
        tech_stack: Optional list of detected technology dicts from tech_detect.
                    Used to generate tech-specific dorks.

    Returns:
        Dict of {category: [dork_strings]}
    """
    if categories is None:
        categories = list(DORK_TEMPLATES.keys())

    dorks = {}

    # Standard dorks
    for cat in categories:
        if cat in DORK_TEMPLATES:
            dorks[cat] = [
                tpl.format(domain=domain) for tpl in DORK_TEMPLATES[cat]
            ]

    # Technology-specific dorks
    if tech_stack:
        tech_dorks = []
        for tech_item in tech_stack:
            if tech_item.get("type") != "technology":
                continue
            tech_name = tech_item.get("name", "")
            if tech_name in TECH_DORKS:
                for tpl in TECH_DORKS[tech_name]:
                    tech_dorks.append(tpl.format(domain=domain))
        if tech_dorks:
            dorks["tech_specific"] = tech_dorks

    # GitHub dorks
    dorks["github"] = [tpl.format(domain=domain) for tpl in GITHUB_DORKS]

    return dorks


def _search_google_cse(query, delay=1.0):
    """
    Search using Google Custom Search (requires API key).
    Falls back to scraping if no API key available.
    Returns list of {title, url, snippet} dicts.
    """
    import os
    api_key = os.environ.get("GOOGLE_API_KEY", "")
    cse_id = os.environ.get("GOOGLE_CSE_ID", "")

    if api_key and cse_id:
        try:
            resp = smart_request(
                "get",
                "https://www.googleapis.com/customsearch/v1",
                params={"key": api_key, "cx": cse_id, "q": query, "num": 10},
                delay=delay,
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                results = []
                for item in data.get("items", []):
                    results.append({
                        "title": item.get("title", ""),
                        "url": item.get("link", ""),
                        "snippet": item.get("snippet", ""),
                    })
                return results
        except ScanExceptions:
            pass
    return []


def _search_bing_api(query, delay=1.0):
    """
    Search using Bing Web Search API (free tier available).
    Returns list of {title, url, snippet} dicts.
    """
    import os
    api_key = os.environ.get("BING_API_KEY", "")

    if not api_key:
        return []

    try:
        resp = smart_request(
            "get",
            "https://api.bing.microsoft.com/v7.0/search",
            params={"q": query, "count": 10},
            headers={"Ocp-Apim-Subscription-Key": api_key},
            delay=delay,
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            results = []
            for item in data.get("webPages", {}).get("value", []):
                results.append({
                    "title": item.get("name", ""),
                    "url": item.get("url", ""),
                    "snippet": item.get("snippet", ""),
                })
            return results
    except ScanExceptions:
        pass
    return []


def _search_duckduckgo_lite(query, delay=2.0):
    """
    Search using DuckDuckGo HTML-lite interface.
    No API key needed. Rate-limited friendly.
    Returns list of {title, url, snippet} dicts.
    """
    try:
        resp = smart_request(
            "post",
            "https://lite.duckduckgo.com/lite/",
            data={"q": query},
            delay=delay,
            timeout=10,
        )
        if resp.status_code == 200:
            results = []
            # Basic HTML parsing for DuckDuckGo Lite results
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")
            for link in soup.find_all("a", class_="result-link"):
                href = link.get("href", "")
                title = link.get_text(strip=True)
                if href and "duckduckgo.com" not in href:
                    results.append({
                        "title": title,
                        "url": href,
                        "snippet": "",
                    })
            return results[:10]
    except ScanExceptions:
        pass
    return []


def scan_google_dorks(url, delay=0.5, tech_stack=None, categories=None):
    """
    Main entry point: Generate and execute Google Dorks for target.

    Tries multiple search backends (Google CSE → Bing → DuckDuckGo).
    Returns a structured results dict.

    Args:
        url: Target URL (e.g. https://example.com)
        delay: Request delay between searches
        tech_stack: Optional list of detected technologies from tech_detect
        categories: Optional list of dork categories to scan

    Returns:
        dict with keys: domain, dorks_generated, results, discovered_urls
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    parts = hostname.split(".")
    domain = ".".join(parts[-2:]) if len(parts) > 2 else hostname

    print(
        f"\n{Colors.BOLD}{Colors.CYAN}"
        f"──── GOOGLE DORKING ENGINE ────{Colors.END}"
    )
    log_info(f"Generating dorks for {domain}...")

    # Generate dorks
    all_dorks = generate_dorks(domain, categories=categories, tech_stack=tech_stack)

    total_dorks = sum(len(v) for v in all_dorks.values())
    log_info(f"Generated {total_dorks} dorks across {len(all_dorks)} categories")

    # Select high-value dorks to actually search (limit to avoid rate-limits)
    priority_categories = [
        "sensitive_files", "credentials_exposure", "admin_panels",
        "api_endpoints", "backup_debug", "tech_specific",
    ]
    search_dorks = []
    for cat in priority_categories:
        if cat in all_dorks:
            search_dorks.extend(all_dorks[cat][:5])  # Top 5 per category

    # Also add top error_pages and subdomains
    for cat in ["error_pages", "subdomains"]:
        if cat in all_dorks:
            search_dorks.extend(all_dorks[cat][:3])

    log_info(f"Searching {len(search_dorks)} high-priority dorks...")

    all_results = {}
    discovered_urls = set()

    for i, dork in enumerate(search_dorks):
        log_info(f"  [{i+1}/{len(search_dorks)}] {dork[:70]}...")

        # Try search backends in order
        results = _search_google_cse(dork, delay=delay)
        if not results:
            results = _search_bing_api(dork, delay=delay)
        if not results:
            results = _search_duckduckgo_lite(dork, delay=max(delay, 2.0))

        if results:
            all_results[dork] = results
            for r in results:
                url_found = r.get("url", "")
                if url_found and domain in url_found:
                    discovered_urls.add(url_found)
            log_success(f"  → {len(results)} result(s)")
        else:
            # Even if we can't search, the dork itself is valuable intel
            all_results[dork] = []

        # Rate limiting between searches
        time.sleep(max(delay, 0.5))

    # Print summary
    total_results = sum(len(v) for v in all_results.values())
    print(f"\n{Colors.BOLD}[*] Google Dorking Summary{Colors.END}")
    log_info(f"  Dorks generated: {total_dorks}")
    log_info(f"  Dorks searched: {len(search_dorks)}")
    log_success(f"  Search results: {total_results}")
    log_success(f"  Unique URLs discovered: {len(discovered_urls)}")

    # Print categorized dork list (for manual use)
    if not total_results:
        log_info("No search API available. Dorks saved for manual use:")
        for cat, dorks in all_dorks.items():
            print(f"\n  {Colors.CYAN}{Colors.BOLD}[{cat.upper()}]{Colors.END}")
            for dork in dorks[:3]:
                print(f"    {Colors.GREY}{dork}{Colors.END}")
            if len(dorks) > 3:
                print(f"    {Colors.DIM}... +{len(dorks) - 3} more{Colors.END}")

    print(
        f"\n{Colors.BOLD}{Colors.CYAN}"
        f"──── GOOGLE DORKING COMPLETE ────{Colors.END}\n"
    )

    return {
        "domain": domain,
        "dorks_generated": total_dorks,
        "dorks_searched": len(search_dorks),
        "all_dorks": all_dorks,
        "results": all_results,
        "discovered_urls": list(discovered_urls),
    }
