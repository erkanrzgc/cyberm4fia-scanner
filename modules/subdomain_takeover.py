"""
cyberm4fia-scanner - Subdomain Takeover Scanner
Detects dangling CNAME records pointing to unclaimed cloud services
Inspired by Subzy, Can-I-Take-Over-XYZ
"""

from urllib.parse import urlparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.colors import log_info, log_success, log_warning
from utils.request import smart_request
from utils.request import ScanExceptions

# ─────────────────────────────────────────────────────
# Fingerprint database - services vulnerable to takeover
# ─────────────────────────────────────────────────────
FINGERPRINTS = [
    {
        "service": "GitHub Pages",
        "cnames": ["github.io", "github.map.fastly.net"],
        "response_fingerprints": [
            "There isn't a GitHub Pages site here.",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
        "nxdomain": False,
    },
    {
        "service": "Heroku",
        "cnames": ["herokuapp.com", "herokussl.com", "herokudns.com"],
        "response_fingerprints": [
            "No such app",
            "no-such-app",
            "herokucdn.com/error-pages/no-such-app",
        ],
        "nxdomain": False,
    },
    {
        "service": "AWS S3 Website",
        "cnames": ["s3.amazonaws.com", "s3-website"],
        "response_fingerprints": [
            "NoSuchBucket",
            "The specified bucket does not exist",
        ],
        "nxdomain": True,
    },
    {
        "service": "Shopify",
        "cnames": ["myshopify.com", "shops.myshopify.com"],
        "response_fingerprints": [
            "Sorry, this shop is currently unavailable",
            "Only one step left!",
        ],
        "nxdomain": False,
    },
    {
        "service": "Tumblr",
        "cnames": ["tumblr.com", "domains.tumblr.com"],
        "response_fingerprints": [
            "Whatever you were looking for doesn't currently exist at this address",
            "There's nothing here.",
        ],
        "nxdomain": False,
    },
    {
        "service": "WordPress.com",
        "cnames": ["wordpress.com"],
        "response_fingerprints": [
            "Do you want to register",
        ],
        "nxdomain": False,
    },
    {
        "service": "Azure (Web Apps)",
        "cnames": [
            "azurewebsites.net",
            "cloudapp.net",
            "azure-api.net",
            "azurefd.net",
            "blob.core.windows.net",
            "trafficmanager.net",
        ],
        "response_fingerprints": [
            "404 Web Site not found",
            "You may be seeing this error due to the app being stopped",
        ],
        "nxdomain": True,
    },
    {
        "service": "Fastly",
        "cnames": ["fastly.net", "global.fastly.net", "fastly.com"],
        "response_fingerprints": [
            "Fastly error: unknown domain",
        ],
        "nxdomain": False,
    },
    {
        "service": "Pantheon",
        "cnames": ["pantheonsite.io"],
        "response_fingerprints": [
            "404 error unknown site!",
            "The gods are wise",
        ],
        "nxdomain": False,
    },
    {
        "service": "Surge.sh",
        "cnames": ["surge.sh"],
        "response_fingerprints": [
            "project not found",
        ],
        "nxdomain": False,
    },
    {
        "service": "Fly.io",
        "cnames": ["fly.dev", "edgeapp.net"],
        "response_fingerprints": [
            "404 Not Found",
        ],
        "nxdomain": True,
    },
    {
        "service": "Netlify",
        "cnames": ["netlify.app", "netlify.com"],
        "response_fingerprints": [
            "Not Found - Request ID",
        ],
        "nxdomain": False,
    },
    {
        "service": "Ghost",
        "cnames": ["ghost.io"],
        "response_fingerprints": [
            "Site does not exist",
        ],
        "nxdomain": False,
    },
    {
        "service": "Zendesk",
        "cnames": ["zendesk.com"],
        "response_fingerprints": [
            "Help Center Closed",
        ],
        "nxdomain": False,
    },
    {
        "service": "Unbounce",
        "cnames": ["unbouncepages.com"],
        "response_fingerprints": [
            "The requested URL was not found on this server",
        ],
        "nxdomain": False,
    },
    {
        "service": "AWS Elastic Beanstalk",
        "cnames": ["elasticbeanstalk.com"],
        "response_fingerprints": [],
        "nxdomain": True,
    },
    {
        "service": "Bitbucket",
        "cnames": ["bitbucket.io"],
        "response_fingerprints": [
            "Repository not found",
        ],
        "nxdomain": False,
    },
    {
        "service": "Intercom",
        "cnames": ["custom.intercom.help"],
        "response_fingerprints": [
            "This page is reserved for a",
            "Uh oh. That page doesn't exist",
        ],
        "nxdomain": False,
    },
]

def resolve_cname(subdomain):
    """Resolve CNAME for a subdomain using DNS."""
    try:
        import subprocess

        result = subprocess.run(
            ["dig", "+short", "CNAME", subdomain],
            capture_output=True,
            text=True,
            timeout=5,
        )
        cname = result.stdout.strip().rstrip(".")
        return cname if cname else None
    except ScanExceptions:
        return None

def check_nxdomain(subdomain):
    """Check if a domain resolves to NXDOMAIN (no DNS record)."""
    try:
        socket.getaddrinfo(subdomain, 80)
        return False  # Resolves — not NXDOMAIN
    except socket.gaierror:
        return True  # NXDOMAIN

def check_subdomain_takeover(subdomain, delay=0):
    """Check a single subdomain for potential takeover."""
    findings = []

    # Step 1: Resolve CNAME
    cname = resolve_cname(subdomain)
    if not cname:
        return findings

    # Step 2: Match CNAME against known vulnerable services
    for fp in FINGERPRINTS:
        cname_match = any(c in cname.lower() for c in fp["cnames"])
        if not cname_match:
            continue

        # Step 3: Check NXDOMAIN (dangling DNS)
        is_nxdomain = check_nxdomain(subdomain)

        if is_nxdomain and fp["nxdomain"]:
            findings.append(
                {
                    "type": "subdomain_takeover",
                    "subdomain": subdomain,
                    "cname": cname,
                    "service": fp["service"],
                    "evidence": "NXDOMAIN (dangling record)",
                    "severity": "CRITICAL",
                    "description": (
                        f"Subdomain {subdomain} has a CNAME pointing to "
                        f"{fp['service']} ({cname}), but the service does not exist. "
                        f"An attacker can claim this service and take over the subdomain."
                    ),
                }
            )
            return findings

        # Step 4: Check HTTP fingerprint
        if not is_nxdomain and fp["response_fingerprints"]:
            try:
                for scheme in ["https", "http"]:
                    url = f"{scheme}://{subdomain}"
                    resp = smart_request("get", url, delay=delay, timeout=8)
                    body = resp.text

                    for sig in fp["response_fingerprints"]:
                        if sig.lower() in body.lower():
                            findings.append(
                                {
                                    "type": "subdomain_takeover",
                                    "subdomain": subdomain,
                                    "cname": cname,
                                    "service": fp["service"],
                                    "evidence": f"HTTP fingerprint: '{sig}'",
                                    "severity": "HIGH",
                                    "description": (
                                        f"Subdomain {subdomain} points to {fp['service']} "
                                        f"({cname}) and returns a takeover-indicative page."
                                    ),
                                }
                            )
                            return findings
            except ScanExceptions:
                pass

    return findings

def discover_subdomains(domain):
    """Use crt.sh to discover subdomains for takeover testing."""
    subdomains = set()
    try:
        resp = smart_request(
            "get",
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith(domain) and "*" not in sub:
                        subdomains.add(sub)
    except ScanExceptions:
        log_warning("crt.sh lookup failed. Using only provided domain.")

    if not subdomains:
        subdomains.add(domain)

    return list(subdomains)

def scan_subdomain_takeover(url, delay=0, threads=10):
    """Main entry point for subdomain takeover scanning."""
    log_info("Starting Subdomain Takeover Scanner...")

    parsed = urlparse(url)
    domain = (
        parsed.hostname
        or url.replace("https://", "").replace("http://", "").split("/")[0]
    )

    # Strip subdomains to get root domain for crt.sh
    parts = domain.split(".")
    if len(parts) > 2:
        root_domain = ".".join(parts[-2:])
    else:
        root_domain = domain

    log_info(f"Discovering subdomains for {root_domain}...")
    subdomains = discover_subdomains(root_domain)
    log_info(f"Found {len(subdomains)} unique subdomains to check")

    all_findings = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(check_subdomain_takeover, sub, delay): sub
            for sub in subdomains
        }

        for future in as_completed(futures):
            _ = futures[future]
            try:
                results = future.result()
                for finding in results:
                    all_findings.append(finding)
                    if finding["severity"] == "CRITICAL":
                        log_success(
                            f"[CRITICAL TAKEOVER] {finding['subdomain']} → "
                            f"{finding['service']} ({finding['cname']})"
                        )
                    else:
                        log_warning(
                            f"[POTENTIAL TAKEOVER] {finding['subdomain']} → "
                            f"{finding['service']}"
                        )
            except ScanExceptions:
                pass

    log_success(
        f"Subdomain Takeover scan complete. "
        f"Found {len(all_findings)} potential takeover(s)."
    )
    return all_findings
