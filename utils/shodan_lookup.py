"""
cyberm4fia-scanner - Shodan Integration & Whois/ASN Lookup
OSINT enrichment for target reconnaissance
"""

import re
import socket
from urllib.parse import urlparse

from utils.colors import log_info, log_success, log_warning, log_error
from utils.request import smart_request
from utils.request import ScanExceptions

def shodan_lookup(ip, api_key=None):
    """
    Query Shodan for host information.
    If api_key is provided, uses the official API.
    Otherwise, uses the public Shodan Internetdb (no key needed).
    """
    log_info(f"Querying Shodan for {ip}...")
    result = {
        "ip": ip,
        "ports": [],
        "vulns": [],
        "hostnames": [],
        "os": None,
        "tags": [],
    }

    # Shodan InternetDB — free, no API key needed
    try:
        resp = smart_request("get", f"https://internetdb.shodan.io/{ip}", timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            result["ports"] = data.get("ports", [])
            result["vulns"] = data.get("vulns", [])
            result["hostnames"] = data.get("hostnames", [])
            result["tags"] = data.get("tags", [])
            result["cpes"] = data.get("cpes", [])

            if result["ports"]:
                log_success(f"Shodan ports: {', '.join(map(str, result['ports']))}")
            if result["vulns"]:
                log_warning(f"Known CVEs: {', '.join(result['vulns'][:10])}")
            if result["hostnames"]:
                log_info(f"Hostnames: {', '.join(result['hostnames'][:5])}")
            if result["cpes"]:
                log_info(f"CPEs: {', '.join(result['cpes'][:5])}")

            return result
        elif resp.status_code == 404:
            log_info("No Shodan data available for this IP")
    except ScanExceptions as e:
        log_warning(f"Shodan InternetDB lookup failed: {e}")

    # If API key provided, use full Shodan API
    if api_key:
        try:
            resp = smart_request(
                "get",
                f"https://api.shodan.io/shodan/host/{ip}?key={api_key}",
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                result["ports"] = data.get("ports", [])
                result["vulns"] = (
                    list(data.get("vulns", {}).keys()) if data.get("vulns") else []
                )
                result["hostnames"] = data.get("hostnames", [])
                result["os"] = data.get("os")
                result["org"] = data.get("org")
                result["isp"] = data.get("isp")
                result["country"] = data.get("country_name")

                log_success(
                    f"Shodan (API): {data.get('org', 'Unknown')} | {data.get('country_name', '')}"
                )
                if result["vulns"]:
                    log_warning(
                        f"Known CVEs ({len(result['vulns'])}): {', '.join(result['vulns'][:5])}"
                    )
        except ScanExceptions:
            pass

    return result

def whois_lookup(domain):
    """Perform WHOIS lookup for a domain."""
    log_info(f"WHOIS lookup for {domain}...")
    result = {}

    try:
        import subprocess

        proc = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=15,
        )
        output = proc.stdout

        if output:
            # Parse key fields
            patterns = {
                "registrar": r"Registrar:\s*(.+)",
                "creation_date": r"Creation Date:\s*(.+)",
                "expiry_date": r"(?:Registry Expiry Date|Expiration Date):\s*(.+)",
                "name_servers": r"Name Server:\s*(.+)",
                "registrant_org": r"Registrant Organization:\s*(.+)",
                "registrant_country": r"Registrant Country:\s*(.+)",
                "dnssec": r"DNSSEC:\s*(.+)",
            }

            for key, pattern in patterns.items():
                matches = re.findall(pattern, output, re.IGNORECASE)
                if matches:
                    if key == "name_servers":
                        result[key] = [m.strip().lower() for m in matches]
                    else:
                        result[key] = matches[0].strip()

            if result.get("registrar"):
                log_info(f"Registrar: {result['registrar']}")
            if result.get("creation_date"):
                log_info(f"Created: {result['creation_date']}")
            if result.get("registrant_org"):
                log_info(f"Organization: {result['registrant_org']}")
            if result.get("name_servers"):
                log_info(f"NS: {', '.join(result['name_servers'][:3])}")

            result["raw"] = output[:2000]
        else:
            log_warning("WHOIS returned no data")

    except FileNotFoundError:
        log_warning("whois command not found. Install with: apt install whois")
    except subprocess.TimeoutExpired:
        log_warning("WHOIS lookup timed out")
    except ScanExceptions as e:
        log_warning(f"WHOIS lookup failed: {e}")

    return result

def asn_lookup(ip):
    """Get ASN (Autonomous System Number) information for an IP."""
    log_info(f"ASN lookup for {ip}...")
    result = {}

    # Use Team Cymru's IP-to-ASN API
    try:
        resp = smart_request(
            "get",
            f"https://api.hackertarget.com/aslookup/?q={ip}",
            timeout=8,
        )
        if resp.status_code == 200 and "API count" not in resp.text:
            lines = resp.text.strip().split("\n")
            if lines:
                parts = lines[0].split(",")
                if len(parts) >= 3:
                    result["asn"] = parts[0].strip().strip('"')
                    result["ip_range"] = parts[1].strip().strip('"')
                    result["description"] = parts[2].strip().strip('"')

                    log_success(f"ASN: {result['asn']} | {result['description']}")
                    log_info(f"IP Range: {result['ip_range']}")
    except ScanExceptions:
        pass

    # Fallback: BGPView API
    if not result:
        try:
            resp = smart_request(
                "get",
                f"https://api.bgpview.io/ip/{ip}",
                timeout=8,
            )
            if resp.status_code == 200:
                data = resp.json()
                prefixes = data.get("data", {}).get("rir_allocation", {})
                if prefixes:
                    result["rir"] = prefixes.get("rir_name", "Unknown")
                    result["prefix"] = prefixes.get("prefix", "")
                    log_info(f"RIR: {result.get('rir', 'Unknown')}")
        except ScanExceptions:
            pass

    return result

def scan_osint(url, shodan_api_key=None, delay=0):
    """Main OSINT enrichment entry point."""
    log_info("Starting OSINT Enrichment...")

    parsed = urlparse(url)
    hostname = parsed.hostname or url
    parts = hostname.split(".")
    if len(parts) > 2:
        root_domain = ".".join(parts[-2:])
    else:
        root_domain = hostname

    # Resolve IP
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        log_error(f"Cannot resolve {hostname}")
        return {}

    results = {"ip": ip, "domain": root_domain}

    # Shodan
    shodan_data = shodan_lookup(ip, shodan_api_key)
    results["shodan"] = shodan_data

    # WHOIS
    is_ip = all(c.isdigit() or c == "." for c in hostname)
    if not is_ip:
        whois_data = whois_lookup(root_domain)
        results["whois"] = whois_data

    # ASN
    asn_data = asn_lookup(ip)
    results["asn"] = asn_data

    log_success("OSINT enrichment complete.")
    return results
