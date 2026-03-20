"""
cyberm4fia-scanner - Subdomain Scanner Module v2
Passive Subdomain Enumeration via Multiple Public APIs
"""

import re
import socket
from urllib.parse import urlparse

import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.colors import log_info, log_success, log_warning, log_error
from utils.request import ScanExceptions

def _normalize_domain(domain):
    """Normalize input into a clean hostname for passive subdomain APIs."""
    value = (domain or "").strip().lower()
    if value.startswith(("http://", "https://")):
        parsed = urlparse(value)
        value = parsed.hostname or value
    value = value.split("/")[0].split(":")[0].strip(".")
    return value

def _query_crtsh(domain):
    """Query Certificate Transparency logs via crt.sh."""
    subs = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = httpx.get(url, timeout=15, follow_redirects=False)
        if resp.status_code == 200:
            for entry in resp.json():
                for sub in entry.get("name_value", "").split("\n"):
                    sub = sub.strip().lower().lstrip("*.").strip(".")
                    if sub.endswith(domain) and sub != domain:
                        subs.add(sub)
    except ScanExceptions:
        pass
    return subs

def _query_hackertarget(domain):
    """Query HackerTarget host search."""
    subs = set()
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        resp = httpx.get(url, timeout=10)
        if resp.status_code == 200 and "API count" not in resp.text:
            for line in resp.text.split("\n"):
                parts = line.split(",")
                if parts:
                    sub = parts[0].strip().lower().lstrip("*.").strip(".")
                    if sub.endswith(domain) and sub != domain:
                        subs.add(sub)
    except ScanExceptions:
        pass
    return subs

def _query_alienvault(domain):
    """Query AlienVault OTX passive DNS."""
    subs = set()
    try:
        url = (
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        )
        resp = httpx.get(
            url,
            timeout=3,
            follow_redirects=False,
            headers={"Accept": "application/json"},
        )
        if resp.status_code == 200:
            data = resp.json()
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname", "").lower()
                if hostname.endswith(domain) and hostname != domain:
                    subs.add(hostname)
    except ScanExceptions:
        pass
    return subs

def _query_urlscan(domain):
    """Query urlscan.io for subdomains."""
    subs = set()
    try:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"
        resp = httpx.get(url, timeout=10)
        if resp.status_code == 200:
            for result in resp.json().get("results", []):
                page = result.get("page", {})
                hostname = page.get("domain", "").lower()
                if hostname.endswith(domain) and hostname != domain:
                    subs.add(hostname)
    except ScanExceptions:
        pass
    return subs

def _query_rapiddns(domain):
    """Query RapidDNS for subdomains."""
    subs = set()
    try:
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        resp = httpx.get(url, timeout=10)
        if resp.status_code == 200:
            found = re.findall(
                r"([a-zA-Z0-9\-]+\." + re.escape(domain) + r")", resp.text
            )
            for sub in found:
                sub = sub.lower().strip(".")
                if sub != domain:
                    subs.add(sub)
    except ScanExceptions:
        pass
    return subs

def _query_threatcrowd(domain):
    """Query ThreatCrowd API."""
    subs = set()
    try:
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        resp = httpx.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            for sub in data.get("subdomains", []):
                sub = sub.strip().lower()
                if sub.endswith(domain) and sub != domain:
                    subs.add(sub)
    except ScanExceptions:
        pass
    return subs

def _resolve_subdomain(sub):
    """Try to resolve a subdomain to check if it's live."""
    try:
        ip = socket.gethostbyname(sub)
        return (sub, ip)
    except socket.gaierror:
        return (sub, None)

def scan_subdomains(domain):
    """Scan for subdomains using multiple passive sources."""
    domain = _normalize_domain(domain)
    if not domain:
        log_error("Invalid domain for subdomain scan")
        return []

    log_info(f"Starting Passive Subdomain Recon for: {domain}")
    all_subs = set()

    # Run all sources in parallel
    sources = {
        "CRT.sh": _query_crtsh,
        "HackerTarget": _query_hackertarget,
        "AlienVault OTX": _query_alienvault,
        "URLScan.io": _query_urlscan,
        "RapidDNS": _query_rapiddns,
        "ThreatCrowd": _query_threatcrowd,
    }

    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {}
        for name, fn in sources.items():
            futures[executor.submit(fn, domain)] = name

        for future in as_completed(futures):
            source_name = futures[future]
            try:
                subs = future.result()
                if subs:
                    all_subs.update(subs)
                    log_success(f"{source_name}: +{len(subs)} subdomains")
                else:
                    log_info(f"{source_name}: no results")
            except ScanExceptions:
                log_warning(f"{source_name}: query failed")

    if not all_subs:
        log_warning("No subdomains found.")
        return []

    # Resolve subdomains to check which are live
    log_info(f"Resolving {len(all_subs)} subdomains...")
    live = []
    dead = []

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(_resolve_subdomain, sub) for sub in all_subs]
        for future in as_completed(futures):
            sub, ip = future.result()
            if ip:
                live.append((sub, ip))
            else:
                dead.append(sub)

    # Display results
    log_success(f"Total: {len(all_subs)} unique | {len(live)} live | {len(dead)} dead")

    if live:
        log_success("Live subdomains:")
        for sub, ip in sorted(live):
            print(f"    ✅ {sub} → {ip}")

    if dead and len(dead) <= 20:
        log_info("Unresolvable subdomains:")
        for sub in sorted(dead)[:20]:
            print(f"    ❌ {sub}")

    return [sub for sub, _ in sorted(live)]
