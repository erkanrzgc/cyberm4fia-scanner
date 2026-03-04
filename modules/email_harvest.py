"""
cyberm4fia-scanner - Email Harvester
Collects email addresses associated with a target domain
"""

import sys
import os
import re
from urllib.parse import urlparse, urljoin, quote

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.colors import log_info, log_success
from utils.request import smart_request


def harvest_from_page(url, delay=0):
    """Extract emails from a single page."""
    emails = set()
    try:
        resp = smart_request("get", url, delay=delay, timeout=8)
        body = resp.text
        found = re.findall(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            body,
        )
        emails.update(e.lower() for e in found)
    except Exception:
        pass
    return emails


def harvest_from_google(domain, delay=0.5):
    """Search Google for emails (passive, no API key needed)."""
    emails = set()
    queries = [
        f'"{domain}" email',
        f'"{domain}" contact',
        f'"@{domain}"',
        f"site:{domain} email",
    ]

    for query in queries:
        try:
            search_url = f"https://www.google.com/search?q={quote(query)}&num=20"
            resp = smart_request(
                "get",
                search_url,
                delay=delay,
                timeout=10,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                },
            )
            found = re.findall(
                r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
                resp.text,
            )
            domain_emails = [e.lower() for e in found if domain in e.lower()]
            emails.update(domain_emails)
        except Exception:
            pass

    return emails


def harvest_from_hunter(domain, api_key=None):
    """Use Hunter.io API if api_key is provided."""
    if not api_key:
        return set()

    emails = set()
    try:
        url = (
            f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
        )
        resp = smart_request("get", url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data.get("data", {}).get("emails", []):
                emails.add(entry.get("value", "").lower())
    except Exception:
        pass
    return emails


def harvest_from_pgp(domain, delay=0):
    """Search PGP key servers for emails."""
    emails = set()
    try:
        url = f"https://keys.openpgp.org/vks/v1/by-email/{domain}"
        resp = smart_request("get", url, delay=delay, timeout=8)
        found = re.findall(
            r"[a-zA-Z0-9._%+\-]+@" + re.escape(domain),
            resp.text,
        )
        emails.update(e.lower() for e in found)
    except Exception:
        pass
    return emails


def harvest_from_github(domain, delay=0.5):
    """Search GitHub for emails associated with domain."""
    emails = set()
    try:
        url = f"https://api.github.com/search/code?q={quote(f'@{domain}')}&per_page=30"
        resp = smart_request(
            "get",
            url,
            delay=delay,
            timeout=10,
            headers={"Accept": "application/vnd.github.v3+json"},
        )
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("items", []):
                # Extract from text_matches if available
                text = str(item)
                found = re.findall(
                    r"[a-zA-Z0-9._%+\-]+@" + re.escape(domain),
                    text,
                )
                emails.update(e.lower() for e in found)
    except Exception:
        pass
    return emails


def scan_email_harvest(url, delay=0):
    """Main email harvester entry point."""
    log_info("Starting Email Harvester...")

    parsed = urlparse(url)
    domain = parsed.hostname or url
    # Get root domain
    parts = domain.split(".")
    if len(parts) > 2:
        root_domain = ".".join(parts[-2:])
    else:
        root_domain = domain

    all_emails = set()

    # Source 1: Target website pages
    log_info(f"Harvesting from {url}...")
    page_emails = harvest_from_page(url, delay)
    all_emails.update(page_emails)

    # Check common pages
    for path in ["/contact", "/about", "/team", "/staff", "/privacy", "/impressum"]:
        emails = harvest_from_page(urljoin(url, path), delay)
        all_emails.update(emails)

    # Source 2: Google dorking (passive)
    log_info("Searching Google for emails...")
    google_emails = harvest_from_google(root_domain, delay)
    all_emails.update(google_emails)

    # Source 3: GitHub
    log_info("Searching GitHub for emails...")
    github_emails = harvest_from_github(root_domain, delay)
    all_emails.update(github_emails)

    # Source 4: PGP key servers
    log_info("Checking PGP key servers...")
    pgp_emails = harvest_from_pgp(root_domain, delay)
    all_emails.update(pgp_emails)

    # Filter to only target domain emails
    domain_emails = sorted([e for e in all_emails if root_domain in e])
    other_emails = sorted([e for e in all_emails if root_domain not in e])

    if domain_emails:
        log_success(f"Found {len(domain_emails)} email(s) for {root_domain}:")
        for email in domain_emails:
            log_success(f"  → {email}")

    if other_emails:
        log_info(f"Found {len(other_emails)} related email(s):")
        for email in other_emails[:10]:
            log_info(f"  → {email}")

    findings = []
    for email in domain_emails:
        findings.append(
            {
                "type": "email",
                "email": email,
                "domain": root_domain,
                "description": f"Email address found: {email}",
            }
        )

    log_success(f"Email harvest complete. {len(all_emails)} total email(s) found.")
    return findings
