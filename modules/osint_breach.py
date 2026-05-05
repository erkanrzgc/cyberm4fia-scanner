"""
cyberm4fia-scanner - OSINT Breach Intelligence
Queries HudsonRock Cavalier, HIBP, and breach corpuses for compromised
employee credentials and infostealer log hits against target domains.
"""

import time
from urllib.parse import urlparse

from utils.colors import log_info, log_success, log_warning, log_error, Colors
from utils.request import smart_request, ScanExceptions


BREACH_SEVERITY = {
    "critical": 10,
    "high": 1,
    "medium": 0,
    "info": 0,
}


def _search_hudsonrock_domain(domain, delay=1.0):
    """
    Query HudsonRock Cavalier API for domain-level breach data.
    Public, unauthenticated JSON API. Rate limit ~1 req/sec.
    """
    findings = []
    url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={domain}"

    try:
        resp = smart_request("get", url, delay=delay, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            total = data.get("total", 0)
            employees = data.get("employees", 0)
            users = data.get("users", 0)
            third_parties = data.get("third_parties", 0)
            total_stealers = data.get("totalStealers", 0)

            finding = {
                "type": "breach_intel",
                "source": "HudsonRock Cavalier",
                "domain": domain,
                "total_hits": total,
                "employees_compromised": employees,
                "end_users": users,
                "third_parties": third_parties,
                "total_stealers_corpus": total_stealers,
                "confidence": "firm",
            }

            # Add employee URLs (redacted in free tier)
            employee_urls = data.get("data", {}).get("employees_urls", [])
            finding["employee_urls"] = employee_urls[:100]

            client_urls = data.get("data", {}).get("clients_urls", [])
            finding["client_urls"] = client_urls[:100]

            # Stealer families
            stealer_families = data.get("data", {}).get("stealer_families", [])
            finding["stealer_families"] = [
                {"family": s.get("_key"), "count": s.get("_value")}
                for s in stealer_families
            ]

            # Determine severity
            if employees >= 10:
                finding["severity"] = "CRITICAL"
                finding["description"] = (
                    f"{employees} employee(s) compromised in infostealer logs. "
                    f"SSO_EXPOSURE — immediate credential rotation + MFA audit required."
                )
            elif employees >= 1:
                finding["severity"] = "HIGH"
                finding["description"] = (
                    f"{employees} employee(s) compromised in infostealer logs. "
                    f"Investigate affected accounts."
                )
            elif users >= 1:
                finding["severity"] = "MEDIUM"
                finding["description"] = (
                    f"{users} end-user account(s) associated with domain in breach data. "
                    f"Credential-stuffing risk."
                )
            else:
                finding["severity"] = "INFO"
                finding["description"] = "Domain present in breach corpus with 0 named accounts."

            findings.append(finding)

            if employees >= 10:
                log_success(
                    f"[HudsonRock] CRITICAL: {employees} employees compromised "
                    f"({total} total hits)"
                )
            elif employees > 0:
                log_warning(
                    f"[HudsonRock] HIGH: {employees} employees compromised "
                    f"({total} total hits)"
                )
            else:
                log_info(
                    f"[HudsonRock] {total} total hits, {employees} employees"
                )

    except ScanExceptions:
        log_warning("[HudsonRock] API unavailable")
    except Exception as e:
        log_error(f"[HudsonRock] Error: {e}")

    return findings


def _search_hudsonrock_email(email, delay=1.0):
    findings = []
    url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={email}"

    try:
        resp = smart_request("get", url, delay=delay, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            total = data.get("total", 0)
            if total > 0:
                findings.append({
                    "type": "breach_intel",
                    "source": "HudsonRock Cavalier",
                    "email": email,
                    "total_hits": total,
                    "confidence": "firm",
                    "severity": "HIGH" if total > 0 else "INFO",
                    "description": f"Email found in {total} stealer log(s)",
                    "details": data.get("data", {}),
                })
    except ScanExceptions:
        pass
    except Exception:
        pass

    return findings


def _search_hibp_domain(domain, api_key=None, delay=1.5):
    findings = []
    if not api_key:
        return findings

    url = f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}"
    try:
        resp = smart_request(
            "get", url,
            headers={"hibp-api-key": api_key, "user-agent": "cyberm4fia-scanner"},
            delay=delay, timeout=15,
        )
        if resp.status_code == 200:
            breaches = resp.json()
            if breaches:
                breach_names = [b.get("Name", "") for b in breaches[:20]]
                findings.append({
                    "type": "breach_intel",
                    "source": "Have I Been Pwned",
                    "domain": domain,
                    "breaches": breach_names,
                    "breach_count": len(breaches),
                    "confidence": "firm",
                    "severity": "HIGH" if len(breaches) >= 2 else "MEDIUM",
                    "description": f"Domain found in {len(breaches)} known breach(es)",
                })
                log_warning(f"[HIBP] Domain found in {len(breaches)} breach(es)")
    except ScanExceptions:
        pass
    except Exception:
        pass

    return findings


def scan_breach_intel(url, emails=None, hibp_api_key=None, delay=0):
    """
    Query breach intelligence sources for compromised accounts.

    Sources: HudsonRock Cavalier (free, no key), HIBP (API key required).

    Args:
        url: Target URL
        emails: Optional list of known emails to check individually
        hibp_api_key: HIBP API key for domain breach search
        delay: Request delay

    Returns:
        list of findings dicts
    """
    parsed = urlparse(url)
    domain = parsed.hostname or ""
    if domain.startswith("www."):
        domain = domain[4:]

    print(f"\n{Colors.BOLD}{Colors.CYAN}──── BREACH INTELLIGENCE ────{Colors.END}")
    log_info(f"Querying breach sources for {domain}...")

    all_findings = []

    # 1. HudsonRock Cavalier — domain search
    log_info("[*] Querying HudsonRock Cavalier (infostealer logs)...")
    hr_findings = _search_hudsonrock_domain(domain, delay=max(delay, 1.0))
    all_findings.extend(hr_findings)

    # 2. HIBP domain search
    if hibp_api_key:
        log_info("[*] Querying Have I Been Pwned...")
        hibp_findings = _search_hibp_domain(domain, api_key=hibp_api_key, delay=max(delay, 1.5))
        all_findings.extend(hibp_findings)

    # 3. Individual email checks
    if emails:
        log_info(f"[*] Checking {len(emails)} individual email(s) via HudsonRock...")
        for email in emails[:50]:
            email_findings = _search_hudsonrock_email(email, delay=max(delay, 1.0))
            all_findings.extend(email_findings)
            time.sleep(max(delay, 1.0))

    # Summary
    critical = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in all_findings if f.get("severity") == "HIGH")
    total = len(all_findings)

    if critical:
        log_success(f"[!] {critical} CRITICAL breach finding(s) — immediate action recommended")
    log_success(f"Breach intel complete. {total} finding(s) ({critical} critical, {high} high).")

    print(f"{Colors.BOLD}{Colors.CYAN}──── BREACH INTEL COMPLETE ────{Colors.END}\n")
    return all_findings
