"""
cyberm4fia-scanner - CORS Misconfiguration Module
Detects overly permissive CORS configurations
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from urllib.parse import urlparse
from utils.colors import log_info, log_success, log_vuln
from utils.request import smart_request, lock, Stats


# Test origins to send as Origin header
def _generate_test_origins(target_url):
    """Generate malicious origins to test CORS."""
    parsed = urlparse(target_url)
    domain = parsed.hostname or "example.com"

    return [
        "https://evil.com",
        "https://attacker.com",
        f"https://{domain}.evil.com",
        f"https://evil{domain}",
        f"https://{domain}%60attacker.com",
        "null",
        f"https://sub.{domain}",
        "http://localhost",
        "http://127.0.0.1",
    ]


def scan_cors(url):
    """Scan for CORS misconfigurations."""
    log_info("Testing CORS configuration...")
    vulns = []

    test_origins = _generate_test_origins(url)

    for origin in test_origins:
        try:
            headers = {"Origin": origin}
            resp = smart_request("get", url, headers=headers, delay=0.2)

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if not acao:
                continue

            # Check for dangerous configurations
            is_vuln = False
            vuln_detail = ""

            if acao == "*":
                is_vuln = True
                vuln_detail = "Wildcard (*) — any origin allowed"
            elif acao == origin and origin not in (
                "null",
                f"https://{urlparse(url).hostname}",
            ):
                is_vuln = True
                vuln_detail = f"Origin reflected: {origin}"
                if acac.lower() == "true":
                    vuln_detail += " + Credentials allowed (CRITICAL)"

            if acao == "null":
                is_vuln = True
                vuln_detail = "null origin accepted (iframe sandbox bypass)"

            if is_vuln:
                with lock:
                    Stats.vulnerabilities_found += 1

                severity = "high"
                if "Credentials" in vuln_detail:
                    severity = "critical"
                elif acao == "*":
                    severity = "medium"

                log_vuln("CORS MISCONFIGURATION FOUND!")
                log_success(f"Detail: {vuln_detail}")
                log_success(f"ACAO: {acao} | ACAC: {acac}")

                vulns.append(
                    {
                        "type": "CORS_Misconfig",
                        "param": "Origin",
                        "payload": origin,
                        "detail": vuln_detail,
                        "acao": acao,
                        "acac": acac,
                        "severity": severity,
                        "url": url,
                    }
                )
                break  # Found one, enough

        except Exception:
            pass

    if not vulns:
        # Report secure config
        try:
            resp = smart_request("get", url, delay=0.1)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            if acao:
                log_info(f"CORS configured: ACAO={acao} (no misconfiguration found)")
            else:
                log_info("No CORS headers detected")
        except Exception:
            pass

    return vulns
