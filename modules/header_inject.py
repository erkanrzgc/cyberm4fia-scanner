"""
cyberm4fia-scanner - Header Injection Module
HTTP Header injection and Host header attacks
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.colors import log_info, log_success, log_vuln
from utils.request import smart_request, lock, Stats


# Header injection payloads
HEADER_PAYLOADS = {
    "host_override": [
        {"Host": "evil.com"},
        {"Host": "localhost"},
        {"Host": "127.0.0.1"},
        {"X-Forwarded-Host": "evil.com"},
        {"X-Host": "evil.com"},
    ],
    "ip_spoof": [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"CF-Connecting-IP": "127.0.0.1"},
        {"True-Client-IP": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1, 10.0.0.1"},
    ],
    "crlf": [
        {"X-Test": "value\r\nInjected-Header: true"},
        {"X-Test": "value%0d%0aInjected: true"},
        {"X-Test": "value\r\nSet-Cookie: hacked=1"},
    ],
}

# Signatures for successful injection
HEADER_SIGNATURES = {
    "host_redirect": [
        "evil.com",
        "location: http://evil.com",
        "location: https://evil.com",
    ],
    "ip_bypass": [
        "admin",
        "dashboard",
        "panel",
        "internal",
        "management",
    ],
    "crlf_inject": [
        "injected-header: true",
        "injected: true",
        "set-cookie: hacked",
    ],
}


def _check_host_header(url, delay):
    """Test Host header injection/override."""
    vulns = []

    # Warm up connection
    try:
        smart_request("get", url, delay=delay)
    except Exception:
        return vulns

    for header_dict in HEADER_PAYLOADS["host_override"]:
        try:
            resp = smart_request("get", url, headers=header_dict, delay=delay)

            header_name = list(header_dict.keys())[0]
            header_val = list(header_dict.values())[0]

            # Check if evil host appears in response
            resp_lower = resp.text.lower()
            for sig in HEADER_SIGNATURES["host_redirect"]:
                if sig in resp_lower:
                    with lock:
                        Stats.vulnerabilities_found += 1
                    log_vuln("HOST HEADER INJECTION!")
                    log_success(f"Header: {header_name}: {header_val}")
                    log_success(f"Signature: {sig}")
                    vulns.append(
                        {
                            "type": "Header_Host_Inject",
                            "param": header_name,
                            "payload": header_val,
                            "signature": sig,
                            "url": url,
                        }
                    )
                    return vulns  # One is enough

            # Check for redirect to evil host
            if resp.status_code in (301, 302, 307, 308):
                location = resp.headers.get("Location", "").lower()
                if header_val.lower() in location:
                    with lock:
                        Stats.vulnerabilities_found += 1
                    log_vuln("HOST HEADER REDIRECT!")
                    log_success(f"Redirects to: {resp.headers.get('Location')}")
                    vulns.append(
                        {
                            "type": "Header_Host_Redirect",
                            "param": header_name,
                            "payload": header_val,
                            "redirect": resp.headers.get("Location"),
                            "url": url,
                        }
                    )
                    return vulns

        except Exception:
            pass

    return vulns


def _check_ip_spoof(url, delay):
    """Test IP spoofing via headers."""
    vulns = []

    # Get double baseline to measure natural variance
    try:
        baseline1 = smart_request("get", url, delay=delay)
        baseline2 = smart_request("get", url, delay=delay)
        baseline_status = baseline1.status_code
        baseline_len = len(baseline1.text)
        # Natural variance = difference between two normal loads
        natural_variance = abs(len(baseline1.text) - len(baseline2.text))
        # Threshold = natural variance + 30% of page size (minimum 500 chars)
        threshold = max(natural_variance * 3, baseline_len * 0.3, 500)
    except Exception:
        return vulns

    for header_dict in HEADER_PAYLOADS["ip_spoof"]:
        # Test on main URL first
        try:
            resp = smart_request("get", url, headers=header_dict, delay=delay)

            # If response significantly changed
            if (
                resp.status_code != baseline_status
                or abs(len(resp.text) - baseline_len) > threshold
            ):
                header_name = list(header_dict.keys())[0]
                header_val = list(header_dict.values())[0]

                with lock:
                    Stats.vulnerabilities_found += 1
                log_vuln("IP SPOOFING BYPASS!")
                log_success(f"Header: {header_name}: {header_val}")
                log_success(f"Status changed: {baseline_status} → {resp.status_code}")
                vulns.append(
                    {
                        "type": "Header_IP_Spoof",
                        "param": header_name,
                        "payload": header_val,
                        "url": url,
                        "status_change": (f"{baseline_status} → {resp.status_code}"),
                    }
                )
                break

        except Exception:
            pass

    return vulns


def _check_crlf(url, delay):
    """Test CRLF injection in headers."""
    vulns = []

    for header_dict in HEADER_PAYLOADS["crlf"]:
        try:
            resp = smart_request("get", url, headers=header_dict, delay=delay)

            # Check response headers for injected values
            resp_headers_str = str(resp.headers).lower()
            for sig in HEADER_SIGNATURES["crlf_inject"]:
                if sig in resp_headers_str:
                    header_name = list(header_dict.keys())[0]
                    with lock:
                        Stats.vulnerabilities_found += 1
                    log_vuln("CRLF HEADER INJECTION!")
                    log_success(f"Injected via: {header_name}")
                    vulns.append(
                        {
                            "type": "Header_CRLF",
                            "param": header_name,
                            "payload": str(header_dict[header_name]),
                            "signature": sig,
                            "url": url,
                        }
                    )
                    return vulns
        except Exception:
            pass

    return vulns


def scan_header_inject(url, delay=0.3):
    """Scan for header injection vulnerabilities."""
    log_info("Testing Header Injection attacks...")
    all_vulns = []

    # Host header attacks
    log_info("  → Host header override...")
    all_vulns.extend(_check_host_header(url, delay))

    # IP spoofing
    log_info("  → IP spoofing bypass...")
    all_vulns.extend(_check_ip_spoof(url, delay))

    # CRLF injection
    log_info("  → CRLF injection...")
    all_vulns.extend(_check_crlf(url, delay))

    if not all_vulns:
        log_info("No header injection vulns found")

    return all_vulns
