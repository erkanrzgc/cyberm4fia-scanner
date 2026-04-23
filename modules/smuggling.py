"""
cyberm4fia-scanner - HTTP Request Smuggling Scanner
Detects CL.TE, TE.CL, and TE.TE desync vulnerabilities.
Can bypass WAFs, poison caches, and hijack sessions.
"""

import socket
import ssl
import time
import os

from urllib.parse import urlparse
from utils.colors import log_info, log_success, log_warning
from utils.request import ScanExceptions

# ─────────────────────────────────────────────────────
# Raw HTTP Request Sender
# ─────────────────────────────────────────────────────
def _send_raw(host, port, data, use_ssl=False, timeout=10):
    """Send a raw HTTP request and return the response."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)

        sock.connect((host, port))
        sock.sendall(data.encode() if isinstance(data, str) else data)

        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break

        sock.close()
        return response.decode("utf-8", errors="ignore")

    except ScanExceptions as e:
        return f"ERROR: {e}"

# ─────────────────────────────────────────────────────
# CL.TE Detection (Frontend uses Content-Length, Backend uses Transfer-Encoding)
# ─────────────────────────────────────────────────────
def _test_cl_te(host, port, use_ssl, path="/"):
    """
    CL.TE: Frontend reads Content-Length, Backend reads Transfer-Encoding.
    Send a request where CL says body is short, but TE has extra data.
    If backend processes the extra data as a new request → vulnerable.
    """
    findings = []

    # Timing-based detection: send malformed chunked request
    # If CL.TE exists, backend will wait for next chunk → timeout difference
    smuggle_payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"1\r\n"
        f"Z\r\n"
        f"Q"  # Incomplete chunk — backend waits for more
    )

    # Normal request for baseline timing
    normal_payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    )

    # Baseline timing
    start = time.time()
    _send_raw(host, port, normal_payload, use_ssl, timeout=5)
    baseline_time = time.time() - start

    # Smuggle timing
    start = time.time()
    _send_raw(host, port, smuggle_payload, use_ssl, timeout=10)
    smuggle_time = time.time() - start

    # If smuggle request took significantly longer → backend waited for chunk
    if smuggle_time > baseline_time + 3.0:
        findings.append(
            {
                "type": "HTTP Request Smuggling",
                "variant": "CL.TE",
                "severity": "CRITICAL",
                "evidence": f"Timing diff: normal={baseline_time:.1f}s vs smuggle={smuggle_time:.1f}s",
                "description": "Backend uses Transfer-Encoding while frontend uses Content-Length. WAF bypass possible.",
            }
        )

    return findings

# ─────────────────────────────────────────────────────
# TE.CL Detection (Frontend uses Transfer-Encoding, Backend uses Content-Length)
# ─────────────────────────────────────────────────────
def _test_te_cl(host, port, use_ssl, path="/"):
    """
    TE.CL: Frontend reads Transfer-Encoding, Backend reads Content-Length.
    Send chunked body where CL is shorter than actual → leftover becomes next request.
    """
    findings = []

    smuggle_payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 6\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"0\r\n"
        f"\r\n"
        f"X"  # This leftover should not be processed
    )

    normal_payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    )

    start = time.time()
    _send_raw(host, port, normal_payload, use_ssl, timeout=5)
    baseline_time = time.time() - start

    start = time.time()
    _send_raw(host, port, smuggle_payload, use_ssl, timeout=10)
    smuggle_time = time.time() - start

    if smuggle_time > baseline_time + 3.0:
        findings.append(
            {
                "type": "HTTP Request Smuggling",
                "variant": "TE.CL",
                "severity": "CRITICAL",
                "evidence": f"Timing diff: normal={baseline_time:.1f}s vs smuggle={smuggle_time:.1f}s",
                "description": "Frontend uses Transfer-Encoding while backend uses Content-Length. Cache poisoning possible.",
            }
        )

    return findings

# ─────────────────────────────────────────────────────
# Transfer-Encoding Obfuscation (TE.TE)
# ─────────────────────────────────────────────────────
def _test_te_te(host, port, use_ssl, path="/"):
    """
    TE.TE: Both understand Transfer-Encoding, but one can be tricked
    with obfuscated variants to ignore it.
    """
    findings = []

    te_obfuscations = [
        "Transfer-Encoding: xchunked",
        "Transfer-Encoding : chunked",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
        "Transfer-Encoding:\tchunked",
        "Transfer-Encoding: chunked\r\n Transfer-Encoding: cow",
        "X: x\r\nTransfer-Encoding: chunked",
        "Transfer-Encoding\r\n: chunked",
    ]

    normal_payload = (
        f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\n\r\n"
    )

    start = time.time()
    _send_raw(host, port, normal_payload, use_ssl, timeout=5)
    baseline_time = time.time() - start

    for te_header in te_obfuscations:
        payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"{te_header}\r\n"
            f"\r\n"
            f"1\r\n"
            f"Z\r\n"
            f"Q"
        )

        start = time.time()
        _send_raw(host, port, payload, use_ssl, timeout=10)
        test_time = time.time() - start

        if test_time > baseline_time + 3.0:
            findings.append(
                {
                    "type": "HTTP Request Smuggling",
                    "variant": "TE.TE Obfuscation",
                    "severity": "HIGH",
                    "te_header": te_header.replace("\r\n", " | "),
                    "evidence": "Timing diff with obfuscated TE header",
                    "description": f"TE obfuscation bypass detected: {te_header[:40]}",
                }
            )
            break  # One is enough

    return findings

# ─────────────────────────────────────────────────────
# Header Injection via Smuggling
# ─────────────────────────────────────────────────────
def _test_header_smuggle(host, port, use_ssl, path="/"):
    """
    Test if duplicate/conflicting headers cause different behavior.
    """
    findings = []

    # Test conflicting Content-Length headers
    payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 0\r\n"
        f"Content-Length: 50\r\n"
        f"\r\n"
    )

    resp = _send_raw(host, port, payload, use_ssl, timeout=5)

    # If server doesn't reject duplicate CL → potential smuggling
    if "400" not in resp[:50] and "ERROR" not in resp:
        findings.append(
            {
                "type": "HTTP Request Smuggling",
                "variant": "Duplicate Content-Length",
                "severity": "MEDIUM",
                "description": "Server accepts duplicate Content-Length headers. May enable CL.CL smuggling.",
            }
        )

    return findings

# ─────────────────────────────────────────────────────
# Main Scanner
# ─────────────────────────────────────────────────────
def scan_smuggling(url, delay=0):
    """
    Main HTTP Request Smuggling scanner entry point.
    Tests CL.TE, TE.CL, TE.TE, and header conflicts.
    """
    log_info("Starting HTTP Request Smuggling Scanner...")

    parsed = urlparse(url)
    host = parsed.hostname
    use_ssl = parsed.scheme == "https"
    port = parsed.port or (443 if use_ssl else 80)
    path = parsed.path or "/"

    if not host:
        log_warning("Invalid URL for smuggling test")
        return []

    all_findings = []

    # Test CL.TE
    log_info("  → Testing CL.TE desync...")
    all_findings.extend(_test_cl_te(host, port, use_ssl, path))

    # Test TE.CL
    log_info("  → Testing TE.CL desync...")
    all_findings.extend(_test_te_cl(host, port, use_ssl, path))

    # Test TE.TE obfuscation
    log_info("  → Testing TE.TE obfuscation (7 variants)...")
    all_findings.extend(_test_te_te(host, port, use_ssl, path))

    # Test duplicate headers
    log_info("  → Testing duplicate Content-Length...")
    all_findings.extend(_test_header_smuggle(host, port, use_ssl, path))

    # Integrate external Smuggler tool if available
    smuggler_path = "tools/mcp-for-security/smuggler-mcp/smuggler/smuggler.py"
    if os.path.exists(smuggler_path):
        log_info("  → Running advanced Smuggler MCP payload set...")
        import subprocess
        try:
            cmd = ["python3", smuggler_path, "-u", url, "-q", "--no-color"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            for line in result.stdout.splitlines():
                if "CRITICAL" in line:
                    all_findings.append({
                        "type": "HTTP Request Smuggling",
                        "variant": "Smuggler Script Match",
                        "severity": "CRITICAL",
                        "description": "Detected via advanced Smuggler script",
                        "evidence": line.strip()
                    })
        except subprocess.TimeoutExpired:
            log_warning("Smuggler script timed out.")
        except Exception as e:
            log_warning(f"Error running Smuggler script: {e}")

    for f in all_findings:
        f["url"] = url
        if f.get("severity") == "CRITICAL":
            log_success(f"🔥 [CRITICAL] {f['variant']}: {f['description']}")
        elif f.get("severity") == "HIGH":
            log_warning(f"⚠️  [HIGH] {f['variant']}: {f['description']}")
        else:
            log_info(f"[{f['severity']}] {f['variant']}: {f['description']}")

    if not all_findings:
        log_info("No smuggling vulnerabilities detected.")

    log_success(f"Smuggling scan complete. {len(all_findings)} finding(s).")
    return all_findings
