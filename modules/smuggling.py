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

    # Test HTTP/2 downgrade desync (http-request-smuggler v3 pattern)
    log_info("  → Testing HTTP/2 downgrade desync...")
    all_findings.extend(_test_h2_downgrade(url))

    # Test parser discrepancy via exotic Content-Length / chunked
    # encodings (http-request-smuggler 2025 parser-discrepancy techniques)
    log_info("  → Testing parser discrepancy permutations...")
    all_findings.extend(_test_parser_discrepancy(host, port, use_ssl, path))

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


# ──────────────────────────────────────────────────────────────────────
# HTTP/2 downgrade desync (PortSwigger http-request-smuggler v3)
# ──────────────────────────────────────────────────────────────────────

def _test_h2_downgrade(url):
    """Detect HTTP/2 → HTTP/1.1 downgrade smuggling.

    Many edge proxies negotiate HTTP/2 with clients but speak HTTP/1.1
    to the origin. If the downgrader doesn't re-validate header
    semantics, an attacker can smuggle a second request inside the HTTP/2
    body by abusing CRLF in pseudo-headers or by submitting a CL+TE pair
    over HTTP/2 (where CL is ignored but the downgrader emits both).

    Detection is heuristic: send a benign HTTP/2 POST with a duplicated
    Transfer-Encoding header and look for response-time discrepancies
    that indicate the backend stalled waiting for the next chunk.
    """
    try:
        import httpx
    except ImportError:
        return []

    findings = []
    try:
        with httpx.Client(http2=True, verify=False, timeout=10.0) as client:
            # Probe 1: send HTTP/2 with smuggling-style headers in the body
            r = client.post(
                url,
                headers={
                    "Content-Type": "text/plain",
                    # In HTTP/2 these headers should be rejected by RFC 7540
                    # §8.1.2.2 — many downgraders forward them anyway.
                    "Transfer-Encoding": "chunked",
                    "Content-Length": "6",
                },
                content=b"0\r\n\r\nG",
            )
            if r.http_version != "HTTP/2":
                # Server didn't negotiate H2 — no downgrade surface
                return []
            # If the origin reads body as smuggled GET we may see a 400 with
            # H/1.1-style parsing error in headers.
            evidence_markers = ("malformed", "bad request", "invalid http", "te", "chunked")
            body_lower = (r.text or "")[:500].lower()
            if r.status_code in (400, 421) and any(m in body_lower for m in evidence_markers):
                findings.append({
                    "type": "HTTP Request Smuggling",
                    "variant": "HTTP/2 downgrade",
                    "severity": "HIGH",
                    "description": (
                        "HTTP/2 downgrade signal: server negotiated H2 but "
                        "rejected smuggled CL/TE pair with HTTP/1.1-style "
                        "parser error — origin sees downgraded request."
                    ),
                    "evidence": f"status={r.status_code}, body_marker={body_lower[:120]}",
                })
    except httpx.HTTPError as exc:
        # Network errors are not findings.
        return []
    except Exception:  # noqa: BLE001
        return []
    return findings


# ──────────────────────────────────────────────────────────────────────
# Parser discrepancy permutations (http-request-smuggler 2025)
# ──────────────────────────────────────────────────────────────────────

# 7 well-known parser-discrepancy header permutations that survive
# many WAF / edge defences. From "HTTP/1.1 Must Die" research, 2025.
_DISCREPANCY_HEADERS = (
    # Each tuple is (label, raw_request_headers_bytes_extra)
    ("CL\\rTE", b"Content-Length\r : 6\r\nTransfer-Encoding: chunked\r\n"),
    ("TE-space", b"Transfer-Encoding : chunked\r\nContent-Length: 6\r\n"),
    ("TE-tab",    b"Transfer-Encoding:\tchunked\r\nContent-Length: 6\r\n"),
    ("CL-tab",    b"Content-Length:\t6\r\nTransfer-Encoding: chunked\r\n"),
    ("TE-vchunk", b"Transfer-Encoding: vchunked\r\nContent-Length: 6\r\n"),
    ("CL-LF-only", b"Content-Length: 6\nTransfer-Encoding: chunked\r\n"),
    ("TE-comment", b"Transfer-Encoding: chunked(comment)\r\nContent-Length: 6\r\n"),
)


def _test_parser_discrepancy(host, port, use_ssl, path):
    """Send 7 parser-discrepancy permutations + measure timing.

    Reuses ``_send_raw`` from this module so the timing logic stays
    consistent with the CL.TE / TE.CL probes above. ``_send_raw`` returns
    the response body (or an "ERROR: …" string on failure) — we measure
    elapsed time around the call ourselves.
    """
    import time as _time

    findings = []
    baseline_body = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"Content-Type: text/plain\r\n"
        f"Content-Length: 6\r\n"
        f"\r\n"
        f"hello!"
    )
    t0 = _time.monotonic()
    try:
        baseline_resp = _send_raw(host, port, baseline_body, use_ssl)
    except Exception:  # noqa: BLE001
        return []
    baseline_time = _time.monotonic() - t0
    if not baseline_resp or str(baseline_resp).startswith("ERROR:"):
        return []

    for label, extra_bytes in _DISCREPANCY_HEADERS:
        extra_str = extra_bytes.decode("utf-8", errors="replace")
        body = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n"
            f"Content-Type: text/plain\r\n"
            f"{extra_str}"
            f"\r\n"
            f"0\r\n\r\nG"
        )
        t1 = _time.monotonic()
        try:
            resp = _send_raw(host, port, body, use_ssl, timeout=8)
        except Exception:  # noqa: BLE001
            continue
        elapsed = _time.monotonic() - t1
        if not resp or str(resp).startswith("ERROR:"):
            continue
        # A clear timing gap (≥3 s slower than baseline) on an otherwise
        # 200/400 response indicates the backend stalled waiting for the
        # next smuggled chunk — strong parser-discrepancy signal.
        if elapsed - baseline_time >= 3.0:
            findings.append({
                "type": "HTTP Request Smuggling",
                "variant": f"Parser discrepancy: {label}",
                "severity": "HIGH",
                "description": (
                    f"Parser discrepancy permutation '{label}' caused a "
                    f"{elapsed - baseline_time:.1f}s timing gap vs baseline "
                    f"({elapsed:.1f}s vs {baseline_time:.1f}s) — backend "
                    "appears to wait for smuggled chunk."
                ),
                "evidence": f"timing delta: {elapsed - baseline_time:.2f}s",
            })
    return findings
