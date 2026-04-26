"""
cyberm4fia-scanner - HTTP Method Abuse Scanner

Many web servers/applications enable dangerous HTTP methods by mistake:
* TRACE  → reflected cross-site tracing (XST)
* PUT    → arbitrary file upload if write enabled
* DELETE → resource deletion
* OPTIONS that *advertise* PUT/DELETE/CONNECT
* PATCH on resources without auth

This module enumerates allowed methods and flags the dangerous ones.
Independent reimplementation; method names are RFC standard.
"""

from __future__ import annotations

import uuid
from urllib.parse import urljoin

from utils.colors import log_info, log_success
from utils.request import BlockedTargetPath, ScanExceptions, smart_request


# Methods we always probe. GET is included to establish a baseline.
PROBE_METHODS: tuple[str, ...] = (
    "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH",
    "OPTIONS", "TRACE", "CONNECT", "PROPFIND", "MOVE",
)

# Methods considered "dangerous if accepted on a resource we can write to".
DANGEROUS_METHODS: frozenset[str] = frozenset({
    "PUT", "DELETE", "PATCH", "TRACE", "CONNECT", "PROPFIND", "MOVE",
})


def _parse_allow_header(value: str) -> list[str]:
    if not value:
        return []
    return [m.strip().upper() for m in value.split(",") if m.strip()]


def scan_http_methods(url: str, *, delay: float = 0.0,
                      attempt_write: bool = False) -> list[dict]:
    """Enumerate allowed HTTP methods and report dangerous ones.

    ``attempt_write`` adds an actual PUT with a small probe file;
    leave off (default) to be passive — we only read OPTIONS + status.
    """
    findings: list[dict] = []

    log_info(f"🔧 HTTP-Methods: probing {url[:60]}")

    # 1. OPTIONS — what the server *says* it allows.
    try:
        opt_resp = smart_request("options", url, delay=delay,
                                 allow_redirects=False)
    except (ScanExceptions, BlockedTargetPath):
        opt_resp = None

    advertised: list[str] = []
    if opt_resp is not None:
        headers = getattr(opt_resp, "headers", {}) or {}
        for name in ("Allow", "allow", "Access-Control-Allow-Methods"):
            if name in headers:
                advertised += _parse_allow_header(headers[name])
        advertised = sorted(set(advertised))

    if advertised:
        dangerous_advertised = [m for m in advertised if m in DANGEROUS_METHODS]
        if dangerous_advertised:
            findings.append({
                "type": "HTTP_Method_Advertised",
                "url": url,
                "evidence": f"Server advertises dangerous methods via Allow: {', '.join(dangerous_advertised)}",
                "methods": dangerous_advertised,
                "severity": "Medium",
                "confidence": 60,
                "module": "http_methods",
            })

    # 2. Active probe — does the server actually accept it (status != 405/501)?
    accepted: dict[str, int] = {}
    for method in PROBE_METHODS:
        try:
            resp = smart_request(method.lower(), url, delay=delay,
                                 allow_redirects=False, timeout=10)
        except (ScanExceptions, BlockedTargetPath):
            continue
        if resp is None:
            continue
        status = getattr(resp, "status_code", 0)
        # 405 Method Not Allowed / 501 Not Implemented => clean reject.
        if status in (405, 501):
            continue
        accepted[method] = status

    dangerous_accepted = [m for m, _ in accepted.items() if m in DANGEROUS_METHODS]
    if dangerous_accepted:
        findings.append({
            "type": "HTTP_Method_Accepted",
            "url": url,
            "evidence": (
                "Dangerous methods accepted (non-405): "
                + ", ".join(f"{m}={accepted[m]}" for m in dangerous_accepted)
            ),
            "methods": dangerous_accepted,
            "severity": "High",
            "confidence": 75,
            "module": "http_methods",
        })

    # 3. TRACE-specific — Cross-Site Tracing risk.
    if "TRACE" in accepted and accepted["TRACE"] == 200:
        findings.append({
            "type": "HTTP_TRACE_Enabled",
            "url": url,
            "evidence": "TRACE returns 200 — Cross-Site Tracing (XST) feasible.",
            "severity": "Medium",
            "confidence": 90,
            "cve_class": "CWE-693",
            "module": "http_methods",
        })

    # 4. PUT write probe — opt-in; uploads a small marker file.
    if attempt_write and "PUT" in accepted and accepted["PUT"] in (200, 201, 204):
        token = uuid.uuid4().hex[:12]
        probe_path = f"/cyberm4fia-probe-{token}.txt"
        target = urljoin(url, probe_path)
        try:
            put_resp = smart_request(
                "put", target, delay=delay,
                data=f"cyberm4fia probe: {token}",
                headers={"Content-Type": "text/plain"},
                allow_redirects=False,
            )
        except (ScanExceptions, BlockedTargetPath):
            put_resp = None
        if put_resp is not None and getattr(put_resp, "status_code", 0) in (200, 201, 204):
            try:
                check = smart_request("get", target, delay=delay)
            except (ScanExceptions, BlockedTargetPath):
                check = None
            body = getattr(check, "text", "") or ""
            if token in body:
                log_success(f"  ✅ PUT write CONFIRMED at {target}")
                findings.append({
                    "type": "HTTP_PUT_Write",
                    "url": target,
                    "evidence": f"PUT successful + GET reflects token '{token}'.",
                    "payload": probe_path,
                    "severity": "Critical",
                    "confidence": 95,
                    "module": "http_methods",
                })

    return findings
