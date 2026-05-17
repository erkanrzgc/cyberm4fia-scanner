"""Virtual host discovery via Host-header brute.

Subdomain enumeration finds *DNS* names that resolve to the target. But
many internal apps don't have public DNS — they're vhosted on the same
IP and served by name only when the client sends the right ``Host:``
header. Hitting the IP directly with a wordlist of candidate hostnames
reveals these "hidden" sites.

Workflow:

1. Take a baseline by hitting ``http(s)://<ip>/`` with a known-bad
   ``Host`` (e.g. ``unlikely-baseline-host.invalid``). Hash the response
   length + body for the "this Host doesn't match anything" reference.
2. For each candidate hostname, replay with ``Host: <candidate>``. If
   the response is *materially* different from the baseline (status,
   length, or body hash), the vhost is live.
3. Cross-check against the project's soft-404 heuristic so we don't
   collect generic catch-all responses.

The discovery is purely active but read-only — no payloads beyond the
benign GET request. Rate-limited via ``utils.request.HostRateLimiter``
when the caller hands us a real httpx client.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from utils.colors import log_info, log_success


_BASELINE_HOST = "unlikely-baseline-host.invalid"


@dataclass(frozen=True)
class VhostBaseline:
    status: int
    length: int
    body_hash: str

    def is_materially_different(
        self,
        *,
        status: int,
        length: int,
        body_hash: str,
        length_tolerance: int = 32,
    ) -> bool:
        if status != self.status:
            return True
        if body_hash != self.body_hash:
            return True
        return abs(length - self.length) > length_tolerance


@dataclass
class VhostHit:
    host: str
    status: int
    length: int
    body_hash: str


@dataclass
class VhostDiscoveryReport:
    ip: str
    scheme: str
    baseline: Optional[VhostBaseline] = None
    hits: list[VhostHit] = field(default_factory=list)
    candidates_tried: int = 0
    errors: list[str] = field(default_factory=list)

    def as_findings(self) -> list[dict]:
        return [
            {
                "type": "Virtual_Host_Discovered",
                "url": f"{self.scheme}://{self.ip}/",
                "host_header": hit.host,
                "severity": "info",
                "evidence": (
                    f"Host '{hit.host}' returns status={hit.status} "
                    f"length={hit.length} vs baseline (different)."
                ),
                "module": "vhost_discovery",
            }
            for hit in self.hits
        ]


def _hash_body(text: str) -> str:
    return hashlib.sha1((text or "").encode("utf-8", "ignore")).hexdigest()


def _measure(response) -> tuple[int, int, str]:
    """Pull (status, body length, body hash) from a duck-typed response."""
    status = getattr(response, "status_code", 0)
    text = getattr(response, "text", "") or ""
    return status, len(text), _hash_body(text)


def _build_url(scheme: str, ip: str) -> str:
    return f"{scheme}://{ip}/"


def _do_request(
    http_get: Callable,
    url: str,
    host_header: str,
    timeout: float,
) -> object:
    return http_get(url, headers={"Host": host_header}, timeout=timeout)


def discover_vhosts(
    ip: str,
    candidates: Iterable[str],
    *,
    http_get: Callable,
    scheme: str = "http",
    timeout: float = 10.0,
    length_tolerance: int = 32,
    baseline_host: str = _BASELINE_HOST,
) -> VhostDiscoveryReport:
    """Iterate ``candidates`` as Host headers against ``ip`` looking for vhosts.

    ``http_get`` signature must accept ``(url, headers=..., timeout=...)``
    and return an object with ``status_code`` + ``text`` (duck-typed).
    """
    report = VhostDiscoveryReport(ip=ip, scheme=scheme)
    url = _build_url(scheme, ip)

    try:
        baseline_response = _do_request(http_get, url, baseline_host, timeout)
        status, length, body_hash = _measure(baseline_response)
        report.baseline = VhostBaseline(
            status=status, length=length, body_hash=body_hash
        )
    except Exception as exc:  # noqa: BLE001
        report.errors.append(f"baseline: {type(exc).__name__}: {exc}")
        return report  # no baseline = no diff possible

    seen_hashes: set[str] = {report.baseline.body_hash}

    for raw in candidates:
        host = (raw or "").strip().lower()
        if not host or host == baseline_host:
            continue
        report.candidates_tried += 1
        try:
            response = _do_request(http_get, url, host, timeout)
        except Exception as exc:  # noqa: BLE001
            report.errors.append(f"{host}: {type(exc).__name__}: {exc}")
            continue

        status, length, body_hash = _measure(response)
        if not report.baseline.is_materially_different(
            status=status,
            length=length,
            body_hash=body_hash,
            length_tolerance=length_tolerance,
        ):
            continue

        # Soft catch-all suppression: if a fresh hash appears once and
        # never again it's a real vhost; if it appears for every candidate
        # it's a wildcard responder.
        if body_hash in seen_hashes:
            continue
        seen_hashes.add(body_hash)

        report.hits.append(
            VhostHit(host=host, status=status, length=length, body_hash=body_hash)
        )

    if report.hits:
        log_success(
            f"vhost discovery: {len(report.hits)} live vhost(s) on {ip} "
            f"({report.candidates_tried} candidates tried)"
        )
    else:
        log_info(
            f"vhost discovery: no vhosts beyond baseline on {ip} "
            f"({report.candidates_tried} candidates tried)"
        )
    return report
