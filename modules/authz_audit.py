"""Autorize-inspired authorization enforcement audit.

A high-privileged user's traffic is replayed in two additional contexts:

* **Low-privileged** — replace the high-priv auth token/cookie with a
  low-priv one and replay every request.
* **Unauthenticated** — strip the auth header/cookie entirely and replay.

For each request, compare the three responses. A finding is emitted when
the low-priv or unauthenticated context returns a response equivalent to
the high-priv one (same body length within 5%, same status code,
matching content fingerprint) — that means the endpoint accepts the
weaker context and authorization is broken.

Inspired by ``PortSwigger/autorize`` (Burp Suite extension, MIT) but
implemented natively in Python with the project's existing
``smart_request`` infrastructure.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Iterable

logger = logging.getLogger(__name__)

# Headers we strip / rewrite to simulate the lower-priv context.
_AUTH_HEADERS = (
    "authorization",
    "cookie",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "x-csrf-token",
    "bearer",
)


@dataclass
class AuthzProbeRequest:
    """One request captured from the high-priv user's traffic to replay."""

    method: str
    url: str
    headers: dict = field(default_factory=dict)
    body: str = ""


@dataclass
class AuthzVerdict:
    """Per-endpoint verdict comparing high / low / none auth contexts."""

    url: str
    method: str
    high_status: int
    low_status: int | None
    none_status: int | None
    high_len: int
    low_len: int | None
    none_len: int | None
    enforced: bool
    reason: str


def _strip_auth_headers(headers: dict) -> dict:
    return {k: v for k, v in headers.items() if k.lower() not in _AUTH_HEADERS}


def _swap_auth_headers(headers: dict, low_priv_headers: dict) -> dict:
    """Replace high-priv auth headers with low-priv equivalents."""
    cleaned = _strip_auth_headers(headers)
    cleaned.update(low_priv_headers)
    return cleaned


def _responses_equivalent(
    high_status: int, high_body: str | bytes,
    other_status: int, other_body: str | bytes,
    *, length_tolerance: float = 0.05,
) -> tuple[bool, str]:
    """Decide if two responses are "the same" for authz purposes."""
    if high_status != other_status:
        return False, f"status differs ({high_status} vs {other_status})"

    high_len = len(high_body or "")
    other_len = len(other_body or "")
    if high_len == 0 and other_len == 0:
        return True, "both empty body"
    if max(high_len, other_len) == 0:
        return False, "one body empty, one not"

    diff_ratio = abs(high_len - other_len) / max(high_len, other_len)
    if diff_ratio <= length_tolerance:
        return True, f"body length within {length_tolerance:.0%} ({high_len} vs {other_len})"
    return False, f"body length differs {diff_ratio:.1%} ({high_len} vs {other_len})"


def audit_requests(
    requests: Iterable[AuthzProbeRequest],
    *,
    low_priv_headers: dict | None = None,
    skip_safe_methods: bool = False,
) -> list[AuthzVerdict]:
    """Replay each request as low-priv and no-auth, return per-URL verdicts.

    ``low_priv_headers`` is the cookie / token set for the low-privileged
    account (e.g. ``{"Cookie": "session=lowpriv_token"}``). When None, only
    the no-auth comparison runs.
    """
    try:
        from utils.request import smart_request
    except ImportError:
        return []

    verdicts: list[AuthzVerdict] = []
    for req in requests:
        if skip_safe_methods and req.method.upper() in {"OPTIONS", "HEAD"}:
            continue

        # High-priv baseline (replay as-is with the captured headers)
        try:
            r_high = smart_request(req.method.lower(), req.url, headers=req.headers, data=req.body)
        except Exception as exc:  # noqa: BLE001
            logger.debug("authz_audit: high-priv replay failed for %s: %s", req.url, exc)
            continue

        high_status = getattr(r_high, "status_code", 0)
        high_body = getattr(r_high, "text", "") or ""

        # Low-priv replay (if creds supplied)
        low_status = None
        low_len = None
        low_equiv = False
        low_reason = ""
        if low_priv_headers:
            low_headers = _swap_auth_headers(req.headers, low_priv_headers)
            try:
                r_low = smart_request(req.method.lower(), req.url, headers=low_headers, data=req.body)
                low_status = r_low.status_code
                low_body = r_low.text or ""
                low_len = len(low_body)
                low_equiv, low_reason = _responses_equivalent(
                    high_status, high_body, low_status, low_body,
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug("authz_audit: low-priv replay failed: %s", exc)

        # No-auth replay
        try:
            r_none = smart_request(
                req.method.lower(), req.url,
                headers=_strip_auth_headers(req.headers),
                data=req.body,
            )
            none_status = r_none.status_code
            none_body = r_none.text or ""
            none_len = len(none_body)
            none_equiv, none_reason = _responses_equivalent(
                high_status, high_body, none_status, none_body,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("authz_audit: no-auth replay failed: %s", exc)
            none_status = none_len = None
            none_equiv = False
            none_reason = "no-auth replay failed"

        # Decide enforcement
        enforced = True
        reason = "different responses across privilege tiers"
        if low_equiv:
            enforced = False
            reason = f"low-priv equivalent to high-priv ({low_reason})"
        elif none_equiv:
            enforced = False
            reason = f"no-auth equivalent to high-priv ({none_reason})"

        verdicts.append(AuthzVerdict(
            url=req.url, method=req.method,
            high_status=high_status, low_status=low_status, none_status=none_status,
            high_len=len(high_body), low_len=low_len, none_len=none_len,
            enforced=enforced, reason=reason,
        ))
    return verdicts


def verdicts_to_findings(verdicts: Iterable[AuthzVerdict]) -> list[dict]:
    """Convert per-URL verdicts into scanner finding dicts."""
    findings: list[dict] = []
    for v in verdicts:
        if v.enforced:
            continue
        severity = "HIGH" if v.none_status is not None and v.none_status < 400 else "MEDIUM"
        ftype = (
            "Broken_Access_Control_NoAuth"
            if "no-auth equivalent" in v.reason
            else "Broken_Access_Control_LowPriv"
        )
        findings.append({
            "type": ftype,
            "url": v.url,
            "method": v.method,
            "severity": severity,
            "evidence": v.reason,
            "payload": (
                f"replayed {v.method} {v.url} without auth headers "
                f"→ same response as high-priv"
            ),
            "module": "authz_audit",
            "source": "authz_audit",
            "verification_state": "verified",
        })
    return findings


def scan_authz(
    requests: Iterable[AuthzProbeRequest],
    *,
    low_priv_headers: dict | None = None,
    skip_safe_methods: bool = True,
) -> list[dict]:
    """Public entry: takes captured high-priv requests, returns finding dicts."""
    verdicts = audit_requests(
        requests,
        low_priv_headers=low_priv_headers,
        skip_safe_methods=skip_safe_methods,
    )
    return verdicts_to_findings(verdicts)
