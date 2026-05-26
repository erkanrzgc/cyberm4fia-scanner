"""Permissions-Policy active verifier (heuristic).

A missing or wildcard ``Permissions-Policy`` lets an embedding page
negotiate access to powerful features (camera, microphone, geolocation,
payment, USB, MIDI) via the iframe ``allow=`` attribute. The browser
prompts the user with the *target's* origin — phishing-grade trust.

The verifier promotes the finding when:

1. The page does *not* send ``Permissions-Policy`` (or sends one that
   leaves at least one sensitive feature unrestricted).
2. The page is also clickjacking-framable — XFO missing AND CSP
   ``frame-ancestors`` absent or wildcard. Without framability the
   iframe abuse vector doesn't apply.

Both signals together → promote to ``Permissions_Policy_Abuse``.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from .base import VerificationOutcome, applies_to_header, apply_outcome

logger = logging.getLogger(__name__)

_HEADER_TARGETS = ("permissions-policy",)

# Features whose presence in a 3rd-party iframe is dangerous. The list
# mirrors the high-risk subset of the Permissions Policy spec.
_SENSITIVE_FEATURES = (
    "camera",
    "microphone",
    "geolocation",
    "payment",
    "usb",
    "midi",
    "serial",
    "hid",
    "fullscreen",
    "display-capture",
    "publickey-credentials-get",
)

# Frame-ancestors directive parser (also used by clickjacking verifier;
# duplicated narrowly here to avoid import gymnastics).
_FRAME_ANCESTORS_RE = re.compile(r"frame-ancestors\s+([^;]+)", re.IGNORECASE)
_VALID_XFO = ("deny", "sameorigin")


def _parse_permissions_policy(value: str) -> dict[str, str]:
    """Return ``{feature: directive}`` from a Permissions-Policy header.

    Permissions Policy syntax: ``feature=(allowlist), other=(self)``.
    A missing feature inherits the browser default (often permissive for
    embedded contexts).
    """
    result: dict[str, str] = {}
    if not value:
        return result
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            continue
        feature, _, directive = part.partition("=")
        result[feature.strip().lower()] = directive.strip()
    return result


def _is_directive_restrictive(directive: str) -> bool:
    """``()`` or ``(none)`` => fully denied. Anything else has at least one origin."""
    d = directive.strip().strip("(").strip(")").strip()
    if d == "" or d.lower() == "none":
        return True
    return False


@dataclass
class PermissionsPolicyVerifier:
    finding_kind: str = "Missing_Security_Header"
    header_targets: tuple[str, ...] = _HEADER_TARGETS

    def applies_to(self, finding: dict) -> bool:
        return applies_to_header(finding, self.header_targets)

    def verify(self, finding: dict, target_url: str) -> VerificationOutcome:
        headers = self._fetch_headers(target_url)
        if headers is None:
            return VerificationOutcome(verified=False, evidence="active probe failed")

        policy_value = (headers.get("permissions-policy") or "").strip()
        directives = _parse_permissions_policy(policy_value)
        unrestricted: list[str] = []
        for feature in _SENSITIVE_FEATURES:
            directive = directives.get(feature)
            if directive is None:
                unrestricted.append(feature)
                continue
            if not _is_directive_restrictive(directive):
                unrestricted.append(feature)

        # Need framability for the iframe abuse vector.
        framable = self._is_framable(headers)

        signals: list[str] = []
        if not policy_value:
            signals.append("Permissions-Policy absent")
        else:
            signals.append(
                f"{len(unrestricted)} sensitive feature(s) unrestricted: "
                + ", ".join(unrestricted[:5])
            )
        if not framable:
            signals.append("page is NOT framable — abuse vector blocked")

        if unrestricted and framable:
            return VerificationOutcome(
                verified=True,
                promoted_type="Permissions_Policy_Abuse",
                evidence="; ".join(signals),
                severity_override="medium",
                cvss_override=5.4,
            )
        return VerificationOutcome(verified=False, evidence="; ".join(signals))

    # ── helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _fetch_headers(url: str) -> dict | None:
        try:
            from utils.request import smart_request
        except ImportError:
            return None
        try:
            resp = smart_request("get", url)
        except Exception:
            return None
        return {k.lower(): v for k, v in resp.headers.items()}

    @staticmethod
    def _is_framable(headers: dict) -> bool:
        xfo = (headers.get("x-frame-options") or "").strip().lower()
        if xfo in _VALID_XFO:
            return False
        csp = headers.get("content-security-policy") or ""
        m = _FRAME_ANCESTORS_RE.search(csp)
        if m:
            directive = m.group(1).strip().lower()
            if "'none'" in directive or directive == "'self'":
                return False
            # Specific origins still block the *attacker* origin from framing
            if directive and directive != "*":
                return False
        return True


def verify_permissions_policy(findings: list, target_url: str) -> list:
    verifier = PermissionsPolicyVerifier()
    for f in findings:
        if not verifier.applies_to(f):
            continue
        outcome = verifier.verify(f, target_url)
        apply_outcome(f, outcome)
    return findings
