"""Referrer-Policy leak active verifier (heuristic).

A Referrer-Policy leak only matters when:

1. The page in question carries a secret in its URL (reset_token, OAuth
   code, share-link ID, magic-login token) **or** could plausibly do so.
2. The page loads at least one cross-origin subresource (image, font, JS,
   CSS, analytics) whose origin would receive the Referer.

When both conditions hold and no ``Referrer-Policy`` header restricts the
leak, promote to ``Referrer_Leak_Exploitable``.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from .base import VerificationOutcome, applies_to_header, apply_outcome

logger = logging.getLogger(__name__)

_HEADER_TARGETS = ("referrer-policy",)

# Patterns that suggest a secret lives in URLs on this site.
_SENSITIVE_URL_HINTS = re.compile(
    r"(reset[_-]?token|reset[_-]?password|forgot[_-]?password|"
    r"oauth/callback|/callback\?code=|access[_-]?token|magic[_-]?link|"
    r"verify[_-]?email|/share/|/invite/|/auth/code|state=[A-Za-z0-9]{12,}|"
    r"sso/.*token|saml)",
    re.IGNORECASE,
)

# Cross-origin subresource pattern (best-effort, no JS execution).
_SUBRESOURCE_RE = re.compile(
    r'(?:src|href)\s*=\s*["\']https?://([^/"\']+)/[^"\']*\.'
    r"(?:js|css|woff2?|ttf|otf|eot|png|jpg|jpeg|gif|svg|ico|webp|mjs)",
    re.IGNORECASE,
)

# Policies that fully neutralise the leak — anything else is potentially
# exploitable depending on the value.
_SAFE_POLICIES = (
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
)


@dataclass
class ReferrerLeakVerifier:
    finding_kind: str = "Missing_Security_Header"
    header_targets: tuple[str, ...] = _HEADER_TARGETS

    def applies_to(self, finding: dict) -> bool:
        return applies_to_header(finding, self.header_targets)

    def verify(self, finding: dict, target_url: str) -> VerificationOutcome:
        signals: list[str] = []

        page = self._fetch(target_url)
        if page is None:
            return VerificationOutcome(verified=False, evidence="active probe failed")

        policy = (page.headers.get("referrer-policy") or "").strip().lower()
        if policy in _SAFE_POLICIES:
            return VerificationOutcome(
                verified=False,
                evidence=f"safe Referrer-Policy in effect: {policy}",
            )
        if policy:
            signals.append(f"weak Referrer-Policy: {policy}")
        else:
            signals.append("Referrer-Policy absent (browser default applies)")

        cross_origins = self._cross_origin_subresources(page.text, target_url)
        if cross_origins:
            signals.append(
                f"{len(cross_origins)} cross-origin subresource origin(s): "
                + ", ".join(sorted(cross_origins)[:5])
            )

        sensitive = self._has_sensitive_url_hint(page.text)
        if sensitive:
            signals.append(f"sensitive URL pattern in body: {sensitive}")

        if cross_origins and (sensitive or self._url_looks_sensitive(target_url)):
            return VerificationOutcome(
                verified=True,
                promoted_type="Referrer_Leak_Exploitable",
                evidence="; ".join(signals),
                severity_override="medium",
                cvss_override=4.3,
            )

        return VerificationOutcome(
            verified=False,
            evidence="; ".join(signals) or "no sensitive URLs + no cross-origin subresources detected",
        )

    # ── helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _fetch(url: str):
        try:
            import httpx
        except ImportError:
            return None
        try:
            return httpx.get(url, follow_redirects=True, timeout=5.0, verify=False)
        except Exception as exc:  # noqa: BLE001
            logger.debug("referrer fetch %s failed: %s", url, exc)
            return None

    @staticmethod
    def _cross_origin_subresources(body: str, target_url: str) -> set[str]:
        if not body:
            return set()
        target_host = (urlparse(target_url).hostname or "").lower()
        hosts = set()
        for host in _SUBRESOURCE_RE.findall(body):
            h = host.lower().split(":")[0]
            if h and h != target_host and not h.endswith("." + target_host):
                hosts.add(h)
        return hosts

    @staticmethod
    def _has_sensitive_url_hint(body: str) -> str:
        if not body:
            return ""
        m = _SENSITIVE_URL_HINTS.search(body)
        return m.group(0) if m else ""

    @staticmethod
    def _url_looks_sensitive(url: str) -> bool:
        return bool(_SENSITIVE_URL_HINTS.search(url))


def verify_referrer_leak(findings: list, target_url: str) -> list:
    verifier = ReferrerLeakVerifier()
    for f in findings:
        if not verifier.applies_to(f):
            continue
        outcome = verifier.verify(f, target_url)
        apply_outcome(f, outcome)
    return findings
