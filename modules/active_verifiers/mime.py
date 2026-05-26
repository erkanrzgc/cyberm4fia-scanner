"""MIME confusion active verifier (heuristic).

Full active exploitation of a MIME-confusion bug requires:

* An attacker-controlled file uploaded through a real user-content endpoint
* Re-fetching the served file and confirming the browser executes the
  embedded script

That requires an authenticated account on the target and is not safe to do
without explicit engagement scope. Instead, this verifier looks for the
*pre-conditions* that make the attack viable, and promotes the finding only
when all of them are satisfied on the same host:

1. ``X-Content-Type-Options: nosniff`` is absent on the page that carries
   user content (the missing-header finding gives us this).
2. The site exposes an upload endpoint (heuristic: any of the common paths
   replies with ``405 Method Not Allowed`` to ``GET`` or returns a multipart
   form on the homepage).
3. A representative user-content URL on the host (avatars / attachments)
   responds with a generic / wrong Content-Type — i.e. ``application/octet-
   stream``, ``text/plain``, or no Content-Type at all.

When all three line up, promote to ``MIME_Confusion_Exploitable``.
Otherwise keep the suspected finding and record the failed gate.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from urllib.parse import urljoin

from .base import VerificationOutcome, applies_to_header, apply_outcome

logger = logging.getLogger(__name__)

_HEADER_TARGETS = ("x-content-type-options",)
_UPLOAD_PROBES = (
    "/upload", "/api/upload", "/files/upload", "/attachments/new",
    "/avatar/upload", "/api/v1/files", "/api/files", "/admin/upload",
)
_USER_CONTENT_PROBES = (
    "/uploads/", "/files/", "/attachments/", "/avatars/", "/static/uploads/",
    "/media/", "/user-content/", "/cdn/",
)
_GENERIC_CONTENT_TYPES = (
    "application/octet-stream", "text/plain", "binary/octet-stream",
)
_UPLOAD_FORM_RE = re.compile(
    r'enctype="multipart/form-data"|<input[^>]*type="file"', re.IGNORECASE
)


@dataclass
class MIMEConfusionVerifier:
    finding_kind: str = "Missing_Security_Header"
    header_targets: tuple[str, ...] = _HEADER_TARGETS

    def applies_to(self, finding: dict) -> bool:
        return applies_to_header(finding, self.header_targets)

    def verify(self, finding: dict, target_url: str) -> VerificationOutcome:
        signals: list[str] = []
        upload = self._find_upload_endpoint(target_url)
        if upload:
            signals.append(f"upload endpoint reachable: {upload}")

        weak_ct = self._find_weak_content_type(target_url)
        if weak_ct:
            signals.append(weak_ct)

        if upload and weak_ct:
            return VerificationOutcome(
                verified=True,
                promoted_type="MIME_Confusion_Exploitable",
                evidence="; ".join(signals),
                severity_override="high",
                cvss_override=6.5,
            )

        # Partial signal — keep the suspected finding but annotate.
        if upload or weak_ct:
            return VerificationOutcome(
                verified=False,
                evidence="; ".join(signals) + " (need both upload + weak Content-Type)",
            )
        return VerificationOutcome(
            verified=False,
            evidence="no upload endpoint + no weak Content-Type detected",
        )

    # ── helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _try_get(url: str):
        try:
            import httpx
        except ImportError:
            return None
        try:
            return httpx.get(url, follow_redirects=False, timeout=5.0, verify=False)
        except Exception as exc:  # noqa: BLE001
            logger.debug("mime probe GET %s failed: %s", url, exc)
            return None

    def _find_upload_endpoint(self, target_url: str) -> str:
        for path in _UPLOAD_PROBES:
            probe_url = urljoin(target_url, path)
            r = self._try_get(probe_url)
            if r is None:
                continue
            # 405 = endpoint exists but expects POST = strong signal
            if r.status_code == 405:
                return probe_url
            # 200 with a form is also a signal but weaker
            if r.status_code == 200 and _UPLOAD_FORM_RE.search(r.text or ""):
                return probe_url

        # Fallback: scrape the homepage for multipart forms
        r = self._try_get(target_url)
        if r and r.status_code == 200 and _UPLOAD_FORM_RE.search(r.text or ""):
            return target_url + " (homepage form)"
        return ""

    def _find_weak_content_type(self, target_url: str) -> str:
        for path in _USER_CONTENT_PROBES:
            probe_url = urljoin(target_url, path)
            r = self._try_get(probe_url)
            if r is None or r.status_code not in (200, 403, 404):
                continue
            ct = (r.headers.get("content-type") or "").lower().split(";")[0].strip()
            if not ct or ct in _GENERIC_CONTENT_TYPES:
                return f"weak Content-Type at {path}: {ct or '(absent)'}"
        return ""


def verify_mime_confusion(findings: list, target_url: str) -> list:
    verifier = MIMEConfusionVerifier()
    for f in findings:
        if not verifier.applies_to(f):
            continue
        outcome = verifier.verify(f, target_url)
        apply_outcome(f, outcome)
    return findings
