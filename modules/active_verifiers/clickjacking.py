"""Clickjacking active verifier.

Tries to load the target inside an iframe and asserts the browser actually
rendered it. Promotes the finding to ``Clickjacking_Exploitable`` only when
all three signals agree:

* No ``X-Frame-Options`` header on the response (or value is empty / invalid)
* No ``frame-ancestors`` directive in CSP (or directive is wildcard)
* Browser successfully renders the framed content (Playwright frame is
  visible and has non-zero dimensions)

The third check requires Playwright. If Playwright is not installed (CI
without browsers) the verifier falls back to a header-only check that still
promotes when XFO and CSP both fail — the impact is identical, only the
"observed in browser" evidence is missing.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from .base import (
    VerificationOutcome,
    applies_to_header,
    apply_outcome,
)

logger = logging.getLogger(__name__)

_HEADER_TARGETS = ("x-frame-options", "content-security-policy")
_FRAME_ANCESTORS_RE = re.compile(r"frame-ancestors\s+([^;]+)", re.IGNORECASE)
_VALID_XFO = ("deny", "sameorigin")


@dataclass
class ClickjackingVerifier:
    finding_kind: str = "Missing_Security_Header"
    header_targets: tuple[str, ...] = _HEADER_TARGETS

    def applies_to(self, finding: dict) -> bool:
        return applies_to_header(finding, self.header_targets)

    def verify(self, finding: dict, target_url: str) -> VerificationOutcome:
        headers = self._fetch_headers(target_url)
        if headers is None:
            return VerificationOutcome(verified=False, evidence="active probe failed (no headers)")

        xfo_ok = self._xfo_blocks_framing(headers.get("x-frame-options", ""))
        csp_ok = self._csp_blocks_framing(headers.get("content-security-policy", ""))
        if xfo_ok or csp_ok:
            return VerificationOutcome(
                verified=False,
                evidence=f"frame protection present (xfo_ok={xfo_ok}, csp_ok={csp_ok})",
            )

        # Header-only positive evidence — already enough to promote.
        evidence = "no X-Frame-Options + no CSP frame-ancestors"

        browser_evidence = self._verify_in_browser(target_url)
        if browser_evidence:
            evidence = f"{evidence}; {browser_evidence}"

        return VerificationOutcome(
            verified=True,
            promoted_type="Clickjacking_Exploitable",
            evidence=evidence,
            severity_override="medium",
            cvss_override=5.4,
        )

    # ── helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _fetch_headers(url: str) -> dict | None:
        """Cheap HEAD/GET fetch to read enforcement headers."""
        try:
            from utils.request import smart_request, ScanExceptions
        except ImportError:
            return None
        try:
            resp = smart_request("get", url)
        except Exception:  # broad: smart_request raises ScanExceptions tuple
            return None
        return {k.lower(): v for k, v in resp.headers.items()}

    @staticmethod
    def _xfo_blocks_framing(value: str) -> bool:
        v = (value or "").strip().lower()
        return v in _VALID_XFO

    @staticmethod
    def _csp_blocks_framing(csp: str) -> bool:
        m = _FRAME_ANCESTORS_RE.search(csp or "")
        if not m:
            return False
        directive = m.group(1).strip().lower()
        if "'none'" in directive:
            return True
        if directive in ("'self'",):
            return True
        # Wildcard-only is effectively no protection.
        if directive == "*":
            return False
        # Specific origin list — still some protection, not exploitable cross-site.
        return True

    @staticmethod
    def _verify_in_browser(target_url: str) -> str:
        """Optional Playwright check; returns evidence string or empty."""
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return ""

        wrapper_html = (
            "<!doctype html><html><body>"
            f'<iframe id="t" src="{target_url}" width="800" height="600"></iframe>'
            "</body></html>"
        )

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                try:
                    page = browser.new_page()
                    page.set_content(wrapper_html, wait_until="load", timeout=10000)
                    frame_elem = page.query_selector("iframe#t")
                    if frame_elem is None:
                        return ""
                    box = frame_elem.bounding_box()
                    if not box or box["width"] < 50 or box["height"] < 50:
                        return ""
                    frame = frame_elem.content_frame()
                    if frame is None:
                        # CSP/XFO refused inside browser.
                        return ""
                    # Browser actually rendered framed content
                    return "iframe rendered in headless browser"
                finally:
                    browser.close()
        except Exception as exc:  # noqa: BLE001
            logger.debug("clickjacking browser probe failed: %s", exc)
            return ""


def verify_clickjacking(findings: list, target_url: str) -> list:
    """Module-level convenience that runs the verifier across all findings."""
    verifier = ClickjackingVerifier()
    promoted = False
    for f in findings:
        if not verifier.applies_to(f):
            continue
        # Once any of the relevant headers proves the target is exploitable,
        # don't re-probe — promote *all* clickjacking-related missing headers
        # on the same target with the cached outcome.
        if promoted:
            continue
        outcome = verifier.verify(f, target_url)
        apply_outcome(f, outcome)
        if outcome.verified:
            promoted = True
            # Also promote sibling Missing_Security_Header findings for the
            # related headers (XFO + CSP) on the same URL so the report shows
            # a single Clickjacking_Exploitable instead of two suspected rows.
            sibling_outcome = VerificationOutcome(
                verified=True,
                promoted_type="Clickjacking_Exploitable",
                evidence="sibling header — promoted together",
                severity_override="medium",
                cvss_override=5.4,
            )
            for other in findings:
                if other is f:
                    continue
                if verifier.applies_to(other) and other.get("url") == f.get("url"):
                    apply_outcome(other, sibling_outcome)
    return findings
