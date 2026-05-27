"""Collapse legacy findings into their promoted-sibling equivalents.

Several modules emit findings that describe the *same root cause* an active
verifier has already promoted to its ``*_Exploitable`` form:

* ``modules/guaranteed_checks`` emits ``Clickjacking_Vulnerable`` — the active
  verifier emits ``Clickjacking_Exploitable`` from a Missing_Security_Header.
* ``modules/cookie_hsts_audit`` emits ``Weak_HSTS`` — the HSTS verifier emits
  ``HSTS_Downgrade_Exploitable`` from the same Missing_Security_Header.
* ``modules/csp_bypass`` emits ``CSP_Bypass`` (weakness="missing_csp") — the
  same gap is also a ``Missing_Security_Header`` for Content-Security-Policy.

If both live in the same report the operator sees the same problem twice.
This pass keeps the promoted finding (richer evidence, real CVSS) and drops
the legacy duplicates on the same URL.

Conservative: legacy findings are only removed when a promoted sibling
*exists for the same URL*. If verification didn't promote, the legacy
finding stays as-is.
"""

from __future__ import annotations

import logging
from typing import Iterable

logger = logging.getLogger(__name__)

# promoted_type → legacy types it supersedes (per-URL).
# When the promoted finding exists on a URL, every legacy type on that URL
# is dropped from the report.
_PROMOTED_OVERRIDES: dict[str, tuple[str, ...]] = {
    "Clickjacking_Exploitable": (
        "Clickjacking_Vulnerable",
    ),
    "HSTS_Downgrade_Exploitable": (
        "Weak_HSTS",
    ),
    # When CSP is missing-and-exploitable the active CSP verifier promotes
    # the Missing_Security_Header; the legacy csp_bypass weakness
    # ``missing_csp`` describes the same gap.
    "Missing_Security_Header": (),  # placeholder — see _is_csp_missing
}


def _normalise_url(finding: dict) -> str:
    return str(finding.get("url") or "").rstrip("/")


def _is_csp_missing_header(finding: dict) -> bool:
    """A Missing_Security_Header finding whose param is CSP."""
    if finding.get("type") != "Missing_Security_Header":
        return False
    return str(finding.get("param") or "").strip().lower() == "content-security-policy"


def _is_legacy_csp_missing(finding: dict) -> bool:
    """A csp_bypass.py finding whose weakness is missing_csp."""
    if finding.get("type") != "CSP_Bypass":
        return False
    return str(finding.get("weakness") or "").strip().lower() == "missing_csp"


def collapse_promoted_siblings(findings: Iterable[dict]) -> list[dict]:
    """Drop legacy findings whose promoted sibling exists on the same URL.

    Returns a new list; the input is not mutated.
    """
    findings = list(findings)
    if not findings:
        return findings

    # Index promoted types → set of URLs that carry them.
    promoted_urls: dict[str, set[str]] = {ptype: set() for ptype in _PROMOTED_OVERRIDES}
    csp_missing_urls: set[str] = set()

    for f in findings:
        ftype = f.get("type", "")
        if ftype in promoted_urls:
            promoted_urls[ftype].add(_normalise_url(f))
        if _is_csp_missing_header(f):
            csp_missing_urls.add(_normalise_url(f))

    def should_drop(f: dict) -> bool:
        ftype = f.get("type", "")
        url = _normalise_url(f)
        # Standard promoted-type overrides.
        for promoted_type, legacy_types in _PROMOTED_OVERRIDES.items():
            if ftype in legacy_types and url in promoted_urls.get(promoted_type, set()):
                return True
        # Special case: legacy CSP_Bypass missing_csp is replaced by the
        # enriched Missing_Security_Header / promoted Exploitable variant.
        if _is_legacy_csp_missing(f) and url in csp_missing_urls:
            return True
        return False

    kept: list[dict] = []
    dropped = 0
    for f in findings:
        if should_drop(f):
            dropped += 1
            logger.debug(
                "promoted_dedup: dropping legacy %s on %s — promoted sibling present",
                f.get("type"),
                _normalise_url(f),
            )
            continue
        kept.append(f)

    if dropped:
        logger.info(
            "promoted_dedup: collapsed %d legacy finding(s) into promoted siblings",
            dropped,
        )
    return kept
