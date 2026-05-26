"""SPA / template-mirror false-positive filter for scanner findings.

Used after passive/active modules emit findings. A finding whose URL responds
with the homepage template (or any catch-all fingerprint from the fuzzer
calibration baseline) is most likely a soft 404 / SPA history fallback, not a
real vulnerability — drop it before it hits the report.

The filter intentionally skips ``Missing_Security_Header`` findings: header
issues are valid for the homepage itself, and double-emitting them is handled
by ``deduplicate_findings``.
"""

from __future__ import annotations

import logging
from typing import Iterable, Optional

from utils.response_fingerprint import BaselineSet, compute_fingerprint

logger = logging.getLogger(__name__)

# Finding types whose meaning is intrinsic to the response *content* — if that
# content is the homepage template, the finding is bogus.
_CONTENT_DEPENDENT_TYPES: frozenset[str] = frozenset(
    {
        "Unknown_Vulnerability",
        "Unclassified Observation",
        "Sensitive_Information_Exposure",
        "Sensitive Information Exposure",
        "Secret_Leak",
        "Debug_Info",
        "Recon",
        "Tech_Fingerprint",
        "Endpoint_Discovered",
    }
)


def _looks_like_template_mirror(
    finding: dict,
    baseline: BaselineSet,
) -> bool:
    """Return True if the finding's captured response matches the baseline."""
    body = (
        finding.get("response_body")
        or finding.get("response_snippet")
        or finding.get("body_preview")
        or finding.get("body")
        or ""
    )
    if not body:
        return False
    headers = finding.get("response_headers") or {}
    fp = compute_fingerprint(body, headers)
    return baseline.matches(fp)


def filter_template_mirror_findings(
    findings: Iterable[dict],
    baseline: Optional[BaselineSet],
) -> list[dict]:
    """Drop content-dependent findings whose response matches the baseline.

    ``baseline`` of ``None`` or empty is a no-op (returns the input as-is).
    """
    if baseline is None or not baseline.fingerprints:
        return list(findings)

    kept: list[dict] = []
    dropped = 0
    for f in findings:
        ftype = str(f.get("type", "") or "")
        if ftype in _CONTENT_DEPENDENT_TYPES and _looks_like_template_mirror(f, baseline):
            dropped += 1
            logger.debug(
                "spa_filter: dropping %s on %s — response matches catch-all baseline",
                ftype,
                f.get("url", ""),
            )
            continue
        kept.append(f)

    if dropped:
        logger.info(
            "spa_filter: removed %d SPA-fallback false positive(s) before reporting",
            dropped,
        )
    return kept
