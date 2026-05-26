"""Active verifiers — promote suspected findings to ``verified`` by
running a real browser / network probe.

Each verifier consumes a list of ``Missing_Security_Header`` (or related)
findings, performs a live check, and returns the *same* findings annotated
with ``verified=True`` plus ``promoted_type`` set to the corresponding
``*_Exploitable`` registry entry. Findings that don't pass the active check
are returned with ``verified=False`` and kept as low-severity advisories.

The verifiers are intentionally idempotent on the input list so the scanner
pipeline can run them all sequentially without duplicating findings.
"""

from __future__ import annotations

from .base import ActiveVerifier, VerificationOutcome
from .clickjacking import ClickjackingVerifier, verify_clickjacking
from .hsts import HSTSVerifier, verify_hsts
from .mime import MIMEConfusionVerifier, verify_mime_confusion
from .referrer import ReferrerLeakVerifier, verify_referrer_leak

__all__ = [
    "ActiveVerifier",
    "VerificationOutcome",
    "ClickjackingVerifier",
    "HSTSVerifier",
    "MIMEConfusionVerifier",
    "ReferrerLeakVerifier",
    "verify_clickjacking",
    "verify_hsts",
    "verify_mime_confusion",
    "verify_referrer_leak",
    "run_all_verifiers",
]


def run_all_verifiers(findings: list, target_url: str) -> list:
    """Run every active verifier in turn and return the enriched list.

    Verifiers must be tolerant of missing dependencies (no Playwright, no
    network); on failure they return the input unchanged.
    """
    findings = verify_clickjacking(findings, target_url)
    findings = verify_hsts(findings, target_url)
    findings = verify_mime_confusion(findings, target_url)
    findings = verify_referrer_leak(findings, target_url)
    return findings
