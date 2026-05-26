"""Base abstractions for active verifiers.

A verifier takes a list of suspected findings + the target URL, runs a
live check, and returns the same findings with extra metadata. The contract
is intentionally narrow so verifiers can be composed and tested in isolation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional, Protocol

logger = logging.getLogger(__name__)


@dataclass
class VerificationOutcome:
    """Result of a single verification probe.

    ``verified=True`` upgrades the finding's ``verification_state`` to
    ``"verified"`` and promotes its ``type`` to the registry entry named by
    ``promoted_type``. ``verified=False`` leaves the finding intact but
    records the evidence string for the report.
    """

    verified: bool
    promoted_type: Optional[str] = None
    evidence: str = ""
    cvss_override: Optional[float] = None
    severity_override: Optional[str] = None


class ActiveVerifier(Protocol):
    """Structural protocol every concrete verifier implements."""

    finding_kind: str  # e.g. "Missing_Security_Header"
    header_targets: tuple[str, ...]  # case-insensitive header names handled

    def applies_to(self, finding: dict) -> bool: ...

    def verify(self, finding: dict, target_url: str) -> VerificationOutcome: ...


def filter_applicable(findings: list, verifier: ActiveVerifier) -> list:
    """Sub-select findings the verifier cares about."""
    return [f for f in findings if verifier.applies_to(f)]


def apply_outcome(finding: dict, outcome: VerificationOutcome) -> dict:
    """Mutate a finding in place with the verification result.

    Returns the same dict for chaining. We update the dict (rather than
    rebuilding) so caller-held references stay consistent.
    """
    finding["verified"] = outcome.verified
    if outcome.verified:
        finding["verification_state"] = "verified"
        if outcome.promoted_type:
            finding["type"] = outcome.promoted_type
        if outcome.severity_override:
            finding["severity"] = outcome.severity_override.upper()
        if outcome.cvss_override is not None:
            finding["cvss"] = outcome.cvss_override
    if outcome.evidence:
        existing = finding.get("evidence", "") or ""
        finding["evidence"] = (existing + " | " + outcome.evidence).strip(" |")
    return finding


def applies_to_header(finding: dict, headers: tuple[str, ...]) -> bool:
    """Common ``applies_to`` predicate: Missing_Security_Header for a header set."""
    if finding.get("type") != "Missing_Security_Header":
        return False
    param = str(finding.get("param", "")).strip().lower()
    return param in {h.lower() for h in headers}
