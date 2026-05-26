"""Per-severity process exit codes for CI/CD integration.

CI pipelines (GitHub Actions, GitLab CI, Jenkins) decide pipeline status
from the scanner's exit code. We surface severity tiers as distinct codes so
operators can pick a threshold:

    0  -> scan clean (no Critical/High findings)
    1  -> at least one Critical finding (block deploy)
    2  -> at least one High finding (warn / require review)
    3  -> at least one Medium finding (advisory)
    4  -> at least one Low/Info finding (informational)
    10 -> scanner internal error (separate from finding-driven codes)

Higher severities win — a scan with both Critical and Low returns 1.

The mapping is intentionally narrow (single int) so it composes with the
GitHub Actions ``continue-on-error: true`` pattern and with shell ``||``.
"""

from __future__ import annotations

import logging
import os
from typing import Iterable, Optional

logger = logging.getLogger(__name__)

CODE_CLEAN = 0
CODE_CRITICAL = 1
CODE_HIGH = 2
CODE_MEDIUM = 3
CODE_LOW = 4
CODE_INTERNAL_ERROR = 10

# Ordered from worst → least-bad. First match wins.
_SEVERITY_ORDER = (
    ("critical", CODE_CRITICAL),
    ("high", CODE_HIGH),
    ("medium", CODE_MEDIUM),
    ("low", CODE_LOW),
    ("info", CODE_LOW),  # info findings also exit 4 — same advisory tier
)

# Env-var override: SCAN_EXIT_THRESHOLD=critical|high|medium|low|info|never
# Anything *less severe* than the threshold is downgraded to exit 0.
# Gate rule: ``chosen <= threshold_code`` fails the build; otherwise clean.
# ``never`` => threshold_code=0 so chosen (>=1 whenever a finding exists) is
# always greater and the build stays clean.
_THRESHOLD_LEVELS = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
    "info": 4,
    "never": 0,
}


def compute_exit_code(findings: Iterable[dict], *, threshold: Optional[str] = None) -> int:
    """Decide the CI-facing exit code for a finished scan.

    ``findings`` is the list of finding dicts (or Finding objects with a
    ``.severity`` attribute / ``["severity"]`` key).
    """
    severities: set[str] = set()
    for f in findings or ():
        sev = _extract_severity(f)
        if sev:
            severities.add(sev.lower())

    chosen = CODE_CLEAN
    for sev_name, code in _SEVERITY_ORDER:
        if sev_name in severities:
            chosen = code
            break

    threshold = (threshold or os.environ.get("SCAN_EXIT_THRESHOLD") or "info").lower()
    threshold_code = _THRESHOLD_LEVELS.get(threshold, _THRESHOLD_LEVELS["info"])
    if chosen > threshold_code:
        # Finding tier is below the configured gate → don't fail the build.
        return CODE_CLEAN
    return chosen


def _extract_severity(finding) -> str:
    if isinstance(finding, dict):
        return str(finding.get("severity") or "").strip().lower()
    sev = getattr(finding, "severity", "")
    return str(sev or "").strip().lower()


def describe(code: int) -> str:
    return {
        CODE_CLEAN: "clean (no actionable findings at threshold)",
        CODE_CRITICAL: "CRITICAL findings present",
        CODE_HIGH: "HIGH findings present",
        CODE_MEDIUM: "MEDIUM findings present",
        CODE_LOW: "LOW/INFO findings present",
        CODE_INTERNAL_ERROR: "scanner internal error",
    }.get(code, f"unknown ({code})")
