"""Finding model + CVSS/CWE registry + normalization + SARIF.

This package replaces the former 1169-LOC ``utils/finding.py`` with five
cohesive sub-modules. The public surface (everything in ``__all__``)
is preserved verbatim so every existing ``from utils.finding import X``
keeps working.

Sub-modules:
  - types          → Observation, AttackPath, Finding dataclasses
  - registry       → VULN_REGISTRY mapping vuln types to severity/CVSS/CWE
  - normalization  → confidence scoring, vuln→Finding conversion, dedup
  - artifacts      → build_scan_artifacts, build_attack_paths, normalize_all
  - sarif          → generate_sarif (SARIF 2.1.0)

Private helpers (``_truncate_text``, ``_stable_id``, ``_DEFAULT_VULN``
etc.) intentionally remain in their sub-modules and are NOT re-exported
from the package root. The single exception is ``_infer_confidence``,
which is exercised directly by ``tests/test_confidence.py``.
"""

from .artifacts import build_attack_paths, build_scan_artifacts, normalize_all
from .normalization import (
    _infer_confidence,
    compute_confidence_score,
    deduplicate_findings,
    normalize_vuln,
    observation_from_vuln,
)
from .registry import VULN_REGISTRY
from .sarif import generate_sarif
from .types import AttackPath, Finding, Observation

__all__ = [
    # types
    "Observation",
    "AttackPath",
    "Finding",
    # registry
    "VULN_REGISTRY",
    # normalization
    "compute_confidence_score",
    "_infer_confidence",
    "observation_from_vuln",
    "normalize_vuln",
    "deduplicate_findings",
    # artifacts
    "normalize_all",
    "build_scan_artifacts",
    "build_attack_paths",
    # sarif
    "generate_sarif",
]
