"""Finding model + CVSS/CWE registry + normalization + SARIF.

This package replaces the former 1169-LOC ``utils/finding.py`` with five
cohesive sub-modules. The public surface is preserved verbatim so every
existing ``from utils.finding import X`` keeps working.

Sub-modules:
  - types          → Observation, AttackPath, Finding dataclasses
  - registry       → VULN_REGISTRY mapping vuln types to severity/CVSS/CWE
  - normalization  → confidence scoring, vuln→Finding conversion, dedup
  - artifacts      → build_scan_artifacts, build_attack_paths, normalize_all
  - sarif          → generate_sarif (SARIF 2.1.0)
"""

from .artifacts import build_attack_paths, build_scan_artifacts, normalize_all
from .normalization import (
    _build_asset_id,
    _build_replay_recipe,
    _coerce_evidence_items,
    _coerce_repro_steps,
    _extract_request_details,
    _extract_response_snippet,
    _infer_confidence,
    _infer_exploitability,
    _infer_surface,
    _infer_verification_state,
    _normalize_with_observations,
    _score_to_confidence,
    _stable_id,
    _truncate_text,
    compute_confidence_score,
    deduplicate_findings,
    normalize_vuln,
    observation_from_vuln,
)
from .registry import VULN_REGISTRY, _DEFAULT_VULN
from .sarif import generate_sarif
from .types import AttackPath, Finding, Observation, _sarif_level

__all__ = [
    # types
    "Observation",
    "AttackPath",
    "Finding",
    # registry
    "VULN_REGISTRY",
    # normalization
    "compute_confidence_score",
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
