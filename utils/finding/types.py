"""Core dataclasses + small helpers for the finding subsystem.

Kept in a single module because ``Finding.to_sarif_result`` calls
``_sarif_level`` and the three dataclasses share field semantics.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional


def _sarif_level(severity: str) -> str:
    """Map severity to SARIF level."""
    return {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }.get(severity.lower(), "warning")


@dataclass
class Observation:
    """Raw scanner observation before reasoning/verification enrichment."""

    id: str
    observation_type: str
    url: str
    module: str
    asset_id: str
    surface: str
    description: str = ""
    severity: str = "info"
    confidence: str = "low"
    evidence: str = ""
    param: str = ""
    payload: str = ""
    request: Optional[dict] = None
    response_snippet: Optional[str] = None
    repro_steps: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    raw: Optional[dict] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class AttackPath:
    """Inferred attack path derived from one or more findings."""

    id: str
    name: str
    severity: str
    description: str
    finding_refs: list[str] = field(default_factory=list)
    steps: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class Finding:
    """Standardized vulnerability finding."""

    title: str
    severity: str  # critical / high / medium / low / info
    cvss: float  # 0.0 - 10.0
    cwe: str  # CWE-79 etc.
    url: str
    module: str  # Which scanner module found it
    finding_type: str = ""
    description: str = ""
    param: str = ""
    payload: str = ""
    evidence: str = ""
    cve: str = ""
    component: str = ""
    version: str = ""
    confidence: str = "medium"
    remediation: str = ""
    id: str = ""
    asset_id: str = ""
    surface: str = "web"
    verification_state: str = "suspected"
    exploitability: str = "low"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    # Extra fields for module-specific data
    context: Optional[str] = None
    source: Optional[str] = None
    exploit_data: Optional[dict] = None
    repro_steps: Optional[list[str]] = None
    request: Optional[dict] = None
    response_snippet: Optional[str] = None
    evidence_items: Optional[list[dict]] = None
    preconditions: Optional[list[str]] = None
    replay_recipe: Optional[dict] = None
    observation_refs: Optional[list[str]] = None
    attack_path_refs: Optional[list[str]] = None
    extra: Optional[dict] = None

    # Validation pipeline fields (0-Day Machine hallucination gate system)
    validation_stage: str = "suspected"  # suspected → evidence_confirmed → verified → confirmed → exploitable
    validation_gates: Optional[dict] = None
    validation_history: Optional[list[dict]] = None
    promoted_at: str = ""
    demoted_at: str = ""
    demote_reason: str = ""

    def to_dict(self) -> dict:
        """Convert to dict (JSON-serializable)."""
        d = asdict(self)
        d["type"] = d.pop("finding_type") or self.module
        # Remove None values for cleaner output
        return {k: v for k, v in d.items() if v is not None}

    def to_sarif_result(self) -> dict:
        """Convert to SARIF result format."""
        return {
            "ruleId": self.cwe,
            "level": _sarif_level(self.severity),
            "message": {"text": self.title},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": self.url},
                    }
                }
            ],
            "properties": {
                "severity": self.severity,
                "cvss": self.cvss,
                "confidence": self.confidence,
                "param": self.param,
                "payload": self.payload,
            },
        }
