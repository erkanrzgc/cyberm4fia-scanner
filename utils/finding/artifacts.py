"""Higher-level builders that assemble observations + findings + attack paths."""

from __future__ import annotations

from .normalization import _normalize_with_observations, _stable_id
from .types import AttackPath, Finding


def normalize_all(vuln_list: list) -> list:
    """Convert a list of legacy vuln dicts to Finding objects."""
    _, normalized = _normalize_with_observations(vuln_list)
    return normalized


def build_scan_artifacts(vuln_list: list) -> dict:
    """Build observations, reasoned findings, and inferred attack paths."""
    observations, normalized = _normalize_with_observations(vuln_list)

    attack_paths = build_attack_paths(normalized)
    return {
        "observations": observations,
        "findings": normalized,
        "attack_paths": attack_paths,
    }


def build_attack_paths(findings: list[Finding]) -> list[AttackPath]:
    """Infer attack paths from reasoned findings and attach path refs back to findings."""
    if not findings:
        return []

    from utils.vuln_chain import analyze_chains

    chain_inputs = [finding.to_dict() for finding in findings]
    raw_paths = analyze_chains(chain_inputs)
    if not raw_paths:
        return []

    attack_paths = []
    for raw_path in raw_paths:
        path_id = _stable_id(
            "path",
            raw_path.get("chain"),
            raw_path.get("source_vuln"),
            raw_path.get("source_url"),
        )
        finding_refs = []
        source_vuln = raw_path.get("source_vuln")
        source_url = raw_path.get("source_url")
        for finding in findings:
            if (
                finding.finding_type or finding.module
            ) == source_vuln and finding.url == source_url:
                finding_refs.append(finding.id)
                refs = list(finding.attack_path_refs or [])
                if path_id not in refs:
                    refs.append(path_id)
                    finding.attack_path_refs = refs
                    if finding.verification_state == "verified":
                        finding.verification_state = "chained"
                break

        attack_paths.append(
            AttackPath(
                id=path_id,
                name=raw_path.get("chain", raw_path.get("escalation", "Attack Path")),
                severity=str(raw_path.get("severity", "medium")).lower(),
                description=raw_path.get("description", ""),
                finding_refs=finding_refs,
                steps=raw_path.get("steps") or [raw_path],
            )
        )

    return attack_paths
