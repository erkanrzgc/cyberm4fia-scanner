"""
cyberm4fia-scanner — Output Formatter

Centralized output formatting for scan results.
Supports: plain text, JSON, SARIF, JSON Lines streaming.
"""

import json
import os
from datetime import datetime
from utils.colors import log_success, log_info
from utils.finding import build_scan_artifacts, generate_sarif, normalize_all


def save_findings_json(
    findings: list,
    scan_dir: str,
    url: str,
    mode: str,
    stats: dict,
    artifacts: dict | None = None,
):
    """Save findings as enhanced JSON with CVSS/CWE data."""
    artifacts = artifacts or build_scan_artifacts(findings)
    normalized = artifacts["findings"]

    report = {
        "scanner": "cyberm4fia-scanner",
        "target": url,
        "mode": mode,
        "timestamp": datetime.now().isoformat(),
        "stats": stats,
        "summary": {
            "total": len(normalized),
            "critical": sum(1 for f in normalized if f.severity == "critical"),
            "high": sum(1 for f in normalized if f.severity == "high"),
            "medium": sum(1 for f in normalized if f.severity == "medium"),
            "low": sum(1 for f in normalized if f.severity == "low"),
            "info": sum(1 for f in normalized if f.severity == "info"),
        },
        "observations": [obs.to_dict() for obs in artifacts["observations"]],
        "findings": [f.to_dict() for f in normalized],
        "attack_paths": [path.to_dict() for path in artifacts["attack_paths"]],
    }

    json_file = os.path.join(scan_dir, "findings.json")
    with open(json_file, "w") as f:
        json.dump(report, f, indent=2, default=str)

    log_success(f"Enhanced JSON report: {json_file}")
    return json_file


def save_sarif(findings: list, scan_dir: str):
    """Save findings as SARIF 2.1.0 for GitHub Security tab."""
    normalized = normalize_all(findings)
    sarif_data = generate_sarif(normalized)

    sarif_file = os.path.join(scan_dir, "results.sarif")
    with open(sarif_file, "w") as f:
        json.dump(sarif_data, f, indent=2)

    log_success(f"SARIF report: {sarif_file}")
    return sarif_file


def save_jsonl_stream(finding_dict: dict, stream_file: str):
    """Append a single finding as JSON Line (streaming output)."""
    normalized = normalize_all([finding_dict])
    if normalized:
        with open(stream_file, "a") as f:
            f.write(json.dumps(normalized[0].to_dict(), default=str) + "\n")


def print_severity_summary(findings: list):
    """Print a severity breakdown to console."""
    from utils.finding import normalize_all as _norm

    normalized = _norm(findings)
    if not normalized:
        log_info("No vulnerabilities found.")
        return

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in normalized:
        severity = f.severity.lower()
        if severity in counts:
            counts[severity] += 1

    parts = []
    if counts["critical"]:
        parts.append(f"🔴 {counts['critical']} Critical")
    if counts["high"]:
        parts.append(f"🟠 {counts['high']} High")
    if counts["medium"]:
        parts.append(f"🟡 {counts['medium']} Medium")
    if counts["low"]:
        parts.append(f"🔵 {counts['low']} Low")
    if counts["info"]:
        parts.append(f"⚪ {counts['info']} Info")

    log_info(f"Severity breakdown: {' | '.join(parts)}")
