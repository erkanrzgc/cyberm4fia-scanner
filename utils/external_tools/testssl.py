"""testssl.sh adapter — deep TLS/SSL vulnerability scanner.

Complements :mod:`utils.external_tools.sslyze` (which focuses on weak protocols)
with vuln-level checks: Heartbleed, ROBOT, CCS, FREAK, LOGJAM, CRIME, BEAST,
etc., each tagged with its own severity. Uses testssl's flat JSON output for
robust parsing — far simpler than sslyze's nested schema.

Requires the ``testssl.sh`` binary in PATH (https://github.com/drwetter/testssl.sh).
"""

from __future__ import annotations

import json
import re
from typing import Any

from utils.external_tools.base import ExternalTool

# testssl severity -> our scanner severity vocabulary
_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "WARN": "low",
}

# Only severities we treat as actionable findings.
_ACTIONABLE = set(_SEVERITY_MAP)


class TestsslTool(ExternalTool):
    binary = "testssl.sh"
    default_timeout = 900.0  # full TLS audit can be slow

    def get_command(
        self,
        target: str,
        *,
        extra_args: list[str] | None = None,
    ) -> list[str]:
        cmd = [
            self.binary,
            "--jsonfile-pretty", "/dev/stdout",
            "--quiet",
            "--color", "0",
            target,
        ]
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
        match = re.search(r"\[.*\]", stdout, re.DOTALL)
        vulns: list[dict] = []
        if match:
            try:
                items = json.loads(match.group(0))
            except json.JSONDecodeError:
                items = []
            for item in items:
                if not isinstance(item, dict):
                    continue
                sev = str(item.get("severity") or "").upper()
                if sev in _ACTIONABLE:
                    vulns.append({
                        "id": str(item.get("id") or "unknown"),
                        "severity": sev,
                        "finding": str(item.get("finding") or ""),
                    })
        return {"vulnerabilities": vulns, "count": len(vulns)}

    def to_findings(self, parsed: Any, *, target: str = "") -> list[dict]:
        findings = []
        for v in (parsed or {}).get("vulnerabilities", []):
            findings.append({
                "type": "TLS_Vulnerability",
                "url": target,
                "title": f"{v['id']}: {v.get('finding','')}".strip(": "),
                "severity": _SEVERITY_MAP.get(v.get("severity", ""), "low"),
                "evidence": v.get("finding", ""),
                "module": "testssl",
            })
        return findings
