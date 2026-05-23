"""gitleaks adapter — secrets detection in source paths and git history.

The battle-tested tool behind our :mod:`core/ai_skills/offensive-secrets-exposure`
skill. Takes a *path* target (not a URL): typically the working copy or a
cloned repo. Outputs JSON to stdout via ``--report-path /dev/stdout``.

Requires the ``gitleaks`` binary in PATH (https://github.com/gitleaks/gitleaks).
"""

from __future__ import annotations

import json
import re
from typing import Any

from utils.external_tools.base import ExternalTool


class GitleaksTool(ExternalTool):
    binary = "gitleaks"
    default_timeout = 600.0

    def get_command(
        self,
        target: str,
        *,
        no_git: bool = True,
        extra_args: list[str] | None = None,
    ) -> list[str]:
        cmd = [
            self.binary, "detect",
            "--source", target,
            "--report-format", "json",
            "--report-path", "/dev/stdout",
            "--no-banner",
        ]
        if no_git:
            cmd.append("--no-git")
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
        leaks: list[dict] = []
        match = re.search(r"\[.*\]", stdout, re.DOTALL)
        if match:
            try:
                items = json.loads(match.group(0))
            except json.JSONDecodeError:
                items = []
            for item in items:
                if not isinstance(item, dict):
                    continue
                leaks.append({
                    "rule": str(item.get("RuleID") or "unknown"),
                    "description": str(item.get("Description") or ""),
                    "file": str(item.get("File") or ""),
                    "line": int(item.get("StartLine") or 0),
                    "match": str(item.get("Match") or "")[:80],   # truncate; secrets sensitive
                })
        return {"leaks": leaks, "count": len(leaks)}

    def to_findings(self, parsed: Any, *, target: str = "") -> list[dict]:
        findings = []
        for leak in (parsed or {}).get("leaks", []):
            location = f"{leak['file']}:{leak['line']}" if leak.get("file") else target
            findings.append({
                "type": "Secret_Leak",
                "url": location,
                "title": f"{leak['rule']}: {leak.get('description','')}".strip(": "),
                "severity": "high",
                "evidence": leak.get("match", ""),
                "module": "gitleaks",
            })
        return findings
