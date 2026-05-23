"""kube-hunter adapter — Kubernetes cluster vulnerability scanner.

Pairs with the imported ``kubernetes-pentesting`` skill, giving the agent an
actual scanner for the techniques that skill documents. Parses kube-hunter's
``--report json`` output, which is a flat list of vulnerability records with
their own severity classification.

Requires the ``kube-hunter`` binary in PATH (https://github.com/aquasecurity/kube-hunter).
"""

from __future__ import annotations

import json
import re
from typing import Any

from utils.external_tools.base import ExternalTool

# kube-hunter severity -> our scanner severity vocabulary
_SEVERITY_MAP = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "vulnerability": "medium",   # some versions emit category names; default conservatively
}


class KubeHunterTool(ExternalTool):
    binary = "kube-hunter"
    default_timeout = 900.0

    def get_command(
        self,
        target: str,
        *,
        extra_args: list[str] | None = None,
    ) -> list[str]:
        cmd = [
            self.binary,
            "--remote", target,
            "--report", "json",
            "--quick",
        ]
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
        match = re.search(r"\{.*\}", stdout, re.DOTALL)
        vulns: list[dict] = []
        if match:
            try:
                data = json.loads(match.group(0))
            except json.JSONDecodeError:
                data = {}
            for v in data.get("vulnerabilities") or []:
                if not isinstance(v, dict):
                    continue
                vulns.append({
                    "vulnerability": str(v.get("vulnerability") or "Unknown"),
                    "description": str(v.get("description") or ""),
                    "severity": str(v.get("severity") or "low").lower(),
                    "category": str(v.get("category") or ""),
                    "location": str(v.get("location") or ""),
                })
        return {"vulnerabilities": vulns, "count": len(vulns)}

    def to_findings(self, parsed: Any, *, target: str = "") -> list[dict]:
        findings = []
        for v in (parsed or {}).get("vulnerabilities", []):
            findings.append({
                "type": "Kubernetes_Vuln",
                "url": target,
                "title": v["vulnerability"],
                "severity": _SEVERITY_MAP.get(v.get("severity", "low"), "low"),
                "evidence": v.get("description") or v.get("category", ""),
                "module": "kube-hunter",
            })
        return findings
