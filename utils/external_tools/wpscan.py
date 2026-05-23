"""wpscan adapter — WordPress vulnerability scanning.

Far deeper than ``modules/cms_enum`` for WordPress targets: enumerates core,
plugin, and theme vulnerabilities. Parses wpscan's ``--format json`` output.

Requires the ``wpscan`` binary in PATH (https://github.com/wpscanteam/wpscan).
An API token (``--api-token``) unlocks the vulnerability database.
"""

from __future__ import annotations

import json
from typing import Any

from utils.external_tools.base import ExternalTool


class WpscanTool(ExternalTool):
    binary = "wpscan"
    default_timeout = 600.0

    def get_command(
        self,
        target: str,
        *,
        api_token: str | None = None,
        extra_args: list[str] | None = None,
    ) -> list[str]:
        cmd = [
            self.binary,
            "--url", target,
            "--format", "json",
            "--no-banner",
        ]
        if api_token:
            cmd.extend(["--api-token", api_token])
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
        start = stdout.find("{")
        end = stdout.rfind("}")
        vulns: list[dict] = []
        if start >= 0 and end > start:
            try:
                data = json.loads(stdout[start:end + 1])
            except json.JSONDecodeError:
                data = {}
            vulns.extend(self._collect(data.get("version", {}), "core"))
            for name, info in (data.get("plugins") or {}).items():
                vulns.extend(self._collect(info, f"plugin:{name}"))
            for name, info in (data.get("themes") or {}).items():
                vulns.extend(self._collect(info, f"theme:{name}"))
        return {"vulnerabilities": vulns, "count": len(vulns)}

    @staticmethod
    def _collect(section: dict, source: str) -> list[dict]:
        out = []
        for v in (section or {}).get("vulnerabilities", []) or []:
            out.append({
                "title": str(v.get("title") or "Unknown vulnerability"),
                "source": source,
                "references": v.get("references", {}),
            })
        return out

    def to_findings(self, parsed: Any, *, target: str = "") -> list[dict]:
        findings = []
        for v in (parsed or {}).get("vulnerabilities", []):
            source = v.get("source", "")
            findings.append({
                "type": "WordPress_Vuln",
                "url": target,
                "title": f"[{source}] {v['title']}" if source else v["title"],
                "severity": "high",
                "evidence": json.dumps(v.get("references", {})),
                "module": "wpscan",
            })
        return findings
