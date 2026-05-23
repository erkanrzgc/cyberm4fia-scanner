"""gowitness adapter — visual reconnaissance (HTTP screenshots).

Adds a previously-absent capability to the scanner: rapid visual triage of
HTTP services. gowitness v3 supports ``--write-stdout`` to emit JSON metadata
per capture; the screenshot file is a side effect saved to disk.

Requires the ``gowitness`` binary in PATH (https://github.com/sensepost/gowitness).
"""

from __future__ import annotations

import json
import re
from typing import Any

from utils.external_tools.base import ExternalTool


class GowitnessTool(ExternalTool):
    binary = "gowitness"
    default_timeout = 180.0

    def get_command(
        self,
        target: str,
        *,
        screenshot_path: str = "./screenshots",
        extra_args: list[str] | None = None,
    ) -> list[str]:
        cmd = [
            self.binary, "scan", "single",
            "--url", target,
            "--screenshot-path", screenshot_path,
            "--write-stdout",
        ]
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
        captures: list[dict] = []
        # Each capture is one JSON object; multiple URLs would emit multiple
        # objects (one per line is common, but we also handle a single object).
        for match in re.finditer(r"\{.*?\}", stdout, re.DOTALL):
            try:
                obj = json.loads(match.group(0))
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict) or "url" not in obj:
                continue
            captures.append({
                "url": str(obj.get("final_url") or obj.get("url") or ""),
                "title": str(obj.get("title") or ""),
                "status": int(obj.get("status_code") or 0),
                "screenshot": str(obj.get("screenshot_path") or ""),
            })
        return {"captures": captures, "count": len(captures)}

    def to_findings(self, parsed: Any, *, target: str = "") -> list[dict]:
        findings = []
        for c in (parsed or {}).get("captures", []):
            findings.append({
                "type": "Visual_Capture",
                "url": c["url"] or target,
                "title": f"Screenshot captured ({c['status']})",
                "severity": "info",
                "evidence": f"title={c['title']!r} screenshot={c['screenshot']}",
                "module": "gowitness",
            })
        return findings
