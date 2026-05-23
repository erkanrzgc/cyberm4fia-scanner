"""arjun adapter — HTTP parameter discovery.

Finds hidden GET/POST parameters that the scanner's injection modules
(sqli/xss/idor) can then target. Complements the hand-rolled
``modules/param_discovery`` with arjun's wordlist-driven heuristics.

Requires the ``arjun`` binary in PATH (https://github.com/s0md3v/Arjun).
"""

from __future__ import annotations

import json
import re
from typing import Any

from utils.external_tools.base import ExternalTool


class ArjunTool(ExternalTool):
    binary = "arjun"
    default_timeout = 300.0

    def get_command(
        self,
        target: str,
        *,
        method: str = "GET",
        extra_args: list[str] | None = None,
    ) -> list[str]:
        cmd = [
            self.binary,
            "-u", target,
            "-m", method,
            "-oJ", "/dev/stdout",
        ]
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
        # arjun emits {"<endpoint>": ["p1", "p2", ...]}; logs may precede it.
        match = re.search(r"\{.*\}", stdout, re.DOTALL)
        params: dict[str, list[str]] = {}
        if match:
            try:
                data = json.loads(match.group(0))
                if isinstance(data, dict):
                    params = {
                        str(k): [str(p) for p in v]
                        for k, v in data.items()
                        if isinstance(v, list)
                    }
            except json.JSONDecodeError:
                pass
        count = sum(len(v) for v in params.values())
        return {"params": params, "count": count}

    def to_findings(self, parsed: Any, *, target: str = "") -> list[dict]:
        findings = []
        for endpoint, names in (parsed or {}).get("params", {}).items():
            if not names:
                continue
            findings.append({
                "type": "Discovered_Parameters",
                "url": endpoint,
                "title": f"{len(names)} hidden parameter(s) discovered",
                "severity": "info",
                "evidence": ", ".join(names),
                "module": "arjun",
            })
        return findings
