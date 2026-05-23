"""CloudHunter adapter — multi-cloud bucket discovery (AWS / GCP / Azure).

Strengthens the hand-rolled ``modules/cloud_enum`` with a tool that probes
three cloud providers at once and reports permissive ACLs. CloudHunter's
output is human-readable; we parse the canonical ``[FOUND]`` lines and treat
publicly-readable buckets as high-severity findings.

Requires the ``cloudhunter`` binary in PATH (https://github.com/belane/CloudHunter).
Output schema can vary between forks — this parser is defensive and best-effort.
"""

from __future__ import annotations

import re
from typing import Any

from utils.external_tools.base import ExternalTool

# Matches: "[FOUND] aws example-prod (public-read)"
_FOUND_LINE = re.compile(
    r"\[FOUND\]\s+(?P<cloud>\w+)\s+(?P<name>\S+)\s*\((?P<acl>[^)]+)\)",
    re.IGNORECASE,
)

# ACL keywords that mark a bucket as publicly accessible.
_PUBLIC_MARKERS = ("public", "world", "anyone", "allusers")


def _is_public(acl: str) -> bool:
    acl_lower = acl.lower()
    return any(marker in acl_lower for marker in _PUBLIC_MARKERS)


class CloudHunterTool(ExternalTool):
    binary = "cloudhunter"
    default_timeout = 600.0

    def get_command(
        self,
        target: str,
        *,
        extra_args: list[str] | None = None,
    ) -> list[str]:
        cmd = [self.binary, target]
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
        buckets: list[dict] = []
        for line in stdout.splitlines():
            m = _FOUND_LINE.search(line)
            if not m:
                continue
            buckets.append({
                "cloud": m.group("cloud").lower(),
                "name": m.group("name"),
                "acl": m.group("acl").strip(),
            })
        return {"buckets": buckets, "count": len(buckets)}

    def to_findings(self, parsed: Any, *, target: str = "") -> list[dict]:
        findings = []
        for b in (parsed or {}).get("buckets", []):
            public = _is_public(b.get("acl", ""))
            findings.append({
                "type": "Cloud_Bucket_Public" if public else "Cloud_Bucket_Discovered",
                "url": target,
                "title": f"{b['cloud'].upper()} bucket {b['name']} ({b['acl']})",
                "severity": "high" if public else "info",
                "evidence": f"cloud={b['cloud']} name={b['name']} acl={b['acl']}",
                "module": "cloudhunter",
            })
        return findings
