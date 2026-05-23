"""smbmap adapter — SMB share/permission enumeration.

Fills a previously-zero gap in this scanner: SMB/CIFS surface analysis on
Windows/AD-joined hosts. Parses smbmap's human-readable table output, which
is stable across versions, into structured share + permission tuples.

Requires the ``smbmap`` binary in PATH (https://github.com/ShawnDEvans/smbmap).
"""

from __future__ import annotations

import re
from typing import Any

from utils.external_tools.base import ExternalTool

# smbmap permission -> finding severity (NO ACCESS rows are not findings at all)
_PERMISSION_SEVERITY = {
    "READ, WRITE": "high",
    "WRITE ONLY": "high",
    "READ ONLY": "medium",
}

# Match: "<share-name>   <PERMISSION>" — permission is one of the known phrases.
_SHARE_LINE = re.compile(
    r"^\s+(\S+)\s+(NO ACCESS|READ ONLY|READ, WRITE|WRITE ONLY)\s*$"
)


class SmbmapTool(ExternalTool):
    binary = "smbmap"
    default_timeout = 300.0

    def get_command(
        self,
        target: str,
        *,
        username: str = "",
        password: str = "",
        extra_args: list[str] | None = None,
    ) -> list[str]:
        cmd = [self.binary, "-H", target]
        if username:
            cmd.extend(["-u", username])
            cmd.extend(["-p", password or ""])
        else:
            # Null/anonymous session — smbmap's default when -u is empty.
            cmd.extend(["-u", "", "-p", ""])
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
        shares: list[dict] = []
        for line in stdout.splitlines():
            m = _SHARE_LINE.match(line)
            if not m:
                continue
            shares.append({"share": m.group(1), "permission": m.group(2)})
        return {"shares": shares, "count": len(shares)}

    def to_findings(self, parsed: Any, *, target: str = "") -> list[dict]:
        findings = []
        for s in (parsed or {}).get("shares", []):
            perm = s.get("permission", "")
            severity = _PERMISSION_SEVERITY.get(perm)
            if not severity:
                continue   # NO ACCESS / unknown — not a finding
            findings.append({
                "type": "SMB_Accessible_Share",
                "url": target,
                "title": f"SMB share '{s['share']}' is {perm}",
                "severity": severity,
                "evidence": f"share={s['share']} permission={perm}",
                "module": "smbmap",
            })
        return findings
