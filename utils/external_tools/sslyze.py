"""sslyze adapter — TLS configuration audit.

Surfaces weak/legacy protocol support that ``modules/recon`` (which only reads
the negotiated protocol version) cannot. Parses sslyze's ``--json_out``
structured result and flags any accepted SSLv2/SSLv3/TLS 1.0/1.1 ciphers.

Requires the ``sslyze`` binary in PATH (https://github.com/nabla-c0d3/sslyze).
"""

from __future__ import annotations

import json
from typing import Any

from utils.external_tools.base import ExternalTool

# sslyze scan_result key -> (human label, severity)
_WEAK_PROTOCOLS = {
    "ssl_2_0_cipher_suites": ("SSLv2", "critical"),
    "ssl_3_0_cipher_suites": ("SSLv3", "high"),
    "tls_1_0_cipher_suites": ("TLS 1.0", "medium"),
    "tls_1_1_cipher_suites": ("TLS 1.1", "medium"),
}
_SEVERITY = {label: sev for label, sev in _WEAK_PROTOCOLS.values()}


class SslyzeTool(ExternalTool):
    binary = "sslyze"
    default_timeout = 300.0

    def get_command(
        self,
        target: str,
        *,
        extra_args: list[str] | None = None,
    ) -> list[str]:
        cmd = [self.binary, "--json_out=-", target]
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
        weak: list[str] = []
        start = stdout.find("{")
        end = stdout.rfind("}")
        if start >= 0 and end > start:
            try:
                data = json.loads(stdout[start:end + 1])
            except json.JSONDecodeError:
                data = {}
            for server in data.get("server_scan_results", []):
                scan = server.get("scan_result", {})
                for key, (label, _sev) in _WEAK_PROTOCOLS.items():
                    accepted = (
                        scan.get(key, {})
                        .get("result", {})
                        .get("accepted_cipher_suites", [])
                    )
                    if accepted and label not in weak:
                        weak.append(label)
        return {"weak_protocols": weak}

    def to_findings(self, parsed: Any, *, target: str = "") -> list[dict]:
        findings = []
        for label in (parsed or {}).get("weak_protocols", []):
            findings.append({
                "type": "Weak_TLS_Protocol",
                "url": target,
                "title": f"{label} enabled",
                "severity": _SEVERITY.get(label, "medium"),
                "evidence": f"Server accepts cipher suites over {label}",
                "module": "sslyze",
            })
        return findings
