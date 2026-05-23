"""masscan adapter — fast asynchronous network port scanning.

Complements the scanner's built-in socket scanner (``modules/recon``) with
masscan's internet-scale speed. Uses list output (``-oL -``) to stdout, which
parses far more reliably than masscan's quirky JSON.

Requires the ``masscan`` binary in PATH (https://github.com/robertdavidgraham/masscan).
Note: masscan typically needs root/CAP_NET_RAW for raw-socket scanning.
"""

from __future__ import annotations

from typing import Any

from utils.external_tools.base import ExternalTool

_DEFAULT_PORTS = "1-1000"
_DEFAULT_RATE = 1000


class MasscanTool(ExternalTool):
    binary = "masscan"
    default_timeout = 600.0

    def get_command(
        self,
        target: str,
        *,
        ports: str = _DEFAULT_PORTS,
        rate: int = _DEFAULT_RATE,
        extra_args: list[str] | None = None,
    ) -> list[str]:
        cmd = [
            self.binary, target,
            "-p", str(ports),
            "--rate", str(rate),
            "-oL", "-",          # list format to stdout
        ]
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
        open_ports: list[dict[str, Any]] = []
        for raw in stdout.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # masscan list line: "open tcp 443 192.0.2.1 1620000000"
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "open":
                port = int(parts[2]) if parts[2].isdigit() else parts[2]
                open_ports.append({
                    "status": parts[0],
                    "proto": parts[1],
                    "port": port,
                    "ip": parts[3],
                })
        return {"open_ports": open_ports, "count": len(open_ports)}
