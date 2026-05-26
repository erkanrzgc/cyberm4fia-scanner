"""Audit which scanner modules properly carry the authenticated session.

Two sources of "session loss" exist in the codebase:

1. Modules that import ``httpx`` / ``requests`` directly instead of going
   through ``utils.request.smart_request`` — they bypass cookie/header
   propagation, proxy config, WAF calibration, and rate-limiting.
2. Modules that *do* use ``smart_request`` but don't pass any custom
   ``headers=`` / ``cookies=`` — fine for unauthenticated scans, but means
   the module won't see authenticated-only surface area.

This module produces an audit report (not a finding) consumed by the
scanner's startup banner so the operator knows which modules will / won't
see the post-login pages.

Run standalone:

    python3 -m modules.auth_session_audit
"""

from __future__ import annotations

import ast
import logging
import os
from dataclasses import dataclass, field
from typing import Iterable

logger = logging.getLogger(__name__)

_MODULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules"
)

# Async-only modules that legitimately need raw httpx for concurrent
# request loops — these are exempt from the "must use smart_request" rule
# provided they accept a caller-supplied client / headers parameter.
_RAW_HTTPX_EXEMPT = {
    "endpoint_fuzzer",   # async fuzzer; reads get_global_headers()
    "race_condition",    # concurrent burst, accepts headers via get_global_headers
    "subdomain_enum",    # DNS + parallel HTTPS probes
}


@dataclass(frozen=True)
class ModuleAuditEntry:
    """How a single module relates to the authenticated session."""

    module: str
    uses_smart_request: bool
    uses_raw_http: bool
    reads_global_headers: bool
    exempt: bool

    @property
    def session_aware(self) -> bool:
        """True if the module will see the authenticated session."""
        if self.uses_smart_request:
            return True
        if self.uses_raw_http and self.reads_global_headers:
            return True
        return False

    @property
    def status(self) -> str:
        if self.session_aware:
            return "ok"
        if self.exempt:
            return "exempt"
        return "gap"


@dataclass
class AuthSessionAudit:
    """Aggregated audit result across the modules/ directory."""

    entries: list[ModuleAuditEntry] = field(default_factory=list)

    @property
    def gaps(self) -> list[ModuleAuditEntry]:
        return [e for e in self.entries if e.status == "gap"]

    @property
    def session_aware(self) -> list[ModuleAuditEntry]:
        return [e for e in self.entries if e.status == "ok"]

    def to_dict(self) -> dict:
        return {
            "total": len(self.entries),
            "session_aware": len(self.session_aware),
            "exempt": len([e for e in self.entries if e.status == "exempt"]),
            "gaps": len(self.gaps),
            "gap_modules": sorted(e.module for e in self.gaps),
        }


def _scan_module(path: str) -> ModuleAuditEntry | None:
    name = os.path.basename(path)[:-3]
    if name.startswith("_") or name == "header_exploit_map":
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
    except OSError:
        return None
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    uses_smart = False
    uses_raw_http = False
    reads_global_headers = False

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod == "utils.request":
                for n in node.names:
                    if n.name == "smart_request":
                        uses_smart = True
                    if n.name == "get_global_headers":
                        reads_global_headers = True
        if isinstance(node, ast.Import):
            for n in node.names:
                if n.name in {"httpx", "requests", "aiohttp"}:
                    uses_raw_http = True
        if isinstance(node, ast.Attribute):
            # heuristic: catches `httpx.get`, `requests.post`, …
            if isinstance(node.value, ast.Name) and node.value.id in {
                "httpx", "requests", "aiohttp"
            }:
                uses_raw_http = True
        if isinstance(node, ast.Name) and node.id == "smart_request":
            uses_smart = True
        if isinstance(node, ast.Name) and node.id == "get_global_headers":
            reads_global_headers = True

    return ModuleAuditEntry(
        module=name,
        uses_smart_request=uses_smart,
        uses_raw_http=uses_raw_http,
        reads_global_headers=reads_global_headers,
        exempt=name in _RAW_HTTPX_EXEMPT,
    )


def audit_modules(modules_dir: str = _MODULES_DIR) -> AuthSessionAudit:
    """Walk the modules/ directory and audit every .py file."""
    audit = AuthSessionAudit()
    for entry in sorted(os.listdir(modules_dir)):
        if not entry.endswith(".py") or entry == "__init__.py":
            continue
        full = os.path.join(modules_dir, entry)
        if not os.path.isfile(full):
            continue
        rec = _scan_module(full)
        if rec is None:
            continue
        # Only audit modules that actually do network I/O.
        if not (rec.uses_smart_request or rec.uses_raw_http):
            continue
        audit.entries.append(rec)
    return audit


def format_audit_banner(audit: AuthSessionAudit) -> str:
    """Short text banner suitable for the scanner startup log."""
    if not audit.entries:
        return "auth-session-audit: no network-capable modules detected"
    lines = [
        f"auth-session-audit: {len(audit.session_aware)}/"
        f"{len(audit.entries)} modules will carry the authenticated session"
    ]
    if audit.gaps:
        names = ", ".join(e.module for e in audit.gaps)
        lines.append(f"  ⚠ {len(audit.gaps)} gap module(s): {names}")
        lines.append(
            "    (these use raw httpx/requests without get_global_headers — "
            "they will scan as unauthenticated even when --session is in effect)"
        )
    return "\n".join(lines)


def main() -> int:
    """CLI entrypoint — prints the audit report and exits."""
    audit = audit_modules()
    print(format_audit_banner(audit))
    print("\n=== Full table ===")
    print(f"{'module':<32} {'smart':<6} {'raw':<6} {'globalH':<8} {'status':<8}")
    for e in audit.entries:
        print(
            f"{e.module:<32} {str(e.uses_smart_request):<6} "
            f"{str(e.uses_raw_http):<6} {str(e.reads_global_headers):<8} {e.status:<8}"
        )
    return 0 if not audit.gaps else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
