"""Anti-shallow depth tracker — enforces minimum probe + bypass-level coverage."""

from __future__ import annotations

from dataclasses import dataclass, field

from ._constants import (
    BROWSER_REQUIRED_MODULES,
    MIN_PROBES_PER_CLASS,
    WAF_BYPASS_LEVELS,
    WAF_SENSITIVE_MODULES,
)


@dataclass
class ModuleDepth:
    """Tracks exploration depth for a single vulnerability class module."""
    module_id: str
    probes_sent: int = 0
    bypass_levels_attempted: set = field(default_factory=set)
    last_result: str = ""
    exhaustion_status: str = "active"   # active, exhausted, blocked
    blocker_reason: str = ""
    waf_detected: bool = False
    browser_used: bool = False

    def meets_min_probes(self) -> bool:
        required = MIN_PROBES_PER_CLASS.get(self.module_id, 5)
        return self.probes_sent >= required

    def all_bypass_levels_attempted(self) -> bool:
        return len(self.bypass_levels_attempted) >= len(WAF_BYPASS_LEVELS)

    def is_exhausted(self) -> bool:
        if self.exhaustion_status == "exhausted":
            return True
        if self.meets_min_probes() and self.all_bypass_levels_attempted() and self.blocker_reason:
            self.exhaustion_status = "exhausted"
            return True
        return False

    def record_blocker(self, reason: str):
        self.blocker_reason = reason
        self.exhaustion_status = "blocked"


class DepthTracker:
    """Enforces anti-shallow exploration: no module returns 'not vulnerable'
    without meeting minimum probe counts and attempting all bypass levels."""

    def __init__(self):
        self.modules: dict[str, ModuleDepth] = {}

    def get_or_create(self, module_id: str) -> ModuleDepth:
        if module_id not in self.modules:
            self.modules[module_id] = ModuleDepth(module_id=module_id)
        return self.modules[module_id]

    def record_probe(self, module_id: str, count: int = 1):
        md = self.get_or_create(module_id)
        md.probes_sent += count

    def record_bypass_level(self, module_id: str, level: int):
        md = self.get_or_create(module_id)
        md.bypass_levels_attempted.add(level)

    def record_browser_use(self, module_id: str):
        md = self.get_or_create(module_id)
        md.browser_used = True

    def check_anti_shallow(self, module_id: str, result) -> tuple[bool, str]:
        """Returns (can_declare_done: bool, reason: str)."""
        md = self.get_or_create(module_id)

        has_findings = False
        if isinstance(result, list):
            has_findings = len(result) > 0
        elif isinstance(result, dict) and result.get("error") is None:
            has_findings = True

        if has_findings:
            return True, ""

        required_probes = MIN_PROBES_PER_CLASS.get(module_id, 5)
        if md.probes_sent < required_probes:
            return False, (
                f"Anti-shallow: {module_id} has 0 findings but only "
                f"{md.probes_sent}/{required_probes} minimum probes sent. "
                f"Run {required_probes - md.probes_sent} more probes before declaring done."
            )

        if module_id in BROWSER_REQUIRED_MODULES and not md.browser_used:
            return False, (
                f"Anti-shallow: {module_id} requires a browser probe before "
                f"declaring 'not vulnerable'. curl results from CDN-based targets "
                f"are not valid 'not vulnerable' verdicts."
            )

        if module_id in WAF_SENSITIVE_MODULES and not md.all_bypass_levels_attempted():
            remaining_levels = set(WAF_BYPASS_LEVELS.keys()) - md.bypass_levels_attempted
            return False, (
                f"Anti-shallow: {module_id} has not attempted "
                f"WAF bypass levels: {sorted(remaining_levels)}. "
                f"WAF block is not a valid dead-end verdict."
            )

        return True, ""

    def exhaustion_summary(self) -> dict:
        summary = {}
        for mod_id, md in self.modules.items():
            summary[mod_id] = {
                "probes": md.probes_sent,
                "bypass_levels": sorted(md.bypass_levels_attempted),
                "browser_used": md.browser_used,
                "status": md.exhaustion_status,
                "blocker": md.blocker_reason,
            }
        return summary

    def enforce_waf_bypass_decision(self, module_id: str, waf_detected: bool):
        """If WAF is detected, mark module as needing full bypass ladder."""
        md = self.get_or_create(module_id)
        md.waf_detected = waf_detected

    def is_chainable(self, vuln_type: str) -> bool:
        """Check if a vulnerability type is chainable to higher impact."""
        chainable_primitives = {
            "ssrf", "xss", "sqli", "lfi", "xxe", "idor", "ssti",
            "open_redirect", "file_upload", "jwt", "subdomain_takeover",
            "command_injection", "deserialization", "proto_pollution",
        }
        return vuln_type.lower() in chainable_primitives

    def get_chain_candidates(self, vuln_type: str) -> list[str]:
        """Given a vulnerability type, return list of escalation targets."""
        chain_map = {
            "ssrf": ["cloud_metadata", "internal_access", "auth_bypass"],
            "xss": ["session_hijack", "account_takeover", "data_theft"],
            "sqli": ["data_exfil", "rce", "auth_bypass"],
            "lfi": ["source_disclosure", "rce", "credential_theft"],
            "xxe": ["ssrf", "credential_theft", "data_exfil"],
            "idor": ["ato", "data_breach", "account_manipulation"],
            "ssti": ["rce", "data_exfil", "internal_access"],
            "open_redirect": ["oauth_theft", "phishing"],
            "file_upload": ["rce", "xss", "app_takeover"],
            "jwt": ["auth_bypass", "session_hijack", "ato"],
            "subdomain_takeover": ["phishing", "cookie_theft", "ato"],
            "command_injection": ["rce", "reverse_shell", "data_exfil"],
            "deserialization": ["rce", "data_exfil"],
            "proto_pollution": ["rce", "xss", "data_exfil"],
        }
        return chain_map.get(vuln_type.lower(), [])
