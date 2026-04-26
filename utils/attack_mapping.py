"""
cyberm4fia-scanner — MITRE ATT&CK Technique Mapping for Findings

Inspired by Azure-Sentinel detection rules: every vulnerability finding gets
tagged with the MITRE ATT&CK techniques it enables, so report consumers
(blue teams, customers, auditors) can pivot from "what we found" to "what an
attacker would do with it" using the standard ATT&CK matrix.

Coverage
--------
This is a curated subset of MITRE ATT&CK Enterprise v14 — only techniques
actually relevant to the vuln_types this scanner produces. Adding a new
mapping is one line; adding a new technique to the catalog is a one-row dict.

Usage
-----
    from utils.attack_mapping import techniques_for_vuln, tag_finding_dict

    techniques_for_vuln("XSS_Param")
    # → [TechniqueRef(id="T1059.007", name="JavaScript", tactic="Execution"), ...]

    tag_finding_dict({"type": "SQLi_Param", "url": "..."})
    # adds an "attack_techniques" key with the technique IDs and tactics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


# ─── Catalog of techniques we reference ──────────────────────────────────────


@dataclass(frozen=True)
class TechniqueRef:
    id: str                 # MITRE ATT&CK ID, e.g. "T1190"
    name: str               # short human-readable name
    tactic: str             # primary kill-chain tactic
    url: str = ""           # link to attack.mitre.org page

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "tactic": self.tactic,
            "url": self.url or f"https://attack.mitre.org/techniques/{self.id.replace('.', '/')}/",
        }


# Single source of truth — every entry referenced anywhere below must live here.
TECHNIQUE_CATALOG: dict[str, TechniqueRef] = {
    "T1190": TechniqueRef("T1190", "Exploit Public-Facing Application", "Initial Access"),
    "T1133": TechniqueRef("T1133", "External Remote Services", "Initial Access"),
    "T1059": TechniqueRef("T1059", "Command and Scripting Interpreter", "Execution"),
    "T1059.007": TechniqueRef("T1059.007", "JavaScript", "Execution"),
    "T1059.006": TechniqueRef("T1059.006", "Python", "Execution"),
    "T1059.004": TechniqueRef("T1059.004", "Unix Shell", "Execution"),
    "T1059.003": TechniqueRef("T1059.003", "Windows Command Shell", "Execution"),
    "T1505.003": TechniqueRef("T1505.003", "Web Shell", "Persistence"),
    "T1078": TechniqueRef("T1078", "Valid Accounts", "Defense Evasion"),
    "T1110": TechniqueRef("T1110", "Brute Force", "Credential Access"),
    "T1110.001": TechniqueRef("T1110.001", "Password Guessing", "Credential Access"),
    "T1110.003": TechniqueRef("T1110.003", "Password Spraying", "Credential Access"),
    "T1212": TechniqueRef("T1212", "Exploitation for Credential Access", "Credential Access"),
    "T1083": TechniqueRef("T1083", "File and Directory Discovery", "Discovery"),
    "T1046": TechniqueRef("T1046", "Network Service Discovery", "Discovery"),
    "T1018": TechniqueRef("T1018", "Remote System Discovery", "Discovery"),
    "T1213": TechniqueRef("T1213", "Data from Information Repositories", "Collection"),
    "T1213.003": TechniqueRef("T1213.003", "Code Repositories", "Collection"),
    "T1552": TechniqueRef("T1552", "Unsecured Credentials", "Credential Access"),
    "T1552.001": TechniqueRef("T1552.001", "Credentials In Files", "Credential Access"),
    "T1539": TechniqueRef("T1539", "Steal Web Session Cookie", "Credential Access"),
    "T1557": TechniqueRef("T1557", "Adversary-in-the-Middle", "Credential Access"),
    "T1185": TechniqueRef("T1185", "Browser Session Hijacking", "Collection"),
    "T1556": TechniqueRef("T1556", "Modify Authentication Process", "Credential Access"),
    "T1602": TechniqueRef("T1602", "Data from Configuration Repository", "Collection"),
    "T1565": TechniqueRef("T1565", "Data Manipulation", "Impact"),
    "T1499": TechniqueRef("T1499", "Endpoint Denial of Service", "Impact"),
    "T1090": TechniqueRef("T1090", "Proxy", "Command and Control"),
    "T1071.001": TechniqueRef("T1071.001", "Web Protocols", "Command and Control"),
    "T1071.004": TechniqueRef("T1071.004", "DNS", "Command and Control"),
    "T1583.001": TechniqueRef("T1583.001", "Domains (Acquire Infrastructure)", "Resource Development"),
    "T1566.002": TechniqueRef("T1566.002", "Spearphishing Link", "Initial Access"),
    "T1566.003": TechniqueRef("T1566.003", "Spearphishing via Service", "Initial Access"),
    "T1611": TechniqueRef("T1611", "Escape to Host (Container)", "Privilege Escalation"),
    "T1574": TechniqueRef("T1574", "Hijack Execution Flow", "Privilege Escalation"),
}


# ─── Vuln type → techniques ──────────────────────────────────────────────────


# Map every vuln_type the scanner emits to one or more ATT&CK technique IDs.
# Lookup is case-insensitive; missing types fall back to T1190.
_VULN_TO_TECHNIQUES: dict[str, tuple[str, ...]] = {
    # ── XSS family ──
    "XSS": ("T1190", "T1059.007", "T1539", "T1185"),
    "XSS_Param": ("T1190", "T1059.007", "T1539", "T1185"),
    "XSS_Form": ("T1190", "T1059.007", "T1539", "T1185"),
    "Stored_XSS": ("T1190", "T1059.007", "T1539", "T1185"),
    "DOM_XSS": ("T1190", "T1059.007", "T1539"),
    # ── Injection family ──
    "SQLi": ("T1190", "T1213", "T1078"),
    "SQLi_Param": ("T1190", "T1213", "T1078"),
    "SQLi_Form": ("T1190", "T1213", "T1078"),
    "Blind_SQLi_Param": ("T1190", "T1213"),
    "Blind_SQLi_Form": ("T1190", "T1213"),
    "CMDi": ("T1190", "T1059", "T1059.004", "T1059.003"),
    "Command_Injection": ("T1190", "T1059", "T1059.004", "T1059.003"),
    "SSTI": ("T1190", "T1059", "T1505.003"),
    "Header_Injection": ("T1190",),
    "API_Inject": ("T1190", "T1213"),
    # ── File / path ──
    "LFI": ("T1190", "T1083", "T1552.001"),
    "LFI_Param": ("T1190", "T1083", "T1552.001"),
    "LFI_Form": ("T1190", "T1083", "T1552.001"),
    "RFI": ("T1190", "T1059", "T1505.003"),
    "Path_Traversal": ("T1190", "T1083", "T1552.001"),
    "File_Upload": ("T1190", "T1505.003"),
    # ── XXE / Deserialization ──
    "XXE": ("T1190", "T1213", "T1083"),
    "Deserialization": ("T1190", "T1059"),
    # ── Server-side request / SSRF ──
    "SSRF": ("T1190", "T1090", "T1018", "T1602"),
    # ── Auth & access ──
    "Auth_Bypass": ("T1190", "T1078", "T1556"),
    "Brute_Force": ("T1110", "T1110.001"),
    "Password_Spray": ("T1110", "T1110.003"),
    "JWT_Vuln": ("T1190", "T1078", "T1212"),
    "IDOR": ("T1190", "T1078", "T1213"),
    "Account_Takeover": ("T1078", "T1556", "T1539"),
    # ── CSRF / cookie / transport ──
    "CSRF": ("T1190", "T1185"),
    "Open_Redirect": ("T1566.002", "T1190"),
    "Insecure_Cookie": ("T1539", "T1185"),
    "Weak_HSTS": ("T1557",),
    "CSP_Bypass": ("T1190", "T1059.007"),
    "CORS": ("T1190", "T1213"),
    # ── Recon / disclosure ──
    "Subdomain_Takeover": ("T1583.001", "T1133"),
    "Email_Harvest": ("T1213",),
    "Cloud_Enum": ("T1018", "T1602"),
    "Header_IP_Spoof": ("T1078",),
    "Forbidden_Bypass": ("T1078",),
    # ── Brand / phishing ──
    "Typosquatting": ("T1583.001", "T1566.002"),
    "Brand_Impersonation": ("T1583.001", "T1566.003"),
    "QR_Phishing": ("T1566.002",),
    # ── DoS / API ──
    "Rate_Limit_Bypass": ("T1499",),
    "API_Spec_Drift": ("T1190",),
    # ── Container / RCE ──
    "Container_Escape": ("T1611",),
    "RCE": ("T1190", "T1059", "T1505.003"),
}


# ─── Public API ──────────────────────────────────────────────────────────────


def techniques_for_vuln(vuln_type: str) -> list[TechniqueRef]:
    """Return the ATT&CK techniques relevant to a given vuln_type.

    Lookup is case-insensitive on the family root (e.g. "xss_param" → XSS_Param).
    Unknown types fall back to T1190 (Exploit Public-Facing Application).
    """
    if not vuln_type:
        return [TECHNIQUE_CATALOG["T1190"]]
    key = _normalize_key(vuln_type)
    ids = _VULN_TO_TECHNIQUES.get(key) or _fuzzy_lookup(key) or ("T1190",)
    return [TECHNIQUE_CATALOG[tid] for tid in ids if tid in TECHNIQUE_CATALOG]


def tactics_for_vuln(vuln_type: str) -> list[str]:
    """Distinct tactic names hit by a vuln_type, in catalog order."""
    seen: list[str] = []
    for tech in techniques_for_vuln(vuln_type):
        if tech.tactic not in seen:
            seen.append(tech.tactic)
    return seen


def tag_finding_dict(finding: dict, *, type_field: str = "type") -> dict:
    """Return a *new* dict with `attack_techniques` and `attack_tactics` keys
    derived from the finding's vuln type. Original dict is not mutated."""
    if not isinstance(finding, dict):
        return finding
    vuln_type = str(finding.get(type_field) or finding.get("finding_type") or "")
    techs = techniques_for_vuln(vuln_type)
    out = dict(finding)
    out["attack_techniques"] = [t.to_dict() for t in techs]
    out["attack_tactics"] = list({t.tactic for t in techs})
    return out


def tag_findings(findings: Iterable[dict], *, type_field: str = "type") -> list[dict]:
    """Tag a list of finding dicts in one call."""
    return [tag_finding_dict(f, type_field=type_field) for f in findings]


def all_known_vuln_types() -> list[str]:
    """Vuln types we have explicit ATT&CK mappings for. Useful for tests."""
    return sorted(_VULN_TO_TECHNIQUES.keys())


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _normalize_key(vuln_type: str) -> str:
    """Match the literal registry key first (case-sensitive original layout)
    falling back to a normalized version."""
    if vuln_type in _VULN_TO_TECHNIQUES:
        return vuln_type
    # Case-insensitive direct match
    for key in _VULN_TO_TECHNIQUES:
        if key.lower() == vuln_type.lower():
            return key
    return vuln_type


def _fuzzy_lookup(vuln_type: str) -> tuple[str, ...] | None:
    """Match by family root if the exact key wasn't found.
    e.g. 'XSS_Stored_New' → falls back to 'XSS' family."""
    lower = vuln_type.lower()
    for family in ("xss", "sqli", "lfi", "rfi", "ssrf", "ssti", "xxe",
                   "cmdi", "command", "deserial", "auth", "csrf", "idor",
                   "open_redirect", "redirect", "brute", "spray", "jwt",
                   "subdomain", "rce"):
        if family in lower:
            for key, val in _VULN_TO_TECHNIQUES.items():
                if family in key.lower():
                    return val
    return None
