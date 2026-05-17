"""CVE / finding chaining — turn loose vulns into attack paths.

A single Medium-severity finding looks like noise on its own; the same
finding combined with two others can be a full account takeover. This
module walks the finding list looking for *known chains* and emits a
synthesised "attack path" finding when one is matched.

Chains are described declaratively (data files / Python list) rather
than coded — each chain says:

    {
      "name":     "SSRF → AWS IMDS → S3 takeover",
      "requires": ["SSRF", "AWS_Metadata_Reachable"],
      "implies":  ["IAM_Role_Exfiltrable", "S3_Bucket_Access"],
      "severity": "critical",
      "story":    "An attacker with SSRF reaches the EC2 metadata ...",
    }

The chain matcher is purely set-based so it's deterministic; an
optional LLM-augmented mode lets the model propose new chains from the
finding list (separate function, opt-in).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Optional


@dataclass(frozen=True)
class ChainRule:
    name: str
    requires: tuple[str, ...]
    implies: tuple[str, ...] = ()
    severity: str = "high"
    story: str = ""
    mitre_techniques: tuple[str, ...] = ()


# Built-in chain catalogue — well-known multi-step attacks worth
# surfacing to the operator without an LLM call.
DEFAULT_CHAINS: tuple[ChainRule, ...] = (
    ChainRule(
        name="SSRF → AWS IMDS → S3 takeover",
        requires=("SSRF",),
        implies=("Cloud_Metadata_Reachable", "IAM_Role_Exfiltrable"),
        severity="critical",
        story=(
            "SSRF on the application allows a request to "
            "169.254.169.254/latest/meta-data/iam/security-credentials/. "
            "If the EC2 role is over-permissive, the attacker obtains "
            "temporary AWS credentials and can pivot to any resource "
            "the role can reach (often S3 buckets in the same account)."
        ),
        mitre_techniques=("T1552.005", "T1199"),
    ),
    ChainRule(
        name="Subdomain takeover → cookie scope hijack",
        requires=("Subdomain_Takeover",),
        implies=("Session_Cookie_Compromise",),
        severity="critical",
        story=(
            "A dangling CNAME on *.target.com lets the attacker register "
            "the third-party service and serve content from the trusted "
            "domain. Cookies scoped to .target.com are now reachable, "
            "leaking session tokens via the attacker's subdomain."
        ),
        mitre_techniques=("T1583.001",),
    ),
    ChainRule(
        name="XSS → CSRF token theft → IDOR exploitation",
        requires=("XSS_Param", "IDOR"),
        severity="critical",
        story=(
            "Reflected XSS leaks the victim's CSRF token; the attacker "
            "then replays IDOR requests with the victim's session, "
            "reading or modifying data the victim owns."
        ),
        mitre_techniques=("T1059.007", "T1606.002"),
    ),
    ChainRule(
        name="JWT none-alg → token forge",
        requires=("JWT_None_Algorithm",),
        implies=("Auth_Bypass",),
        severity="critical",
        story=(
            "JWT verifier accepts ``alg=none``; attacker re-signs the "
            "token with sub=admin and gets unrestricted access."
        ),
        mitre_techniques=("T1078",),
    ),
    ChainRule(
        name="OAuth open-redirect → access token exfil",
        requires=("OAuth_Misconfiguration",),
        implies=("Access_Token_Theft",),
        severity="critical",
        story=(
            "A redirect_uri that accepts attacker-controlled hosts plus "
            "implicit-flow response_type returns access_token in the "
            "URL fragment to the attacker — full account takeover with "
            "no user interaction beyond clicking the malicious link."
        ),
        mitre_techniques=("T1606.001",),
    ),
    ChainRule(
        name="Exposed .git → source-code disclosure → secret extraction",
        requires=("Git_Repository_Exposed",),
        implies=("Source_Code_Disclosure", "Exposed_Secret"),
        severity="high",
        story=(
            ".git directory is publicly reachable. Attackers clone it, "
            "recover source code, and grep for hard-coded credentials, "
            "API keys, and internal infrastructure references."
        ),
        mitre_techniques=("T1213.003",),
    ),
    ChainRule(
        name="LFI → /proc/self/environ → RCE",
        requires=("LFI_Param",),
        implies=("Information_Disclosure",),
        severity="high",
        story=(
            "Local File Inclusion lets the attacker read /proc/self/environ "
            "or /proc/self/cmdline to recover application secrets and "
            "(via log poisoning or wrapper abuse) escalate to RCE."
        ),
        mitre_techniques=("T1083",),
    ),
    ChainRule(
        name="SQLi → cred dump → reuse on staging",
        requires=("SQLi_Param",),
        implies=("Credential_Disclosure",),
        severity="critical",
        story=(
            "SQL injection dumps the users table. The same credentials "
            "are likely reused across the org's staging / preprod "
            "subdomains discovered during recon."
        ),
        mitre_techniques=("T1190", "T1078.004"),
    ),
)


@dataclass
class AttackPath:
    name: str
    severity: str
    matched_findings: list[dict] = field(default_factory=list)
    story: str = ""
    mitre_techniques: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "type": "Attack_Path",
            "name": self.name,
            "severity": self.severity,
            "story": self.story,
            "mitre_techniques": list(self.mitre_techniques),
            "matched_finding_types": sorted({
                str(f.get("type") or "") for f in self.matched_findings
            }),
            "matched_finding_urls": sorted({
                str(f.get("url") or "") for f in self.matched_findings
                if f.get("url")
            }),
            "module": "cve_chain",
        }


def _types_in_findings(findings: Iterable[dict]) -> set[str]:
    return {str(f.get("type") or "") for f in findings}


def chain_findings(
    findings: list[dict],
    *,
    chains: Iterable[ChainRule] = DEFAULT_CHAINS,
) -> list[AttackPath]:
    """Match every chain whose ``requires`` set is a subset of present types."""
    present = _types_in_findings(findings)
    matched: list[AttackPath] = []

    for chain in chains:
        required = set(chain.requires)
        if not required.issubset(present):
            continue
        relevant = [
            f for f in findings if str(f.get("type")) in required
        ]
        matched.append(
            AttackPath(
                name=chain.name,
                severity=chain.severity,
                matched_findings=relevant,
                story=chain.story,
                mitre_techniques=chain.mitre_techniques,
            )
        )
    return matched


def chain_findings_to_dicts(
    findings: list[dict],
    *,
    chains: Iterable[ChainRule] = DEFAULT_CHAINS,
) -> list[dict]:
    """Convenience wrapper for the standard vuln-dict pipeline."""
    return [path.to_dict() for path in chain_findings(findings, chains=chains)]


# ── LLM-augmented chaining (opt-in) ────────────────────────────────────────


def _build_llm_prompt(findings: list[dict]) -> str:
    """Compact representation of findings for the LLM context budget."""
    rows = []
    for f in findings[:30]:
        rows.append(
            f"- type={f.get('type','?')} url={f.get('url','?')} "
            f"severity={f.get('severity','?')}"
        )
    return (
        "Given these scan findings, propose any plausible multi-step "
        "exploit chain (>=2 findings combined to escalate impact). "
        "Reply as a JSON array of objects:\n"
        '  {"name": "...", "requires": ["Type1","Type2"], '
        '"severity": "critical|high|medium", "story": "..."}\n'
        "Findings:\n" + "\n".join(rows)
    )


def chain_with_llm(
    findings: list[dict],
    *,
    ai_client: Any,
) -> list[AttackPath]:
    """Ask the LLM for additional chains beyond the built-in catalogue.

    The model output is parsed defensively — anything malformed yields
    no extra chains. Only paths whose ``requires`` set is *actually*
    satisfied by the findings are kept (we don't trust the model to
    follow that rule on its own).
    """
    if not ai_client or not getattr(ai_client, "available", False):
        return []

    try:
        raw = ai_client.generate(
            prompt=_build_llm_prompt(findings),
            system=(
                "You are a senior offensive-security operator. Be concrete; "
                "do not invent finding types that aren't in the input."
            ),
            temperature=0.4,
        )
    except Exception:  # noqa: BLE001
        return []

    import json
    import re
    match = re.search(r"\[[\s\S]*\]", raw or "")
    if not match:
        return []
    try:
        parsed = json.loads(match.group(0))
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []

    present = _types_in_findings(findings)
    proposals: list[ChainRule] = []
    for entry in parsed:
        if not isinstance(entry, dict):
            continue
        requires = tuple(
            str(x) for x in (entry.get("requires") or [])
            if isinstance(x, (str, int))
        )
        if not requires or not set(requires).issubset(present):
            continue
        proposals.append(
            ChainRule(
                name=str(entry.get("name", "LLM-proposed chain"))[:160],
                requires=requires,
                severity=str(entry.get("severity", "high")),
                story=str(entry.get("story", ""))[:1000],
            )
        )
    return chain_findings(findings, chains=proposals)
