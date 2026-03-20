"""
cyberm4fia-scanner - Vulnerability Chaining Engine
Analyzes scan findings and builds potential attack paths
"""

from utils.colors import log_info, log_success, log_warning
from utils.request import ScanExceptions

# ─────────────────────────────────────────────────────
# Chain Rules: how vuln A can escalate to vuln B
# ─────────────────────────────────────────────────────
CHAIN_RULES = [
    {
        "from": "SSRF",
        "to": "Cloud Metadata Access",
        "condition": lambda v: (
            "169.254" in v.get("payload", "")
            or "metadata" in v.get("payload", "").lower()
        ),
        "description": "SSRF can reach cloud metadata (169.254.169.254) to steal IAM credentials",
        "severity": "CRITICAL",
    },
    {
        "from": "SSRF",
        "to": "Internal Port Scan",
        "condition": lambda v: True,
        "description": "SSRF allows scanning internal network ports (127.0.0.1, 10.x, 192.168.x)",
        "severity": "HIGH",
    },
    {
        "from": "SSRF",
        "to": "SQLi (Internal)",
        "condition": lambda v: True,
        "description": "SSRF → access internal DB admin panels (phpMyAdmin, Adminer) → SQLi",
        "severity": "CRITICAL",
    },
    {
        "from": "SQLi",
        "to": "Data Exfiltration",
        "condition": lambda v: (
            "union" in v.get("payload", "").lower()
            or "blind" in v.get("type", "").lower()
        ),
        "description": "SQL Injection can dump entire database (users, passwords, PII)",
        "severity": "CRITICAL",
    },
    {
        "from": "SQLi",
        "to": "Remote Code Execution",
        "condition": lambda v: True,
        "description": "SQLi → INTO OUTFILE / xp_cmdshell → RCE on database server",
        "severity": "CRITICAL",
    },
    {
        "from": "Command Injection",
        "to": "Remote Code Execution",
        "condition": lambda v: True,
        "description": "Command Injection directly gives OS-level command execution",
        "severity": "CRITICAL",
    },
    {
        "from": "Command Injection",
        "to": "Reverse Shell",
        "condition": lambda v: True,
        "description": "CMDi → spawn reverse shell → full server access",
        "severity": "CRITICAL",
    },
    {
        "from": "LFI",
        "to": "Source Code Disclosure",
        "condition": lambda v: True,
        "description": "LFI can read application source code, config files, credentials",
        "severity": "HIGH",
    },
    {
        "from": "LFI",
        "to": "Remote Code Execution",
        "condition": lambda v: (
            "log" in v.get("payload", "").lower()
            or "proc" in v.get("payload", "").lower()
        ),
        "description": "LFI → Log Poisoning → RCE (inject PHP into access.log, include via LFI)",
        "severity": "CRITICAL",
    },
    {
        "from": "LFI",
        "to": "Credential Theft",
        "condition": lambda v: (
            "passwd" in v.get("payload", "") or "shadow" in v.get("payload", "")
        ),
        "description": "LFI reads /etc/passwd or /etc/shadow → offline password cracking",
        "severity": "CRITICAL",
    },
    {
        "from": "XSS",
        "to": "Session Hijacking",
        "condition": lambda v: True,
        "description": "XSS → steal session cookies → impersonate users/admins",
        "severity": "HIGH",
    },
    {
        "from": "XSS",
        "to": "Account Takeover",
        "condition": lambda v: "stored" in v.get("type", "").lower(),
        "description": "Stored XSS → automatic credential theft from every visitor",
        "severity": "CRITICAL",
    },
    {
        "from": "SSTI",
        "to": "Remote Code Execution",
        "condition": lambda v: True,
        "description": "SSTI (Jinja2/Twig) → direct OS command execution via template sandbox escape",
        "severity": "CRITICAL",
    },
    {
        "from": "XXE",
        "to": "SSRF",
        "condition": lambda v: True,
        "description": "XXE → SSRF via external entity fetching internal URLs",
        "severity": "HIGH",
    },
    {
        "from": "XXE",
        "to": "Credential Theft",
        "condition": lambda v: True,
        "description": "XXE → read /etc/passwd, config files, AWS credentials",
        "severity": "CRITICAL",
    },
    {
        "from": "Open Redirect",
        "to": "OAuth Token Theft",
        "condition": lambda v: (
            "oauth" in v.get("url", "").lower()
            or "callback" in v.get("url", "").lower()
        ),
        "description": "Open Redirect in OAuth flow → steal authorization code/token",
        "severity": "HIGH",
    },
    {
        "from": "Open Redirect",
        "to": "Phishing",
        "condition": lambda v: True,
        "description": "Open Redirect → redirect users to attacker-controlled phishing page",
        "severity": "MEDIUM",
    },
    {
        "from": "Default Credentials",
        "to": "Full System Access",
        "condition": lambda v: v.get("service", "").lower() in ("ssh", "rdp"),
        "description": "Default SSH/RDP credentials → full OS-level access",
        "severity": "CRITICAL",
    },
    {
        "from": "Default Credentials",
        "to": "Data Exfiltration",
        "condition": lambda v: (
            v.get("service", "").lower() in ("mysql", "postgresql", "mongodb", "redis")
        ),
        "description": "Default DB credentials → dump all data",
        "severity": "CRITICAL",
    },
    {
        "from": "cloud_bucket",
        "to": "Data Breach",
        "condition": lambda v: v.get("access") in ("PUBLIC_LIST", "PUBLIC_WRITE"),
        "description": "Open cloud bucket → access/modify stored data (PII, backups, configs)",
        "severity": "CRITICAL",
    },
    {
        "from": "subdomain_takeover",
        "to": "Phishing / Cookie Theft",
        "condition": lambda v: True,
        "description": "Subdomain takeover → host malicious content on trusted domain → steal cookies",
        "severity": "HIGH",
    },
]

def analyze_chains(vulnerabilities):
    """
    Analyze a list of vulnerabilities and find potential attack chains.
    Returns a list of attack paths.
    """
    if not vulnerabilities:
        return []

    log_info(f"Analyzing {len(vulnerabilities)} finding(s) for attack chains...")

    chains = []
    vuln_types = set()

    for vuln in vulnerabilities:
        vtype = vuln.get("type", "Unknown")
        vuln_types.add(vtype)

    for vuln in vulnerabilities:
        vtype = vuln.get("type", "Unknown")

        for rule in CHAIN_RULES:
            # Match vulnerability type to chain rule
            if rule["from"].lower() in vtype.lower():
                try:
                    if rule["condition"](vuln):
                        chain = {
                            "source_vuln": vtype,
                            "source_url": vuln.get("url", "N/A"),
                            "source_payload": vuln.get("payload", "N/A"),
                            "escalation": rule["to"],
                            "description": rule["description"],
                            "severity": rule["severity"],
                            "chain": f"{vtype} → {rule['to']}",
                        }
                        chains.append(chain)
                except ScanExceptions:
                    pass

    # Build multi-step chains
    multi_chains = []
    for c1 in chains:
        for c2 in chains:
            if c1["escalation"].lower() in c2["source_vuln"].lower() and c1 != c2:
                multi_chain = {
                    "chain": f"{c1['source_vuln']} → {c1['escalation']} → {c2['escalation']}",
                    "severity": "CRITICAL",
                    "description": f"{c1['description']} THEN {c2['description']}",
                    "steps": [c1, c2],
                }
                multi_chains.append(multi_chain)

    chains.extend(multi_chains)

    # Display
    if chains:
        log_success(f"Found {len(chains)} potential attack chain(s):")
        seen = set()
        for chain in chains:
            chain_str = chain["chain"]
            if chain_str not in seen:
                seen.add(chain_str)
                severity = chain["severity"]
                if severity == "CRITICAL":
                    log_warning(f"  🔴 [{severity}] {chain_str}")
                elif severity == "HIGH":
                    log_warning(f"  🟠 [{severity}] {chain_str}")
                else:
                    log_info(f"  🟡 [{severity}] {chain_str}")
                log_info(f"     └─ {chain['description']}")

    # ── AI-Powered Chain Discovery ──
    try:
        from utils.ai_exploit_agent import get_chain_detector
        detector = get_chain_detector()
        if (
            detector.client
            and getattr(detector.client, "available", False)
            and hasattr(detector.client, "generate")
        ):
            ai_chains = detector.detect_chains(vulnerabilities)
            if ai_chains:
                log_success(f"🤖 AI discovered {len(ai_chains)} additional attack chain(s):")
                for ac in ai_chains:
                    chain_name = ac.get("chain_name", "Unknown")
                    sev = ac.get("severity", "High")
                    desc = ac.get("description", "")
                    log_warning(f"  🔴 [{sev}] {chain_name}")
                    if desc:
                        log_info(f"     └─ {desc}")
                    chains.append({
                        "chain": chain_name,
                        "severity": sev,
                        "description": desc,
                        "ai_discovered": True,
                    })
    except ImportError:
        pass

    if not chains:
        log_info("No attack chains identified.")

    return chains
