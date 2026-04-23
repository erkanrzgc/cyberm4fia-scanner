"""
cyberm4fia-scanner — Finding Model & CVSS/CWE Registry

Provides:
  - Observation dataclass for raw scanner observations
  - Finding dataclass for standardized reasoned findings
  - AttackPath dataclass for inferred chaining opportunities
  - VULN_REGISTRY mapping every vuln type to severity, CVSS, CWE, description, remediation
  - normalize_vuln() / normalize_all() to convert legacy dicts into reasoned Finding objects
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
import hashlib
from typing import Optional
from urllib.parse import urlparse


@dataclass
class Observation:
    """Raw scanner observation before reasoning/verification enrichment."""

    id: str
    observation_type: str
    url: str
    module: str
    asset_id: str
    surface: str
    description: str = ""
    severity: str = "info"
    confidence: str = "low"
    evidence: str = ""
    param: str = ""
    payload: str = ""
    request: Optional[dict] = None
    response_snippet: Optional[str] = None
    repro_steps: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    raw: Optional[dict] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class AttackPath:
    """Inferred attack path derived from one or more findings."""

    id: str
    name: str
    severity: str
    description: str
    finding_refs: list[str] = field(default_factory=list)
    steps: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class Finding:
    """Standardized vulnerability finding."""

    title: str
    severity: str  # critical / high / medium / low / info
    cvss: float  # 0.0 - 10.0
    cwe: str  # CWE-79 etc.
    url: str
    module: str  # Which scanner module found it
    finding_type: str = ""
    description: str = ""
    param: str = ""
    payload: str = ""
    evidence: str = ""
    cve: str = ""
    component: str = ""
    version: str = ""
    confidence: str = "medium"
    remediation: str = ""
    id: str = ""
    asset_id: str = ""
    surface: str = "web"
    verification_state: str = "suspected"
    exploitability: str = "low"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    # Extra fields for module-specific data
    context: Optional[str] = None
    source: Optional[str] = None
    exploit_data: Optional[dict] = None
    repro_steps: Optional[list[str]] = None
    request: Optional[dict] = None
    response_snippet: Optional[str] = None
    evidence_items: Optional[list[dict]] = None
    preconditions: Optional[list[str]] = None
    replay_recipe: Optional[dict] = None
    observation_refs: Optional[list[str]] = None
    attack_path_refs: Optional[list[str]] = None
    extra: Optional[dict] = None

    # Validation pipeline fields (0-Day Machine hallucination gate system)
    validation_stage: str = "suspected"  # suspected → evidence_confirmed → verified → confirmed → exploitable
    validation_gates: Optional[dict] = None
    validation_history: Optional[list[dict]] = None
    promoted_at: str = ""
    demoted_at: str = ""
    demote_reason: str = ""

    def to_dict(self) -> dict:
        """Convert to dict (JSON-serializable)."""
        d = asdict(self)
        d["type"] = d.pop("finding_type") or self.module
        # Remove None values for cleaner output
        return {k: v for k, v in d.items() if v is not None}

    def to_sarif_result(self) -> dict:
        """Convert to SARIF result format."""
        return {
            "ruleId": self.cwe,
            "level": _sarif_level(self.severity),
            "message": {"text": self.title},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": self.url},
                    }
                }
            ],
            "properties": {
                "severity": self.severity,
                "cvss": self.cvss,
                "confidence": self.confidence,
                "param": self.param,
                "payload": self.payload,
            },
        }


def _sarif_level(severity: str) -> str:
    """Map severity to SARIF level."""
    return {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }.get(severity.lower(), "warning")


# ──────────────────────────────────────────────
#  CVSS / CWE Registry
# ──────────────────────────────────────────────
# Maps vuln 'type' string → (severity, cvss, cwe, title, remediation)

VULN_REGISTRY = {
    # OSV-Scanner / Software Composition Analysis
    "Known_Vulnerability_SCA": {
        "severity": "high",
        "cvss": 7.0,
        "cwe": "CWE-1035",
        "title": "Vulnerable Third-Party Component",
        "remediation": "Update the affected component to a secure version as recommended by the vendor.",
    },
    "Vulnerable_Dependency": {
        "severity": "high",
        "cvss": 7.0,
        "cwe": "CWE-1352",
        "title": "Exposed Vulnerable Dependency",
        "remediation": "Update the dependency in the manifest and ensure manifests are not exposed to the public.",
    },
    # XSS
    "XSS_Param": {
        "severity": "high",
        "cvss": 6.1,
        "cwe": "CWE-79",
        "title": "Reflected XSS (Parameter)",
        "remediation": "Sanitize user input and use Content-Security-Policy headers.",
    },
    "XSS_Form": {
        "severity": "high",
        "cvss": 6.1,
        "cwe": "CWE-79",
        "title": "Reflected XSS (Form)",
        "remediation": "Sanitize user input and use Content-Security-Policy headers.",
    },
    "Stored_XSS": {
        "severity": "critical",
        "cvss": 9.0,
        "cwe": "CWE-79",
        "title": "Stored XSS",
        "remediation": "Encode output and sanitize all user-supplied data before storage.",
    },
    "DOM_XSS": {
        "severity": "high",
        "cvss": 6.1,
        "cwe": "CWE-79",
        "title": "DOM-based XSS",
        "remediation": "Avoid using innerHTML/document.write with user-controlled data.",
    },
    # SQLi
    "SQLi_Param": {
        "severity": "critical",
        "cvss": 9.8,
        "cwe": "CWE-89",
        "title": "SQL Injection (Parameter)",
        "remediation": "Use parameterized queries / prepared statements.",
    },
    "SQLi_Form": {
        "severity": "critical",
        "cvss": 9.8,
        "cwe": "CWE-89",
        "title": "SQL Injection (Form)",
        "remediation": "Use parameterized queries / prepared statements.",
    },
    "Blind_SQLi_Param": {
        "severity": "critical",
        "cvss": 9.8,
        "cwe": "CWE-89",
        "title": "Blind SQL Injection (Parameter)",
        "remediation": "Use parameterized queries / prepared statements.",
    },
    "Blind_SQLi_Form": {
        "severity": "critical",
        "cvss": 9.8,
        "cwe": "CWE-89",
        "title": "Blind SQL Injection (Form)",
        "remediation": "Use parameterized queries / prepared statements.",
    },
    # LFI / RFI
    "LFI_Param": {
        "severity": "high",
        "cvss": 7.5,
        "cwe": "CWE-98",
        "title": "Local File Inclusion (Parameter)",
        "remediation": "Whitelist allowed files and avoid user-controlled file paths.",
    },
    "LFI_Form": {
        "severity": "high",
        "cvss": 7.5,
        "cwe": "CWE-98",
        "title": "Local File Inclusion (Form)",
        "remediation": "Whitelist allowed files and avoid user-controlled file paths.",
    },
    "RFI_Param": {
        "severity": "critical",
        "cvss": 9.8,
        "cwe": "CWE-98",
        "title": "Remote File Inclusion (Parameter)",
        "remediation": "Disable allow_url_include and whitelist file paths.",
    },
    "RFI_Form": {
        "severity": "critical",
        "cvss": 9.8,
        "cwe": "CWE-98",
        "title": "Remote File Inclusion (Form)",
        "remediation": "Disable allow_url_include and whitelist file paths.",
    },
    # CMDi
    "CMDi_Param": {
        "severity": "critical",
        "cvss": 9.8,
        "cwe": "CWE-78",
        "title": "OS Command Injection (Parameter)",
        "remediation": "Avoid passing user input to system commands. Use safe APIs.",
    },
    "CMDi_Form": {
        "severity": "critical",
        "cvss": 9.8,
        "cwe": "CWE-78",
        "title": "OS Command Injection (Form)",
        "remediation": "Avoid passing user input to system commands. Use safe APIs.",
    },
    "Blind_CMDi_Param": {
        "severity": "high",
        "cvss": 8.1,
        "cwe": "CWE-78",
        "title": "Blind Command Injection (Parameter)",
        "remediation": "Avoid passing user input to system commands. Use safe APIs.",
    },
    "Blind_CMDi_Form": {
        "severity": "high",
        "cvss": 8.1,
        "cwe": "CWE-78",
        "title": "Blind Command Injection (Form)",
        "remediation": "Avoid passing user input to system commands. Use safe APIs.",
    },
    # SSRF
    "SSRF_Param": {
        "severity": "high",
        "cvss": 7.5,
        "cwe": "CWE-918",
        "title": "SSRF (Parameter)",
        "remediation": "Validate and whitelist URLs. Block internal/private IP ranges.",
    },
    "SSRF_Form": {
        "severity": "high",
        "cvss": 7.5,
        "cwe": "CWE-918",
        "title": "SSRF (Form)",
        "remediation": "Validate and whitelist URLs. Block internal/private IP ranges.",
    },
    # SSTI
    "SSTI": {
        "severity": "critical",
        "cvss": 9.8,
        "cwe": "CWE-1336",
        "title": "Server-Side Template Injection",
        "remediation": "Use sandboxed template engines and avoid user input in templates.",
    },
    # XXE
    "XXE": {
        "severity": "critical",
        "cvss": 9.1,
        "cwe": "CWE-611",
        "title": "XML External Entity Injection",
        "remediation": "Disable external entity processing in XML parsers.",
    },
    "XXE-SSRF": {
        "severity": "critical",
        "cvss": 9.1,
        "cwe": "CWE-611",
        "title": "XXE with SSRF",
        "remediation": "Disable external entity processing and DTD loading.",
    },
    "XXE-XInclude": {
        "severity": "critical",
        "cvss": 9.1,
        "cwe": "CWE-611",
        "title": "XXE via XInclude",
        "remediation": "Disable XInclude processing in XML parsers.",
    },
    "XXE-Potential": {
        "severity": "medium",
        "cvss": 5.3,
        "cwe": "CWE-611",
        "title": "Potential XXE (XML Endpoint Detected)",
        "remediation": "Verify XML parser configuration disables external entities.",
    },
    # CORS
    "CORS_Misconfig": {
        "severity": "medium",
        "cvss": 5.3,
        "cwe": "CWE-942",
        "title": "CORS Misconfiguration",
        "remediation": "Set strict Access-Control-Allow-Origin. Avoid wildcard with credentials.",
    },
    # Header Injection
    "Header_Host_Inject": {
        "severity": "medium",
        "cvss": 5.3,
        "cwe": "CWE-113",
        "title": "Host Header Injection",
        "remediation": "Validate Host header and use a whitelist of allowed hostnames.",
    },
    "Header_Host_Redirect": {
        "severity": "medium",
        "cvss": 5.3,
        "cwe": "CWE-113",
        "title": "Host Header Redirect",
        "remediation": "Do not use Host header for redirects. Use a fixed base URL.",
    },
    "Header_IP_Spoof": {
        "severity": "low",
        "cvss": 3.7,
        "cwe": "CWE-290",
        "title": "IP Address Spoofing via Headers",
        "remediation": "Do not trust X-Forwarded-For for authentication/authorization.",
    },
    "Header_CRLF": {
        "severity": "medium",
        "cvss": 5.3,
        "cwe": "CWE-113",
        "title": "CRLF Injection (HTTP Response Splitting)",
        "remediation": "Strip CR/LF characters from user input in HTTP headers.",
    },
    # Open Redirect
    "Open Redirect": {
        "severity": "medium",
        "cvss": 4.7,
        "cwe": "CWE-601",
        "title": "Open Redirect",
        "remediation": "Validate redirect URLs against a whitelist of allowed domains.",
    },
    "Open Redirect (DOM)": {
        "severity": "medium",
        "cvss": 4.7,
        "cwe": "CWE-601",
        "title": "Open Redirect (DOM-based)",
        "remediation": "Validate redirect destinations in client-side JavaScript.",
    },
    # CSRF
    "CSRF": {
        "severity": "medium",
        "cvss": 4.3,
        "cwe": "CWE-352",
        "title": "Cross-Site Request Forgery",
        "remediation": "Implement anti-CSRF tokens and SameSite cookie attribute.",
    },
    # Cloud
    "Cloud_Open_Bucket": {
        "severity": "high",
        "cvss": 7.5,
        "cwe": "CWE-284",
        "title": "Open Cloud Storage Bucket",
        "remediation": "Restrict bucket access policies. Disable public listing.",
    },
    # Subdomain Takeover
    "Subdomain_Takeover": {
        "severity": "high",
        "cvss": 7.5,
        "cwe": "CWE-284",
        "title": "Subdomain Takeover",
        "remediation": "Remove dangling CNAME records or claim the subdomain.",
    },
    # API Security
    "API_BOLA": {
        "severity": "high",
        "cvss": 7.5,
        "cwe": "CWE-639",
        "title": "Broken Object Level Authorization",
        "remediation": "Implement proper authorization checks on every API endpoint.",
    },
    "API_Rate_Limit": {
        "severity": "medium",
        "cvss": 4.3,
        "cwe": "CWE-770",
        "title": "Missing API Rate Limiting",
        "remediation": "Implement rate limiting on all API endpoints.",
    },
    "API_Mass_Assignment": {
        "severity": "high",
        "cvss": 7.5,
        "cwe": "CWE-915",
        "title": "Mass Assignment",
        "remediation": "Whitelist allowed fields. Do not bind request body directly to models.",
    },
    "API_Verb_Tampering": {
        "severity": "medium",
        "cvss": 5.3,
        "cwe": "CWE-650",
        "title": "HTTP Verb Tampering",
        "remediation": "Restrict allowed HTTP methods per endpoint.",
    },
    "API_GraphQL_Introspection": {
        "severity": "low",
        "cvss": 3.7,
        "cwe": "CWE-200",
        "title": "GraphQL Introspection Enabled",
        "remediation": "Disable introspection in production environments.",
    },
    "API_Auth_Scheme": {
        "severity": "info",
        "cvss": 0.0,
        "cwe": "CWE-287",
        "title": "API Authentication Scheme Detected",
        "remediation": "Supply valid credentials matching the documented auth scheme before running authenticated API tests.",
    },
    "API_Unauth_Access": {
        "severity": "critical",
        "cvss": 9.1,
        "cwe": "CWE-306",
        "title": "Unauthenticated Access to Protected API Endpoint",
        "remediation": "Enforce authentication and authorization checks before returning protected API data.",
    },
    "API_BFLA": {
        "severity": "critical",
        "cvss": 9.1,
        "cwe": "CWE-285",
        "title": "Broken Function Level Authorization",
        "remediation": "Validate authorization for privileged API operations on every HTTP method.",
    },
    "API_Auth_Response_Diff": {
        "severity": "info",
        "cvss": 0.0,
        "cwe": "CWE-200",
        "title": "Protected API Response Diff Observed",
        "remediation": "Review whether unauthenticated and authenticated responses expose only the intended fields.",
    },
    # Race Condition
    "Race_Condition": {
        "severity": "high",
        "cvss": 7.5,
        "cwe": "CWE-362",
        "title": "Race Condition / TOCTOU",
        "remediation": "Use proper locking, transactions, or idempotency tokens.",
    },
    # Credential Spray
    "Default_Credentials": {
        "severity": "critical",
        "cvss": 9.8,
        "cwe": "CWE-798",
        "title": "Default Credentials Found",
        "remediation": "Change all default credentials immediately.",
    },
    # JWT
    "JWT_None_Alg": {
        "severity": "critical",
        "cvss": 9.8,
        "cwe": "CWE-347",
        "title": "JWT None Algorithm Accepted",
        "remediation": "Reject tokens with 'none' algorithm. Enforce strong algorithms.",
    },
    "JWT_Weak_Secret": {
        "severity": "high",
        "cvss": 7.5,
        "cwe": "CWE-326",
        "title": "JWT Weak Secret",
        "remediation": "Use a strong, random secret key for JWT signing.",
    },
    # Smuggling
    "HTTP_Smuggling": {
        "severity": "critical",
        "cvss": 9.8,
        "cwe": "CWE-444",
        "title": "HTTP Request Smuggling",
        "remediation": "Normalize request parsing. Use HTTP/2 end-to-end.",
    },
    # Prototype Pollution
    "Proto_Pollution": {
        "severity": "high",
        "cvss": 7.5,
        "cwe": "CWE-1321",
        "title": "Prototype Pollution",
        "remediation": "Validate object keys. Freeze Object.prototype.",
    },
    # Deserialization
    "Insecure_Deserialization": {
        "severity": "critical",
        "cvss": 9.8,
        "cwe": "CWE-502",
        "title": "Insecure Deserialization",
        "remediation": "Do not deserialize untrusted data. Use safe serialization formats.",
    },
    # Passive findings (for the new passive scanner)
    "Missing_Security_Header": {
        "severity": "info",
        "cvss": 0.0,
        "cwe": "CWE-693",
        "title": "Missing Security Header",
        "remediation": "Add the recommended security headers to HTTP responses.",
    },
    "Secret_Leak": {
        "severity": "high",
        "cvss": 7.5,
        "cwe": "CWE-200",
        "title": "Sensitive Information Exposure",
        "remediation": "Remove secrets from source code. Use environment variables.",
    },
    "Debug_Info": {
        "severity": "medium",
        "cvss": 5.3,
        "cwe": "CWE-215",
        "title": "Debug Information Exposed",
        "remediation": "Disable debug mode in production. Remove stack traces from responses.",
    },
    "Internal_IP_Leak": {
        "severity": "low",
        "cvss": 3.7,
        "cwe": "CWE-200",
        "title": "Internal IP Address Disclosure",
        "remediation": "Remove internal IP addresses from HTTP responses and headers.",
    },
    # CVE Threat Intelligence (SiberAdar Feed)
    "CVE_Intel": {
        "severity": "info",
        "cvss": 0.0,
        "cwe": "",
        "title": "CVE Threat Intelligence (SiberAdar)",
        "remediation": "Review CVE details and apply vendor patches.",
    },
    # CSP Bypass
    "CSP_Bypass": {
        "severity": "high",
        "cvss": 6.1,
        "cwe": "CWE-693",
        "title": "Content Security Policy Bypass",
        "remediation": "Remove 'unsafe-inline'/'unsafe-eval' from CSP. Use nonces or hashes. Restrict script-src to trusted domains only.",
    },
    # Cookie Security
    "Insecure_Cookie": {
        "severity": "medium",
        "cvss": 5.3,
        "cwe": "CWE-614",
        "title": "Insecure Cookie Configuration",
        "remediation": "Set Secure, HttpOnly, and SameSite flags on all cookies. Use narrow Domain/Path scopes.",
    },
    # HSTS
    "Weak_HSTS": {
        "severity": "medium",
        "cvss": 4.3,
        "cwe": "CWE-319",
        "title": "Weak HSTS Configuration",
        "remediation": "Set Strict-Transport-Security with max-age>=31536000, includeSubDomains, and preload.",
    },
}

# Default for unknown types
_DEFAULT_VULN = {
    "severity": "medium",
    "cvss": 5.0,
    "cwe": "CWE-0",
    "title": "Unknown Vulnerability",
    "remediation": "Investigate and remediate based on the finding details.",
}


def _truncate_text(value, limit=280):
    text = str(value or "").strip()
    if not text:
        return None
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _extract_request_details(vuln_dict):
    request = vuln_dict.get("request")
    if isinstance(request, dict):
        return request

    request_fields = {
        "method": vuln_dict.get("request_method"),
        "headers": vuln_dict.get("request_headers"),
        "body": vuln_dict.get("request_body"),
    }
    request_fields = {
        key: value
        for key, value in request_fields.items()
        if value not in (None, "", {}, [])
    }
    return request_fields or None


def _extract_response_snippet(vuln_dict):
    return _truncate_text(
        vuln_dict.get("response_snippet")
        or vuln_dict.get("response")
        or vuln_dict.get("body_preview")
    )


def _coerce_repro_steps(vuln_dict):
    repro_steps = vuln_dict.get("repro_steps")
    if isinstance(repro_steps, list):
        return [str(step) for step in repro_steps if str(step).strip()] or None
    if isinstance(repro_steps, str) and repro_steps.strip():
        return [repro_steps.strip()]

    steps = []
    url = vuln_dict.get("url")
    if url:
        steps.append(f"Request {url}")
    param = vuln_dict.get("param")
    payload = vuln_dict.get("payload")
    if param and payload:
        steps.append(f"Set parameter '{param}' to '{payload}'")
    elif param:
        steps.append(f"Inspect parameter '{param}'")
    return steps or None


def compute_confidence_score(vuln_dict):
    """
    Compute a 0-100 confidence score for a vulnerability finding.
    
    Scoring criteria:
    - Payload reflection in response:  +30
    - Expected status code:            +20
    - Evidence string match:           +25
    - Exploit data / PoC proof:        +25
    - Timing-only (blind):             -15
    - WAF bypass technique used:       +10
    - Multiple confirmation vectors:   +10
    """
    score = 0

    payload = str(vuln_dict.get("payload", ""))
    evidence = str(vuln_dict.get("evidence", "")).lower()
    response = str(vuln_dict.get("response_snippet", "") or vuln_dict.get("response", ""))
    vuln_type = str(vuln_dict.get("type", "")).lower()
    description = str(vuln_dict.get("description", "")).lower()

    # 1. Payload reflected in response (+30)
    if payload and response and payload in response:
        score += 30
    elif payload and evidence and payload.lower() in evidence:
        score += 25

    # 2. Status code indicates success (+20)
    status = vuln_dict.get("status_code") or vuln_dict.get("response_code")
    if status:
        status = int(status) if str(status).isdigit() else 0
        if status in (200, 500, 302):
            score += 20
        elif status in (403, 406, 503):
            score -= 10  # WAF block indicators

    # 3. Evidence string present (+25)
    if evidence and len(evidence) > 10:
        score += 25
    elif evidence:
        score += 10

    # 4. Exploit data / PoC present (+25)
    if vuln_dict.get("exploit_data"):
        score += 25

    # 5. Confirmed / verified keywords (+15)
    if "confirmed" in evidence or "confirmed" in description:
        score += 15
    elif "verified" in evidence or "verified" in description:
        score += 10

    # 6. Timing-only detection penalty (-15)
    if "blind" in vuln_type or "time" in vuln_type:
        if not vuln_dict.get("exploit_data") and "confirmed" not in evidence:
            score -= 15

    # 7. WAF bypass bonus (+10)
    if vuln_dict.get("waf_bypassed") or "waf" in description:
        score += 10

    # 8. Multiple evidence items (+10)
    if vuln_dict.get("response_snippet") and vuln_dict.get("evidence"):
        score += 10

    # Clamp to 0-100
    return max(0, min(100, score))


def _score_to_confidence(score):
    """Map a 0-100 confidence score to a label."""
    if score >= 80:
        return "confirmed"
    elif score >= 60:
        return "high"
    elif score >= 40:
        return "medium"
    return "low"


def _infer_confidence(vuln_dict, severity):
    """Infer confidence level using smart scoring."""
    explicit = vuln_dict.get("confidence")
    if explicit and str(explicit).lower() in ("confirmed", "high", "medium", "low"):
        return str(explicit).lower()

    score = compute_confidence_score(vuln_dict)

    # Severity-based floor: critical/high vulns get at least medium
    if score < 40 and severity in {"critical", "high"}:
        score = max(score, 40)

    return _score_to_confidence(score)



def _stable_id(prefix, *parts):
    raw = "::".join(str(part or "") for part in parts)
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}_{digest}"


def _build_asset_id(url):
    parsed = urlparse(url or "")
    host = parsed.netloc or parsed.path or "unknown"
    return _stable_id("asset", host)


def _infer_surface(vuln_dict):
    vuln_type = str(vuln_dict.get("type", "")).lower()
    url = str(vuln_dict.get("url", "")).lower()

    if vuln_type.startswith("api_") or "/api/" in url:
        return "api"
    if any(
        token in vuln_type for token in ("cloud", "takeover", "bucket", "subdomain")
    ):
        return "infrastructure"
    if any(token in vuln_type for token in ("header", "cors", "csrf")):
        return "http"
    return "web"


def _coerce_evidence_items(vuln_dict):
    items = []
    evidence = str(vuln_dict.get("evidence", "")).strip()
    if evidence:
        items.append({"kind": "evidence", "value": evidence})

    response_snippet = _extract_response_snippet(vuln_dict)
    if response_snippet:
        items.append({"kind": "response_snippet", "value": response_snippet})

    request = _extract_request_details(vuln_dict)
    if request:
        items.append({"kind": "request", "value": request})

    exploit_data = vuln_dict.get("exploit_data")
    if exploit_data:
        items.append({"kind": "exploit_data", "value": exploit_data})

    return items or None


def _infer_verification_state(vuln_dict, confidence):
    if vuln_dict.get("verification_state"):
        return str(vuln_dict["verification_state"]).lower()
    if vuln_dict.get("exploit_data"):
        return "exploitable"
    if confidence in {"confirmed", "high"}:
        return "verified"
    return "suspected"


def _infer_exploitability(vuln_dict, severity, verification_state):
    explicit = vuln_dict.get("exploitability")
    if explicit:
        return str(explicit).lower()
    if vuln_dict.get("exploit_data") or verification_state == "exploitable":
        return "high"
    if severity in {"critical", "high"} and verification_state == "verified":
        return "medium"
    if severity in {"critical", "high"}:
        return "medium"
    return "low"


def _build_replay_recipe(vuln_dict, request_details, repro_steps):
    if vuln_dict.get("replay_recipe"):
        return vuln_dict["replay_recipe"]

    url = vuln_dict.get("url", "")
    if not url:
        return None

    recipe = {
        "method": (request_details or {}).get("method")
        or vuln_dict.get("method")
        or vuln_dict.get("request_method")
        or "GET",
        "url": url,
        "steps": repro_steps or [],
    }
    if vuln_dict.get("param"):
        recipe["param"] = vuln_dict["param"]
    if vuln_dict.get("payload"):
        recipe["payload"] = vuln_dict["payload"]
    return recipe


def observation_from_vuln(vuln_dict: dict) -> Observation:
    """Adapt a legacy module result into a raw observation."""
    vuln_type = vuln_dict.get("type", "Unknown")
    registry = VULN_REGISTRY.get(vuln_type, _DEFAULT_VULN)
    severity = str(vuln_dict.get("severity", registry["severity"])).lower()
    confidence = _infer_confidence(vuln_dict, severity)
    url = vuln_dict.get("url", "")
    request_details = _extract_request_details(vuln_dict)
    repro_steps = _coerce_repro_steps(vuln_dict)
    response_snippet = _extract_response_snippet(vuln_dict)

    return Observation(
        id=_stable_id(
            "obs",
            vuln_type,
            url,
            vuln_dict.get("param"),
            vuln_dict.get("payload"),
            vuln_dict.get("evidence"),
        ),
        observation_type=vuln_type,
        url=url,
        module=vuln_type,
        asset_id=_build_asset_id(url),
        surface=_infer_surface(vuln_dict),
        description=vuln_dict.get("description", registry["title"]),
        severity=severity,
        confidence=confidence,
        evidence=str(vuln_dict.get("evidence", "")),
        param=vuln_dict.get("param", ""),
        payload=vuln_dict.get("payload", ""),
        request=request_details,
        response_snippet=response_snippet,
        repro_steps=repro_steps,
        tags=[vuln_type.lower(), _infer_surface(vuln_dict)],
        raw=dict(vuln_dict),
    )


def normalize_vuln(vuln_dict: dict) -> Finding:
    """
    Convert a legacy vulnerability dict into a Finding object.
    Enriches it with CVSS, CWE, severity, and remediation from the registry.
    """
    observation = observation_from_vuln(vuln_dict)
    raw = observation.raw or vuln_dict
    vuln_type = observation.observation_type
    registry = VULN_REGISTRY.get(vuln_type, _DEFAULT_VULN)
    severity = observation.severity
    evidence_items = _coerce_evidence_items(raw)
    verification_state = _infer_verification_state(raw, observation.confidence)
    replay_recipe = _build_replay_recipe(
        raw, observation.request, observation.repro_steps
    )

    return Finding(
        title=registry["title"],
        severity=severity,
        cvss=registry["cvss"],
        cwe=registry["cwe"],
        url=observation.url,
        module=vuln_type,
        finding_type=vuln_type,
        description=raw.get("description", registry["title"]),
        param=raw.get("param", ""),
        payload=raw.get("payload", ""),
        evidence=raw.get("evidence", ""),
        cve=raw.get("cve", ""),
        component=raw.get("component", ""),
        version=raw.get("version", ""),
        confidence=observation.confidence,
        remediation=registry["remediation"],
        id=_stable_id(
            "finding",
            vuln_type,
            observation.url,
            raw.get("param"),
            raw.get("payload"),
            raw.get("evidence"),
        ),
        asset_id=observation.asset_id,
        surface=observation.surface,
        verification_state=verification_state,
        exploitability=_infer_exploitability(raw, severity, verification_state),
        context=str(raw.get("context", "")) if raw.get("context") else None,
        source=raw.get("source"),
        exploit_data=raw.get("exploit_data"),
        repro_steps=observation.repro_steps,
        request=observation.request,
        response_snippet=observation.response_snippet,
        evidence_items=evidence_items,
        preconditions=raw.get("preconditions") or None,
        replay_recipe=replay_recipe,
        observation_refs=[observation.id],
        attack_path_refs=list(raw.get("attack_path_refs", []) or []) or None,
        extra={
            k: v
            for k, v in raw.items()
            if k
            not in (
                "type",
                "url",
                "description",
                "param",
                "payload",
                "evidence",
                "cve",
                "component",
                "version",
                "severity",
                "confidence",
                "context",
                "source",
                "exploit_data",
                "repro_steps",
                "request",
                "request_method",
                "request_headers",
                "request_body",
                "response",
                "response_snippet",
                "body_preview",
                "preconditions",
                "replay_recipe",
                "verification_state",
                "exploitability",
                "attack_path_refs",
            )
        }
        or None,
    )


def deduplicate_findings(vuln_list: list) -> list:
    """Remove duplicate vulnerabilities (same type, payload, param) or deduplicate host-level findings."""
    seen = set()
    unique_vulns = []

    for vuln in vuln_list:
        if isinstance(vuln, Finding):
            vuln = vuln.to_dict()
        vuln_type = vuln.get("type", "")
        url = vuln.get("url", "")
        param = vuln.get("param", "")
        payload = vuln.get("payload", "")
        evidence = vuln.get("evidence", "")

        from urllib.parse import urlparse

        host = urlparse(url).netloc

        # Site-wide issues only need to be reported once per host,
        # so we strip the path/query parameters.
        if vuln_type in [
            "Missing_Security_Header",
            "Debug_Info",
            "Tech_Fingerprint",
            "CVE_Intel",
        ]:
            sig = f"{vuln_type}::{host}::{evidence}"
        else:
            # For injection/XSS, we need exact URL, param, and payload to match
            sig = f"{vuln_type}::{url}::{param}::{payload}"

        if sig not in seen:
            seen.add(sig)
            unique_vulns.append(vuln)

    return unique_vulns


def _normalize_with_observations(
    vuln_list: list,
) -> tuple[list[Observation], list[Finding]]:
    """Normalize legacy results while preserving their raw observation layer."""
    observations = []
    normalized = []
    for vuln in vuln_list:
        if isinstance(vuln, Finding):
            normalized.append(vuln)
            observation_refs = vuln.observation_refs or [
                _stable_id(
                    "obs", vuln.finding_type or vuln.module, vuln.url, vuln.param
                )
            ]
            observations.append(
                Observation(
                    id=observation_refs[0],
                    observation_type=vuln.finding_type or vuln.module,
                    url=vuln.url,
                    module=vuln.module,
                    asset_id=vuln.asset_id or _build_asset_id(vuln.url),
                    surface=vuln.surface or "web",
                    description=vuln.description,
                    severity=vuln.severity,
                    confidence=vuln.confidence,
                    evidence=vuln.evidence,
                    param=vuln.param,
                    payload=vuln.payload,
                    request=vuln.request,
                    response_snippet=vuln.response_snippet,
                    repro_steps=vuln.repro_steps,
                    raw=vuln.to_dict(),
                )
            )
        elif isinstance(vuln, Observation):
            observations.append(vuln)
            normalized.append(normalize_vuln(vuln.raw or vuln.to_dict()))
        else:
            observation = observation_from_vuln(vuln)
            observations.append(observation)
            normalized.append(normalize_vuln(vuln))

    return observations, normalized


def normalize_all(vuln_list: list) -> list:
    """Convert a list of legacy vuln dicts to Finding objects."""
    _, normalized = _normalize_with_observations(vuln_list)
    return normalized


def build_scan_artifacts(vuln_list: list) -> dict:
    """Build observations, reasoned findings, and inferred attack paths."""
    observations, normalized = _normalize_with_observations(vuln_list)

    attack_paths = build_attack_paths(normalized)
    return {
        "observations": observations,
        "findings": normalized,
        "attack_paths": attack_paths,
    }


def build_attack_paths(findings: list[Finding]) -> list[AttackPath]:
    """Infer attack paths from reasoned findings and attach path refs back to findings."""
    if not findings:
        return []

    from utils.vuln_chain import analyze_chains

    chain_inputs = [finding.to_dict() for finding in findings]
    raw_paths = analyze_chains(chain_inputs)
    if not raw_paths:
        return []

    attack_paths = []
    for raw_path in raw_paths:
        path_id = _stable_id(
            "path",
            raw_path.get("chain"),
            raw_path.get("source_vuln"),
            raw_path.get("source_url"),
        )
        finding_refs = []
        source_vuln = raw_path.get("source_vuln")
        source_url = raw_path.get("source_url")
        for finding in findings:
            if (
                finding.finding_type or finding.module
            ) == source_vuln and finding.url == source_url:
                finding_refs.append(finding.id)
                refs = list(finding.attack_path_refs or [])
                if path_id not in refs:
                    refs.append(path_id)
                    finding.attack_path_refs = refs
                    if finding.verification_state == "verified":
                        finding.verification_state = "chained"
                break

        attack_paths.append(
            AttackPath(
                id=path_id,
                name=raw_path.get("chain", raw_path.get("escalation", "Attack Path")),
                severity=str(raw_path.get("severity", "medium")).lower(),
                description=raw_path.get("description", ""),
                finding_refs=finding_refs,
                steps=raw_path.get("steps") or [raw_path],
            )
        )

    return attack_paths


def generate_sarif(findings: list, tool_name: str = "cyberm4fia-scanner") -> dict:
    """Generate a SARIF 2.1.0 report from a list of Finding objects."""
    # Collect unique rules
    rules = {}
    results = []
    for f in findings:
        if f.cwe not in rules:
            rules[f.cwe] = {
                "id": f.cwe,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{f.cwe.split('-')[1]}.html"
                if "-" in f.cwe
                else "",
                "properties": {"cvss": f.cvss, "severity": f.severity},
            }
        results.append(f.to_sarif_result())

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "informationUri": "https://github.com/erkanrzgc/cyberm4fia-scanner",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
