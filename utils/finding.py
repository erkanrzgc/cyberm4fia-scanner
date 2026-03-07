"""
cyberm4fia-scanner — Finding Model & CVSS/CWE Registry

Provides:
  - Finding dataclass for standardized vulnerability representation
  - VULN_REGISTRY mapping every vuln type to severity, CVSS, CWE, description, remediation
  - normalize_vuln() to convert legacy dicts into Finding objects
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional


@dataclass
class Finding:
    """Standardized vulnerability finding."""

    title: str
    severity: str  # critical / high / medium / low / info
    cvss: float  # 0.0 - 10.0
    cwe: str  # CWE-79 etc.
    url: str
    module: str  # Which scanner module found it
    description: str = ""
    param: str = ""
    payload: str = ""
    evidence: str = ""
    remediation: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    # Extra fields for module-specific data
    context: Optional[str] = None
    source: Optional[str] = None
    exploit_data: Optional[dict] = None
    extra: Optional[dict] = None

    def to_dict(self) -> dict:
        """Convert to dict (JSON-serializable)."""
        d = asdict(self)
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
}

# Default for unknown types
_DEFAULT_VULN = {
    "severity": "medium",
    "cvss": 5.0,
    "cwe": "CWE-0",
    "title": "Unknown Vulnerability",
    "remediation": "Investigate and remediate based on the finding details.",
}


def normalize_vuln(vuln_dict: dict) -> Finding:
    """
    Convert a legacy vulnerability dict into a Finding object.
    Enriches it with CVSS, CWE, severity, and remediation from the registry.
    """
    vuln_type = vuln_dict.get("type", "Unknown")
    registry = VULN_REGISTRY.get(vuln_type, _DEFAULT_VULN)

    return Finding(
        title=registry["title"],
        severity=vuln_dict.get("severity", registry["severity"]).lower(),
        cvss=registry["cvss"],
        cwe=registry["cwe"],
        url=vuln_dict.get("url", ""),
        module=vuln_type,
        param=vuln_dict.get("param", ""),
        payload=vuln_dict.get("payload", ""),
        evidence=vuln_dict.get("evidence", ""),
        remediation=registry["remediation"],
        context=str(vuln_dict.get("context", "")) if vuln_dict.get("context") else None,
        source=vuln_dict.get("source"),
        exploit_data=vuln_dict.get("exploit_data"),
        extra={
            k: v
            for k, v in vuln_dict.items()
            if k
            not in (
                "type",
                "url",
                "param",
                "payload",
                "evidence",
                "severity",
                "context",
                "source",
                "exploit_data",
            )
        }
        or None,
    )


def deduplicate_findings(vuln_list: list) -> list:
    """Remove duplicate vulnerabilities (same type, payload, param) or deduplicate host-level findings."""
    seen = set()
    unique_vulns = []
    
    for vuln in vuln_list:
        vuln_type = vuln.get("type", "")
        url = vuln.get("url", "")
        param = vuln.get("param", "")
        payload = vuln.get("payload", "")
        evidence = vuln_dict.get("evidence", "") if 'vuln_dict' in locals() else vuln.get("evidence", "")
        
        from urllib.parse import urlparse
        host = urlparse(url).netloc
        
        # Site-wide issues only need to be reported once per host, 
        # so we strip the path/query parameters.
        if vuln_type in ["Missing_Security_Header", "Debug_Info", "Tech_Fingerprint", "CVE_Intel"]:
            sig = f"{vuln_type}::{host}::{evidence}"
        else:
            # For injection/XSS, we need exact URL, param, and payload to match
            sig = f"{vuln_type}::{url}::{param}::{payload}"
            
        if sig not in seen:
            seen.add(sig)
            unique_vulns.append(vuln)
            
    return unique_vulns


def normalize_all(vuln_list: list) -> list:
    """Convert a list of legacy vuln dicts to Finding objects."""
    return [normalize_vuln(v) for v in vuln_list]


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
