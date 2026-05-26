"""CVSS / CWE / severity / remediation registry for known vuln types.

Maps vuln 'type' string → dict with severity, cvss, cwe, title, remediation.
Used by ``normalization.normalize_vuln`` to enrich legacy module dicts.
"""

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
    # ── Header → Exploit chain promotions ─────────────────────────────────
    "Clickjacking_Exploitable": {
        "severity": "medium",
        "cvss": 5.4,
        "cwe": "CWE-1021",
        "title": "Clickjacking Exploitable (Missing Frame Protection)",
        "remediation": "Send X-Frame-Options: DENY and CSP frame-ancestors 'none' on every HTML response.",
    },
    "HSTS_Downgrade_Exploitable": {
        "severity": "high",
        "cvss": 7.4,
        "cwe": "CWE-319",
        "title": "HSTS Downgrade / SSL Strip Exploitable",
        "remediation": "Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload and submit the domain to hstspreload.org.",
    },
    "MIME_Confusion_Exploitable": {
        "severity": "high",
        "cvss": 6.5,
        "cwe": "CWE-79",
        "title": "MIME Confusion Exploitable (No nosniff + User Content)",
        "remediation": "Send X-Content-Type-Options: nosniff and validate Content-Type for uploaded/user-controlled files.",
    },
    "Referrer_Leak_Exploitable": {
        "severity": "medium",
        "cvss": 4.3,
        "cwe": "CWE-200",
        "title": "Referrer Policy Leak Exploitable",
        "remediation": "Set Referrer-Policy: strict-origin-when-cross-origin (or no-referrer for sensitive flows).",
    },
    "Permissions_Policy_Abuse": {
        "severity": "medium",
        "cvss": 5.4,
        "cwe": "CWE-732",
        "title": "Permissions-Policy Abuse (Feature Access via 3rd-Party Frame)",
        "remediation": "Send Permissions-Policy that disables sensitive features (camera, microphone, geolocation, payment) site-wide and per-iframe via allow=.",
    },
}

# Default for unknown types.
#
# Findings that fall back here are kept at info/0.0 instead of being elevated
# to "medium / CVSS 5.0" — that elevation used to produce 19 spurious
# "Unknown Vulnerability" rows on the narinkaucuk.com.tr scan. They are also
# marked ``validation_stage="needs_triage"`` so report generators can route
# them into a separate triage queue instead of the main findings list.
_DEFAULT_VULN = {
    "severity": "info",
    "cvss": 0.0,
    "cwe": "CWE-0",
    "title": "Unclassified Observation",
    "remediation": "Triage manually — the scanner could not map this finding to a known vulnerability type.",
    "validation_stage": "needs_triage",
}
