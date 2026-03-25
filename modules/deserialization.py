"""
cyberm4fia-scanner - Insecure Deserialization Scanner
Detects serialized objects in cookies/responses and tests for exploitation.
Targets: PHP (unserialize), Java (ObjectInputStream), Python (pickle), .NET.
"""

import re
import base64

from utils.colors import log_info, log_success, log_warning
from utils.request import smart_request
from utils.request import ScanExceptions

# ─────────────────────────────────────────────────────
# Serialization Signatures
# ─────────────────────────────────────────────────────
SIGNATURES = {
    "php": {
        "patterns": [
            r'[OaCis]:\d+:[\{"]',  # O:4:"User":1:{ ... }
            r"a:\d+:\{",  # a:2:{s:4:"name" ...
            r's:\d+:"[^"]+";',  # s:5:"hello";
        ],
        "magic_bytes": [],
        "description": "PHP serialized object (unserialize)",
        "risk": "RCE via __wakeup, __destruct gadget chains",
    },
    "java": {
        "patterns": [
            r"rO0AB",  # Base64 of Java serialized (0xACED0005)
            r"\\xac\\xed\\x00\\x05",  # Raw hex
        ],
        "magic_bytes": [b"\xac\xed\x00\x05"],
        "description": "Java serialized object (ObjectInputStream)",
        "risk": "RCE via Commons Collections, Spring, etc.",
    },
    "dotnet": {
        "patterns": [
            r"AAEAAAD/",  # Base64 of .NET BinaryFormatter
            r"TypeObject",
            r"ObjectStateFormatter",
            r"__VIEWSTATE",
        ],
        "magic_bytes": [b"\x00\x01\x00\x00\x00"],
        "description": ".NET serialized object (BinaryFormatter/ViewState)",
        "risk": "RCE via ObjectDataProvider, TypeConfuseDelegate",
    },
    "python_pickle": {
        "patterns": [
            r"gASV",  # Base64 of pickle protocol 4
            r"\\x80\\x04\\x95",  # Raw pickle v4
            r"cos\nsystem",  # Older pickle RCE
        ],
        "magic_bytes": [b"\x80\x04\x95", b"\x80\x03"],
        "description": "Python pickle object",
        "risk": "RCE via os.system, subprocess",
    },
    "yaml": {
        "patterns": [
            r"!!python/object",
            r"!!python/object/apply",
            r"!!ruby/object",
        ],
        "magic_bytes": [],
        "description": "YAML deserialization (unsafe load)",
        "risk": "RCE via !!python/object:os.system",
    },
}

# Exploitation payloads (safe probes — not destructive)
PROBE_PAYLOADS = {
    "php": [
        # PHP serialized object that triggers __toString
        'O:8:"stdClass":1:{s:4:"test";s:10:"cyberm4fia";}',
        # Broken serialization to trigger error
        'O:9:"CYBERM4FI":0:{}',
        # Type juggling
        'a:1:{s:4:"role";s:5:"admin";}',
    ],
    "java": [
        # ysoserial-style detection (URLDNS — safe, makes DNS lookup)
        # We send a known bad Java serialized object to see if it's processed
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAABAAAAAAdA",
    ],
    "dotnet": [
        # Trigger ViewState deserializer
        "/wEPDwULLTE2MTY2MzM5MDlkZA==",
    ],
}

# Common cookie/header names that carry serialized data
SERIALIZED_PARAMS = [
    "session",
    "token",
    "data",
    "state",
    "viewstate",
    "__VIEWSTATE",
    "__EVENTVALIDATION",
    "user",
    "auth",
    "object",
    "serialized",
    "payload",
    "config",
    "prefs",
]

def _decode_value(value):
    """Try to decode a value that might be base64-encoded serialized data."""
    raw = value
    # Try base64 decode
    try:
        decoded = base64.b64decode(value + "==")
        return decoded, raw
    except ScanExceptions:
        pass
    # Try URL-decoded base64
    try:
        import urllib.parse

        unquoted = urllib.parse.unquote(value)
        decoded = base64.b64decode(unquoted + "==")
        return decoded, raw
    except ScanExceptions:
        pass
    return value.encode() if isinstance(value, str) else value, raw

def _detect_serialization(text, source="response"):
    """Detect serialized objects in text using signatures."""
    findings = []

    for lang, sig_data in SIGNATURES.items():
        for pattern in sig_data["patterns"]:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                findings.append(
                    {
                        "type": "Insecure Deserialization",
                        "language": lang,
                        "source": source,
                        "pattern": pattern,
                        "match": matches[0][:100] if matches[0] else "",
                        "description": sig_data["description"],
                        "risk": sig_data["risk"],
                        "severity": "HIGH",
                    }
                )
                break  # One match per language is enough

    return findings

def _scan_cookies(url, delay=0):
    """Scan cookies for serialized objects."""
    findings = []

    try:
        resp = smart_request("get", url, delay=delay, timeout=10)

        # Check Set-Cookie headers
        for header_name, header_value in resp.headers.items():
            if header_name.lower() == "set-cookie":
                # Extract cookie value
                parts = header_value.split(";")[0].split("=", 1)
                if len(parts) == 2:
                    cookie_name, cookie_value = parts
                    # Check raw value
                    raw_findings = _detect_serialization(
                        cookie_value, f"Cookie: {cookie_name}"
                    )
                    findings.extend(raw_findings)

                    # Check decoded value
                    decoded, _ = _decode_value(cookie_value)
                    if isinstance(decoded, bytes):
                        decoded_str = decoded.decode("utf-8", errors="ignore")
                        decoded_findings = _detect_serialization(
                            decoded_str, f"Cookie (decoded): {cookie_name}"
                        )
                        findings.extend(decoded_findings)

                        # Check magic bytes
                        for lang, sig_data in SIGNATURES.items():
                            for magic in sig_data["magic_bytes"]:
                                if decoded.startswith(magic):
                                    findings.append(
                                        {
                                            "type": "Insecure Deserialization",
                                            "language": lang,
                                            "source": f"Cookie (magic bytes): {cookie_name}",
                                            "description": sig_data["description"],
                                            "risk": sig_data["risk"],
                                            "severity": "CRITICAL",
                                        }
                                    )

    except ScanExceptions:
        pass

    return findings

def _scan_response_body(url, delay=0):
    """Scan response body for serialized object patterns."""
    findings = []

    try:
        resp = smart_request("get", url, delay=delay, timeout=10)
        body_findings = _detect_serialization(resp.text, "Response Body")
        findings.extend(body_findings)

        # Check for hidden inputs with serialized data
        import re as regex

        hidden_inputs = regex.findall(
            r'<input[^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']+)["\']',
            resp.text,
            regex.IGNORECASE,
        )
        for value in hidden_inputs:
            input_findings = _detect_serialization(value, "Hidden Input")
            findings.extend(input_findings)

            decoded, _ = _decode_value(value)
            if isinstance(decoded, bytes):
                decoded_str = decoded.decode("utf-8", errors="ignore")
                decoded_findings = _detect_serialization(
                    decoded_str, "Hidden Input (decoded)"
                )
                findings.extend(decoded_findings)

    except ScanExceptions:
        pass

    return findings

def _test_deserialization_injection(url, delay=0):
    """Send probe payloads to test if deserialization is exploitable."""
    findings = []

    for lang, payloads in PROBE_PAYLOADS.items():
        for payload in payloads:
            try:
                # Test via Cookie header
                headers = {"Cookie": f"session={payload}"}
                resp = smart_request(
                    "get", url, headers=headers, delay=delay, timeout=5
                )

                # Check for deserialization error signatures
                error_sigs = {
                    "php": ["unserialize()", "Serialization", "__wakeup", "O:"],
                    "java": [
                        "InvalidClassException",
                        "ClassNotFoundException",
                        "ObjectInputStream",
                        "java.io.",
                    ],
                    "dotnet": [
                        "ViewState",
                        "System.Runtime",
                        "BinaryFormatter",
                        "ObjectStateFormatter",
                    ],
                }

                for sig in error_sigs.get(lang, []):
                    if sig.lower() in resp.text.lower():
                        findings.append(
                            {
                                "type": "Insecure Deserialization",
                                "language": lang,
                                "source": "Injection Probe",
                                "evidence": f"Error signature '{sig}' in response",
                                "severity": "CRITICAL",
                                "url": url,
                                "description": f"{lang.upper()} deserialization confirmed — error leaked",
                            }
                        )
                        break

                # Test via POST body
                resp2 = smart_request(
                    "post", url, data={"data": payload}, delay=delay, timeout=5
                )
                for sig in error_sigs.get(lang, []):
                    if sig.lower() in resp2.text.lower():
                        findings.append(
                            {
                                "type": "Insecure Deserialization",
                                "language": lang,
                                "source": "POST Injection",
                                "evidence": f"Error signature '{sig}' in response",
                                "severity": "CRITICAL",
                                "url": url,
                                "description": f"{lang.upper()} deserialization via POST body",
                            }
                        )
                        break

            except ScanExceptions:
                pass

    return findings

def scan_deserialization(url, delay=0):
    """
    Main Insecure Deserialization scanner entry point.
    Scans cookies, response bodies, hidden inputs, and probes for exploitation.
    """
    log_info("Starting Insecure Deserialization Scanner...")
    all_findings = []

    # Scan cookies
    log_info("  → Scanning cookies for serialized objects...")
    all_findings.extend(_scan_cookies(url, delay))

    # Scan response body
    log_info("  → Scanning response body for serialization patterns...")
    all_findings.extend(_scan_response_body(url, delay))

    # Active probing
    log_info("  → Testing deserialization injection probes...")
    all_findings.extend(_test_deserialization_injection(url, delay))

    for f in all_findings:
        f["url"] = url
        if f.get("severity") == "CRITICAL":
            log_success(
                f"🔥 [CRITICAL] {f.get('language', '').upper()} Deserialization: {f.get('description', '')}"
            )
        elif f.get("severity") == "HIGH":
            log_warning(
                f"⚠️  [HIGH] {f.get('language', '').upper()}: {f.get('description', '')}"
            )
        else:
            log_info(f"[{f['severity']}] {f.get('description', '')}")

    if not all_findings:
        log_info("No deserialization vulnerabilities detected.")

    # ── AI Exploit Agent (Final Escalation) ──
    if not all_findings:
        try:
            from utils.ai_exploit_agent import get_exploit_agent, ExploitContext
            from urllib.parse import urlparse, parse_qs
            agent = get_exploit_agent()
            if agent and agent.available:
                from utils.waf import waf_detector
                waf_name = getattr(waf_detector, "detected_waf", "") or ""

                ctx = ExploitContext(
                    url=url,
                    vuln_type="Deserialization",
                    waf=waf_name,
                    http_method="POST",
                )
                result = agent.exploit_deserialization(ctx)
                if result and result.success:
                    all_findings.append({
                        "type": "Insecure Deserialization",
                        "url": url,
                        "payload": result.payload,
                        "evidence": result.evidence[:200],
                        "severity": "CRITICAL",
                        "description": (
                            f"AI-discovered deserialization vulnerability. "
                            f"Confidence: {result.confidence:.0f}%"
                        ),
                        "source": f"AI Agent (Gen-{result.iteration})",
                        "ai_curl": result.curl_command,
                        "ai_poc_script": result.python_script,
                        "ai_nuclei": result.nuclei_template,
                    })
                    log_success(
                        f"[CRITICAL] Deserialization at: {url} "
                        f"[AI Agent Gen-{result.iteration}]"
                    )
        except ImportError:
            pass

    log_success(f"Deserialization scan complete. {len(all_findings)} finding(s).")
    return all_findings
