"""
cyberm4fia-scanner - LFI Module
Local File Inclusion detection (Threaded)
"""


from utils.colors import Colors, log_info, log_success, log_vuln
from utils.request import (
    get_thread_count,
    increment_vulnerability_count,
    smart_request,
)
from modules.payloads import LFI_PAYLOADS, LFI_SIGNATURES
from utils.payload_filter import PayloadFilter
from modules.smart_payload import probe_lfi_context
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import base64
import re
from utils.request import ScanExceptions

def _detect_php_wrapper_output(response_text, payload):
    """Detect and decode PHP wrapper (base64/rot13) output from response."""
    if "php://filter" not in payload:
        return None

    # Extract potential base64 encoded content
    # PHP filter output is usually a long base64 string in the response body
    b64_pattern = re.findall(r"([A-Za-z0-9+/=]{40,})", response_text)
    for b64_str in b64_pattern:
        try:
            decoded = base64.b64decode(b64_str).decode("utf-8", errors="replace")
            # Check if it looks like PHP/HTML source code
            if any(
                marker in decoded.lower()
                for marker in [
                    "<?php",
                    "<html",
                    "<?=",
                    "function ",
                    "class ",
                    "$_",
                    "require",
                    "include",
                    "password",
                    "database",
                    "config",
                ]
            ):
                return decoded
        except ScanExceptions:
            continue
    return None

def detect_lfi(text, baseline_text=None):
    """Check if response indicates successful LFI, optionally ignoring baseline signatures."""
    text_lower = text.lower()
    baseline_lower = baseline_text.lower() if baseline_text else ""

    for os_type, signatures in LFI_SIGNATURES.items():
        for sig in signatures:
            sig_lower = sig.lower()
            if sig_lower in text_lower:
                # Baseline validation: Ignore if the signature was already on the normal page
                if baseline_lower and sig_lower in baseline_lower:
                    continue
                return os_type, sig
    return None, None

def _test_lfi_param(param, params, parsed, delay, target_context=None):
    """Test a single param for LFI (helper for threading)"""
    flat_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
    probe = probe_lfi_context(
        urlunparse(parsed), param, flat_params, method="get", delay=delay
    )
    smart = probe.get("smart_payloads", [])
    if smart:
        all_payloads = smart + [p for p in LFI_PAYLOADS if p not in smart]
    else:
        all_payloads = LFI_PAYLOADS
        
    if target_context:
        all_payloads = PayloadFilter.filter_payloads(all_payloads, target_context)

    # 1. Fetch Baseline to prevent False Positives
    baseline_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
    try:
        baseline_resp = smart_request("get", baseline_url, delay=delay)
        baseline_text = baseline_resp.text
    except ScanExceptions:
        baseline_text = ""

    for payload in all_payloads:
        test_params = params.copy()
        test_params[param] = [payload]
        test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
        try:
            resp = smart_request("get", test_url, delay=delay)
            os_type, sig = detect_lfi(resp.text, baseline_text=baseline_text)
            if os_type:
                increment_vulnerability_count()
                source = "🧠 Smart" if payload in smart else "📋 Static"
                log_vuln(f"LFI VULNERABILITY FOUND! [{source}]")
                log_success(f"Param: {param} | OS: {os_type} | Signature: {sig}")
                log_success(f"Payload: {payload}")
                if "root:" in resp.text or "[drivers]" in resp.text:
                    lines = [
                        line
                        for line in resp.text.split("\n")
                        if sig in line or "root:" in line
                    ][:3]
                    if lines:
                        print(
                            f"{Colors.BOLD}    --- File Content Preview ---{Colors.END}"
                        )
                        for line in lines:
                            print(f"    {line[:80]}")
                        print(
                            f"{Colors.BOLD}    -----------------------------{Colors.END}"
                        )

                # Check for PHP wrapper decoded output
                wrapper_content = _detect_php_wrapper_output(resp.text, payload)
                if wrapper_content:
                    log_success("📄 PHP Source Code Extracted:")
                    print(f"{Colors.BOLD}    --- Source Code Preview ---{Colors.END}")
                    for line in wrapper_content.split("\n")[:10]:
                        print(f"    {Colors.CYAN}{line[:100]}{Colors.END}")
                    if len(wrapper_content.split("\n")) > 10:
                        print(
                            f"    {Colors.DIM}... ({len(wrapper_content.split(chr(10)))} lines total){Colors.END}"
                        )
                    print(f"{Colors.BOLD}    ----------------------------{Colors.END}")

                return {
                    "type": "LFI_Param",
                    "param": param,
                    "payload": payload,
                    "os": os_type,
                    "signature": sig,
                    "url": test_url,
                    "wrapper_content": wrapper_content,
                }
        except ScanExceptions:
            pass
    return None

def _test_lfi_form_input(inp, inputs, method, target, delay, target_context=None):
    """Test a single form input for LFI (helper for threading)"""
    form_data = {n: "test" for n in inputs}
    probe = probe_lfi_context(
        target, inp, {}, method=method, form_data=form_data, delay=delay
    )
    smart = probe.get("smart_payloads", [])
    if smart:
        all_payloads = smart + [p for p in LFI_PAYLOADS if p not in smart]
    else:
        all_payloads = LFI_PAYLOADS
        
    if target_context:
        all_payloads = PayloadFilter.filter_payloads(all_payloads, target_context)

    # 1. Fetch Baseline
    baseline_data = {n: "test" for n in inputs}
    try:
        baseline_resp = smart_request(
            method,
            target,
            data=baseline_data if method == "post" else None,
            params=baseline_data if method != "post" else None,
            delay=delay,
        )
        baseline_text = baseline_resp.text
    except ScanExceptions:
        baseline_text = ""

    for payload in all_payloads:
        data = {n: "test" for n in inputs}
        data[inp] = payload
        try:
            resp = smart_request(
                method,
                target,
                data=data if method == "post" else None,
                params=data if method != "post" else None,
                delay=delay,
            )
            os_type, sig = detect_lfi(resp.text, baseline_text=baseline_text)
            if os_type:
                increment_vulnerability_count()
                source = "🧠 Smart" if payload in smart else "📋 Static"
                log_vuln(f"LFI VULNERABILITY FOUND! [{source}]")
                log_success(f"Form field: {inp} | OS: {os_type}")
                log_success(f"Payload: {payload}")
                if "root:" in resp.text or "[drivers]" in resp.text:
                    lines = [
                        line
                        for line in resp.text.split("\n")
                        if sig in line or "root:" in line
                    ][:3]
                    if lines:
                        print(
                            f"{Colors.BOLD}    --- File Content Preview ---{Colors.END}"
                        )
                        for line in lines:
                            print(f"    {line[:80]}")
                        print(
                            f"{Colors.BOLD}    -----------------------------{Colors.END}"
                        )

                # Check for PHP wrapper decoded output
                wrapper_content = _detect_php_wrapper_output(resp.text, payload)
                if wrapper_content:
                    log_success("📄 PHP Source Code Extracted:")
                    print(f"{Colors.BOLD}    --- Source Code Preview ---{Colors.END}")
                    for line in wrapper_content.split("\n")[:10]:
                        print(f"    {Colors.CYAN}{line[:100]}{Colors.END}")
                    if len(wrapper_content.split("\n")) > 10:
                        print(
                            f"    {Colors.DIM}... ({len(wrapper_content.split(chr(10)))} lines total){Colors.END}"
                        )
                    print(f"{Colors.BOLD}    ----------------------------{Colors.END}")

                return {
                    "type": "LFI_Form",
                    "field": inp,
                    "payload": payload,
                    "os": os_type,
                    "signature": sig,
                    "url": target,
                    "method": method,
                    "wrapper_content": wrapper_content,
                }
        except ScanExceptions:
            pass
    return None

def scan_lfi(url, forms, delay, options=None, threads=None):
    """Scan for Local File Inclusion vulnerabilities (threaded)"""
    from utils.tamper import get_tamper_chain

    if threads is None:
        threads = get_thread_count()
        
    options = options or {}
    target_context = options.get("target_context")

    # Apply tamper chain for WAF bypass variants
    chain = get_tamper_chain()
    payloads = list(LFI_PAYLOADS)
    if chain.active:
        payloads = chain.apply_list(payloads)

    log_info(f"Testing LFI with {len(payloads)} payloads ({threads} threads)...")
    vulns = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []

        # URL params
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in params.keys():
            futures.append(
                executor.submit(_test_lfi_param, param, params, parsed, delay, target_context)
            )

        # Forms
        for form in forms:
            action = form.get("action") or url
            method = form.get("method", "get").lower()
            target = urljoin(url, action)
            inputs = [
                i.get("name")
                for i in form.find_all(["input", "textarea"])
                if i.get("name")
            ]
            for inp in inputs:
                futures.append(
                    executor.submit(
                        _test_lfi_form_input, inp, inputs, method, target, delay, target_context
                    )
                )

        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    vulns.append(result)
            except ScanExceptions:
                pass

    # ── AI Exploit Agent (Final Escalation) ──
    if not vulns and params:
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
                        vuln_type="LFI",
                        waf=waf_name,
                        http_method="GET",
                    )
                    result = agent.exploit_lfi(ctx)
                    if result and result.success:
                        increment_vulnerability_count()
                        log_vuln(f"LFI in: {param} [🤖 AI Agent Gen-{result.iteration}]")
                        vulns.append({
                            "type": "LFI_Param",
                            "param": param,
                            "payload": result.payload,
                            "url": url,
                            "source": f"🤖 AI Agent (confidence: {result.confidence:.0f}%)",
                            "evidence": result.evidence[:200],
                            "ai_curl": result.curl_command,
                            "ai_poc_script": result.python_script,
                        })
                        break
        except ImportError:
            pass

    return vulns


# ── Async version ─────────────────────────────────────────────────────────

async def async_scan_lfi(url, forms, delay, options=None):
    """Async version of scan_lfi — uses asyncio.gather instead of ThreadPoolExecutor."""
    import asyncio
    from utils.async_request import async_smart_request, get_async_client

    options = options or {}
    target_context = options.get("target_context")

    payloads = list(LFI_PAYLOADS)
    if target_context:
        payloads = PayloadFilter.filter_payloads(payloads, target_context)

    log_info(f"Testing LFI (async) with {len(payloads)} payloads...")
    vulns = []

    async with get_async_client() as client:

        async def _test_param(param, params, parsed):
            all_payloads = list(payloads)

            # Baseline
            baseline_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
            try:
                baseline_resp = await async_smart_request(client, "get", baseline_url, delay=delay)
                baseline_text = baseline_resp.text
            except ScanExceptions:
                baseline_text = ""

            for payload in all_payloads:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                try:
                    resp = await async_smart_request(client, "get", test_url, delay=delay)
                    os_type, sig = detect_lfi(resp.text, baseline_text=baseline_text)
                    if os_type:
                        increment_vulnerability_count()
                        log_vuln("LFI VULNERABILITY FOUND!")
                        log_success(f"Param: {param} | OS: {os_type} | Signature: {sig}")
                        return {
                            "type": "LFI_Param", "param": param, "payload": payload,
                            "os": os_type, "signature": sig, "url": test_url,
                            "wrapper_content": _detect_php_wrapper_output(resp.text, payload),
                        }
                except ScanExceptions:
                    pass
            return None

        async def _test_form(inp, inputs, method, target):
            all_payloads = list(payloads)

            baseline_data = {n: "test" for n in inputs}
            try:
                baseline_resp = await async_smart_request(
                    client, method, target,
                    data=baseline_data if method == "post" else None,
                    params=baseline_data if method != "post" else None,
                    delay=delay,
                )
                baseline_text = baseline_resp.text
            except ScanExceptions:
                baseline_text = ""

            for payload in all_payloads:
                data = {n: "test" for n in inputs}
                data[inp] = payload
                try:
                    resp = await async_smart_request(
                        client, method, target,
                        data=data if method == "post" else None,
                        params=data if method != "post" else None,
                        delay=delay,
                    )
                    os_type, sig = detect_lfi(resp.text, baseline_text=baseline_text)
                    if os_type:
                        increment_vulnerability_count()
                        log_vuln("LFI VULNERABILITY FOUND!")
                        return {
                            "type": "LFI_Form", "field": inp, "payload": payload,
                            "os": os_type, "signature": sig, "url": target, "method": method,
                            "wrapper_content": _detect_php_wrapper_output(resp.text, payload),
                        }
                except ScanExceptions:
                    pass
            return None

        tasks = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in params.keys():
            tasks.append(_test_param(param, params, parsed))

        for form in forms:
            action = form.get("action") or url
            method = form.get("method", "get").lower()
            target = urljoin(url, action)
            inputs = [i.get("name") for i in form.find_all(["input", "textarea"]) if i.get("name")]
            for inp in inputs:
                tasks.append(_test_form(inp, inputs, method, target))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, dict):
                vulns.append(result)

    return vulns
