"""
cyberm4fia-scanner - XSS Module
Cross-Site Scripting detection
"""

from utils.colors import log_info, log_success, log_vuln, log_warning
from utils.request import (
    get_oob_client,
    increment_vulnerability_count,
    smart_request,
)
from modules.payloads import XSS_FLAT_PAYLOADS
from utils.payload_filter import PayloadFilter
from modules.smart_payload import probe_xss_context
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from typing import Any, Optional
from utils.request import ScanExceptions

def analyze_context(soup, payload):
    """Analyze where payload appears in page"""
    html = str(soup)
    contexts = []

    if payload in html:
        if f'value="{payload}"' in html or f"value='{payload}'" in html:
            contexts.append("ATTRIBUTE_VALUE")
        if f">{payload}<" in html:
            contexts.append("TAG_CONTENT")
        # Check if payload is inside a text node of a script tag
        # More robust check: use BeautifulSoup's parent logic or strict index checking

        # Simple text based check: Find all script blocks and check if payload is inside one
        # Because soup.find_all('script') might decode entities, raw text search is safer for reflection check

        # Find all script blocks with their start/end indices
        for match in re.finditer(
            r"<script[^>]*>(.*?)</script>", html, re.IGNORECASE | re.DOTALL
        ):
            if payload in match.group(
                0
            ):  # Check if payload is inside this specific script block
                contexts.append("INSIDE_SCRIPT")
                break

    # Safe contexts: payload appears inside non-executable containers.
    # If only safe contexts are detected, skip vulnerability reporting.
    escaped_payload = re.escape(payload)
    for safe_tag in ("textarea", "title", "option"):
        pattern = rf"<{safe_tag}\b[^>]*>.*?{escaped_payload}.*?</{safe_tag}>"
        if re.search(pattern, html, re.IGNORECASE | re.DOTALL):
            contexts.append("SAFE_CONTEXT")
            break

    if not contexts:
        contexts.append("REFLECTED")

    return list(dict.fromkeys(contexts))

def is_valid_xss_reflection(payload, contexts):
    """Apply conservative validation to reduce false positives."""
    ctx = set(contexts)
    dangerous = {"ATTRIBUTE_VALUE", "INSIDE_SCRIPT", "TAG_CONTENT"}

    # If payload is reflected inside non-executable containers, treat as safe unless
    # we have explicit attribute execution context.
    if "SAFE_CONTEXT" in ctx and "ATTRIBUTE_VALUE" not in ctx:
        return False

    if any(char in payload for char in ["<", ">"]):
        # If payload contains HTML tags like <img, <script, <svg and is reflected exactly
        # but context detection failed (e.g. inside <pre> tag), it's likely vulnerable.
        # We check if it looks like a tag injection.
        if re.search(r"<[a-z/]+", payload, re.IGNORECASE):
            # If exact payload with tags is reflected and not in safe context,
            # it is a valid XSS (HTML Injection).
            return True

        is_valid = bool(ctx & dangerous)
    else:
        is_valid = "ATTRIBUTE_VALUE" in ctx or "INSIDE_SCRIPT" in ctx

    if (
        "javascript:" in payload.lower()
        and "ATTRIBUTE_VALUE" not in ctx
        and "INSIDE_SCRIPT" not in ctx
    ):
        return False

    return is_valid

def scan_xss_param(url: str, param: str, original_params: dict, payloads: list, delay: float, target_context: Optional[dict] = None) -> list:
    """Scan a single parameter for XSS"""
    vulns = []

    # Phase 1: Smart Probe — context-aware targeted payloads
    probe_result = probe_xss_context(
        url, param, original_params, method="get", delay=delay
    )
    smart_payloads = probe_result.get("smart_payloads", [])

    # Build payload list: smart first, then static fallback
    if smart_payloads:
        all_payloads = smart_payloads + [p for p in payloads if p not in smart_payloads]
    else:
        all_payloads = list(payloads)

    if target_context:
        all_payloads = PayloadFilter.filter_payloads(all_payloads, target_context)

    oob_client = get_oob_client()
    if oob_client and oob_client.ready:
        oob_url = oob_client.generate_payload("xss", param)
        all_payloads.append(f"\"><script src='{oob_url}'></script>")

    for payload in all_payloads:
        test_params = original_params.copy()
        test_params[param] = payload

        parsed = urlparse(url)
        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

        try:
            resp = smart_request("get", test_url, delay=delay)
            vuln_found = _check_xss_reflection(
                resp, payload, param, test_url, smart_payloads
            )
            if vuln_found:
                vulns.append(vuln_found)
                break

            # --- SMART WAF BYPASS LOGIC ---
            from utils.waf import waf_detector

            if waf_detector.is_waf_block(resp.status_code, resp.text):
                waf_name = waf_detector.detected_waf or "Generic WAF"
                log_warning(f"WAF Block ({waf_name}) detected on param '{param}'")

                # 1. Try Auto-Tamper
                from utils.tamper import TamperChain

                tampers = waf_detector.get_recommended_tampers()
                if tampers:
                    log_info(
                        f"Applying auto-tamper for {waf_name}: {'+'.join(tampers)}"
                    )
                    chain = TamperChain(tampers)
                    tampered_payload = chain.apply(payload)
                    if tampered_payload != payload:
                        test_params[param] = tampered_payload
                        test_url = urlunparse(
                            parsed._replace(query=urlencode(test_params))
                        )
                        resp_t = smart_request("get", test_url, delay=delay)
                        vuln_found = _check_xss_reflection(
                            resp_t,
                            tampered_payload,
                            param,
                            test_url,
                            smart_payloads,
                            source="⚡ Auto-Tamper",
                        )
                        if vuln_found:
                            vulns.append(vuln_found)
                            break

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
                            engine = EvolvingWAFBypassEngine(ai_client, waf_name, "XSS")
                            current_payload = payload

                            for iteration in range(
                                1, 4
                            ):  # Up to 3 mutation generations
                                ai_payloads = engine.mutate(current_payload, iteration)

                                for ai_p in ai_payloads:
                                    test_params[param] = ai_p
                                    test_url = urlunparse(
                                        parsed._replace(query=urlencode(test_params))
                                    )
                                    resp_ai = smart_request(
                                        "get", test_url, delay=delay
                                    )

                                    # 2a. Check if it worked
                                    vuln_found = _check_xss_reflection(
                                        resp_ai,
                                        ai_p,
                                        param,
                                        test_url,
                                        smart_payloads,
                                        source=f"🤖 AI Gen-{iteration}",
                                    )
                                    if vuln_found:
                                        vulns.append(vuln_found)
                                        break

                                    # 2b. If WAF blocked it, feed it back into the engine
                                    if waf_detector.is_waf_block(
                                        resp_ai.status_code, resp_ai.text
                                    ):
                                        engine.analyze_failure(ai_p)
                                        current_payload = (
                                            ai_p  # Mutate from the best/last attempt
                                        )

                                if vulns:
                                    break  # Break outer mutation loop if we got a hit

                            if vulns:
                                break  # Break target params loop if AI found something

                        # 3. Protocol-Level Evasion (If AI failed or unavailable)
                        if not vulns:
                            log_info(
                                f"🛡️ Falling back to Protocol-Level Evasion for {waf_name}..."
                            )

                            # Evasion Level 1: Unicode Normalization
                            test_params[param] = payload
                            test_url = urlunparse(
                                parsed._replace(query=urlencode(test_params))
                            )
                            resp_ev1 = smart_request(
                                "get", test_url, delay=delay, evasion_level=1
                            )
                            vuln_found = _check_xss_reflection(
                                resp_ev1,
                                payload,
                                param,
                                test_url,
                                smart_payloads,
                                source="🛡️ Unicode Evasion",
                            )

                            if vuln_found:
                                vulns.append(vuln_found)
                                break

                            # Evasion Level 2: Chunked Transfer
                            if waf_detector.is_waf_block(
                                resp_ev1.status_code, resp_ev1.text
                            ):
                                # Chunking is mostly effective over POST data padding, but we test URL too
                                resp_ev2 = smart_request(
                                    "get", test_url, delay=delay, evasion_level=2
                                )
                                vuln_found = _check_xss_reflection(
                                    resp_ev2,
                                    payload,
                                    param,
                                    test_url,
                                    smart_payloads,
                                    source="🧱 Chunked Evasion",
                                )
                                if vuln_found:
                                    vulns.append(vuln_found)
                                    break

                                # Evasion Level 3: WAF Resource Exhaustion (ReDoS)
                                if waf_detector.is_waf_block(
                                    resp_ev2.status_code, resp_ev2.text
                                ):
                                    log_warning(
                                        f"💥 Bruteforcing {waf_name} via Resource Exhaustion (Level 3)"
                                    )
                                    resp_ev3 = smart_request(
                                        "get", test_url, delay=delay, evasion_level=3
                                    )
                                    vuln_found = _check_xss_reflection(
                                        resp_ev3,
                                        payload,
                                        param,
                                        test_url,
                                        smart_payloads,
                                        source="💥 ReDoS Evasion",
                                    )
                                    if vuln_found:
                                        vulns.append(vuln_found)
                                        break

        except ScanExceptions:
            pass  # Individual payload failure is expected

    return vulns

def _check_xss_reflection(
    resp, payload, target_name, url_or_action, smart_payloads, source=None
):
    """Helper to check reflection and log XSS"""
    if payload in resp.text:
        soup = BeautifulSoup(resp.text, "lxml")
        contexts = analyze_context(soup, payload)
        if is_valid_xss_reflection(payload, contexts):
            increment_vulnerability_count()
            if not source:
                source = "🧠 Smart" if payload in smart_payloads else "📋 Static"
            log_vuln(f"XSS in: {target_name} [{source}]")
            log_success(f"Target: {target_name} | Payload: {payload[:50]}...")
            return {
                "type": "XSS_Param" if "?" in url_or_action else "XSS_Form",
                "param" if "?" in url_or_action else "field": target_name,
                "payload": payload,
                "context": contexts,
                "url" if "?" in url_or_action else "form_action": url_or_action,
                "source": source,
            }
    return None

def scan_xss_form(form: Any, url: str, payloads: list, delay: float, target_context: Optional[dict] = None) -> list:
    """Scan a form for XSS"""
    vulns = []
    action = form.get("action") or url
    method = form.get("method", "get").lower()
    target = urljoin(url, action)

    inputs = form.find_all(["input", "textarea"])
    input_names = [i.get("name") for i in inputs if i.get("name")]

    for inp_name in input_names:
        # Phase 1: Smart Probe for form fields
        form_data = {n: "test" for n in input_names}
        probe_result = probe_xss_context(
            target, inp_name, {}, method=method, form_data=form_data, delay=delay
        )
        smart_payloads = probe_result.get("smart_payloads", [])

        if smart_payloads:
            all_payloads = smart_payloads + [
                p for p in payloads if p not in smart_payloads
            ]
        else:
            all_payloads = payloads

        if target_context:
            all_payloads = PayloadFilter.filter_payloads(all_payloads, target_context)

        for payload in all_payloads:
            data = {n: "test" for n in input_names}
            data[inp_name] = payload

            try:
                if method == "post":
                    resp = smart_request("post", target, data=data, delay=delay)
                else:
                    resp = smart_request("get", target, params=data, delay=delay)

                vuln_found = _check_xss_reflection(
                    resp, payload, inp_name, target, smart_payloads
                )
                if vuln_found:
                    vuln_found["method"] = method
                    vulns.append(vuln_found)
                    break

                # --- SMART WAF BYPASS LOGIC ---
                from utils.waf import waf_detector

                if waf_detector.is_waf_block(resp.status_code, resp.text):
                    waf_name = waf_detector.detected_waf or "Generic WAF"
                    log_warning(
                        f"WAF Block ({waf_name}) detected on form field '{inp_name}'"
                    )

                    from utils.tamper import TamperChain

                    tampers = waf_detector.get_recommended_tampers()
                    if tampers:
                        log_info(
                            f"Applying auto-tamper for {waf_name}: {'+'.join(tampers)}"
                        )
                        chain = TamperChain(tampers)
                        tampered_payload = chain.apply(payload)
                        if tampered_payload != payload:
                            data[inp_name] = tampered_payload
                            resp_t = (
                                smart_request("post", target, data=data, delay=delay)
                                if method == "post"
                                else smart_request(
                                    "get", target, params=data, delay=delay
                                )
                            )
                            vuln_found = _check_xss_reflection(
                                resp_t,
                                tampered_payload,
                                inp_name,
                                target,
                                smart_payloads,
                                source="⚡ Auto-Tamper",
                            )
                            if vuln_found:
                                vuln_found["method"] = method
                                vulns.append(vuln_found)
                                break

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
                                    ai_client, waf_name, "XSS"
                                )
                                current_payload = payload

                                for iteration in range(1, 4):
                                    ai_payloads = engine.mutate(
                                        current_payload, iteration
                                    )

                                    for ai_p in ai_payloads:
                                        data[inp_name] = ai_p
                                        resp_ai = (
                                            smart_request(
                                                "post", target, data=data, delay=delay
                                            )
                                            if method == "post"
                                            else smart_request(
                                                "get", target, params=data, delay=delay
                                            )
                                        )
                                        vuln_found = _check_xss_reflection(
                                            resp_ai,
                                            ai_p,
                                            inp_name,
                                            target,
                                            smart_payloads,
                                            source=f"🤖 AI Gen-{iteration}",
                                        )
                                        if vuln_found:
                                            vuln_found["method"] = method
                                            vulns.append(vuln_found)
                                            break

                                        if waf_detector.is_waf_block(
                                            resp_ai.status_code, resp_ai.text
                                        ):
                                            engine.analyze_failure(ai_p)
                                            current_payload = ai_p

                                    if vulns:
                                        break

                                if vulns:
                                    break

                            # 3. Protocol-Level Evasion (If AI failed or unavailable)
                            if not vulns:
                                log_info(
                                    f"🛡️ Falling back to Protocol-Level Evasion for {waf_name}..."
                                )

                                # Evasion Level 1: Unicode Normalization
                                data[inp_name] = payload
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
                                vuln_found = _check_xss_reflection(
                                    resp_ev1,
                                    payload,
                                    inp_name,
                                    target,
                                    smart_payloads,
                                    source="🛡️ Unicode Evasion",
                                )

                                if vuln_found:
                                    vuln_found["method"] = method
                                    vulns.append(vuln_found)
                                    break

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
                                    vuln_found = _check_xss_reflection(
                                        resp_ev2,
                                        payload,
                                        inp_name,
                                        target,
                                        smart_payloads,
                                        source="🧱 Chunked Evasion",
                                    )
                                    if vuln_found:
                                        vuln_found["method"] = method
                                        vulns.append(vuln_found)
                                        break

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
                                        vuln_found = _check_xss_reflection(
                                            resp_ev3,
                                            payload,
                                            inp_name,
                                            target,
                                            smart_payloads,
                                            source="💥 ReDoS Evasion",
                                        )
                                        if vuln_found:
                                            vuln_found["method"] = method
                                            vulns.append(vuln_found)
                                            break

            except ScanExceptions:
                pass  # Individual payload failure is expected

    return vulns

def scan_xss(url: str, forms: list, delay: float, options: Optional[dict] = None, threads: int = 10) -> list:
    """Main XSS scanning function"""
    from utils.tamper import get_tamper_chain
    
    options = options or {}
    target_context = options.get("target_context")

    payloads = XSS_FLAT_PAYLOADS
    # Apply global tamper chain if set manually
    chain = get_tamper_chain()
    if chain.active:
        payloads = chain.apply_list(payloads)

    log_info(f"Testing XSS with {len(payloads)} payloads...")
    all_vulns = []

    # Parse URL parameters
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Scan URL params
    if params:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for param in params:
                futures.append(
                    executor.submit(
                        scan_xss_param,
                        url,
                        param,
                        {k: v[0] for k, v in params.items()},
                        payloads,
                        delay,
                        target_context
                    )  # pyre-ignore
                )

            for future in as_completed(futures):
                try:
                    all_vulns.extend(future.result())
                except ScanExceptions:
                    pass  # Individual future result failure

    # Scan forms
    for form in forms:
        vulns = scan_xss_form(form, url, payloads, delay, target_context)
        all_vulns.extend(vulns)

    # ── AI Exploit Agent (Final Escalation) ──
    # If no XSS found by static/smart payloads AND URL has params, try AI agent
    if not all_vulns and params:
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
                        vuln_type="XSS",
                        waf=waf_name,
                        http_method="GET",
                    )
                    result = agent.exploit_xss(ctx)
                    if result and result.success:
                        increment_vulnerability_count()
                        log_vuln(f"XSS in: {param} [🤖 AI Agent Gen-{result.iteration}]")
                        all_vulns.append({
                            "type": "XSS_Param",
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

    return all_vulns

