"""
cyberm4fia-scanner - XSS Module
Cross-Site Scripting detection
"""

from utils.colors import log_info, log_vuln, log_warning
from utils.request import (
    get_oob_client,
    increment_vulnerability_count,
    smart_request,
)
from modules.payloads import XSS_FLAT_PAYLOADS
from utils.payload_filter import PayloadFilter
from modules.smart_payload import probe_xss_context
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
import re
from typing import Optional
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

import functools
from utils.concurrency import run_concurrent_tasks

def _test_xss_param_payload(payload, url, param, original_params, delay, smart_payloads):
    test_params = original_params.copy()
    test_params[param] = payload
    parsed = urlparse(url)
    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
    try:
        resp = smart_request("get", test_url, delay=delay)
        vuln_found = _check_xss_reflection(resp, payload, param, test_url, smart_payloads)
        if vuln_found:
            return vuln_found

        from utils.waf import waf_detector
        if not waf_detector.is_waf_block(resp.status_code, resp.text):
            return None

        waf_name = waf_detector.detected_waf or "Generic WAF"
        log_warning(f"WAF Block ({waf_name}) detected on param '{param}'")

        # Track the URL most recently sent so check_fn reports the right
        # location. The closures mutate ``test_url`` via the outer scope.
        nonlocal_state = {"test_url": test_url}

        def request_fn(p, *, evasion_level=0):
            test_params[param] = p
            url_for_call = urlunparse(parsed._replace(query=urlencode(test_params)))
            nonlocal_state["test_url"] = url_for_call
            return smart_request(
                "get", url_for_call, delay=delay, evasion_level=evasion_level
            )

        def check_fn(response, p, source):
            return _check_xss_reflection(
                response,
                p,
                param,
                nonlocal_state["test_url"],
                smart_payloads,
                source=source,
            )

        from utils.waf_evasion import apply_waf_bypass_chain

        return apply_waf_bypass_chain(
            payload=payload,
            blocked_response=resp,
            request_fn=request_fn,
            check_fn=check_fn,
            waf_name=waf_name,
            vuln_label="XSS",
        )
    except ScanExceptions:
        pass
    return None

def _test_xss_form_payload(payload, target, inp_name, input_names, method, delay, smart_payloads):
    data = {n: "test" for n in input_names}
    data[inp_name] = payload
    try:
        resp = smart_request("post", target, data=data, delay=delay) if method == "post" else smart_request("get", target, params=data, delay=delay)
        vuln_found = _check_xss_reflection(resp, payload, inp_name, target, smart_payloads)
        if vuln_found:
            vuln_found["method"] = method
            return vuln_found

        from utils.waf import waf_detector
        if not waf_detector.is_waf_block(resp.status_code, resp.text):
            return None

        waf_name = waf_detector.detected_waf or "Generic WAF"
        log_warning(f"WAF Block ({waf_name}) detected on form field '{inp_name}'")

        def request_fn(p, *, evasion_level=0):
            data[inp_name] = p
            if method == "post":
                return smart_request(
                    "post", target, data=data, delay=delay, evasion_level=evasion_level
                )
            return smart_request(
                "get", target, params=data, delay=delay, evasion_level=evasion_level
            )

        def check_fn(response, p, source):
            finding = _check_xss_reflection(
                response, p, inp_name, target, smart_payloads, source=source
            )
            if finding:
                finding["method"] = method
            return finding

        from utils.waf_evasion import apply_waf_bypass_chain

        return apply_waf_bypass_chain(
            payload=payload,
            blocked_response=resp,
            request_fn=request_fn,
            check_fn=check_fn,
            waf_name=waf_name,
            vuln_label="XSS",
        )
    except ScanExceptions:
        pass
    return None

def scan_xss(url: str, forms: list, delay: float, options: Optional[dict] = None, threads: int = 10) -> list:
    from utils.tamper import get_tamper_chain
    options = options or {}
    target_context = options.get("target_context")
    payloads = list(XSS_FLAT_PAYLOADS)
    chain = get_tamper_chain()
    if chain.active:
        payloads = chain.apply_list(payloads)

    log_info(f"Testing XSS with {len(payloads)} payloads...")
    tasks = []

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if params:
        for param in params:
            original_params = {k: v[0] for k, v in params.items()}
            probe_result = probe_xss_context(url, param, original_params, method="get", delay=delay)
            smart_payloads = probe_result.get("smart_payloads", [])
            all_payloads = smart_payloads + [p for p in payloads if p not in smart_payloads] if smart_payloads else list(payloads)
            if target_context:
                all_payloads = PayloadFilter.filter_payloads(all_payloads, target_context)
            oob_client = get_oob_client()
            if oob_client and oob_client.ready:
                oob_url = oob_client.generate_payload("xss", param)
                all_payloads.append(f"\"><script src='{oob_url}'></script>")
            for payload in all_payloads:
                tasks.append(functools.partial(_test_xss_param_payload, payload, url, param, original_params, delay, smart_payloads))

    for form in forms:
        action = form.get("action") or url
        method = form.get("method", "get").lower()
        target = urljoin(url, action)
        inputs = form.find_all(["input", "textarea"])
        input_names = [i.get("name") for i in inputs if i.get("name")]
        for inp_name in input_names:
            form_data = {n: "test" for n in input_names}
            probe_result = probe_xss_context(target, inp_name, {}, method=method, form_data=form_data, delay=delay)
            smart_payloads = probe_result.get("smart_payloads", [])
            all_payloads = smart_payloads + [p for p in payloads if p not in smart_payloads] if smart_payloads else list(payloads)
            if target_context:
                all_payloads = PayloadFilter.filter_payloads(all_payloads, target_context)
            for payload in all_payloads:
                tasks.append(functools.partial(_test_xss_form_payload, payload, target, inp_name, input_names, method, delay, smart_payloads))

    all_vulns = run_concurrent_tasks(tasks, max_workers=threads)

    unique_vulns = []
    seen = set()
    for v in all_vulns:
        if not v: continue
        key = f"{v.get('type')}:{v.get('field', v.get('param'))}:{v.get('payload')}"
        if key not in seen:
            seen.add(key)
            unique_vulns.append(v)
    all_vulns = unique_vulns

    if not all_vulns and params:
        try:
            from utils.ai_exploit_agent import get_exploit_agent, ExploitContext
            agent = get_exploit_agent()
            if agent and agent.available:
                from utils.waf import waf_detector
                waf_name = getattr(waf_detector, "detected_waf", "") or ""
                for param in params:
                    ctx = ExploitContext(url=url, param=param, vuln_type="XSS", waf=waf_name, http_method="GET")
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
