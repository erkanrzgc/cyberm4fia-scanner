"""
cyberm4fia-scanner - XSS Module
Cross-Site Scripting detection
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.colors import log_info, log_success, log_vuln
from utils.request import smart_request, lock, Stats, Config
from modules.payloads import XSS_FLAT_PAYLOADS
from modules.smart_payload import probe_xss_context
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed
import re


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


def scan_xss_param(url, param, original_params, payloads, delay):
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

    if Config.OOB_CLIENT and Config.OOB_CLIENT.ready:
        oob_url = Config.OOB_CLIENT.generate_payload("xss", param)
        all_payloads.append(f"\"><script src='{oob_url}'></script>")

    for payload in all_payloads:
        test_params = original_params.copy()
        test_params[param] = payload

        parsed = urlparse(url)
        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

        try:
            resp = smart_request("get", test_url, delay=delay)

            # Check if payload is reflected
            if payload in resp.text:
                soup = BeautifulSoup(resp.text, "lxml")
                contexts = analyze_context(soup, payload)

                if is_valid_xss_reflection(payload, contexts):
                    with lock:
                        Stats.vulnerabilities_found += 1

                    source = "🧠 Smart" if payload in smart_payloads else "📋 Static"
                    log_vuln(f"XSS in param: {param} [{source}]")
                    log_success(
                        f"Param: {param} | Context: {', '.join(contexts)} | Payload: {payload[:50]}..."
                    )

                    vulns.append(
                        {
                            "type": "XSS_Param",
                            "param": param,
                            "payload": payload,
                            "context": contexts,
                            "url": test_url,
                            "source": source,
                        }
                    )
                    break
        except Exception:
            pass  # Individual payload failure is expected

    return vulns


def scan_xss_form(form, url, payloads, delay):
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

        for payload in all_payloads:
            data = {n: "test" for n in input_names}
            data[inp_name] = payload

            try:
                if method == "post":
                    resp = smart_request("post", target, data=data, delay=delay)
                else:
                    resp = smart_request("get", target, params=data, delay=delay)

                if payload in resp.text:
                    soup = BeautifulSoup(resp.text, "lxml")
                    contexts = analyze_context(soup, payload)

                    if is_valid_xss_reflection(payload, contexts):
                        with lock:
                            Stats.vulnerabilities_found += 1

                        source = (
                            "🧠 Smart" if payload in smart_payloads else "📋 Static"
                        )
                        log_vuln(f"XSS in form field: {inp_name} [{source}]")
                        log_success(f"Field: {inp_name} | Payload: {payload[:50]}...")

                        vulns.append(
                            {
                                "type": "XSS_Form",
                                "field": inp_name,
                                "payload": payload,
                                "form_action": target,
                                "method": method,
                                "source": source,
                            }
                        )
                        break
            except Exception:
                pass  # Individual payload failure is expected

    return vulns


def scan_xss(url, forms, delay, threads=10):
    """Main XSS scanning function"""
    from utils.tamper import get_tamper_chain

    payloads = XSS_FLAT_PAYLOADS
    # Apply tamper chain for WAF bypass variants
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
                    )
                )

            for future in as_completed(futures):
                try:
                    all_vulns.extend(future.result())
                except Exception as e:
                    pass  # Individual future result failure

    # Scan forms
    for form in forms:
        vulns = scan_xss_form(form, url, payloads, delay)
        all_vulns.extend(vulns)

    return all_vulns
