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

from utils.request import smart_request, lock, Stats, Config
from utils.colors import Colors, log_info, log_success, log_vuln
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


def _test_sqli_form_input(inp, inputs, method, target, delay):
    """Test a single form input for SQLi (helper for threading)"""
    # Smart probe: detect DB type + generate targeted payloads
    probe = probe_sqli_context(
        target, inp, {}, method=method, form_data=inputs.copy(), delay=delay
    )
    smart = probe.get("smart_payloads", [])
    if smart:
        all_payloads = smart + [p for p in SQLI_PAYLOADS if p not in smart]
    else:
        all_payloads = SQLI_PAYLOADS

    for payload in all_payloads:
        data = inputs.copy()
        data[inp] = payload
        try:
            resp = smart_request(
                method,
                target,
                data=data if method == "post" else None,
                params=data if method != "post" else None,
                delay=delay,
            )
            error = detect_sqli(resp.text)
            if error:
                with lock:
                    Stats.vulnerabilities_found += 1
                source = "🧠 Smart" if payload in smart else "📋 Static"
                log_vuln(f"SQLi VULNERABILITY FOUND! [{source}]")
                log_success(f"Field: {inp} | Error: {error}")
                log_success(f"Payload: {payload}")
                return {
                    "type": "SQLi_Form",
                    "field": inp,
                    "payload": payload,
                    "error": error,
                    "url": target,
                    "method": method,
                    "form_data": data,
                }
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
            error = detect_sqli(resp.text)
            if error:
                with lock:
                    Stats.vulnerabilities_found += 1
                source = "🧠 Smart" if payload in smart else "📋 Static"
                log_vuln(f"SQLi VULNERABILITY FOUND! [{source}]")
                log_success(f"Param: {param} | Error: {error}")
                log_success(f"Payload: {payload}")
                return {
                    "type": "SQLi_Param",
                    "param": param,
                    "payload": payload,
                    "error": error,
                    "url": test_url,
                }
        except Exception:
            pass
    return None


def scan_sqli(url, forms, delay, threads=None):
    """Scan for SQL injection vulnerabilities (threaded)"""
    from utils.tamper import get_tamper_chain

    if threads is None:
        threads = Config.THREADS

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

                                with lock:
                                    Stats.vulnerabilities_found += 1

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
                            with lock:
                                Stats.vulnerabilities_found += 1

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
