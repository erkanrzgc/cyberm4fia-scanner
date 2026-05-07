"""Module dispatcher — `MODULE_MAP`, form crawler, and `execute_module`."""

from __future__ import annotations

import importlib
import time
from urllib.parse import urlparse

from utils.colors import log_error, log_info, log_success, log_warning

MODULE_MAP = {
    "recon":             ("modules.recon", "run_recon", False),
    "tech_detect":       ("modules.tech_detect", "scan_technology", False),
    "header_audit":      ("modules.passive", "scan_passive", False),
    "xss":               ("modules.xss", "scan_xss", True),
    "sqli":              ("modules.sqli", "scan_sqli", True),
    "lfi":               ("modules.lfi", "scan_lfi", True),
    "cmdi":              ("modules.cmdi", "scan_cmdi", True),
    "ssrf":              ("modules.ssrf", "scan_ssrf", True),
    "ssti":              ("modules.ssti", "scan_ssti", False),
    "xxe":               ("modules.xxe", "scan_xxe", False),
    "csrf":              ("modules.csrf", "scan_csrf", True),
    "cors":              ("modules.cors", "scan_cors", False),
    "jwt":               ("modules.jwt_attack", "scan_jwt", False),
    "open_redirect":     ("modules.open_redirect", "scan_open_redirect", False),
    "header_inject":     ("modules.header_inject", "scan_header_inject", False),
    "dom_xss":           ("modules.dom_xss", "scan_dom_xss", False),
    "smuggling":         ("modules.smuggling", "scan_smuggling", False),
    "deserialization":   ("modules.deserialization", "scan_deserialization", False),
    "proto_pollution":   ("modules.proto_pollution", "scan_proto_pollution", True),
    "business_logic":    ("modules.business_logic", "scan_business_logic", True),
    "race_condition":    ("modules.race_condition", "scan_race_condition", True),
    "forbidden_bypass":  ("modules.forbidden_bypass", "scan_forbidden_bypass", False),
    "file_upload":       ("modules.file_upload", "scan_file_upload", True),
    "account_takeover":  ("modules.account_takeover", "scan_account_takeover", False),
    "auth_bypass":       ("modules.auth_bypass", "scan_auth_bypass", False),
    "csp_bypass":        ("modules.csp_bypass", "scan_csp_bypass", False),
    "cookie_hsts":       ("modules.cookie_hsts_audit", "scan_cookie_hsts", False),
    "subdomain":         ("modules.subdomain", "scan_subdomains", False),
    "secrets":           ("modules.secrets_scanner", "scan_secrets", False),
    "cloud_enum":        ("modules.cloud_enum", "scan_cloud_storage", False),
    "rfi":               ("modules.rfi", "scan_rfi", True),
    "api_scanner":       ("modules.api_scanner", "scan_api", False),
    "email_harvest":     ("modules.email_harvest", "scan_email_harvest", False),
    "endpoint_fuzzer":   ("modules.endpoint_fuzzer", "scan_fuzzer_async", False),
    "subdomain_takeover":("modules.subdomain_takeover", "scan_subdomain_takeover", False),
    "spray":             ("modules.spray", "scan_spray", False),
}


def _get_forms(target, delay=0, _cache={}):
    """Crawl and cache forms (singleton per target)."""
    if target in _cache:
        return _cache[target]
    try:
        from modules.dynamic_crawler import run_dynamic_spider
        log_info("  Crawling for forms...")
        pages = run_dynamic_spider(target, delay=delay)
        forms = []
        for page in (pages or []):
            forms.extend(page.get("forms", []))
        _cache[target] = forms
        log_info(f"  Found {len(forms)} forms across {len(pages or [])} pages")
    except Exception:
        _cache[target] = []
    return _cache[target]


def execute_module(mod_id, target, memory, delay=0):
    """Execute a single scanner module and return results."""
    if mod_id not in MODULE_MAP:
        log_warning(f"  Unknown module '{mod_id}', skipping")
        return None

    mod_path, func_name, needs_forms = MODULE_MAP[mod_id]
    memory.modules_run.add(mod_id)

    try:
        module = importlib.import_module(mod_path)
        func = getattr(module, func_name)
        start = time.time()

        if needs_forms:
            forms = _get_forms(target, delay)
            result = func(target, forms, delay)
        elif mod_id == "recon":
            result = func(target, deep=False)
        elif mod_id == "subdomain":
            domain = urlparse(target).hostname
            result = func(domain)
        elif mod_id == "secrets":
            import httpx
            try:
                resp = httpx.get(target, timeout=10, verify=False)
                result = func(target, resp.text)
            except Exception:
                result = []
        elif mod_id == "endpoint_fuzzer":
            import asyncio
            try:
                result = asyncio.run(func(target))
            except Exception:
                result = func(target)
        elif mod_id == "spray":
            host = urlparse(target).hostname
            open_ports = []
            if memory.recon_data and isinstance(memory.recon_data, dict):
                open_ports = memory.recon_data.get("open_ports", [])
            if open_ports:
                result = func(host, open_ports)
            else:
                log_warning("  spray: no open ports from recon, skipping")
                result = []
        elif mod_id == "subdomain_takeover":
            result = func(target)
        else:
            result = func(target)

        elapsed = time.time() - start

        # Extract metadata
        if mod_id == "tech_detect" and isinstance(result, list):
            memory.tech_stack = result
            for t in result:
                if isinstance(t, dict) and t.get("type") == "waf":
                    memory.waf_detected = t.get("name", "Unknown WAF")

        if mod_id == "recon" and isinstance(result, dict):
            memory.recon_data = result

        # Store findings
        if isinstance(result, list):
            findings = [r for r in result if isinstance(r, dict) and r.get("type")]
            memory.add_findings(findings)

        # Anti-shallow: count probes
        if isinstance(result, list):
            probe_count = len(result)
        elif isinstance(result, dict) and "error" not in result:
            probe_count = 1
        else:
            probe_count = 0
        if hasattr(memory, 'depth_tracker') and memory.depth_tracker:
            memory.depth_tracker.record_probe(mod_id, max(probe_count, 1))
        elif hasattr(memory, '_orchestrator_depth'):
            memory._orchestrator_depth.record_probe(mod_id, max(probe_count, 1))

        log_success(f"  ✓ {mod_id} ({elapsed:.1f}s)")
        return result

    except Exception as e:
        log_error(f"  ✗ {mod_id}: {e}")
        return {"error": str(e)}
