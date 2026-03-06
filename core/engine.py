"""
cyberm4fia-scanner — Async Scan Engine

Replaces ThreadPoolExecutor-based module orchestration with asyncio.
Runs vulnerability scan modules concurrently using asyncio.to_thread()
for CPU-bound scan functions, and native async for I/O-bound operations.

Usage:
    from core.engine import run_modules_async

    vulns = run_modules_async(scan_url, forms, delay, options)
"""

import asyncio
from utils.colors import log_info, log_warning


async def _run_module(name: str, func, *args):
    """Run a scan module in a thread (they're sync/CPU-bound)."""
    try:
        result = await asyncio.to_thread(func, *args)
        return name, result or []
    except Exception as e:
        log_warning(f"Module {name} error: {e}")
        return name, []


async def run_modules_async_impl(
    scan_url: str,
    forms: list,
    delay: float,
    options: dict,
    progress_callback=None,
):
    """
    Run all enabled scan modules concurrently using asyncio.

    Args:
        scan_url: Target URL
        forms: HTML forms found on the page
        delay: Request delay
        options: Scan options dict
        progress_callback: Optional callable(module_name) for progress updates

    Returns:
        list of vulnerability dicts
    """
    # Lazy imports to avoid circular dependencies
    from modules.xss import scan_xss
    from modules.sqli import scan_sqli, scan_blind_sqli
    from modules.lfi import scan_lfi
    from modules.rfi import scan_rfi
    from modules.cmdi import scan_cmdi
    from modules.ssrf import scan_ssrf
    from modules.ssti import scan_ssti
    from modules.xxe import scan_xxe
    from modules.dom_xss import scan_dom_xss
    from modules.dom_static import scan_dom_static

    tasks = []

    # Phase 1: Error-based modules (can run fully in parallel)
    if options.get("xss"):
        tasks.append(_run_module("XSS", scan_xss, scan_url, forms, delay))
    if options.get("sqli"):
        tasks.append(_run_module("SQLi", scan_sqli, scan_url, forms, delay))
    if options.get("lfi"):
        tasks.append(_run_module("LFI", scan_lfi, scan_url, forms, delay))
    if options.get("rfi"):
        tasks.append(_run_module("RFI", scan_rfi, scan_url, forms, delay))
    if options.get("cmdi"):
        tasks.append(_run_module("CMDi", scan_cmdi, scan_url, forms, delay))
    if options.get("ssrf"):
        tasks.append(_run_module("SSRF", scan_ssrf, scan_url, forms, delay))
    if options.get("ssti"):
        tasks.append(_run_module("SSTI", scan_ssti, scan_url, forms, delay))
    if options.get("xxe"):
        tasks.append(_run_module("XXE", scan_xxe, scan_url, forms, delay))

    # DOM modules
    if options.get("dom_xss"):
        tasks.append(_run_module("DOM-Static", scan_dom_static, scan_url))
        tasks.append(_run_module("DOM-XSS", scan_dom_xss, scan_url))

    # Template engine
    if options.get("templates"):
        from modules.template_engine import run_templates

        tasks.append(_run_module("Templates", run_templates, scan_url, delay))

    if not tasks:
        return []

    log_info(f"Running {len(tasks)} modules concurrently (async)...")

    all_vulns = []
    completed = 0

    # Run all tasks concurrently
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, Exception):
            log_warning(f"Module error: {result}")
            continue

        name, vulns = result
        completed += 1
        if vulns:
            all_vulns.extend(vulns)
            log_info(f"  {name}: {len(vulns)} finding(s)")
        if progress_callback:
            progress_callback(name)

    # Phase 2: Blind/timing-based modules (sequential for accuracy)
    if options.get("sqli"):
        try:
            blind_vulns = await asyncio.to_thread(
                scan_blind_sqli, scan_url, forms, delay
            )
            if blind_vulns:
                all_vulns.extend(blind_vulns)
        except Exception as e:
            log_warning(f"Blind SQLi error: {e}")

    return all_vulns


def run_modules_async(scan_url, forms, delay, options, progress_callback=None):
    """
    Synchronous wrapper — call from non-async scanner.py code.

    Usage:
        vulns = run_modules_async(scan_url, forms, delay, options)
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Already inside an event loop — use thread pool
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as pool:
            future = pool.submit(
                asyncio.run,
                run_modules_async_impl(
                    scan_url, forms, delay, options, progress_callback
                ),
            )
            return future.result()
    else:
        return asyncio.run(
            run_modules_async_impl(scan_url, forms, delay, options, progress_callback)
        )
