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
from core.module_registry import iter_async_module_specs


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
    tasks = []
    for spec in iter_async_module_specs(options):
        tasks.append(
            _run_module(
                spec.name,
                spec.loader(),
                *spec.build_args(scan_url, forms, delay),
            )
        )

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
