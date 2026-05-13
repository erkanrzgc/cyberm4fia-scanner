"""Extra phase runners (param discovery, API injection, GraphQL, HAR, nuclei,
git history, asset search, guaranteed checks)."""

from __future__ import annotations


# ── Hidden Parameter Discovery runner ────────────────────────────────────────

def _run_param_discovery(state):
    """Discover hidden parameters on crawled endpoints and inject into scan URLs."""
    import asyncio
    from modules.param_discovery import async_discover_params, build_enriched_urls
    from core.module_registry import canonicalize_scan_urls

    urls = state.get("urls_to_scan", [])
    delay = state.get("delay", 0)
    options = state.get("options", {})

    try:
        discovered = asyncio.run(
            async_discover_params(urls, delay, options)
        )
    except RuntimeError:
        # Already inside an event loop
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                asyncio.run,
                async_discover_params(urls, delay, options),
            )
            discovered = future.result()

    if discovered:
        enriched = build_enriched_urls(discovered)
        if enriched:
            state["urls_to_scan"] = canonicalize_scan_urls(
                state["urls_to_scan"] + enriched
            )
        # Store discovered endpoints for API injection module
        state["discovered_api_endpoints"] = discovered

    return []


# ── API Body Injection runner ────────────────────────────────────────────────

def _run_api_injection(state):
    """Run API body injection tests on discovered endpoints."""
    from modules.api_inject import scan_api_injection

    url = state.get("url", "")
    delay = state.get("delay", 0)
    options = state.get("options", {})

    # Gather API endpoints from various discovery sources
    api_endpoints = []

    # From dynamic crawler
    for scan_url in state.get("urls_to_scan", []):
        from modules.api_inject import _detect_api_endpoint
        if _detect_api_endpoint(scan_url):
            api_endpoints.append(scan_url)

    # From param discovery
    for disc in state.get("discovered_api_endpoints", []):
        api_endpoints.append(disc["url"])

    if not api_endpoints:
        return []

    return scan_api_injection(url, api_endpoints, delay, options)


# ── GraphQL Audit runner ─────────────────────────────────────────────────────

def _run_graphql_audit(state):
    """Run advanced GraphQL checks (depth DoS, batching, suggestions, GET CSRF).

    Lives next to api_injection because it shares the same target shape:
    a base URL that may or may not host a /graphql endpoint. The module
    detects the endpoint itself and short-circuits if none is alive.
    """
    from modules.graphql_audit import scan_graphql_audit

    url = state.get("url", "")
    delay = state.get("delay", 0)
    options = state.get("options", {})

    return scan_graphql_audit(url, delay, options)


# ── HAR Analysis runner ─────────────────────────────────────────────────────

def _run_har_analysis(state):
    """Analyze HAR recording to extract API endpoints, auth tokens, and hidden endpoints."""
    har_path = state.get("har_path")
    if not har_path or not state["options"].get("har_output"):
        return []

    from utils.har_analyzer import analyze_har_file
    from utils.colors import log_success, log_warning

    result = analyze_har_file(har_path, base_url=state["url"])
    if not result:
        log_warning("HAR analysis produced no results")
        return []

    endpoints = result.get("endpoints", [])
    findings = result.get("findings", [])

    state["har_endpoints"] = endpoints
    state["har_findings"] = findings

    summary = result.get("summary", {})
    log_success(
        f"HAR analysis complete: {summary.get('api_requests', 0)} API requests, "
        f"{len(endpoints)} unique endpoints"
    )

    discovered_eps = state.get("discovered_api_endpoints", [])
    if isinstance(discovered_eps, list):
        from modules.api_scanner import _dedupe_api_endpoints
        discovered_eps.extend(endpoints)
        state["discovered_api_endpoints"] = _dedupe_api_endpoints(discovered_eps)

    return findings


# ── Nuclei community-template runner ────────────────────────────────────────

def _run_nuclei(state):
    """Run projectdiscovery/nuclei templates against the target."""
    from modules.nuclei_runner import scan_with_nuclei
    from utils.colors import log_info

    options = state.get("options", {}) or {}
    if not options.get("nuclei"):
        return []

    log_info("Running nuclei community-template scan")
    observations = scan_with_nuclei(state["url"], options=options)
    # Nuclei output is rich; surface as findings via standard normalization path.
    return [obs.to_dict() for obs in observations]


# ── Git history secret scanner runner ───────────────────────────────────────

def _run_git_history(state):
    """White-box git history scan + best-effort exposed-.git probe."""
    from modules.git_history_scan import scan_git_history
    from utils.colors import log_info

    options = state.get("options", {}) or {}
    if not options.get("git_history") and not options.get("git_history_path"):
        return []

    log_info("Running git-history secret scan")
    observations = scan_git_history(state["url"], options=options)
    return [obs.to_dict() for obs in observations]


# ── Multi-provider asset search runner ──────────────────────────────────────

def _run_asset_search(state):
    """Query Censys/ZoomEye/FOFA/Onyphe/Netlas/FullHunt/LeakIX in parallel."""
    from utils.asset_search import lookup_all_providers, merge_results
    from utils.colors import log_info, log_success

    options = state.get("options", {}) or {}
    if not options.get("asset_search"):
        return []

    log_info("Running multi-provider asset search")
    results = lookup_all_providers(state["url"])
    if not results:
        return []
    merged = merge_results(results)
    state["asset_search_data"] = merged
    log_success(
        f"AssetSearch: {len(merged['providers'])} providers, "
        f"{len(merged['ports'])} ports, {len(merged['vulns'])} vulns"
    )
    return []


# ── Guaranteed Security Checks runner ────────────────────────────────────────

def _run_guaranteed_checks(state):
    """Run guaranteed security checks that produce findings on any target."""
    from modules.guaranteed_checks import scan_guaranteed

    url = state.get("url", "")
    delay = state.get("delay", 0)
    options = state.get("options", {})

    return scan_guaranteed(url, delay, options)
