#!/usr/bin/env python3
"""
cyberm4fia-scanner v4.0 (Modular Edition)
Educational Purpose Only | by Erkan
All-in-one: XSS, SQLi, LFI, Command Injection,
DOM XSS, Port Scan, Server Recon

This is the modular version. Uses:
- utils/colors.py for logging
- utils/request.py for HTTP
- modules/ for all scanning and utility functions
"""

import sys
import os
from datetime import datetime
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from utils.colors import (
    Colors,
    print_gradient_banner,
    log_info,
    log_success,
    log_error,
    log_warning,
    set_quiet,
)
from utils.request import (
    BlockedTargetPath,
    Config,  # noqa: F401
    RequestBudgetExceeded,
    ScanCancelled,
    ScanExceptions,
    get_runtime_stats,
    is_url_blocked,
    set_json_output_enabled,
    smart_request,
)

from modules.payloads import XSS_FLAT_PAYLOADS
from utils.tamper import TamperChain, set_tamper_chain
from core.scope import ScopeFilter, set_scope, get_scope
from core.module_registry import canonicalize_scan_urls, run_phase_modules
from core.scan_options import (
    DEFAULT_AI_MODEL,
    build_cli_scan_options,
    get_scan_mode_runtime,
)
from core.session import ScanSession
from core.scan_context import ScanContext
from utils.colors import console, save_console_log
from rich.table import Table
from utils.ai import init_ai, init_dual_ai
from modules.compare import (
    compare_scans,
    print_comparison,
    save_comparison_json,
)

# Re-exported from extracted modules for backward compatibility
from core.cli import parse_args, get_input  # noqa: F401
from core.interactive import (  # noqa: F401
    interactive_menu,
    restore_resume_scan_state,
    summarize_restored_config,
    print_restored_config_summary,
)

def print_summary(vulns, recon_data=None, stats=None):
    """Print an attractive ASCII scan summary using Rich"""
    runtime_stats = get_runtime_stats()

    if stats and stats.get("duration_seconds") is not None:
        duration = f"{stats['duration_seconds']}s"
    elif runtime_stats.get("start_time"):
        duration_delta = datetime.now() - datetime.fromtimestamp(
            runtime_stats["start_time"]
        )
        duration = str(duration_delta).split(".")[0]
    else:
        duration = "N/A"

    total_requests = (
        stats.get("total_requests")
        if stats and stats.get("total_requests") is not None
        else runtime_stats["total_requests"]
    )
    waf_blocks = (
        stats.get("waf_blocks")
        if stats and stats.get("waf_blocks") is not None
        else runtime_stats["waf_blocks"]
    )
    retries = (
        stats.get("retries")
        if stats and stats.get("retries") is not None
        else runtime_stats["retries"]
    )
    errors = (
        stats.get("errors")
        if stats and stats.get("errors") is not None
        else runtime_stats["errors"]
    )

    table = Table(
        title="🛡️ cyberm4fia-scanner SCAN SUMMARY 🛡️",
        title_style="bold cyan",
        border_style="cyan",
    )

    table.add_column("Metric", style="white", justify="right")
    table.add_column("Value", style="bold green")

    table.add_row("Duration", duration)
    table.add_row("Total Requests", str(total_requests))
    table.add_row("WAF Blocks", f"[red]{waf_blocks}[/red]")
    table.add_row("Request Retries", str(retries))
    table.add_row("Network Errors", f"[red]{errors}[/red]")

    if recon_data:
        table.add_section()
        ports = recon_data.get("open_ports", [])
        if ports:
            services = ", ".join([f"{p['port']}/{p['service']}" for p in ports])
            table.add_row("Open Ports", services)

        missing = recon_data.get("missing_headers", 0)
        total = recon_data.get("total_headers", 0)
        h_color = "[red]" if missing > 4 else "[yellow]"
        table.add_row("Missing Headers", f"{h_color}{missing}/{total}[/]")

    table.add_section()

    if not vulns:
        table.add_row("Vulnerabilities", "[bold green]0 (Secure)[/bold green]")
        console.print(table)
        return

    # Tally vulnerabilities
    v_counts = {}
    for v in vulns:
        vtype = v.get("type", "Unknown")
        v_counts[vtype] = v_counts.get(vtype, 0) + 1

    table.add_row("Total Vulnerabilities", f"[bold red]{len(vulns)}[/bold red]")
    console.print(table)

    # Detailed Vuln Table
    vuln_table = Table(title="Detected Vulnerabilities", border_style="red")
    vuln_table.add_column("Type", style="bold red")
    vuln_table.add_column("Target / Field", style="yellow")
    vuln_table.add_column("Payload / Details", style="white")

    for v in vulns:
        vtype = v.get("type", "Unknown")
        if vtype == "Template":
            vuln_table.add_row(
                f"{vtype} ({v.get('id')})", v.get("url", ""), v.get("name", "")
            )
        else:
            details = v.get("payload") or v.get("evidence") or v.get("description") or v.get("issue") or ""
            vuln_table.add_row(
                vtype,
                f"{v.get('url', '')} [{v.get('field', 'URL')}]",
                str(details),
            )

    console.print(vuln_table)

def _load_target_urls(target_list_path):
    """Load target URLs from a file, normalizing missing schemes."""
    target_urls = []
    if not target_list_path:
        return target_urls

    try:
        with open(target_list_path, "r") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if not line.startswith(("http://", "https://")):
                    line = "http://" + line
                target_urls.append(line)
    except FileNotFoundError:
        log_error(f"Target list not found: {target_list_path}")
        sys.exit(1)

    log_info(f"Loaded {len(target_urls)} targets from {target_list_path}")
    return target_urls

def _target_session_file(session_file, url):
    """Derive a target-specific session filename for multi-target scans."""
    root, ext = os.path.splitext(session_file)
    if not ext:
        ext = ".json"

    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc.split(":")[0] or "target"
    safe_host = host.replace(".", "_").replace(":", "_")
    return f"{root}__{safe_host}{ext}"

def _session_has_saved_state(session):
    """Return whether a session contains persisted target data."""
    return bool(
        session.data.get("target")
        or session.data.get("options")
        or session.data.get("scanned_urls")
    )

def scan_target(
    url,
    mode,
    delay,
    options,
    runtime_options,
    session=None,
    wordlist_file="wordlists/api_endpoints.txt",
    prompt_input=None,
    summary_printer=print_summary,
    persist_console_log=True,
):
    """Run the full scan pipeline for a single target with isolated runtime state."""
    prompt_input = prompt_input or get_input
    scan_ctx = ScanContext(
        url,
        mode,
        delay,
        options=runtime_options,
        session_options=options,
        session=session,
    )

    with scan_ctx.activate():
        target_host = scan_ctx.target_host
        scan_dir = scan_ctx.scan_dir
        log_file = scan_ctx.log_file

        if options.get("cookie"):
            cookie_val = options["cookie"].strip("\"'")
            log_success(f"Cookie set: {cookie_val[:30]}...")

        log_info(f"Target: {url} | Mode: {mode.title()}")

        # ── Campaign & Intelligence Integration (0-Day Machine) ──
        campaign = None
        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        campaign_id = ""
        try:
            from utils.campaign_manager import CampaignManager
            cm = CampaignManager()
            campaign = cm.create_campaign(url)
            campaign_id = campaign.id
        except Exception:
            pass

        # Pre-scan intelligence briefing
        try:
            from utils.scan_intelligence import get_scan_intelligence
            intel = get_scan_intelligence()
            target_profile = intel.get_target_profile(url)
            if target_profile.total_scans > 0:
                log_info(
                    f"\U0001f9e0 Intelligence: {target_profile.total_scans} past scans, "
                    f"{target_profile.total_findings} findings, "
                    f"WAF: {target_profile.waf_name or 'none'}"
                )
        except Exception:
            pass

        phase_state = {
            "url": url,
            "mode": mode,
            "delay": delay,
            "options": options,
            "target_host": target_host,
            "scan_dir": scan_dir,
            "crawled_forms": [],
            "urls_to_scan": [],
            "recon_data": None,
            "all_vulns": [],
            "wordlist_file": wordlist_file,
            "summary_printer": summary_printer,
            "report_stats_factory": scan_ctx.report_stats,
            "summary_stats_factory": scan_ctx.collect_stats,
            "scan_id": scan_id,
            "campaign_id": campaign_id,
        }

        pre_scan_vulns = run_phase_modules("pre_scan", options, phase_state)
        phase4_vulns = run_phase_modules("phase4_target", options, phase_state)

        # Get URLs to scan
        urls_to_scan = [url]
        crawled_forms = []
        phase_state["urls_to_scan"] = urls_to_scan
        phase_state["crawled_forms"] = crawled_forms
        run_phase_modules("discovery_seed", options, phase_state)
        urls_to_scan = phase_state["urls_to_scan"]
        target_check_vulns = run_phase_modules("target_checks", options, phase_state)
        run_phase_modules("discovery_expand", options, phase_state)
        urls_to_scan = phase_state["urls_to_scan"]
        crawled_forms = phase_state["crawled_forms"]
        urls_to_scan = canonicalize_scan_urls(urls_to_scan)

        log_info(f"Loaded {len(XSS_FLAT_PAYLOADS)} payloads")

        # Scan each URL
        all_vulns = pre_scan_vulns + target_check_vulns + phase4_vulns

        # Apply scope filter to crawled URLs
        scope = get_scope()
        if scope.active:
            urls_to_scan = scope.filter_urls(urls_to_scan)

        blocked_urls = [candidate for candidate in urls_to_scan if is_url_blocked(candidate)]
        if blocked_urls:
            for blocked_url in blocked_urls:
                log_info(f"Skipping risky path by blacklist: {blocked_url}")
            urls_to_scan = [candidate for candidate in urls_to_scan if not is_url_blocked(candidate)]

        # Session: save target info and filter already-scanned URLs
        urls_to_scan = scan_ctx.prepare_urls_for_scan(urls_to_scan)

        for scan_url in urls_to_scan:
            console.print(f"[bold cyan]Scanning:[/bold cyan] {scan_url}")

            try:
                resp = smart_request("get", scan_url)
                soup = BeautifulSoup(resp.content, "lxml")
                forms = soup.find_all("form")
                # Note: crawled_forms are dicts (not BS Tags), so we don't
                # merge them into 'forms' to avoid AttributeError on find_all().
                # Crawled URLs are already in urls_to_scan and will be parsed
                # independently when visited.

                page_state = {
                    "scan_url": scan_url,
                    "response": resp,
                    "forms": forms,
                    "delay": delay,
                    "options": options,
                    "all_vulns": list(all_vulns),
                }
                all_vulns.extend(run_phase_modules("page_hooks", options, page_state))

                # Phase 1: Run error-based modules concurrently (async engine)
                from core.engine import run_modules_async

                module_vulns = run_modules_async(scan_url, forms, delay, options)
                all_vulns.extend(module_vulns)

                # Categorize results for post-processing
                sqli_vulns = [
                    v for v in module_vulns if v.get("type", "").startswith("SQLi")
                ]
                xss_vulns = [
                    v
                    for v in module_vulns
                    if "XSS" in v.get("type", "") or "DOM" in v.get("type", "")
                ]
                cmdi_vulns = [
                    v for v in module_vulns if v.get("type", "").startswith("CMDi")
                ]

                processor_state = {
                    "scan_url": scan_url,
                    "forms": forms,
                    "delay": delay,
                    "options": options,
                    "xss_vulns": xss_vulns,
                    "sqli_vulns": sqli_vulns,
                    "cmdi_vulns": cmdi_vulns,
                    "prompt_input": prompt_input,
                    "all_vulns": list(all_vulns),
                }
                all_vulns.extend(
                    run_phase_modules("result_processors", options, processor_state)
                )

            except (RequestBudgetExceeded, ScanCancelled) as e:
                log_error(str(e))
                break
            except BlockedTargetPath as e:
                log_info(str(e))
            except ScanExceptions as e:
                log_error(f"Failed to scan {scan_url}: {e}")

            # Session: mark URL as done and save incrementally
            scan_ctx.mark_url_done(scan_url)

        # Process OOB callbacks
        all_vulns.extend(scan_ctx.wait_for_oob_hits(wait_seconds=15))

        # ──── Phase 5 / 7 registry-backed post-scan modules ────
        # Note: SSTI and XXE already run via engine (core/engine.py)
        # so they are NOT called again here to avoid duplicates.
        phase_state["urls_to_scan"] = urls_to_scan
        phase_state["crawled_forms"] = crawled_forms
        phase_state["all_vulns"] = list(all_vulns)
        all_vulns.extend(run_phase_modules("post_scan", options, phase_state))
        phase_state["all_vulns"] = list(all_vulns)
        run_phase_modules("result_cleanup", options, phase_state)
        run_phase_modules("analysis", options, phase_state)
        all_vulns = phase_state["all_vulns"]
        run_phase_modules("reporting", options, phase_state)

        # Session: save final state
        scan_ctx.finalize_session(
            all_vulns,
            phase_state.get("finding_count", len(all_vulns)),
        )

        log_success(f"Log saved: {log_file}")
        if persist_console_log:
            save_console_log()

        # ── Validation Pipeline (0-Day Machine hallucination gates) ──
        try:
            from utils.validation_pipeline import ValidationPipeline
            pipeline = ValidationPipeline(verify_replay=options.get("verify", False))
            validated, suspected = pipeline.validate_batch(all_vulns)

            v_count = len(validated)
            s_count = len(suspected)
            if v_count + s_count > 0:
                log_info(
                    f"\U0001f50d Validation: {v_count} confirmed, {s_count} suspected (hallucination bin)"
                )

            # Store in campaign
            if campaign:
                try:
                    cm = CampaignManager()
                    if validated:
                        cm.add_findings(campaign.id, validated, validated=True)
                    if suspected:
                        cm.add_findings(campaign.id, suspected, validated=False)
                except Exception:
                    pass
        except Exception:
            validated = all_vulns
            suspected = []

        # ── Complete campaign ──
        if campaign:
            try:
                duration = 0.0
                try:
                    from utils.request import get_runtime_stats as _grs
                    rs = _grs()
                    if rs.get("start_time"):
                        duration = (datetime.now() - datetime.fromtimestamp(rs["start_time"])).total_seconds()
                except Exception:
                    pass
                cm = CampaignManager()
                cm.complete_campaign(campaign.id, duration=duration)
            except Exception:
                pass

        from utils.finding import build_scan_artifacts

        artifacts = phase_state.get("scan_artifacts")
        if artifacts:
            observations, findings, attack_paths = artifacts["observations"], artifacts["findings"], artifacts["attack_paths"]
        else:
            built_artifacts = build_scan_artifacts(all_vulns)
            observations = built_artifacts["observations"]
            findings = built_artifacts["findings"]
            attack_paths = built_artifacts["attack_paths"]

        finding_count = phase_state.get("finding_count", len(findings))
        stats = scan_ctx.collect_stats(finding_count)
        return {
            "url": url,
            "mode": mode,
            "scan_dir": scan_dir,
            "log_file": log_file,
            "vulnerabilities": all_vulns,
            "observations": [obs.to_dict() for obs in observations],
            "findings": [finding.to_dict() for finding in findings],
            "attack_paths": [path.to_dict() for path in attack_paths],
            "recon_data": phase_state.get("recon_data"),
            "stats": stats,
            "total_vulns": finding_count,
            "campaign_id": campaign_id,
            "validated_count": len(validated),
            "suspected_count": len(suspected),
        }

def main():
    """Main scanner function"""
    print_gradient_banner()

    args = parse_args()

    # Quiet mode
    if args.quiet:
        set_quiet(True)

    # API server mode
    if args.api:
        from api_server import start_api_server

        start_api_server(port=args.port)
        return

    # Scan comparison mode
    if args.compare:
        result = compare_scans(args.compare[0], args.compare[1])
        print_comparison(result)
        save_comparison_json(result, "comparison_report.json")
        return

    # Proxy Interceptor mode
    if getattr(args, "proxy_listen", None):
        if not getattr(args, "scope_proxy", None):
            log_error("You must provide --scope-proxy <domain> when using --proxy-listen")
            sys.exit(1)
        from modules.proxy_interceptor import start_proxy
        start_proxy(listen_port=args.proxy_listen, scope=args.scope_proxy)
        return

    provided_dests = getattr(args, "_provided_dests", set())

    url_from_args = getattr(args, "target", "") or getattr(args, "url", "") or ""
    cli_flags = provided_dests - {"url", "quiet"}
    is_cli_mode = bool(cli_flags) or bool(getattr(args, "target_list", None)) or bool(getattr(args, "resume", None))

    if is_cli_mode:
        url = url_from_args
        if url and not url.startswith(("http://", "https://")):
            url = "http://" + url

        mode, delay, threads = get_scan_mode_runtime(args.mode)

        if args.threads:
            threads = args.threads

        options = build_cli_scan_options(args, threads)
        target_urls = _load_target_urls(getattr(args, "target_list", ""))

        if options.get("resume") and not target_urls:
            session = ScanSession.load(options["resume"])
            restored_target, mode, delay, options = restore_resume_scan_state(
                session,
                options,
                provided_dests=provided_dests,
                mode_override=args.mode if "mode" in provided_dests else None,
            )
            if restored_target:
                url = restored_target
                log_info(f"Resuming scan on {url}")
            if not url:
                log_error("Resume session does not contain a target URL.")
                sys.exit(1)
            print_restored_config_summary(url, mode, options, provided_dests)
        else:
            session = None

        if not target_urls:
            if not url:
                log_error("No target URL provided.")
                sys.exit(1)
            target_urls = [url]

    else:
        try:
            url, mode, delay, options = interactive_menu(initial_url=url_from_args)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Cancelled{Colors.END}")
            sys.exit(0)
        session = None
        target_urls = [url]

    set_json_output_enabled(options.get("json_output"))

    # Initialize tamper chain
    if options.get("tamper"):
        tamper_names = [t.strip() for t in options["tamper"].split(",") if t.strip()]
        chain = TamperChain(tamper_names)
        set_tamper_chain(chain)

    # Initialize scope filter
    if options.get("scope") or options.get("exclude"):
        include = (
            [p.strip() for p in options["scope"].split(",") if p.strip()]
            if options.get("scope")
            else []
        )
        exclude = (
            [p.strip() for p in options["exclude"].split(",") if p.strip()]
            if options.get("exclude")
            else []
        )
        scope = ScopeFilter(include=include, exclude=exclude)
        set_scope(scope)

    multi_target = len(target_urls) > 1

    # Initialize session (resume or new)
    if not multi_target and session is None and options.get("resume"):
        session = ScanSession.load(options["resume"])
        if session.data.get("target"):
            url = session.data["target"]
            log_info(f"Resuming scan on {url}")
    elif not multi_target and session is None and options.get("session"):
        session = ScanSession(options["session"])

    # Initialize AI logic globally if enabled (CLI or Interactive)
    if options.get("ai"):
        nvidia_api_key = options.get("nvidia_api_key", "").strip()
        # Fall back to env if --nvidia-api-key wasn't passed.
        if not nvidia_api_key:
            nvidia_api_key = os.environ.get("NVIDIA_API_KEY", "").strip()
        if not nvidia_api_key:
            log_warning(
                "AI requested (--ai) but NVIDIA_API_KEY is not set. "
                "Add it to .env (NVIDIA_API_KEY=...) or pass --nvidia-api-key. "
                "AI-powered checks will be silently disabled. "
                "Get a key at https://build.nvidia.com/"
            )
        else:
            os.environ["NVIDIA_API_KEY"] = nvidia_api_key
            init_ai(
                model=options.get("ai_model", DEFAULT_AI_MODEL),
                api_key=nvidia_api_key,
            )
            # Initialize dual-model system (WhiteRabbitNeo + Qwen3-Coder)
            init_dual_ai(api_key=nvidia_api_key)

    # If proxy_listen was enabled interactively, start it in the background
    if options.get("proxy_listen"):
        from urllib.parse import urlparse
        import threading
        from modules.proxy_interceptor import start_proxy

        proxy_target = target_urls[0] if target_urls else url
        scope = urlparse(proxy_target).netloc.split(":")[0]
        port = 8081
        t = threading.Thread(target=start_proxy, args=(port, scope), daemon=True)
        t.start()
        # Allow proxy a second to bind
        import time
        time.sleep(1)

    if options.get("proxy_url"):
        log_info(f"Proxy set: {options['proxy_url']}")

    # Run scan for each target
    mode_override = args.mode if "mode" in provided_dests else None
    
    if options.get("agent"):
        from utils.agent_framework import AgentOrchestrator
        for target_idx, current_url in enumerate(target_urls):
            if len(target_urls) > 1:
                console.print(
                    f"\n[bold magenta]━━━ Agent Mission {target_idx + 1}/{len(target_urls)}: {current_url} ━━━[/bold magenta]"
                )
            orchestrator = AgentOrchestrator()
            console.print(f"[bold cyan][*] Starting multi-agent autonomous mission for {current_url}[/bold cyan]")
            orchestrator.run_mission(current_url)
        return

    for target_idx, current_url in enumerate(target_urls):
        current_mode = mode
        current_delay = delay
        current_options = dict(options)
        current_session = session

        if multi_target and options.get("resume"):
            resume_path = _target_session_file(options["resume"], current_url)
            current_session = ScanSession.load(resume_path)
            if _session_has_saved_state(current_session):
                (
                    restored_target,
                    current_mode,
                    current_delay,
                    current_options,
                ) = restore_resume_scan_state(
                    current_session,
                    dict(options),
                    provided_dests=provided_dests,
                    mode_override=mode_override,
                )
                if restored_target:
                    current_url = restored_target
            current_options["resume"] = current_session.session_file or resume_path
            current_options["session"] = ""
        elif multi_target and options.get("session"):
            current_session = ScanSession(
                _target_session_file(options["session"], current_url)
            )
            current_options["session"] = current_session.session_file or ""
            current_options["resume"] = ""

        runtime_options = dict(current_options)

        if len(target_urls) > 1:
            console.print(
                f"\n[bold magenta]━━━ Target {target_idx + 1}/{len(target_urls)}: {current_url} ━━━[/bold magenta]"
            )
        scan_target(
            current_url,
            current_mode,
            current_delay,
            current_options,
            runtime_options,
            session=current_session,
            wordlist_file=current_options.get(
                "wordlist_file",
                getattr(args, "wordlist_file", "wordlists/api_endpoints.txt"),
            ),
        )

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted{Colors.END}")
        sys.exit(0)
