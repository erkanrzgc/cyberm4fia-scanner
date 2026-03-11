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
import argparse
from datetime import datetime
from urllib.parse import urlparse

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bs4 import BeautifulSoup  # noqa: E402

from utils.colors import (  # noqa: E402
    Colors,
    print_gradient_banner,
    log_info,
    log_success,
    log_error,
    set_quiet,
)
from utils.request import (  # noqa: E402
    BlockedTargetPath,
    Config,
    RequestBudgetExceeded,
    ScanCancelled,
    get_runtime_stats,
    is_url_blocked,
    set_json_output_enabled,
    smart_request,
)

from modules.payloads import XSS_FLAT_PAYLOADS  # noqa: E402
from utils.tamper import TamperChain, set_tamper_chain  # noqa: E402
from core.scope import ScopeFilter, set_scope, get_scope  # noqa: E402
from core.module_registry import canonicalize_scan_urls, run_phase_modules  # noqa: E402
from core.scan_options import (  # noqa: E402
    API_SPEC_PROMPT,
    ATTACK_PROFILE_SPECS,
    DEFAULT_AI_MODEL,
    INTERACTIVE_CUSTOM_PROMPT_GROUPS,
    INTERACTIVE_RESUME_PROMPT,
    INTERACTIVE_SCAN_MODE_SPECS,
    JSON_OUTPUT_PROMPT,
    add_parser_arguments,
    apply_interactive_prompt_specs,
    apply_profile_preset,
    build_cli_scan_options,
    build_default_scan_options,
    get_attack_profile_spec,
    get_attack_profile_recommended_prompt_specs,
    get_interactive_scan_mode_spec,
    get_interactive_runtime_prompt_specs,
    normalize_runtime_options,
    get_scan_mode_runtime,
)
from core.session import ScanSession  # noqa: E402
from core.scan_context import ScanContext  # noqa: E402
from utils.colors import console, save_console_log
from rich.table import Table
from rich.panel import Panel
from rich.markup import escape
from utils.ai import init_ai  # noqa: E402
from modules.compare import (  # noqa: E402
    compare_scans,
    print_comparison,
    save_comparison_json,
)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="cyberm4fia-scanner")
    add_parser_arguments(parser)
    effective_argv = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(effective_argv)
    provided_dests = set()
    for token in effective_argv:
        option_token = token.split("=", 1)[0]
        action = parser._option_string_actions.get(option_token)
        if action:
            provided_dests.add(action.dest)
    setattr(args, "_provided_dests", provided_dests)
    return args


def get_input(prompt, default=""):
    """Get user input with default value using rich Console to record it"""
    try:
        val = console.input(f"[bold white]{escape(prompt)}[/] ").strip()
        return val if val else default
    except EOFError:
        return default


def _print_interactive_section(title, subtitle=None):
    """Render a compact section header for the interactive menu."""
    body = f"[bold cyan]{escape(title)}[/]"
    if subtitle:
        body += f"\n[dim]{escape(subtitle)}[/]"
    console.print(Panel.fit(body, border_style="cyan", padding=(0, 2)))


def _print_scan_mode_menu():
    """Render the primary scan mode selector."""
    table = Table(border_style="cyan")
    table.add_column("Choice", style="bold cyan", justify="center")
    table.add_column("Mode", style="bold white")
    table.add_column("Delay", style="magenta", justify="right")
    table.add_column("Threads", style="green", justify="right")
    table.add_column("Use Case", style="white")

    for spec in INTERACTIVE_SCAN_MODE_SPECS:
        table.add_row(
            spec.interactive_choice or "-",
            spec.label,
            f"{spec.delay:.2f}s",
            str(spec.threads),
            spec.description,
        )

    console.print(table)
    console.print(
        "[dim]Lab mode stays available after selecting Normal. Use it only for lab/staging targets.[/]"
    )


def _print_attack_profile_menu():
    """Render attack profile choices in a compact table."""
    table = Table(border_style="cyan")
    table.add_column("Choice", style="bold cyan", justify="center")
    table.add_column("Profile", style="bold white")
    table.add_column("Focus", style="white")

    for spec in ATTACK_PROFILE_SPECS:
        table.add_row(spec.choice, spec.label, spec.description)

    console.print(table)


def _print_preflight_summary(url, mode, profile_spec, options):
    """Render a concise interactive summary before the scan starts."""
    reports = []
    if options.get("json_output"):
        reports.append("json")
    if options.get("html"):
        reports.append("html")
    if options.get("sarif"):
        reports.append("sarif")

    table = Table(title="Interactive Scan Summary", border_style="green")
    table.add_column("Setting", style="bold green", justify="right")
    table.add_column("Value", style="white")
    table.add_row("Target", url)
    table.add_row("Mode", mode.title())
    table.add_row("Profile", profile_spec.label)
    table.add_row("Proxy", options.get("proxy_url") or "-")
    table.add_row("Scope", options.get("scope") or "-")
    table.add_row("Session", options.get("session") or "-")
    table.add_row(
        "Reports",
        ", ".join(reports) if reports else "-",
    )
    console.print(table)


def _resume_override_option_keys(provided_dests):
    """Map explicit CLI args to option keys that should override session values."""
    override_keys = set(provided_dests) & {
        "xss",
        "sqli",
        "lfi",
        "rfi",
        "cmdi",
        "dom_xss",
        "secrets",
        "recon",
        "subdomain",
        "fuzz",
        "ssrf",
        "oob",
        "csrf",
        "cors",
        "header_inject",
        "crawl",
        "passive",
        "cloud",
        "takeover",
        "tech",
        "api_scan",
        "api_spec",
        "ssti",
        "xxe",
        "redirect",
        "spray",
        "email",
        "osint",
        "chain",
        "wordlist",
        "headless",
        "jwt",
        "race",
        "smuggle",
        "proto",
        "deser",
        "bizlogic",
        "cookie",
        "tamper",
        "proxy_url",
        "scope",
        "exclude",
        "session",
        "resume",
        "max_requests",
        "request_timeout",
        "max_host_concurrency",
        "path_blacklist",
        "wordlist_file",
        "threads",
        "exploit",
        "ai",
        "ai_model",
        "proxy_listen",
        "html",
        "sarif",
    }
    if "json" in provided_dests:
        override_keys.add("json_output")
    if "mode" in provided_dests:
        override_keys.add("threads")
    return override_keys


def restore_resume_scan_state(session, options, provided_dests=None, mode_override=None):
    """Restore target, mode and options from a saved session."""
    provided_dests = provided_dests or set()
    restored = session.restore_config(
        default_options=build_default_scan_options(
            threads=options.get("threads", 10),
            ai_model=options.get("ai_model", DEFAULT_AI_MODEL),
        ),
        override_options=options,
        override_keys=_resume_override_option_keys(provided_dests),
    )

    restored_mode = mode_override or restored["mode"] or "normal"
    mode, delay, default_threads = get_scan_mode_runtime(restored_mode)
    restored_options = restored["options"]

    if "threads" not in provided_dests:
        restored_options["threads"] = int(
            restored_options.get("threads", default_threads)
        )

    restored_options["resume"] = session.session_file or restored_options.get(
        "resume", ""
    )
    normalize_runtime_options(restored_options)

    return restored.get("target", ""), mode, delay, restored_options


def summarize_restored_config(target, mode, options, provided_dests=None):
    """Return a compact summary of restored scan configuration."""
    provided_dests = provided_dests or set()
    enabled_checks = sorted(
        key.replace("_", "-")
        for key, value in options.items()
        if isinstance(value, bool)
        and value
        and key
        not in {"html", "sarif", "json_output", "ai", "proxy_listen", "templates", "exploit"}
    )
    reports = []
    if options.get("json_output"):
        reports.append("json")
    if options.get("html"):
        reports.append("html")
    if options.get("sarif"):
        reports.append("sarif")

    summary = {
        "Target": target or "-",
        "Mode": mode,
        "Threads": str(options.get("threads", "-")),
        "Enabled Checks": str(len(enabled_checks)),
        "Sample Checks": ", ".join(enabled_checks[:6]) if enabled_checks else "-",
        "Proxy": options.get("proxy_url") or "-",
        "Scope": options.get("scope") or "-",
        "Exclude": options.get("exclude") or "-",
        "Request Budget": str(options.get("max_requests") or "-"),
        "Timeout": str(options.get("request_timeout") or "-"),
        "Host Concurrency": str(options.get("max_host_concurrency") or "-"),
        "Path Blacklist": options.get("path_blacklist") or "-",
        "Cookie": "set" if options.get("cookie") else "-",
        "Tamper": options.get("tamper") or "-",
        "Exploit Follow-up": "enabled" if options.get("exploit") else "disabled",
        "Session File": options.get("resume") or options.get("session") or "-",
        "Reports": ", ".join(reports) if reports else "-",
        "AI": "enabled" if options.get("ai") else "disabled",
    }

    if provided_dests:
        override_keys = sorted(_resume_override_option_keys(provided_dests))
        if override_keys:
            summary["CLI Overrides"] = ", ".join(override_keys)

    return summary


def print_restored_config_summary(target, mode, options, provided_dests=None):
    """Print a concise table of restored scan configuration."""
    summary = summarize_restored_config(target, mode, options, provided_dests)
    table = Table(title="Resumed Scan Config", border_style="cyan")
    table.add_column("Setting", style="bold cyan", justify="right")
    table.add_column("Value", style="white")

    for key, value in summary.items():
        table.add_row(key, str(value))

    console.print(table)


def interactive_menu():
    """Interactive menu for scan options"""
    _print_interactive_section(
        "Interactive Setup",
        "Configure target, mode, profile, and runtime behavior.",
    )
    url = get_input("\n[?] Target URL:", "")

    resume_path = get_input(
        INTERACTIVE_RESUME_PROMPT.prompt,
        INTERACTIVE_RESUME_PROMPT.default,
    )
    if resume_path:
        session = ScanSession.load(resume_path)
        restored_target, mode, delay, options = restore_resume_scan_state(
            session,
            build_default_scan_options(),
        )
        if restored_target:
            url = restored_target
            log_info(f"Resuming scan on {url}")
        if not url:
            log_error("Resume session does not contain a target URL.")
            sys.exit(1)
        set_json_output_enabled(options.get("json_output"))
        print_restored_config_summary(url, mode, options)
        return url, mode, delay, options

    while not url:
        log_error("No URL provided! Please enter a valid URL.")
        url = get_input("\n[?] Target URL:", "")

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # Scan mode
    _print_interactive_section(
        "Scan Mode",
        "Choose the main noise profile for the scan.",
    )
    _print_scan_mode_menu()
    mode_choice = get_input("[?] Choice [1]:", "1")
    selected_mode_spec = get_interactive_scan_mode_spec(mode_choice)
    selected_mode_key = selected_mode_spec.key
    if selected_mode_key == "normal":
        use_lab_mode = get_input(
            "[?] Enable Lab mode? (y/N) [high-noise, lab/staging only]",
            "N",
        ).lower() == "y"
        if use_lab_mode:
            selected_mode_key = "lab"
    mode, delay, threads = get_scan_mode_runtime(selected_mode_key)

    # Attack Profiles
    _print_interactive_section(
        "Attack Profile",
        "Pick the coverage style you want before runtime tweaks.",
    )
    _print_attack_profile_menu()
    profile_choice = get_input(f"[?] Choice [4]:", "4")
    profile_spec = get_attack_profile_spec(profile_choice)

    # Options Dictionary initialization mapping
    options = build_default_scan_options(threads=threads)

    if profile_spec.choice != "5":
        apply_profile_preset(options, profile_spec.choice)
        recommended_prompt_specs = get_attack_profile_recommended_prompt_specs(
            profile_spec.choice,
            options,
        )
        if recommended_prompt_specs:
            _print_interactive_section(
                f"Recommended Extras: {profile_spec.label}",
                "High-signal toggles for the selected profile.",
            )
            apply_interactive_prompt_specs(
                options,
                recommended_prompt_specs,
                get_input,
            )
    else:
        # Profile 5: Custom Choice
        _print_interactive_section(
            "Custom Selection",
            "Choose modules one by one.",
        )
        for section_title, prompt_specs in INTERACTIVE_CUSTOM_PROMPT_GROUPS:
            if section_title != "Custom Selection":
                _print_interactive_section(section_title)
            apply_interactive_prompt_specs(options, prompt_specs, get_input)

    if options.get("api_scan") and not options.get("api_spec"):
        options["api_spec"] = get_input(API_SPEC_PROMPT.prompt, API_SPEC_PROMPT.default)

    runtime_prompt_specs = get_interactive_runtime_prompt_specs(
        selected_mode_key,
        profile_spec.choice,
        options,
    )
    if runtime_prompt_specs:
        _print_interactive_section(
            "Runtime Settings",
            "Connection, scope, session, and output controls.",
        )
        apply_interactive_prompt_specs(options, runtime_prompt_specs, get_input)
    options["ai_model"] = DEFAULT_AI_MODEL
    options["threads"] = threads

    options["json_output"] = bool(
        get_input(JSON_OUTPUT_PROMPT.prompt, JSON_OUTPUT_PROMPT.default).lower() == "y"
    )
    normalize_runtime_options(options)
    set_json_output_enabled(options["json_output"])
    _print_preflight_summary(url, mode, profile_spec, options)

    return url, mode, delay, options


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


def scan_target(url, mode, delay, options, runtime_options, session=None, wordlist_file="wordlists/api_endpoints.txt"):
    """Run the full scan pipeline for a single target with isolated runtime state."""
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
            "summary_printer": print_summary,
            "report_stats_factory": scan_ctx.report_stats,
            "summary_stats_factory": scan_ctx.collect_stats,
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
                    "prompt_input": get_input,
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
            except Exception as e:
                log_error(f"Failed to scan {scan_url}: {e}")

            # Session: mark URL as done and save incrementally
            scan_ctx.mark_url_done(scan_url)

        # Process OOB callbacks
        scan_ctx.wait_for_oob_hits(wait_seconds=15)

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
        save_console_log()


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

    if args.url or args.resume:
        url = args.url or ""
        if url and not url.startswith(("http://", "https://")):
            url = "http://" + url

        provided_dests = getattr(args, "_provided_dests", set())
        mode, delay, threads = get_scan_mode_runtime(args.mode)

        if args.threads:
            threads = args.threads

        # --all flag enables everything
        use_all = getattr(args, "all", False)

        options = build_cli_scan_options(args, threads)

        if options.get("resume"):
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

    else:
        try:
            url, mode, delay, options = interactive_menu()
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Cancelled{Colors.END}")
            sys.exit(0)
        session = None

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

    # Initialize session (resume or new)
    if session is None and options.get("resume"):
        session = ScanSession.load(options["resume"])
        if session.data.get("target"):
            url = session.data["target"]
            log_info(f"Resuming scan on {url}")
    elif session is None and options.get("session"):
        session = ScanSession(options["session"])

    # Initialize AI logic globally if enabled (CLI or Interactive)
    if options.get("ai"):
        init_ai(model=options.get("ai_model", DEFAULT_AI_MODEL))

    # If proxy_listen was enabled interactively, start it in the background
    if options.get("proxy_listen"):
        from urllib.parse import urlparse
        import threading
        from modules.proxy_interceptor import start_proxy
        
        scope = urlparse(url).netloc.split(':')[0]
        port = 8081
        t = threading.Thread(target=start_proxy, args=(port, scope), daemon=True)
        t.start()
        # Allow proxy a second to bind
        import time
        time.sleep(1)

    # Multi-target support: build URL list
    target_urls = []
    if hasattr(args, "target_list") and args.target_list:
        try:
            with open(args.target_list, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if not line.startswith(("http://", "https://")):
                            line = "http://" + line
                        target_urls.append(line)
            log_info(f"Loaded {len(target_urls)} targets from {args.target_list}")
        except FileNotFoundError:
            log_error(f"Target list not found: {args.target_list}")
            sys.exit(1)
    else:
        target_urls = [url]

    runtime_options = dict(options)

    if runtime_options.get("proxy_url"):
        log_info(f"Proxy set: {runtime_options['proxy_url']}")

    # Run scan for each target
    for target_idx, url in enumerate(target_urls):
        if len(target_urls) > 1:
            console.print(
                f"\n[bold magenta]━━━ Target {target_idx + 1}/{len(target_urls)}: {url} ━━━[/bold magenta]"
            )
        scan_target(
            url,
            mode,
            delay,
            options,
            runtime_options,
            session=session,
            wordlist_file=options.get(
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
