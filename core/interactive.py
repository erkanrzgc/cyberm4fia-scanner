"""
Interactive menu, resume/restore helpers, and preflight UI for cyberm4fia-scanner.
Extracted from scanner.py to keep the main entry-point lean.
"""

import sys

from utils.colors import log_info, log_error, console
from utils.request import set_json_output_enabled
from rich.table import Table
from rich.panel import Panel
from rich.markup import escape

from core.cli import get_input
from core.scan_options import (
    API_SPEC_PROMPT,
    ATTACK_PROFILE_SPECS,
    DEFAULT_AI_MODEL,
    INTERACTIVE_CUSTOM_PROMPT_GROUPS,
    INTERACTIVE_RESUME_PROMPT,
    INTERACTIVE_SCAN_MODE_SPECS,
    JSON_OUTPUT_PROMPT,
    apply_interactive_prompt_specs,
    apply_profile_preset,
    build_default_scan_options,
    get_attack_profile_spec,
    get_attack_profile_recommended_prompt_specs,
    get_interactive_scan_mode_spec,
    get_interactive_runtime_prompt_specs,
    get_scan_mode_runtime,
    normalize_runtime_options,
)
from core.session import ScanSession


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
        pass  # Lab mode prompt removed as requested
    mode, delay, threads = get_scan_mode_runtime(selected_mode_key)

    # Attack Profiles
    _print_interactive_section(
        "Attack Profile",
        "Pick the coverage style you want before runtime tweaks.",
    )
    _print_attack_profile_menu()
    profile_choice = get_input("[?] Choice [4]:", "4")
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
