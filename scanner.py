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
    log_warning,
    set_log_file,
    set_quiet,
)
from utils.request import (  # noqa: E402
    Config,
    Stats,
    smart_request,
    _get_session,
    _global_headers,
)

from modules.payloads import XSS_FLAT_PAYLOADS  # noqa: E402
from modules.xss_exploit import (  # noqa: E402
    run_xss_exploit,
    run_xss_exploit_interactive,
)
from modules.sqli_exploit import run_sqli_exploit  # noqa: E402
from modules.sqli import scan_blind_sqli  # noqa: E402
from modules.cmdi_shell import InteractiveShell  # noqa: E402
from modules.crawler import crawl_site  # noqa: E402
from utils.oob import OOBClient  # noqa: E402

# Phase 4 modules
from modules.cloud_enum import scan_cloud_storage  # noqa: E402
from modules.subdomain_takeover import scan_subdomain_takeover  # noqa: E402
from modules.tech_detect import scan_technology  # noqa: E402
from modules.api_scanner import scan_api  # noqa: E402

# Phase 5 modules
from modules.ssti import scan_ssti  # noqa: E402
from modules.xxe import scan_xxe  # noqa: E402
from modules.open_redirect import scan_open_redirect  # noqa: E402
from modules.spray import scan_spray  # noqa: E402
from modules.email_harvest import scan_email_harvest  # noqa: E402
from utils.shodan_lookup import scan_osint  # noqa: E402
from utils.vuln_chain import analyze_chains  # noqa: E402
from utils.wordlist_gen import generate_wordlist  # noqa: E402

# Phase 7 modules
from modules.race_condition import scan_race_condition  # noqa: E402
from modules.jwt_attack import scan_jwt  # noqa: E402
from utils.headless import render_page, crawl_spa  # noqa: E402
from modules.smuggling import scan_smuggling  # noqa: E402
from modules.proto_pollution import scan_proto_pollution  # noqa: E402
from modules.deserialization import scan_deserialization  # noqa: E402
from modules.business_logic import scan_business_logic  # noqa: E402
from modules.passive import scan_passive  # noqa: E402
from utils.finding import normalize_all  # noqa: E402
from utils.tamper import TamperChain, set_tamper_chain  # noqa: E402
from core.scope import ScopeFilter, set_scope, get_scope  # noqa: E402
from core.session import ScanSession  # noqa: E402
from core.output import save_findings_json, save_sarif, print_severity_summary  # noqa: E402

from rich.console import Console
from rich.table import Table
from utils.ai import (  # noqa: E402
    init_ai,
    get_ai,
    analyze_vulnerability,
    detect_false_positives,
    generate_remediation,
    generate_scan_summary,
)

console = Console()
from modules.recon import run_recon, scan_subdomains  # noqa: E402
from modules.report import (  # noqa: E402
    generate_html_report,
    generate_json_report,
    generate_payload_report,
)
from modules.fuzzer import scan_fuzzer  # noqa: E402
from modules.cors import scan_cors  # noqa: E402
from modules.header_inject import scan_header_inject  # noqa: E402
from modules.compare import (  # noqa: E402
    compare_scans,
    print_comparison,
    save_comparison_json,
)


def parse_args():
    parser = argparse.ArgumentParser(description="cyberm4fia-scanner")
    parser.add_argument("-u", "--url", help="Target URL")
    parser.add_argument(
        "-m",
        "--mode",
        choices=["1", "2", "3", "4"],
        default="2",
        help="Scan mode (1-Quick, 2-Normal, 3-Aggressive, 4-Stealth)",
    )
    parser.add_argument("-c", "--cookie", help="Session cookie (e.g. 'PHPSESSID=...')")
    parser.add_argument("--all", action="store_true", help="Enable ALL scan modules")
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Quiet mode (only show vulns/errors)"
    )
    parser.add_argument("--xss", action="store_true", help="Enable XSS scan")
    parser.add_argument("--sqli", action="store_true", help="Enable SQLi scan")
    parser.add_argument("--lfi", action="store_true", help="Enable LFI scan")
    parser.add_argument("--rfi", action="store_true", help="Enable RFI scan")
    parser.add_argument(
        "--cmdi", action="store_true", help="Enable Command Injection scan"
    )
    parser.add_argument("--dom-xss", action="store_true", help="Enable DOM XSS scan")
    parser.add_argument(
        "--secrets", action="store_true", help="Scan for Secrets & API Keys in JS/HTML"
    )
    parser.add_argument("--recon", action="store_true", help="Enable Server Recon")
    parser.add_argument(
        "--subdomain", action="store_true", help="Enable Subdomain scan"
    )
    parser.add_argument("--fuzz", action="store_true", help="Enable Directory Fuzzer")
    parser.add_argument("--ssrf", action="store_true", help="Enable SSRF scan")
    parser.add_argument(
        "--oob", action="store_true", help="Enable Out-Of-Band (OOB) testing"
    )
    parser.add_argument("--cors", action="store_true", help="Enable CORS check")
    parser.add_argument(
        "--header-inject", action="store_true", help="Enable Header Injection scan"
    )
    parser.add_argument("--crawl", action="store_true", help="Enable Crawling")

    parser.add_argument("--html", action="store_true", help="Generate HTML report")
    parser.add_argument("--json", action="store_true", help="Save JSON report")
    parser.add_argument(
        "--sarif",
        action="store_true",
        help="Save SARIF report (for GitHub Security tab)",
    )
    parser.add_argument(
        "--passive",
        action="store_true",
        help="Enable passive scanning (header/secret/debug checks)",
    )
    parser.add_argument(
        "--tamper",
        type=str,
        default="",
        help="Tamper scripts for WAF bypass (comma-separated, e.g. space2comment,randomcase)",
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=10, help="Number of threads"
    )
    parser.add_argument("--api", action="store_true", help="Start REST API server mode")
    parser.add_argument(
        "--port", type=int, default=8080, help="API server port (default: 8080)"
    )
    parser.add_argument(
        "--compare", nargs=2, metavar=("SCAN1", "SCAN2"), help="Compare two scan dirs"
    )
    # Phase 4 flags
    parser.add_argument(
        "--cloud",
        action="store_true",
        help="Scan for open cloud buckets (S3/Azure/GCP)",
    )
    parser.add_argument(
        "--takeover", action="store_true", help="Scan for subdomain takeover"
    )
    parser.add_argument("--tech", action="store_true", help="Technology fingerprinting")
    parser.add_argument(
        "--api-scan", action="store_true", help="API security scan (OWASP API Top 10)"
    )
    # Phase 5 flags
    parser.add_argument(
        "--ssti", action="store_true", help="SSTI (Template Injection) scan"
    )
    parser.add_argument(
        "--xxe", action="store_true", help="XXE (XML External Entity) scan"
    )
    parser.add_argument("--redirect", action="store_true", help="Open Redirect scan")
    parser.add_argument(
        "--spray", action="store_true", help="Default credential spraying"
    )
    parser.add_argument("--email", action="store_true", help="Email harvesting")
    parser.add_argument(
        "--osint", action="store_true", help="OSINT enrichment (Shodan/Whois)"
    )
    parser.add_argument(
        "--chain", action="store_true", help="Vulnerability chaining analysis"
    )
    parser.add_argument(
        "--wordlist", action="store_true", help="Generate site-specific wordlist"
    )
    parser.add_argument(
        "-l", "--list", dest="target_list", help="File with list of target URLs"
    )
    parser.add_argument(
        "--proxy",
        dest="proxy_url",
        help="Proxy URL (http/socks5, e.g. socks5://127.0.0.1:9050)",
    )
    # Phase 7 flags
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Use headless browser for SPA rendering (requires playwright)",
    )
    parser.add_argument("--race", action="store_true", help="Race condition scanner")
    parser.add_argument("--jwt", action="store_true", help="JWT attack suite")
    parser.add_argument(
        "--smuggle",
        action="store_true",
        help="HTTP request smuggling scanner (CL.TE/TE.CL)",
    )
    parser.add_argument(
        "--proto",
        action="store_true",
        help="Prototype pollution scanner (Node.js)",
    )
    parser.add_argument(
        "--deser",
        action="store_true",
        help="Insecure deserialization scanner",
    )
    parser.add_argument(
        "--bizlogic",
        action="store_true",
        help="Business logic flaw scanner",
    )
    parser.add_argument(
        "--scope",
        type=str,
        default="",
        help="Scope include patterns (comma-separated, e.g. '*.target.com')",
    )
    parser.add_argument(
        "--exclude",
        type=str,
        default="",
        help="Scope exclude patterns (comma-separated, e.g. '/logout,*.pdf')",
    )
    parser.add_argument(
        "--session",
        type=str,
        default="",
        help="Session file for save/resume (e.g. scan1.json)",
    )
    parser.add_argument(
        "--resume",
        type=str,
        default="",
        help="Resume scan from session file",
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Enable AI analysis (Ollama, local & free). Requires Ollama running.",
    )
    parser.add_argument(
        "--ai-model",
        type=str,
        default="WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B",
        help="Ollama model (default: WhiteRabbitNeo-Llama-3.1-8B)",
    )

    return parser.parse_args()


def get_input(prompt, default=""):
    """Get user input with default value"""
    try:
        val = input(f"{Colors.BOLD}{prompt}{Colors.END} ").strip()
        return val if val else default
    except EOFError:
        return default


def interactive_menu():
    """Interactive menu for scan options"""
    url = get_input("[?] Target URL:", "")
    if not url:
        log_error("No URL provided!")
        sys.exit(1)

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # Scan mode
    print(f"{Colors.BOLD}[?] Scan mode:")
    print(f"    1-Quick  2-Normal  3-Aggressive  4-Stealth{Colors.END}")
    mode_choice = get_input("[?] Choice [2]:", "2")

    modes = {
        "1": ("quick", Config.QUICK_DELAY, 10),
        "2": ("normal", Config.REQUEST_DELAY, 10),
        "3": ("aggressive", 0.05, 30),
        "4": ("stealth", Config.STEALTH_DELAY, 1),
    }
    mode, delay, threads = modes.get(mode_choice, ("normal", Config.REQUEST_DELAY, 10))

    # Options
    options = {}
    options["recon"] = get_input("[?] Run Server Recon? (Y/n)", "Y").lower() != "n"
    options["subdomain"] = (
        get_input("[?] Run Subdomain Scan? (y/N)", "N").lower() == "y"
    )
    options["fuzz"] = get_input("[?] Run Directory Fuzzer? (y/N)", "N").lower() == "y"
    options["crawl"] = get_input("[?] Crawl site? (y/N)", "N").lower() == "y"
    options["xss"] = get_input("[?] Test XSS? (y/N)", "N").lower() == "y"
    options["sqli"] = get_input("[?] Test SQLi? (y/N)", "N").lower() == "y"
    options["lfi"] = get_input("[?] Test LFI? (y/N)", "N").lower() == "y"
    options["rfi"] = get_input("[?] Test RFI? (y/N)", "N").lower() == "y"
    options["cmdi"] = get_input("[?] Test Command Injection? (y/N)", "N").lower() == "y"
    options["dom_xss"] = (
        get_input("[?] Test DOM XSS? (y/N) [Requires Selenium]", "N").lower() == "y"
    )
    options["secrets"] = (
        get_input("[?] Scan for Secrets & API Keys in JS/HTML? (y/N)", "N").lower()
        == "y"
    )
    options["oob"] = (
        get_input("[?] Use Out-of-Band (OOB) Testing? (y/N)", "N").lower() == "y"
    )
    options["ssrf"] = get_input("[?] Test SSRF? (y/N)", "N").lower() == "y"
    options["csrf"] = get_input("[?] Test CSRF? (y/N)", "N").lower() == "y"
    options["cors"] = get_input("[?] Check CORS? (y/N)", "N").lower() == "y"
    options["header_inject"] = (
        get_input("[?] Test Header Injection? (y/N)", "N").lower() == "y"
    )
    # Phase 4 options
    print(
        f"\n{Colors.BOLD}{Colors.CYAN}── Phase 4: Infrastructure & Cloud ──{Colors.END}"
    )
    options["tech"] = (
        get_input("[?] Run Technology Fingerprinting? (Y/n)", "Y").lower() != "n"
    )
    options["cloud"] = (
        get_input("[?] Scan Cloud Buckets (S3/Azure/GCP)? (y/N)", "N").lower() == "y"
    )
    options["takeover"] = (
        get_input("[?] Scan Subdomain Takeover? (y/N)", "N").lower() == "y"
    )
    options["api_scan"] = (
        get_input("[?] Run API Security Scan? (y/N)", "N").lower() == "y"
    )

    options["cookie"] = get_input("[?] Cookie (leave empty for none)", "")
    options["html"] = get_input("[?] Generate HTML report? (y/N)", "N").lower() == "y"
    options["threads"] = threads

    Config.JSON_OUTPUT = get_input("[?] Save JSON? (y/N)", "N").lower() == "y"

    return url, mode, delay, options


def print_summary(vulns, recon_data=None):
    """Print an attractive ASCII scan summary using Rich"""
    if Stats.start_time:
        duration_delta = datetime.now() - datetime.fromtimestamp(Stats.start_time)
        duration = str(duration_delta).split(".")[0]
    else:
        duration = "N/A"

    table = Table(
        title="🛡️ cyberm4fia-scanner SCAN SUMMARY 🛡️",
        title_style="bold cyan",
        border_style="cyan",
    )

    table.add_column("Metric", style="white", justify="right")
    table.add_column("Value", style="bold green")

    table.add_row("Duration", duration)
    table.add_row("Total Requests", str(Stats.total_requests))
    table.add_row("WAF Blocks", f"[red]{Stats.waf_blocks}[/red]")
    table.add_row("Request Retries", str(Stats.retries))
    table.add_row("Network Errors", f"[red]{Stats.errors}[/red]")

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
            vuln_table.add_row(
                vtype,
                f"{v.get('url', '')} [{v.get('field', 'URL')}]",
                str(v.get("payload", "")),
            )

    console.print(vuln_table)


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

    if args.url:
        url = args.url
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        modes = {
            "1": ("quick", Config.QUICK_DELAY, 10),
            "2": ("normal", Config.REQUEST_DELAY, 10),
            "3": ("aggressive", 0.05, 30),
            "4": ("stealth", Config.STEALTH_DELAY, 1),
        }
        mode, delay, threads = modes.get(
            args.mode, ("normal", Config.REQUEST_DELAY, 10)
        )

        if args.threads:
            threads = args.threads

        # --all flag enables everything
        use_all = getattr(args, "all", False)

        options = {
            "recon": args.recon or use_all,
            "subdomain": args.subdomain or use_all,
            "fuzz": args.fuzz or use_all,
            "crawl": args.crawl or use_all,
            "xss": args.xss or use_all,
            "sqli": args.sqli or use_all,
            "lfi": args.lfi or use_all,
            "rfi": args.rfi or use_all,
            "cmdi": args.cmdi or use_all,
            "dom_xss": args.dom_xss or use_all,
            "secrets": args.secrets or use_all,
            "oob": args.oob or use_all,
            "ssrf": args.ssrf or use_all,
            "cors": args.cors or use_all,
            "header_inject": args.header_inject or use_all,
            "templates": use_all,
            "cloud": args.cloud or use_all,
            "takeover": args.takeover or use_all,
            "tech": args.tech or use_all,
            "api_scan": args.api_scan or use_all,
            "ssti": args.ssti or use_all,
            "xxe": args.xxe or use_all,
            "redirect": args.redirect or use_all,
            "spray": args.spray or use_all,
            "email": args.email or use_all,
            "osint": args.osint or use_all,
            "chain": args.chain or use_all,
            "wordlist": args.wordlist,
            "headless": args.headless or use_all,
            "race": args.race or use_all,
            "jwt": args.jwt or use_all,
            "smuggle": args.smuggle or use_all,
            "proto": args.proto or use_all,
            "deser": args.deser or use_all,
            "bizlogic": args.bizlogic or use_all,
            "cookie": args.cookie,
            "html": args.html or use_all,
            "passive": args.passive or use_all,
            "sarif": args.sarif,
            "threads": threads,
            "ai": args.ai,
            "ai_model": args.ai_model,
        }
        Config.JSON_OUTPUT = args.json or use_all

        # Initialize tamper chain
        if args.tamper:
            tamper_names = [t.strip() for t in args.tamper.split(",") if t.strip()]
            chain = TamperChain(tamper_names)
            set_tamper_chain(chain)
            Config.TAMPER_CHAIN = chain

        # Initialize scope filter
        if args.scope or args.exclude:
            include = (
                [p.strip() for p in args.scope.split(",") if p.strip()]
                if args.scope
                else []
            )
            exclude = (
                [p.strip() for p in args.exclude.split(",") if p.strip()]
                if args.exclude
                else []
            )
            scope = ScopeFilter(include=include, exclude=exclude)
            set_scope(scope)

        # Initialize AI client
        if options.get("ai"):
            init_ai(model=options.get("ai_model", "deepseek-r1:14b"))

        # Initialize session (resume or new)
        session = None
        if args.resume:
            session = ScanSession.load(args.resume)
            if session.data.get("target"):
                url = session.data["target"]
                log_info(f"Resuming scan on {url}")
        elif args.session:
            session = ScanSession(args.session)

    else:
        try:
            url, mode, delay, options = interactive_menu()
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Cancelled{Colors.END}")
            sys.exit(0)
        session = None

    # Setup
    Stats.reset()
    Stats.start_time = datetime.now().timestamp()

    if options.get("oob"):
        Config.OOB_CLIENT = OOBClient()

    # Set proxy if provided
    if hasattr(args, "proxy_url") and args.proxy_url:
        Config.PROXY = args.proxy_url
        log_info(f"Proxy set: {args.proxy_url}")

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

    # Run scan for each target
    for target_idx, url in enumerate(target_urls):
        if len(target_urls) > 1:
            console.print(
                f"\n[bold magenta]━━━ Target {target_idx + 1}/{len(target_urls)}: {url} ━━━[/bold magenta]"
            )

        parsed_target = urlparse(url)
        target_host = parsed_target.hostname or parsed_target.netloc.split(":")[0]
        safe_target = target_host.replace(".", "_").replace(":", "_")
        scan_dir = f"scans/{safe_target}"
        os.makedirs(scan_dir, exist_ok=True)

        log_file = f"{scan_dir}/scan.txt"
        set_log_file(log_file)
        with open(log_file, "w") as f:
            f.write(f"--- cyberm4fia-scanner Scan: {url} at {datetime.now()} ---\n")

        # Set cookie if provided
        if options.get("cookie"):
            cookie_val = options["cookie"].strip("\"'")
            _global_headers["Cookie"] = cookie_val
            _get_session().headers["Cookie"] = cookie_val
            log_success(f"Cookie set: {cookie_val[:30]}...")

        log_info(f"Target: {url} | Mode: {mode.title()}")

        # Run recon (deep=True if user explicitly selected it)
        recon_data = None
        if options.get("recon"):
            recon_data = run_recon(url, deep=True)
        else:
            recon_data = run_recon(url, deep=False)

        # OSINT enrichment (early — enriches findings)
        if options.get("osint"):
            osint_data = scan_osint(url, delay=delay)  # noqa: F841

        # Technology Fingerprinting (run early — informs other scans)
        if options.get("tech"):
            scan_technology(url, delay=delay)

        # Cloud Storage Enumeration
        if options.get("cloud"):
            cloud_vulns = scan_cloud_storage(url, delay=delay)
        else:
            cloud_vulns = []

        # Subdomain Takeover
        if options.get("takeover"):
            takeover_vulns = scan_subdomain_takeover(url, delay=delay)
        else:
            takeover_vulns = []

        # API Security Scan
        if options.get("api_scan"):
            api_vulns = scan_api(url, delay=delay)
        else:
            api_vulns = []

        # Subdomain Scan (legacy)
        if options.get("subdomain"):
            scan_subdomains(target_host)

        # Directory Fuzzer
        if options.get("fuzz"):
            scan_fuzzer(
                url,
                "wordlists/common.txt",
                threads=options.get("threads", 10),
                delay=delay,
            )

        # CORS check (once per target, before crawl)
        if options.get("cors"):
            cors_vulns = scan_cors(url)
        else:
            cors_vulns = []

        # Header injection (once per target)
        if options.get("header_inject"):
            header_vulns = scan_header_inject(url, delay)
        else:
            header_vulns = []

        # Get URLs to scan
        urls_to_scan = [url]
        crawled_forms = []
        if options.get("headless"):
            # Use headless browser for SPA rendering
            log_info("Using headless browser for SPA crawling...")
            crawl_result = crawl_spa(url, max_pages=20)
            urls_to_scan = crawl_result.get("urls", [url])
            crawled_forms = crawl_result.get("forms", [])
            # Also render the main page to extract JS variables and API calls
            rendered = render_page(url)
            if rendered and rendered.get("js_variables"):
                log_info(f"Exposed JS vars: {list(rendered['js_variables'].keys())}")
        elif options.get("crawl"):
            crawl_result = crawl_site(url, max_pages=30)
            # Handle both old (list) and new (dict) return formats
            if isinstance(crawl_result, dict):
                urls_to_scan = crawl_result.get("urls", [url])
                crawled_forms = crawl_result.get("forms", [])
            else:
                urls_to_scan = crawl_result

        log_info(f"Loaded {len(XSS_FLAT_PAYLOADS)} payloads")
        Config.THREADS = options.get("threads", 10)

        # Scan each URL
        all_vulns = cors_vulns + header_vulns + cloud_vulns + takeover_vulns + api_vulns

        # Apply scope filter to crawled URLs
        scope = get_scope()
        if scope.active:
            urls_to_scan = scope.filter_urls(urls_to_scan)

        # Session: save target info and filter already-scanned URLs
        if session and session.active:
            session.set_target(url, mode, options)
            session.add_pending_urls(urls_to_scan)
            if session.is_resume:
                urls_to_scan = [u for u in urls_to_scan if not session.is_url_done(u)]
                log_info(f"Session resume: {len(urls_to_scan)} URLs remaining")

        for scan_url in urls_to_scan:
            console.print(f"[bold cyan]Scanning:[/bold cyan] {scan_url}")

            try:
                resp = smart_request("get", scan_url)
                soup = BeautifulSoup(resp.content, "lxml")
                forms = soup.find_all("form")
                # Merge crawled forms for this URL
                if crawled_forms:
                    for cf in crawled_forms:
                        if (
                            cf.get("source_page") == scan_url
                            or cf.get("action") == scan_url
                        ):
                            forms.append(cf)

                # Passive scanning (no extra requests — analyzes the response)
                if options.get("passive"):
                    passive_vulns = scan_passive(scan_url, response=resp)
                    all_vulns.extend(passive_vulns)

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

                # Phase 2: Sequential post-processing
                # XSS Exploitation
                if options.get("xss") and xss_vulns:
                    log_info(
                        f"Found {len(xss_vulns)} XSS vulns. Generating exploit payloads..."
                    )
                    run_xss_exploit(xss_vulns, suppress_output=True)

                    # Interactive Cookie Stealer
                    print(
                        f"\n{Colors.BOLD}{Colors.CYAN}"
                        f"[?] XSS found! "
                        f"Start Cookie Stealer? (y/N)"
                        f"{Colors.END}"
                    )
                    choice = get_input("Choice:", "N").lower()
                    if choice == "y":
                        run_xss_exploit_interactive(xss_vulns)

                # SQLi post-processing
                if options.get("sqli"):
                    # Auto-exploit found SQLi vulns
                    if sqli_vulns:
                        log_info(
                            f"Found {len(sqli_vulns)} SQLi vulns. Attempting exploit..."
                        )
                        for v in sqli_vulns:
                            if "exploit_data" not in v:
                                exploit_data = run_sqli_exploit(v)
                                if exploit_data:
                                    v["exploit_data"] = exploit_data
                                    log_success(
                                        "Exploitation successful! Data added to report."
                                    )

                    # Blind SQLi scan (sequential - timing)
                    # Skip if Union-based already found SQLi
                    # Skip if Union-based already found SQLi AND successfully extracted data
                    extracted_data = any(
                        v.get("exploit_data", {}).get("database") for v in sqli_vulns
                    )

                    if sqli_vulns and extracted_data:
                        log_info(
                            "Union-based SQLi successfully extracted data — skipping Blind SQLi (redundant)"
                        )
                    else:
                        if sqli_vulns:
                            log_warning(
                                "Union SQLi found but data extraction failed. Falling back to Blind SQLi..."
                            )
                        print(
                            f"\n{Colors.BOLD}{Colors.CYAN}"
                            f"[?] Run Blind SQLi? "
                            f"(slow, time-based) (y/N)"
                            f"{Colors.END}"
                        )
                        blind_choice = get_input("Choice:", "N").lower()
                        if blind_choice == "y":
                            log_info("Running Time-Based Blind SQLi checks...")
                            blind_vulns = scan_blind_sqli(scan_url, forms, delay)
                            all_vulns.extend(blind_vulns)

                            if blind_vulns:
                                log_info(
                                    f"Found {len(blind_vulns)}"
                                    f" Blind SQLi vulns. "
                                    f"Attempting exploit..."
                                )
                                for v in blind_vulns:
                                    if "exploit_data" not in v:
                                        exploit_data = run_sqli_exploit(v)
                                        if exploit_data:
                                            v["exploit_data"] = exploit_data
                                            log_success(
                                                "Blind Exploitation "
                                                "successful! "
                                                "Data added to "
                                                "report."
                                            )

                # Command Injection post-processing
                if options.get("cmdi") and cmdi_vulns:
                    log_info(f"Found {len(cmdi_vulns)} Command Injection vulns.")
                    print(
                        f"\n{Colors.BOLD}{Colors.CYAN}"
                        f"[?] CMDi found! "
                        f"Start Interactive Shell? (y/N)"
                        f"{Colors.END}"
                    )
                    choice = get_input("Choice:", "N").lower()
                    if choice == "y":
                        shell = InteractiveShell(scan_url, cmdi_vulns[0])
                        shell.run()

            except Exception as e:
                log_error(f"Failed to scan {scan_url}: {e}")

        # Process OOB callbacks
        if Config.OOB_CLIENT and Config.OOB_CLIENT.ready:
            print(
                f"\n{Colors.BOLD}[*] Waiting 15s for late Out-of-Band (OOB) callbacks...{Colors.END}"
            )
            import time

            time.sleep(15)
            oob_hits = Config.OOB_CLIENT.poll()
            if oob_hits:
                log_success(f"Processed {len(oob_hits)} OOB hit(s)!")
            else:
                log_info("No OOB callbacks received.")

        # ──── Phase 5: Post-scan modules ────

        # SSTI scan on discovered URLs
        if options.get("ssti"):
            for scan_url in urls_to_scan:
                ssti_vulns = scan_ssti(scan_url, delay)
                all_vulns.extend(ssti_vulns)

        # XXE scan
        if options.get("xxe"):
            xxe_vulns = scan_xxe(url, delay)
            all_vulns.extend(xxe_vulns)

        # Open Redirect scan
        if options.get("redirect"):
            for scan_url in urls_to_scan:
                redirect_vulns = scan_open_redirect(scan_url, delay)
                all_vulns.extend(redirect_vulns)

        # Credential Sprayer (uses port scan results)
        if options.get("spray"):
            open_ports = recon_data.get("open_ports", []) if recon_data else []
            spray_vulns = scan_spray(target_host, open_ports=open_ports)
            all_vulns.extend(spray_vulns)

        # Email Harvester
        if options.get("email"):
            scan_email_harvest(url, delay)

        # Wordlist Generator
        if options.get("wordlist"):
            wl_file = f"{scan_dir}/wordlist.txt"
            generate_wordlist(url, depth=2, output_file=wl_file, delay=delay)

        # JWT Attack Suite
        if options.get("jwt"):
            jwt_vulns = scan_jwt(url, delay, cookie=options.get("cookie"))
            all_vulns.extend(jwt_vulns)

        # Race Condition Scanner
        if options.get("race"):
            race_vulns = scan_race_condition(
                url, forms=[], delay=delay, cookie=options.get("cookie")
            )
            all_vulns.extend(race_vulns)

        # HTTP Request Smuggling
        if options.get("smuggle"):
            smuggle_vulns = scan_smuggling(url, delay)
            all_vulns.extend(smuggle_vulns)

        # Prototype Pollution
        if options.get("proto"):
            proto_vulns = scan_proto_pollution(url, delay=delay)
            all_vulns.extend(proto_vulns)

        # Insecure Deserialization
        if options.get("deser"):
            deser_vulns = scan_deserialization(url, delay)
            all_vulns.extend(deser_vulns)

        # Business Logic
        if options.get("bizlogic"):
            bizlogic_vulns = scan_business_logic(url, forms=[], delay=delay)
            all_vulns.extend(bizlogic_vulns)

        # Vulnerability Chaining Analysis
        if options.get("chain") and all_vulns:
            analyze_chains(all_vulns)

        # ──── End multi-target loop ────
        # (Note: for multi-target, summary/reports run after all targets are done)

        # ─── AI Analysis Pipeline ────────────────────────────────────────
        if options.get("ai") and all_vulns:
            ai = get_ai()
            if ai.available:
                # Step 1: Filter false positives
                all_vulns = detect_false_positives(ai, all_vulns)

                # Step 2: Deep analysis of each finding
                if all_vulns:
                    log_info("AI analyzing vulnerabilities...")
                    for vuln in all_vulns:
                        analysis = analyze_vulnerability(ai, vuln)
                        if analysis:
                            vuln["ai_analysis"] = analysis

                # Step 3: Remediation recommendations
                remediations = generate_remediation(ai, all_vulns)
                if remediations:
                    log_success(
                        f"AI generated {len(remediations)} remediation guide(s)"
                    )

                # Step 4: Executive summary
                summary = generate_scan_summary(
                    ai,
                    all_vulns,
                    url,
                    {
                        "requests": Stats.total_requests,
                        "vulns": len(all_vulns),
                        "waf": Stats.waf_blocks,
                    },
                )
                if summary:
                    console.print(
                        "\n[bold cyan]═══ AI Executive Summary ═══[/bold cyan]"
                    )
                    console.print(summary)
                    console.print(
                        "[bold cyan]════════════════════════════[/bold cyan]\n"
                    )

        # Summary
        print_summary(all_vulns, recon_data=recon_data)

        # Generate reports
        if options.get("html"):
            generate_html_report(all_vulns, url, mode, scan_dir)

        generate_payload_report(scan_dir, url, all_vulns)

        # Normalize all findings with CVSS/CWE data
        findings = normalize_all(all_vulns)

        if Config.JSON_OUTPUT:
            stats = {
                "requests": Stats.total_requests,
                "vulns": len(findings),
                "waf": Stats.waf_blocks,
            }
            generate_json_report(all_vulns, url, mode, stats, scan_dir)

        # SARIF output (for GitHub Security tab)
        if options.get("sarif"):
            save_sarif(all_vulns, scan_dir)

        # Enhanced JSON with CVSS/CWE severity breakdown
        if Config.JSON_OUTPUT:
            save_findings_json(
                findings,
                scan_dir,
                url,
                mode,
                {
                    "requests": Stats.total_requests,
                    "vulns": len(findings),
                    "waf": Stats.waf_blocks,
                },
            )

        # Severity summary
        print_severity_summary(all_vulns)

        # Session: save final state
        if session and session.active:
            session.add_vulnerabilities(all_vulns)
            session.update_stats(
                {
                    "requests": Stats.total_requests,
                    "vulns": len(findings),
                }
            )
            session.mark_completed()

        log_success(f"Log saved: {log_file}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted{Colors.END}")
        sys.exit(0)
