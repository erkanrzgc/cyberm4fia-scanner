"""
cyberm4fia-scanner - Module registry metadata and runners.
"""

from dataclasses import dataclass
import os
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


@dataclass(frozen=True)
class AsyncModuleSpec:
    """Metadata for concurrent per-page modules."""

    id: str
    option_key: str
    name: str
    phase: str
    requires_forms: bool
    loader: Callable[[], Callable]
    args_factory: Callable[[str, list, float], tuple]

    def build_args(self, scan_url: str, forms: list, delay: float) -> tuple:
        return self.args_factory(scan_url, forms, delay)


@dataclass(frozen=True)
class PhaseModuleSpec:
    """Metadata for scanner pipeline phases executed sequentially."""

    id: str
    option_key: str | None
    name: str
    phase: str
    requires_forms: bool
    collect_results: bool
    runner: Callable[[dict], Any]


_NOISE_QUERY_KEYS = {
    "_rsc",
    "__nextdatareq",
    "fbclid",
    "gclid",
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
}


def canonicalize_scan_url(url: str) -> str:
    """Normalize scan URLs to reduce duplicate work on fragments/noise params."""
    if not url:
        return url

    parsed = urlparse(url)
    query_pairs = [
        (key, value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        if key.lower() not in _NOISE_QUERY_KEYS
    ]
    query_pairs.sort()
    normalized = parsed._replace(
        query=urlencode(query_pairs, doseq=True),
        fragment="",
    )
    return urlunparse(normalized)


def canonicalize_scan_urls(urls: list[str]) -> list[str]:
    """Deduplicate scan URLs after canonicalization while preserving order."""
    seen = set()
    normalized = []

    for url in urls:
        candidate = canonicalize_scan_url(url)
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        normalized.append(candidate)

    return normalized


def _load_xss():
    from modules.xss import scan_xss

    return scan_xss


def _load_sqli():
    from modules.sqli import scan_sqli

    return scan_sqli


def _load_lfi():
    from modules.lfi import scan_lfi

    return scan_lfi


def _load_rfi():
    from modules.rfi import scan_rfi

    return scan_rfi


def _load_cmdi():
    from modules.cmdi import scan_cmdi

    return scan_cmdi


def _load_ssrf():
    from modules.ssrf import scan_ssrf

    return scan_ssrf


def _load_ssti():
    from modules.ssti import scan_ssti

    return scan_ssti


def _load_xxe():
    from modules.xxe import scan_xxe

    return scan_xxe


def _load_dom_xss():
    from modules.dom_xss import scan_dom_xss

    return scan_dom_xss


def _load_templates():
    from modules.template_engine import run_templates

    return run_templates


ASYNC_MODULES = (
    AsyncModuleSpec(
        id="xss",
        option_key="xss",
        name="XSS",
        phase="page_scan",
        requires_forms=True,
        loader=_load_xss,
        args_factory=lambda scan_url, forms, delay: (scan_url, forms, delay),
    ),
    AsyncModuleSpec(
        id="sqli",
        option_key="sqli",
        name="SQLi",
        phase="page_scan",
        requires_forms=True,
        loader=_load_sqli,
        args_factory=lambda scan_url, forms, delay: (scan_url, forms, delay),
    ),
    AsyncModuleSpec(
        id="lfi",
        option_key="lfi",
        name="LFI",
        phase="page_scan",
        requires_forms=True,
        loader=_load_lfi,
        args_factory=lambda scan_url, forms, delay: (scan_url, forms, delay),
    ),
    AsyncModuleSpec(
        id="rfi",
        option_key="rfi",
        name="RFI",
        phase="page_scan",
        requires_forms=True,
        loader=_load_rfi,
        args_factory=lambda scan_url, forms, delay: (scan_url, forms, delay),
    ),
    AsyncModuleSpec(
        id="cmdi",
        option_key="cmdi",
        name="CMDi",
        phase="page_scan",
        requires_forms=True,
        loader=_load_cmdi,
        args_factory=lambda scan_url, forms, delay: (scan_url, forms, delay),
    ),
    AsyncModuleSpec(
        id="ssrf",
        option_key="ssrf",
        name="SSRF",
        phase="page_scan",
        requires_forms=True,
        loader=_load_ssrf,
        args_factory=lambda scan_url, forms, delay: (scan_url, forms, delay),
    ),
    AsyncModuleSpec(
        id="ssti",
        option_key="ssti",
        name="SSTI",
        phase="page_scan",
        requires_forms=False,
        loader=_load_ssti,
        args_factory=lambda scan_url, forms, delay: (scan_url, delay),
    ),
    AsyncModuleSpec(
        id="xxe",
        option_key="xxe",
        name="XXE",
        phase="page_scan",
        requires_forms=False,
        loader=_load_xxe,
        args_factory=lambda scan_url, forms, delay: (scan_url, delay),
    ),
    AsyncModuleSpec(
        id="dom_xss",
        option_key="dom_xss",
        name="DOM-XSS",
        phase="browser_scan",
        requires_forms=False,
        loader=_load_dom_xss,
        args_factory=lambda scan_url, forms, delay: (scan_url,),
    ),
    AsyncModuleSpec(
        id="templates",
        option_key="templates",
        name="Templates",
        phase="template_scan",
        requires_forms=False,
        loader=_load_templates,
        args_factory=lambda scan_url, forms, delay: (scan_url, delay),
    ),
)


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
    from utils.shodan_lookup import scan_osint

    state["osint_data"] = scan_osint(state["url"], delay=state["delay"])
    return []


def _run_tech_intel(state):
    from modules.tech_detect import scan_technology
    from utils.colors import log_warning

    state["tech_results"] = scan_technology(state["url"], delay=state["delay"])

    try:
        from utils.cve_feed import enrich_with_cves

        state["cve_intel"] = enrich_with_cves(state["tech_results"])
    except Exception as exc:
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


def _run_fuzzer_discovery(state):
    from modules.endpoint_fuzzer import scan_fuzzer_async

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


def _run_passive_hook(state):
    from modules.passive import scan_passive

    return scan_passive(state["scan_url"], response=state["response"])


def _run_secrets_hook(state):
    from modules.secrets_scanner import scan_secrets

    return scan_secrets(state["scan_url"], state["response"].text)


def _run_csrf_hook(state):
    from modules.csrf import scan_csrf

    return scan_csrf(state["scan_url"], state["forms"], state["delay"])


def _run_xss_postprocess(state):
    from modules.xss_exploit import run_xss_exploit, run_xss_exploit_interactive
    from utils.colors import Colors, log_info

    options = state.get("options", {})
    xss_vulns = state.get("xss_vulns", [])
    if not xss_vulns or not options.get("exploit"):
        return []

    log_info(f"Found {len(xss_vulns)} XSS vulns. Generating exploit payloads...")
    run_xss_exploit(xss_vulns, suppress_output=True)
    print(
        f"\n{Colors.BOLD}{Colors.CYAN}"
        f"[?] XSS found! "
        f"Start Cookie Stealer? (y/N)"
        f"{Colors.END}"
    )
    choice = state["prompt_input"]("Choice:", "N").lower()
    if choice == "y":
        run_xss_exploit_interactive(xss_vulns)
    return []


def _run_sqli_postprocess(state):
    from modules.sqli import scan_blind_sqli
    from modules.sqli_exploit import run_sqli_exploit
    from utils.colors import Colors, log_info, log_success, log_warning

    options = state.get("options", {})
    sqli_vulns = state.get("sqli_vulns", [])
    if not sqli_vulns or not options.get("exploit"):
        return []

    if sqli_vulns:
        log_info(f"Found {len(sqli_vulns)} SQLi vulns. Attempting exploit...")
        for vuln in sqli_vulns:
            if "exploit_data" not in vuln:
                exploit_data = run_sqli_exploit(vuln)
                if exploit_data:
                    vuln["exploit_data"] = exploit_data
                    log_success("Exploitation successful! Data added to report.")

    extracted_data = any(v.get("exploit_data", {}).get("database") for v in sqli_vulns)
    if sqli_vulns and extracted_data:
        log_info(
            "Union-based SQLi successfully extracted data — skipping Blind SQLi (redundant)"
        )
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
        log_info(
            f"Found {len(blind_vulns)} Blind SQLi vulns. Attempting exploit..."
        )
        for vuln in blind_vulns:
            if "exploit_data" not in vuln:
                exploit_data = run_sqli_exploit(vuln)
                if exploit_data:
                    vuln["exploit_data"] = exploit_data
                    log_success("Blind Exploitation successful! Data added to report.")

    return blind_vulns


def _run_cmdi_postprocess(state):
    from modules.cmdi_shell import InteractiveShell
    from utils.colors import Colors, log_info

    options = state.get("options", {})
    cmdi_vulns = state.get("cmdi_vulns", [])
    if not cmdi_vulns or not options.get("exploit"):
        return []

    log_info(f"Found {len(cmdi_vulns)} Command Injection vulns.")
    print(
        f"\n{Colors.BOLD}{Colors.CYAN}"
        f"[?] CMDi found! "
        f"Start Interactive Shell? (y/N)"
        f"{Colors.END}"
    )
    choice = state["prompt_input"]("Choice:", "N").lower()
    if choice == "y":
        shell = InteractiveShell(state["scan_url"], cmdi_vulns[0])
        shell.run()
    return []


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
    generate_wordlist(state["url"], depth=2, output_file=output_file, delay=state["delay"])
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


def _run_scan_summary(state):
    summary_printer = state.get("summary_printer")
    if summary_printer:
        stats_factory = state.get("summary_stats_factory")
        stats = (
            stats_factory(len(state.get("all_vulns", [])))
            if stats_factory
            else None
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
        state["report_stats_factory"](state.get("finding_count", len(state["all_vulns"]))),
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
        state["report_stats_factory"](state.get("finding_count", len(state["all_vulns"]))),
        state.get("scan_artifacts"),
    )
    return []


def _run_severity_summary(state):
    from core.output import print_severity_summary

    print_severity_summary(state["all_vulns"])
    return []


PHASE_MODULES = (
    PhaseModuleSpec(
        id="recon",
        option_key=None,
        name="Recon",
        phase="pre_scan",
        requires_forms=False,
        collect_results=False,
        runner=_run_recon,
    ),
    PhaseModuleSpec(
        id="osint",
        option_key="osint",
        name="OSINT",
        phase="pre_scan",
        requires_forms=False,
        collect_results=False,
        runner=_run_osint,
    ),
    PhaseModuleSpec(
        id="tech",
        option_key="tech",
        name="Technology Intel",
        phase="pre_scan",
        requires_forms=False,
        collect_results=True,
        runner=_run_tech_intel,
    ),
    PhaseModuleSpec(
        id="cloud",
        option_key="cloud",
        name="Cloud Storage",
        phase="phase4_target",
        requires_forms=False,
        collect_results=True,
        runner=_run_cloud_storage,
    ),
    PhaseModuleSpec(
        id="takeover",
        option_key="takeover",
        name="Subdomain Takeover",
        phase="phase4_target",
        requires_forms=False,
        collect_results=True,
        runner=_run_subdomain_takeover,
    ),
    PhaseModuleSpec(
        id="api_scan",
        option_key="api_scan",
        name="API Scan",
        phase="phase4_target",
        requires_forms=False,
        collect_results=True,
        runner=_run_api_scan,
    ),
    PhaseModuleSpec(
        id="subdomain",
        option_key="subdomain",
        name="Subdomain Discovery",
        phase="phase4_target",
        requires_forms=False,
        collect_results=False,
        runner=_run_subdomain_scan,
    ),
    PhaseModuleSpec(
        id="cors",
        option_key="cors",
        name="CORS",
        phase="target_checks",
        requires_forms=False,
        collect_results=True,
        runner=_run_cors,
    ),
    PhaseModuleSpec(
        id="header_inject",
        option_key="header_inject",
        name="Header Injection",
        phase="target_checks",
        requires_forms=False,
        collect_results=True,
        runner=_run_header_inject,
    ),
    PhaseModuleSpec(
        id="fuzz",
        option_key="fuzz",
        name="Endpoint Fuzzer",
        phase="discovery_seed",
        requires_forms=False,
        collect_results=False,
        runner=_run_fuzzer_discovery,
    ),
    PhaseModuleSpec(
        id="headless",
        option_key="headless",
        name="Headless Discovery",
        phase="discovery_expand",
        requires_forms=False,
        collect_results=False,
        runner=_run_headless_discovery,
    ),
    PhaseModuleSpec(
        id="crawl",
        option_key="crawl",
        name="Crawler Discovery",
        phase="discovery_expand",
        requires_forms=False,
        collect_results=False,
        runner=_run_crawl_discovery,
    ),
    PhaseModuleSpec(
        id="passive",
        option_key="passive",
        name="Passive Scan",
        phase="page_hooks",
        requires_forms=False,
        collect_results=True,
        runner=_run_passive_hook,
    ),
    PhaseModuleSpec(
        id="secrets",
        option_key="secrets",
        name="Secrets Scan",
        phase="page_hooks",
        requires_forms=False,
        collect_results=True,
        runner=_run_secrets_hook,
    ),
    PhaseModuleSpec(
        id="csrf",
        option_key="csrf",
        name="CSRF",
        phase="page_hooks",
        requires_forms=True,
        collect_results=True,
        runner=_run_csrf_hook,
    ),
    PhaseModuleSpec(
        id="xss_postprocess",
        option_key="xss",
        name="XSS Postprocess",
        phase="result_processors",
        requires_forms=False,
        collect_results=False,
        runner=_run_xss_postprocess,
    ),
    PhaseModuleSpec(
        id="sqli_postprocess",
        option_key="sqli",
        name="SQLi Postprocess",
        phase="result_processors",
        requires_forms=False,
        collect_results=True,
        runner=_run_sqli_postprocess,
    ),
    PhaseModuleSpec(
        id="cmdi_postprocess",
        option_key="cmdi",
        name="CMDi Postprocess",
        phase="result_processors",
        requires_forms=False,
        collect_results=False,
        runner=_run_cmdi_postprocess,
    ),
    PhaseModuleSpec(
        id="redirect",
        option_key="redirect",
        name="Open Redirect",
        phase="post_scan",
        requires_forms=False,
        collect_results=True,
        runner=_run_open_redirect,
    ),
    PhaseModuleSpec(
        id="spray",
        option_key="spray",
        name="Credential Spray",
        phase="post_scan",
        requires_forms=False,
        collect_results=True,
        runner=_run_credential_spray,
    ),
    PhaseModuleSpec(
        id="email",
        option_key="email",
        name="Email Harvest",
        phase="post_scan",
        requires_forms=False,
        collect_results=False,
        runner=_run_email_harvest,
    ),
    PhaseModuleSpec(
        id="wordlist",
        option_key="wordlist",
        name="Wordlist Generation",
        phase="post_scan",
        requires_forms=False,
        collect_results=False,
        runner=_run_wordlist_generation,
    ),
    PhaseModuleSpec(
        id="jwt",
        option_key="jwt",
        name="JWT",
        phase="post_scan",
        requires_forms=False,
        collect_results=True,
        runner=_run_jwt_scan,
    ),
    PhaseModuleSpec(
        id="race",
        option_key="race",
        name="Race Condition",
        phase="post_scan",
        requires_forms=False,
        collect_results=True,
        runner=_run_race_condition,
    ),
    PhaseModuleSpec(
        id="smuggle",
        option_key="smuggle",
        name="HTTP Smuggling",
        phase="post_scan",
        requires_forms=False,
        collect_results=True,
        runner=_run_smuggling,
    ),
    PhaseModuleSpec(
        id="proto",
        option_key="proto",
        name="Prototype Pollution",
        phase="post_scan",
        requires_forms=False,
        collect_results=True,
        runner=_run_proto_pollution,
    ),
    PhaseModuleSpec(
        id="deser",
        option_key="deser",
        name="Deserialization",
        phase="post_scan",
        requires_forms=False,
        collect_results=True,
        runner=_run_deserialization,
    ),
    PhaseModuleSpec(
        id="bizlogic",
        option_key="bizlogic",
        name="Business Logic",
        phase="post_scan",
        requires_forms=False,
        collect_results=True,
        runner=_run_business_logic,
    ),
    PhaseModuleSpec(
        id="chain",
        option_key="chain",
        name="Chain Analysis",
        phase="post_scan",
        requires_forms=False,
        collect_results=False,
        runner=_run_chain_analysis,
    ),
    PhaseModuleSpec(
        id="dedupe",
        option_key=None,
        name="Deduplicate Findings",
        phase="result_cleanup",
        requires_forms=False,
        collect_results=False,
        runner=_run_deduplicate_results,
    ),
    PhaseModuleSpec(
        id="ai_analysis",
        option_key="ai",
        name="AI Analysis",
        phase="analysis",
        requires_forms=False,
        collect_results=False,
        runner=_run_ai_analysis,
    ),
    PhaseModuleSpec(
        id="summary",
        option_key=None,
        name="Summary",
        phase="reporting",
        requires_forms=False,
        collect_results=False,
        runner=_run_scan_summary,
    ),
    PhaseModuleSpec(
        id="html_report",
        option_key="html",
        name="HTML Report",
        phase="reporting",
        requires_forms=False,
        collect_results=False,
        runner=_run_html_report,
    ),
    PhaseModuleSpec(
        id="payload_report",
        option_key=None,
        name="Payload Report",
        phase="reporting",
        requires_forms=False,
        collect_results=False,
        runner=_run_payload_report,
    ),
    PhaseModuleSpec(
        id="markdown_report",
        option_key=None,
        name="Markdown Report",
        phase="reporting",
        requires_forms=False,
        collect_results=False,
        runner=_run_markdown_report,
    ),
    PhaseModuleSpec(
        id="poc_generation",
        option_key=None,
        name="PoC Generation",
        phase="reporting",
        requires_forms=False,
        collect_results=False,
        runner=_run_poc_generation,
    ),
    PhaseModuleSpec(
        id="normalize_findings",
        option_key=None,
        name="Normalize Findings",
        phase="reporting",
        requires_forms=False,
        collect_results=False,
        runner=_run_normalize_findings,
    ),
    PhaseModuleSpec(
        id="json_report",
        option_key=None,
        name="JSON Report",
        phase="reporting",
        requires_forms=False,
        collect_results=False,
        runner=_run_json_report,
    ),
    PhaseModuleSpec(
        id="sarif_report",
        option_key="sarif",
        name="SARIF Report",
        phase="reporting",
        requires_forms=False,
        collect_results=False,
        runner=_run_sarif_report,
    ),
    PhaseModuleSpec(
        id="findings_json",
        option_key=None,
        name="Enhanced Findings JSON",
        phase="reporting",
        requires_forms=False,
        collect_results=False,
        runner=_run_findings_json,
    ),
    PhaseModuleSpec(
        id="severity_summary",
        option_key=None,
        name="Severity Summary",
        phase="reporting",
        requires_forms=False,
        collect_results=False,
        runner=_run_severity_summary,
    ),
)


def iter_async_module_specs(options: dict):
    """Yield enabled async module specs in registry order."""
    for spec in ASYNC_MODULES:
        if options.get(spec.option_key):
            yield spec


def iter_phase_module_specs(phase: str, options: dict):
    """Yield enabled scanner phase specs in registry order."""
    for spec in PHASE_MODULES:
        if spec.phase != phase:
            continue
        if spec.option_key is None or options.get(spec.option_key):
            yield spec


def run_phase_modules(phase: str, options: dict, state: dict):
    """Run sequential registry-backed modules for a given scanner phase."""
    collected = []
    for spec in iter_phase_module_specs(phase, options):
        if spec.requires_forms and not state.get("forms"):
            continue
        result = spec.runner(state)
        if spec.collect_results and result:
            collected.extend(result)
            state["all_vulns"] = list(state.get("all_vulns", [])) + list(result)
    return collected
