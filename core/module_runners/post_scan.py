"""Post-scan vuln scanner + analysis runners."""

from __future__ import annotations

import os


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
    import asyncio
    from modules.deserialization import async_scan_deserialization

    return asyncio.run(async_scan_deserialization(state["url"], state["delay"]))


def _run_business_logic(state):
    from modules.business_logic import scan_business_logic

    return scan_business_logic(
        state["url"],
        forms=state.get("crawled_forms", []),
        delay=state["delay"],
    )


def _run_forbidden_bypass(state):
    from modules.forbidden_bypass import scan_forbidden_bypass

    return scan_forbidden_bypass(
        state["url"],
        pages=state.get("crawled_pages", []),
        delay=state["delay"],
    )


def _run_file_upload(state):
    from modules.file_upload import scan_file_upload

    return scan_file_upload(
        state["url"],
        forms=state.get("crawled_forms", []),
        delay=state["delay"],
    )


def _run_account_takeover(state):
    from modules.account_takeover import scan_account_takeover

    return scan_account_takeover(state["url"], delay=state["delay"])


def _run_auth_bypass(state):
    from modules.auth_bypass import scan_auth_bypass

    return scan_auth_bypass(state["url"], delay=state["delay"])


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
        get_dual_ai,
    )
    from utils.colors import console, log_info, log_success

    findings = state.get("all_vulns", [])
    if not findings:
        return []

    # Prefer DualModelAI (routes tasks to WhiteRabbitNeo or Qwen3.5 by role)
    dual = get_dual_ai()
    if dual and dual.available:
        ai = dual
    else:
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

    # ── Feed payload memory with confirmed findings ──
    try:
        from utils.payload_memory import get_memory
        memory = get_memory()
        remembered = 0
        for vuln in findings:
            if vuln.get("payload"):
                memory.remember_from_finding(vuln)
                remembered += 1
        if remembered:
            log_info(f"Payload memory updated: {remembered} finding(s) stored for future scans")
    except Exception:
        pass

    # ── Feed scan intelligence (0-Day Machine knowledge loop) ──
    try:
        from utils.scan_intelligence import get_scan_intelligence
        intel = get_scan_intelligence()
        target = state.get("url", "")
        waf_name = state.get("waf_name", "")
        tech_results = state.get("tech_results", [])
        tech_stack = "[]"
        if tech_results:
            import json as _json
            tech_stack = _json.dumps([t.get("name", "") for t in tech_results if isinstance(t, dict)])

        scan_id = state.get("scan_id", "")
        campaign_id = state.get("campaign_id", "")

        for vuln in findings:
            intel.record_scan_result(
                target=target,
                vuln_type=vuln.get("type", vuln.get("finding_type", "Unknown")),
                payload=vuln.get("payload", ""),
                success=True,
                waf_name=waf_name,
                tech_stack=tech_stack,
                module=vuln.get("module", ""),
                confidence=vuln.get("confidence_score", 0),
                response_code=vuln.get("status_code", 0),
                scan_id=scan_id,
                campaign_id=campaign_id,
            )

        # Record WAF as a defence
        if waf_name:
            intel.record_defence(target, "waf", waf_name)

        log_info(f"Intelligence updated: {len(findings)} finding(s) recorded for knowledge loop")
    except Exception:
        pass

    return []


