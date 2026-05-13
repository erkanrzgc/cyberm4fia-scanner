"""Reporting phase runners (HTML / JSON / SARIF / Markdown / PoC / summaries)."""

from __future__ import annotations


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


def _run_scan_history(state):
    from utils.scan_history import ScanHistory
    from utils.colors import console
    
    url = state.get("url")
    vulns = state.get("all_vulns", [])
    
    if url:
        history = ScanHistory()
        # Compute drift against the last scan
        drift = history.compute_drift(url, vulns)
        # Output the drift report nicely
        console.print("\n[bold cyan]═══ Scan Drift Report ═══[/bold cyan]")
        console.print(drift.to_markdown())
        console.print("[bold cyan]═════════════════════════[/bold cyan]\n")
        # Save current scan to history for future comparisons
        history.save_scan(url, vulns)

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


