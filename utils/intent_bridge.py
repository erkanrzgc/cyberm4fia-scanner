"""Bridge between scanner.py's vuln-dict world and the intent pipeline.

`utils.agent_orchestrator` and `utils.ai_intent_agent` are external entry
points (see ``docs/_audit/EXTERNAL_ENTRY_POINTS.md``) — they should not
import from scanner.py, and scanner.py should not depend on their internal
shapes. This bridge sits between them:

* Vuln dicts (legacy in-memory format used everywhere in modules/) are
  translated into ``Intent`` payloads suitable for ``ExploitStage``.
* The ``MissionContext.findings`` produced by the pipeline are merged
  back into the scanner result so reports/SARIF/HTML pick them up
  without any other code knowing the pipeline ran.

Only the high-value, exploit-suitable vuln types become intents — there
is no point burning LLM iterations to "confirm" an HSTS-missing header.
"""

from __future__ import annotations

from typing import Any

from utils.colors import log_info, log_success, log_warning


_INTENT_GOALS: dict[str, str] = {
    "XSS_Param": "Confirm reflected XSS by executing arbitrary JavaScript in the response",
    "XSS_Form": "Confirm reflected XSS via form input by triggering JavaScript execution",
    "Stored_XSS": "Confirm stored XSS by retrieving an injected payload on a later request",
    "DOM_XSS": "Confirm DOM-based XSS via sink reachable from a controllable source",
    "SQLi_Param": "Confirm SQL injection by extracting a deterministic database value",
    "SQLi_Form": "Confirm SQL injection via form input by extracting a deterministic value",
    "Blind_SQLi_Param": "Confirm blind SQL injection via boolean or time-based oracle",
    "Blind_SQLi_Form": "Confirm blind SQL injection via boolean or time-based oracle",
    "CMDi_Param": "Confirm OS command injection by executing a marker command (e.g. `id`)",
    "CMDi_Form": "Confirm OS command injection via form input by executing a marker command",
    "Blind_CMDi": "Confirm blind OS command injection via time-based or OOB oracle",
    "LFI_Param": "Confirm local file inclusion by reading a known sensitive file",
    "LFI_Form": "Confirm local file inclusion via form input by reading a sensitive file",
    "RFI_Param": "Confirm remote file inclusion by serving and executing a remote stub",
    "SSRF": "Confirm SSRF by triggering a request to an attacker-controlled or internal host",
    "Blind_SSRF": "Confirm blind SSRF via out-of-band callback",
    "SSTI": "Confirm server-side template injection via arithmetic or RCE proof",
    "XXE": "Confirm XML external entity processing by reading a file or triggering OOB",
    "Deserialization": "Confirm unsafe deserialization by triggering a gadget chain",
}


def _high_value_vuln_types() -> set[str]:
    """Vuln types worth spending LLM iterations on (have an _INTENT_GOALS entry)."""
    return set(_INTENT_GOALS.keys())


def findings_to_intents(
    vulns: list[dict[str, Any]],
    *,
    max_intents: int = 25,
) -> list[dict[str, Any]]:
    """Translate legacy vuln dicts into intent payloads for ExploitStage.

    Returns a list of dicts in the shape ``utils.agent_orchestrator.run_mission``
    expects (``goal``, ``target_url``, ``param``, ``vuln_type``,
    ``http_method``, ``notes``, ``constraints``).

    Caps at ``max_intents`` to keep AI cost bounded; the most severe
    findings (by severity → cvss → discovery order) go first.
    """
    if not vulns:
        return []

    high_value = _high_value_vuln_types()
    candidates = [v for v in vulns if v.get("type") in high_value]

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def _sort_key(v: dict[str, Any]) -> tuple[int, float]:
        sev = severity_rank.get(str(v.get("severity") or "").lower(), 5)
        try:
            cvss = -float(v.get("cvss") or 0.0)  # higher cvss first → smaller key
        except (TypeError, ValueError):
            cvss = 0.0
        return (sev, cvss)

    candidates.sort(key=_sort_key)
    candidates = candidates[:max_intents]

    intents: list[dict[str, Any]] = []
    for vuln in candidates:
        vuln_type = str(vuln.get("type") or "")
        goal = _INTENT_GOALS.get(vuln_type) or (
            f"Confirm {vuln_type} on the indicated target"
        )
        intents.append(
            {
                "goal": goal,
                "target_url": str(vuln.get("url") or ""),
                "param": str(vuln.get("param") or vuln.get("parameter") or ""),
                "vuln_type": vuln_type,
                "http_method": str(vuln.get("method") or vuln.get("http_method") or "GET"),
                "notes": str(vuln.get("payload") or vuln.get("evidence") or ""),
                "constraints": [],
            }
        )
    return intents


def merge_pipeline_findings(
    scan_result: dict[str, Any] | None,
    mission_ctx: Any,
) -> dict[str, Any] | None:
    """Merge MissionContext.findings into a scan_target return dict.

    Returns the same result object (mutated) for chaining convenience.
    Safe to call when ``scan_result`` is ``None`` (no-op).
    """
    if not scan_result or mission_ctx is None:
        return scan_result

    new_findings = list(getattr(mission_ctx, "findings", []) or [])
    if not new_findings:
        return scan_result

    existing = list(scan_result.get("vulnerabilities") or [])
    existing_keys = {
        (str(v.get("type")), str(v.get("url")), str(v.get("param") or ""))
        for v in existing
    }
    added = 0
    for f in new_findings:
        key = (
            str(f.get("type")),
            str(f.get("url")),
            str(f.get("param") or ""),
        )
        if key in existing_keys:
            continue
        existing.append(f)
        existing_keys.add(key)
        added += 1

    scan_result["vulnerabilities"] = existing
    scan_result["intent_pipeline_added"] = added
    scan_result["intent_pipeline_stages"] = list(
        getattr(mission_ctx, "stage_results", []) or []
    )
    return scan_result


def run_intent_pipeline(
    scan_result: dict[str, Any] | None,
    *,
    ai_client: Any = None,
    max_iterations: int = 3,
    min_confidence: float = 50.0,
    max_intents: int = 25,
) -> dict[str, Any] | None:
    """Run the Strix-style pipeline over a finished scan.

    No-op when AI is unavailable or no high-value vulns were collected.
    Mutates and returns ``scan_result`` so downstream reporting code
    sees the pipeline's findings inline.
    """
    if not scan_result:
        return scan_result

    target_url = str(scan_result.get("url") or "")
    if not target_url:
        log_warning("intent pipeline skipped: scan_result missing 'url'")
        return scan_result

    vulns = list(scan_result.get("vulnerabilities") or [])
    intents = findings_to_intents(vulns, max_intents=max_intents)
    if not intents:
        log_info(
            "Intent pipeline: no high-value vulns to confirm — skipping LLM stage"
        )
        return scan_result

    if ai_client is None or not getattr(ai_client, "available", False):
        log_warning(
            "Intent pipeline: AI client unavailable; pipeline will run Recon/"
            "Validate/Report only and skip the LLM exploit stage."
        )

    # Imported lazily so unit tests that do not exercise the bridge do not
    # incur the dataclass imports (and avoid circulars).
    from utils.agent_orchestrator import build_default_pipeline, run_mission

    pipeline = build_default_pipeline(
        ai_client=ai_client,
        max_iterations=max_iterations,
        min_confidence=min_confidence,
    )
    log_info(
        f"\U0001f9e0 Intent pipeline launching: {len(intents)} intents, "
        f"max_iterations={max_iterations}"
    )
    ctx = run_mission(
        target_url,
        ai_client=ai_client,
        intents=intents,
        options=dict(scan_result.get("recon_data") or {}),
        pipeline=pipeline,
    )

    merge_pipeline_findings(scan_result, ctx)
    added = scan_result.get("intent_pipeline_added", 0)
    if added:
        log_success(
            f"Intent pipeline confirmed {added} new finding"
            f"{'s' if added != 1 else ''}"
        )
    return scan_result
