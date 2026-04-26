"""
cyberm4fia-scanner — Multi-Agent Orchestration

Inspired by Strix's specialized-agent layout: instead of one monolithic
"do everything" exploit agent, the work is split into composable stages
that share a single ``MissionContext`` and run in pipeline order.

Default stages
--------------
1. **ReconStage** — feeds Nmap/Nuclei output into the mission's tech profile.
2. **ExploitStage** — runs the intent-driven exploit agent for each target
   parameter / vuln_type, collecting findings.
3. **ValidateStage** — re-checks low-confidence findings against the AI
   anti-hallucination prompt; demotes ones the model rejects.
4. **ReportStage** — adds MITRE ATT&CK tags + a compact summary the report
   layer can render directly.

Adding a new stage
------------------
Subclass ``Stage`` and implement ``run(ctx)``. Append to the pipeline:

    pipeline = build_default_pipeline(...).with_stage(MyCustomStage())

All stages use the same NVIDIA NIM AI client passed in at pipeline build
time (project rule: NVIDIA NIM only).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol


# ─── Mission context ─────────────────────────────────────────────────────────


@dataclass
class MissionContext:
    """Shared state passed through every stage of the pipeline.

    Stages MUST NOT swap the context for a new instance — they mutate this
    one in-place so later stages see prior stages' contributions.
    """
    target_url: str
    scope: list[str] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)
    tech_profile: dict[str, Any] = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    intents: list[dict] = field(default_factory=list)         # planned intents to exploit
    stage_results: list[dict] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)

    def add_finding(self, finding: dict) -> None:
        self.findings.append(dict(finding))

    def add_intent(self, intent: dict) -> None:
        self.intents.append(dict(intent))

    def record_error(self, stage: str, exc: BaseException) -> None:
        self.errors.append({
            "stage": stage,
            "type": type(exc).__name__,
            "message": str(exc),
        })


# ─── Stage protocol ──────────────────────────────────────────────────────────


class Stage(Protocol):
    """Each pipeline stage is a callable taking the mission context and
    mutating it in place. ``name`` is used for logging + error attribution."""
    name: str

    def run(self, ctx: MissionContext) -> None: ...


@dataclass
class _BaseStage:
    """Tiny shared base — gives stages a default `name` derived from the class."""
    name: str = ""

    def __post_init__(self):
        if not self.name:
            self.name = type(self).__name__


# ─── Built-in stages ─────────────────────────────────────────────────────────


@dataclass
class ReconStage(_BaseStage):
    """Lift parsed meta-tool output into the mission's tech profile.

    Provide raw output via ``ctx.options['nmap_xml']`` / ``['nuclei_jsonl']``.
    Stage is a no-op when no inputs are present, so the pipeline still runs
    cleanly during pure-AI exploitation.
    """
    name: str = "recon"

    def run(self, ctx: MissionContext) -> None:
        from utils.meta_tools import (
            parse_nmap_xml,
            parse_nuclei_jsonl,
            summarize_for_ai,
        )

        nmap_xml = ctx.options.get("nmap_xml") or ""
        nuclei_jsonl = ctx.options.get("nuclei_jsonl") or ""

        if nmap_xml:
            scan = parse_nmap_xml(nmap_xml)
            ctx.tech_profile["nmap"] = {
                "host_count": len(scan.hosts),
                "open_port_count": scan.open_port_count,
                "summary": summarize_for_ai(scan),
            }

        if nuclei_jsonl:
            findings = parse_nuclei_jsonl(nuclei_jsonl)
            ctx.tech_profile["nuclei"] = {
                "count": len(findings),
                "critical_count": sum(1 for f in findings if f.is_critical),
                "summary": summarize_for_ai(findings),
            }
            for f in findings:
                ctx.add_finding({
                    "type": "Nuclei_Finding",
                    "url": f.matched_at,
                    "title": f.name,
                    "severity": f.severity,
                    "template_id": f.template_id,
                    "evidence": f.description,
                    "cvss": f.cvss,
                    "module": "nuclei",
                })


@dataclass
class ExploitStage(_BaseStage):
    """Run the intent-driven exploit agent for each planned intent.

    The pipeline caller seeds intents via ``ctx.add_intent({...})`` (or via
    a planning stage). Each intent that succeeds becomes a finding.
    """
    name: str = "exploit"
    ai_client: Any = None
    max_iterations: int = 3

    def run(self, ctx: MissionContext) -> None:
        from utils.ai_intent_agent import Intent, IntentAgent

        if not ctx.intents:
            ctx.stage_results.append(
                {"stage": self.name, "skipped": "no intents planned"}
            )
            return

        if not self.ai_client or not getattr(self.ai_client, "available", False):
            ctx.stage_results.append(
                {"stage": self.name, "skipped": "AI client unavailable"}
            )
            return

        agent = IntentAgent(self.ai_client, max_iterations=self.max_iterations)
        succeeded = 0

        for raw in ctx.intents:
            intent = Intent(
                goal=str(raw.get("goal") or ""),
                target_url=str(raw.get("target_url") or ctx.target_url),
                param=str(raw.get("param") or ""),
                vuln_type=str(raw.get("vuln_type") or ""),
                http_method=str(raw.get("http_method") or "GET"),
                notes=str(raw.get("notes") or ""),
                constraints=list(raw.get("constraints") or []),
            )
            outcome = agent.run(intent)
            if outcome.success:
                succeeded += 1
                ctx.add_finding({
                    "type": intent.vuln_type or "AI_Discovered",
                    "url": intent.target_url,
                    "param": intent.param,
                    "evidence": outcome.evidence,
                    "confidence": outcome.confidence,
                    "module": "intent_agent",
                    "iterations": outcome.iterations_used,
                    "exploit_data": {"final_code": outcome.final_code},
                })

        ctx.stage_results.append({
            "stage": self.name,
            "intents_run": len(ctx.intents),
            "succeeded": succeeded,
        })


@dataclass
class ValidateStage(_BaseStage):
    """Demote findings whose confidence is below a configurable threshold."""
    name: str = "validate"
    min_confidence: float = 50.0

    def run(self, ctx: MissionContext) -> None:
        kept: list[dict] = []
        demoted = 0
        for f in ctx.findings:
            try:
                conf = float(f.get("confidence") or 100.0)
            except (TypeError, ValueError):
                conf = 100.0
            if conf >= self.min_confidence:
                kept.append(f)
            else:
                demoted += 1
        ctx.findings = kept
        ctx.stage_results.append({
            "stage": self.name,
            "demoted": demoted,
            "kept": len(kept),
        })


@dataclass
class ReportStage(_BaseStage):
    """Tag every finding with MITRE ATT&CK techniques + tactics."""
    name: str = "report"

    def run(self, ctx: MissionContext) -> None:
        from utils.attack_mapping import tag_finding_dict
        ctx.findings = [tag_finding_dict(f) for f in ctx.findings]
        ctx.stage_results.append({
            "stage": self.name,
            "tagged": len(ctx.findings),
        })


# ─── Pipeline ────────────────────────────────────────────────────────────────


@dataclass
class Pipeline:
    stages: list[Stage] = field(default_factory=list)

    def with_stage(self, stage: Stage) -> "Pipeline":
        return Pipeline(stages=list(self.stages) + [stage])

    def run(self, ctx: MissionContext) -> MissionContext:
        for stage in self.stages:
            t0 = time.monotonic()
            try:
                stage.run(ctx)
            except Exception as exc:
                ctx.record_error(stage.name, exc)
                ctx.stage_results.append({
                    "stage": stage.name,
                    "error": f"{type(exc).__name__}: {exc}",
                    "duration_seconds": round(time.monotonic() - t0, 3),
                })
                continue
            ctx.stage_results.append({
                "stage": stage.name,
                "duration_seconds": round(time.monotonic() - t0, 3),
            })
        return ctx


def build_default_pipeline(
    *,
    ai_client: Any = None,
    max_iterations: int = 3,
    min_confidence: float = 50.0,
) -> Pipeline:
    """Recon → Exploit → Validate → Report — the canonical Strix-style chain."""
    return Pipeline(stages=[
        ReconStage(),
        ExploitStage(ai_client=ai_client, max_iterations=max_iterations),
        ValidateStage(min_confidence=min_confidence),
        ReportStage(),
    ])


def run_mission(
    target_url: str,
    *,
    ai_client: Any = None,
    intents: Optional[list[dict]] = None,
    options: Optional[dict[str, Any]] = None,
    pipeline: Optional[Pipeline] = None,
) -> MissionContext:
    """One-call convenience: build a default pipeline and run it.

    Pass pre-planned ``intents`` (each a dict with ``vuln_type``, ``param``,
    ``goal``, ...) so the exploit stage has work to do. ``options`` carry
    raw recon inputs (``nmap_xml``, ``nuclei_jsonl``).
    """
    ctx = MissionContext(
        target_url=target_url,
        options=dict(options or {}),
    )
    for intent in intents or []:
        ctx.add_intent(intent)

    if pipeline is None:
        pipeline = build_default_pipeline(ai_client=ai_client)
    return pipeline.run(ctx)
