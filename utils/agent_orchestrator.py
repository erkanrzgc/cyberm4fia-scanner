"""
cyberm4fia-scanner — Multi-Agent Orchestration

.. external-entry-point::

   This module is an **external entry point**: it is *not* imported from
   ``scanner.py`` or ``api_server.py``. Wired in by an external Cairn /
   MCP runner via ``utils.mcp_server``. See
   ``docs/_audit/EXTERNAL_ENTRY_POINTS.md``.

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
    planned_signatures: set = field(default_factory=set)      # intents ever queued (loop-safe dedup)

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
class ExternalToolStage(_BaseStage):
    """Run external CLI scanners (masscan, sslyze, wpscan, arjun, ...) and fold
    their results into the mission.

    Each tool's structured output is summarized into ``ctx.tech_profile`` and
    its ``to_findings`` output merged into ``ctx.findings``. Tools that are not
    installed are skipped; a tool raising during result-mapping never blocks the
    others.
    """
    name: str = "external_recon"
    tools: list = field(default_factory=list)
    tool_kwargs: dict = field(default_factory=dict)   # binary -> kwargs

    def run(self, ctx: MissionContext) -> None:
        ran: list[str] = []
        skipped: list[str] = []
        for tool in self.tools:
            binary = getattr(tool, "binary", "?")
            kwargs = self.tool_kwargs.get(binary, {})
            try:
                result = tool.run(ctx.target_url, **kwargs)
            except Exception as exc:
                ctx.record_error(self.name, exc)
                skipped.append(binary)
                continue
            if not getattr(result, "available", False):
                skipped.append(binary)
                continue
            ctx.tech_profile[binary] = {
                "succeeded": getattr(result, "succeeded", False),
                "summary": getattr(result, "parsed", None),
            }
            try:
                for finding in tool.to_findings(result.parsed, target=ctx.target_url):
                    ctx.add_finding(finding)
            except Exception as exc:
                ctx.record_error(self.name, exc)
            ran.append(binary)
        ctx.stage_results.append({"stage": self.name, "ran": ran, "skipped": skipped})


def default_external_tools() -> list:
    """The bundled external-tool adapters, in recon-friendly order.

    Excludes path-based tools (``GitleaksTool``) which need a filesystem target
    rather than the mission's URL — those are invoked explicitly when needed.
    """
    from utils.external_tools import (
        ArjunTool, CloudHunterTool, GowitnessTool, KubeHunterTool,
        MasscanTool, SmbmapTool, SslyzeTool, TestsslTool, WpscanTool,
    )
    return [
        MasscanTool(), ArjunTool(),
        SslyzeTool(), TestsslTool(),
        WpscanTool(), SmbmapTool(),
        KubeHunterTool(),
        GowitnessTool(), CloudHunterTool(),
    ]


def _intent_signature(intent: dict, default_target: str) -> tuple:
    """Stable identity for an intent so the same work is never queued twice."""
    return (
        str(intent.get("vuln_type") or "").lower().strip(),
        str(intent.get("param") or "").lower().strip(),
        str(intent.get("target_url") or default_target).lower().strip(),
        str(intent.get("goal") or "").lower().strip(),
    )


_PLANNER_SYSTEM = (
    "You are the planning brain of an authorized web-app penetration test. "
    "Given the recon tech profile and findings collected so far, propose the "
    "next concrete exploitation intents to attempt. Chain off existing findings "
    "where possible (e.g. an LFI may enable RCE via log poisoning). "
    "Reply with ONLY a JSON array; each item has keys: "
    "vuln_type, param, target_url, goal, http_method, notes. "
    "Return [] when nothing further is worth attempting."
)


@dataclass
class PlannerStage(_BaseStage):
    """Adaptive LLM step: turn the current mission state into the next batch of
    in-scope exploitation intents.

    Unlike the static pipeline (where intents are seeded up front), this stage
    lets the model react to what recon and earlier exploits revealed. Every
    proposal is scope-checked and de-duplicated against work already queued, so
    the surrounding loop converges instead of re-attacking the same target.
    """
    name: str = "plan"
    ai_client: Any = None
    scope: Any = None
    max_intents_per_round: int = 4

    def run(self, ctx: MissionContext) -> None:
        if not self.ai_client or not getattr(self.ai_client, "available", False):
            ctx.stage_results.append(
                {"stage": self.name, "skipped": "AI client unavailable"}
            )
            return

        # Seeded / prior-round intents count as already-known work.
        for existing in ctx.intents:
            ctx.planned_signatures.add(_intent_signature(existing, ctx.target_url))

        proposed = self._ask_llm(ctx)
        scope = self.scope if self.scope is not None else _get_scope()

        added = skipped_scope = skipped_dup = 0
        for item in proposed:
            if not isinstance(item, dict):
                continue
            if added >= self.max_intents_per_round:
                break
            target = str(item.get("target_url") or ctx.target_url)
            if scope is not None and not scope.is_allowed(target):
                skipped_scope += 1
                continue
            sig = _intent_signature(item, ctx.target_url)
            if sig in ctx.planned_signatures:
                skipped_dup += 1
                continue
            ctx.add_intent({**item, "target_url": target})
            ctx.planned_signatures.add(sig)
            added += 1

        ctx.stage_results.append({
            "stage": self.name,
            "proposed": len(proposed),
            "added": added,
            "skipped_scope": skipped_scope,
            "skipped_dup": skipped_dup,
        })

    def _ask_llm(self, ctx: MissionContext) -> list:
        from utils.ai import _extract_json

        prompt = self._build_prompt(ctx)
        try:
            response = self.ai_client.generate(
                prompt, system=_PLANNER_SYSTEM, temperature=0.4
            )
        except Exception:
            return []
        parsed = _extract_json(response or "", expect_array=True)
        return parsed if isinstance(parsed, list) else []

    @staticmethod
    def _build_prompt(ctx: MissionContext) -> str:
        import json as _json

        tech = _json.dumps(ctx.tech_profile, default=str)[:4000]
        findings = _json.dumps(
            [{k: f.get(k) for k in ("type", "url", "param", "severity", "evidence")}
             for f in ctx.findings],
            default=str,
        )[:4000]
        return (
            f"Target: {ctx.target_url}\n\n"
            f"Recon tech profile (JSON):\n{tech}\n\n"
            f"Findings so far (JSON):\n{findings}\n\n"
            "Propose the next exploitation intents as a JSON array."
        )


def _get_scope():
    """Lazily resolve the global scope filter; tolerate its absence."""
    try:
        from core.scope import get_scope
        return get_scope()
    except Exception:
        return None


def _resolve_default_scope(target_url: str):
    """Derive a target-bound scope when no explicit one is configured.

    Used by adaptive missions so the LLM-driven planner cannot, by accident,
    propose intents against unrelated third-party hosts discovered during recon
    (CDN endpoints, OAuth providers, ...). The host of ``target_url`` becomes
    the sole include pattern.
    """
    from urllib.parse import urlparse
    from core.scope import ScopeFilter
    host = urlparse(target_url).hostname or ""
    return ScopeFilter(include=[host] if host else [])


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
    external_tools: Optional[list] = None,
    tool_kwargs: Optional[dict] = None,
) -> Pipeline:
    """Recon → [ExternalRecon] → Exploit → Validate → Report.

    Pass ``external_tools`` (a list of ExternalTool adapters) to insert an
    ``ExternalToolStage`` right after recon — otherwise the chain is unchanged.
    """
    stages: list[Stage] = [ReconStage()]
    if external_tools:
        stages.append(ExternalToolStage(
            tools=external_tools, tool_kwargs=dict(tool_kwargs or {}),
        ))
    stages.extend([
        ExploitStage(ai_client=ai_client, max_iterations=max_iterations),
        ValidateStage(min_confidence=min_confidence),
        ReportStage(),
    ])
    return Pipeline(stages=stages)


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


# ─── Adaptive (LLM-driven) orchestration ──────────────────────────────────────


def run_adaptive_loop(
    ctx: MissionContext,
    planner: Stage,
    exploit: Stage,
    *,
    max_rounds: int = 3,
) -> MissionContext:
    """Drive Plan → Exploit rounds until convergence or the round budget runs out.

    Each round the ``planner`` queues fresh intents onto ``ctx.intents``; the
    ``exploit`` stage runs them; the queue is then drained so the next round
    starts clean and never re-runs prior work. The loop exits early when a
    planning round produces no new intents (nothing left worth attempting).

    ``max_rounds`` is a hard budget cap — it bounds total planner LLM calls and
    guarantees termination even if the planner keeps proposing.
    """
    from utils.llm_budget import BudgetExceeded

    rounds = 0
    budget_hit = False
    for _ in range(max(0, max_rounds)):
        try:
            planner.run(ctx)
            if not ctx.intents:
                break
            rounds += 1
            exploit.run(ctx)
        except BudgetExceeded as exc:
            ctx.stage_results.append({"stage": "adaptive_loop", "halted": str(exc)})
            budget_hit = True
            break
        ctx.intents = []          # drain: prior rounds are done, dedup lives in planned_signatures
    if not budget_hit:
        ctx.stage_results.append({"stage": "adaptive_loop", "rounds": rounds})
    return ctx


def run_adaptive_mission(
    target_url: str,
    *,
    ai_client: Any = None,
    scope: Any = None,
    max_rounds: int = 3,
    max_intents_per_round: int = 4,
    exploit_max_iterations: int = 3,
    max_llm_calls: int = 0,           # 0 = no cap; e.g. 50 caps total LLM calls
    min_confidence: float = 50.0,
    external_tools: Optional[list] = None,
    tool_kwargs: Optional[dict] = None,
    intents: Optional[list[dict]] = None,
    options: Optional[dict[str, Any]] = None,
) -> MissionContext:
    """Recon → [ExternalRecon] → (Plan → Exploit)×N → Validate → Report.

    The LLM-driven counterpart to :func:`run_mission`: instead of a fixed,
    pre-seeded intent list, the planner reacts to recon + accumulated findings
    each round, enabling finding-chaining and skipping irrelevant attacks.
    Any ``intents`` passed in are used as round-zero seeds. ``external_tools``
    run once up front so their findings feed the planner.
    """
    ctx = MissionContext(target_url=target_url, options=dict(options or {}))
    for intent in intents or []:
        ctx.add_intent(intent)

    ReconStage().run(ctx)
    if external_tools:
        ExternalToolStage(
            tools=external_tools, tool_kwargs=dict(tool_kwargs or {}),
        ).run(ctx)

    # Wrap the AI client with a budget guard so a runaway adaptive loop
    # can't burn through the NVIDIA NIM quota silently.
    if ai_client is not None and max_llm_calls > 0:
        from utils.llm_budget import LLMBudgetClient
        ai_client = LLMBudgetClient(ai_client, max_calls=max_llm_calls)

    # Scope-default-on: lock the planner to the target's host when the caller
    # didn't supply or pre-configure a scope. Prevents the LLM from straying
    # to third-party origins surfaced by recon.
    if scope is None:
        active_global = _get_scope()
        if active_global is None or not getattr(active_global, "active", False):
            scope = _resolve_default_scope(target_url)

    planner = PlannerStage(
        ai_client=ai_client, scope=scope,
        max_intents_per_round=max_intents_per_round,
    )
    exploit = ExploitStage(ai_client=ai_client, max_iterations=exploit_max_iterations)
    run_adaptive_loop(ctx, planner, exploit, max_rounds=max_rounds)
    ValidateStage(min_confidence=min_confidence).run(ctx)
    ReportStage().run(ctx)
    return ctx
