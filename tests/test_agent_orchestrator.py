"""Tests for utils/agent_orchestrator — multi-stage pipeline."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from utils.agent_orchestrator import (
    ExploitStage,
    MissionContext,
    Pipeline,
    ReconStage,
    ReportStage,
    ValidateStage,
    build_default_pipeline,
    run_mission,
)


pytestmark = pytest.mark.unit


# ─── Fixtures ────────────────────────────────────────────────────────────────


_NMAP_XML = """<?xml version="1.0"?>
<nmaprun args="nmap -sV t">
  <host><status state="up"/><address addr="1.2.3.4"/>
    <ports><port protocol="tcp" portid="80">
      <state state="open"/><service name="http" product="nginx" version="1.20"/>
    </port></ports></host>
</nmaprun>"""

_NUCLEI_JSONL = json.dumps({
    "template-id": "exposed-env-file",
    "info": {
        "name": ".env exposed", "severity": "high",
        "tags": ["exposure"], "classification": {"cvss-score": 7.5},
        "description": "env reachable",
    },
    "matched-at": "https://t/.env",
    "host": "t",
})


# ─── Mission context invariants ──────────────────────────────────────────────


class TestMissionContext:
    def test_add_finding_does_not_alias_input(self):
        ctx = MissionContext(target_url="http://t/")
        original = {"type": "XSS", "url": "http://t/?q=1"}
        ctx.add_finding(original)
        original["type"] = "MUTATED"
        assert ctx.findings[0]["type"] == "XSS"   # ctx kept its own copy

    def test_record_error_appends_structured_entry(self):
        ctx = MissionContext(target_url="http://t/")
        try:
            raise ValueError("boom")
        except ValueError as exc:
            ctx.record_error("recon", exc)
        assert len(ctx.errors) == 1
        assert ctx.errors[0]["type"] == "ValueError"
        assert ctx.errors[0]["stage"] == "recon"


# ─── Recon stage ─────────────────────────────────────────────────────────────


class TestReconStage:
    def test_populates_tech_profile_from_nmap_xml(self):
        ctx = MissionContext(target_url="http://t/", options={"nmap_xml": _NMAP_XML})
        ReconStage().run(ctx)
        assert ctx.tech_profile["nmap"]["host_count"] == 1
        assert ctx.tech_profile["nmap"]["open_port_count"] == 1

    def test_lifts_nuclei_findings_into_mission_findings(self):
        ctx = MissionContext(
            target_url="http://t/",
            options={"nuclei_jsonl": _NUCLEI_JSONL},
        )
        ReconStage().run(ctx)
        assert len(ctx.findings) == 1
        assert ctx.findings[0]["template_id"] == "exposed-env-file"
        assert ctx.findings[0]["module"] == "nuclei"

    def test_no_inputs_is_no_op(self):
        ctx = MissionContext(target_url="http://t/")
        ReconStage().run(ctx)
        assert ctx.tech_profile == {}
        assert ctx.findings == []


# ─── Exploit stage ───────────────────────────────────────────────────────────


def _ai_client_with(script: str) -> MagicMock:
    cli = MagicMock()
    cli.available = True
    cli.generate = MagicMock(return_value=f"```python\n{script}\n```")
    return cli


class TestExploitStage:
    def test_skips_when_no_intents(self):
        ctx = MissionContext(target_url="http://t/")
        ExploitStage(ai_client=_ai_client_with("result = {'confirmed': False}")).run(ctx)
        assert ctx.findings == []
        # Last stage_result entry should mark the skip.
        assert any("skipped" in r for r in ctx.stage_results)

    def test_skips_when_ai_client_unavailable(self):
        ctx = MissionContext(target_url="http://t/")
        ctx.add_intent({"vuln_type": "XSS", "goal": "x", "target_url": "http://t/"})
        # Client present but `available=False`
        cli = MagicMock(); cli.available = False
        ExploitStage(ai_client=cli).run(ctx)
        assert ctx.findings == []
        assert any(r.get("skipped") == "AI client unavailable" for r in ctx.stage_results)

    def test_records_finding_when_intent_confirms(self):
        ctx = MissionContext(target_url="http://t/")
        ctx.add_intent({
            "vuln_type": "XSS", "param": "q", "goal": "Confirm reflected XSS",
            "target_url": "http://t/?q=1",
        })
        # AI returns a script that immediately confirms.
        script = (
            "result = {'confirmed': True, 'confidence': 90, "
            "'evidence': 'reflected', 'payload': '<svg/onload=1>', "
            "'notes': 'works'}"
        )
        ExploitStage(ai_client=_ai_client_with(script), max_iterations=1).run(ctx)

        assert len(ctx.findings) == 1
        f = ctx.findings[0]
        assert f["type"] == "XSS"
        assert f["confidence"] == 90.0
        assert f["module"] == "intent_agent"


# ─── Validate stage ──────────────────────────────────────────────────────────


class TestValidateStage:
    def test_demotes_low_confidence_findings(self):
        ctx = MissionContext(target_url="http://t/")
        ctx.add_finding({"type": "XSS", "confidence": 80})
        ctx.add_finding({"type": "SQLi", "confidence": 30})
        ValidateStage(min_confidence=50).run(ctx)
        assert len(ctx.findings) == 1
        assert ctx.findings[0]["type"] == "XSS"

    def test_keeps_findings_without_confidence(self):
        ctx = MissionContext(target_url="http://t/")
        ctx.add_finding({"type": "X"})
        ValidateStage(min_confidence=50).run(ctx)
        assert len(ctx.findings) == 1


# ─── Report stage ────────────────────────────────────────────────────────────


class TestReportStage:
    def test_attaches_attack_techniques(self):
        ctx = MissionContext(target_url="http://t/")
        ctx.add_finding({"type": "XSS_Param", "url": "http://t/?q=1"})
        ReportStage().run(ctx)
        f = ctx.findings[0]
        assert "attack_techniques" in f
        ids = [t["id"] for t in f["attack_techniques"]]
        assert "T1059.007" in ids


# ─── Pipeline orchestration ──────────────────────────────────────────────────


class TestPipeline:
    def test_stages_run_in_order(self):
        order: list[str] = []

        class Fake(MagicMock):
            pass

        def make(name):
            stage = Fake()
            stage.name = name
            stage.run = lambda ctx, n=name: order.append(n)
            return stage

        pipeline = Pipeline(stages=[make("a"), make("b"), make("c")])
        pipeline.run(MissionContext(target_url="http://t/"))
        assert order == ["a", "b", "c"]

    def test_stage_errors_are_isolated(self):
        ctx = MissionContext(target_url="http://t/")

        class BoomStage:
            name = "boom"

            def run(self, _ctx):
                raise RuntimeError("explode")

        ran_after = {"flag": False}

        class FollowStage:
            name = "follow"

            def run(self, ctx):
                ran_after["flag"] = True

        Pipeline(stages=[BoomStage(), FollowStage()]).run(ctx)
        assert ran_after["flag"] is True
        assert ctx.errors and ctx.errors[0]["stage"] == "boom"

    def test_default_pipeline_has_four_stages(self):
        pipeline = build_default_pipeline(ai_client=None)
        names = [s.name for s in pipeline.stages]
        assert names == ["recon", "exploit", "validate", "report"]


# ─── End-to-end run_mission ──────────────────────────────────────────────────


class TestRunMissionE2E:
    def test_recon_only_mission_completes_and_tags_findings(self):
        # No AI client → exploit stage skips. Recon lifts the nuclei finding
        # into ctx.findings, validate keeps it (no confidence floor hit),
        # report tags it with ATT&CK technique IDs.
        ctx = run_mission(
            target_url="http://t/",
            options={"nuclei_jsonl": _NUCLEI_JSONL},
            ai_client=None,
        )
        assert len(ctx.findings) == 1
        assert "attack_techniques" in ctx.findings[0]
        # All four stages ran.
        names = [r.get("stage") for r in ctx.stage_results]
        assert names.count("recon") >= 1
        assert "exploit" in names
        assert "validate" in names
        assert "report" in names
