"""Tests for ExternalToolStage — bridges external CLI tools into the mission.

Runs a set of ExternalTool adapters against the target, merges their
``to_findings`` output into ``ctx.findings``, and records a per-tool summary
in ``ctx.tech_profile``. Unavailable or failing tools are skipped cleanly.
"""

from __future__ import annotations

import pytest

from utils.agent_orchestrator import (
    ExternalToolStage,
    MissionContext,
    ReconStage,
    build_default_pipeline,
    run_adaptive_mission,
)
from utils.external_tools.base import ToolResult

pytestmark = pytest.mark.unit


class _FakeTool:
    """Duck-typed ExternalTool stand-in for deterministic stage tests."""

    def __init__(self, binary, result, findings=None, raises=False):
        self.binary = binary
        self._result = result
        self._findings = findings or []
        self._raises = raises
        self.received_kwargs = None

    def run(self, target, **kwargs):
        self.received_kwargs = kwargs
        return self._result

    def to_findings(self, parsed, *, target=""):
        if self._raises:
            raise ValueError("boom")
        return self._findings


class TestExternalToolStage:
    def test_runs_available_tool_and_merges_findings(self):
        ctx = MissionContext(target_url="https://app.test/")
        tool = _FakeTool(
            "masscan",
            ToolResult(tool="masscan", available=True, returncode=0,
                       parsed={"count": 1}),
            findings=[{"type": "Weak_TLS_Protocol", "module": "masscan"}],
        )

        ExternalToolStage(tools=[tool]).run(ctx)

        assert len(ctx.findings) == 1
        assert ctx.tech_profile["masscan"]["summary"] == {"count": 1}
        assert ctx.stage_results[-1]["ran"] == ["masscan"]

    def test_skips_unavailable_tool(self):
        ctx = MissionContext(target_url="https://app.test/")
        tool = _FakeTool(
            "wpscan",
            ToolResult(tool="wpscan", available=False, error="not in PATH"),
        )

        ExternalToolStage(tools=[tool]).run(ctx)

        assert ctx.findings == []
        assert "wpscan" not in ctx.tech_profile
        assert ctx.stage_results[-1]["skipped"] == ["wpscan"]

    def test_forwards_per_tool_kwargs(self):
        ctx = MissionContext(target_url="1.2.3.4")
        tool = _FakeTool(
            "masscan",
            ToolResult(tool="masscan", available=True, returncode=0, parsed={}),
        )

        ExternalToolStage(
            tools=[tool],
            tool_kwargs={"masscan": {"ports": "80,443", "rate": 5000}},
        ).run(ctx)

        assert tool.received_kwargs == {"ports": "80,443", "rate": 5000}

    def test_one_failing_tool_does_not_block_others(self):
        ctx = MissionContext(target_url="https://app.test/")
        bad = _FakeTool(
            "arjun",
            ToolResult(tool="arjun", available=True, returncode=0, parsed={}),
            raises=True,
        )
        good = _FakeTool(
            "sslyze",
            ToolResult(tool="sslyze", available=True, returncode=0, parsed={}),
            findings=[{"type": "Weak_TLS_Protocol", "module": "sslyze"}],
        )

        ExternalToolStage(tools=[bad, good]).run(ctx)

        # The good tool still contributed its finding despite arjun raising.
        assert len(ctx.findings) == 1
        assert ctx.findings[0]["module"] == "sslyze"
        assert "sslyze" in ctx.stage_results[-1]["ran"]


class TestPipelineWiring:
    def test_default_pipeline_omits_external_stage_by_default(self):
        pipeline = build_default_pipeline()
        assert not any(isinstance(s, ExternalToolStage) for s in pipeline.stages)

    def test_external_stage_inserted_right_after_recon(self):
        tool = _FakeTool("masscan",
                         ToolResult(tool="masscan", available=True, returncode=0, parsed={}))
        pipeline = build_default_pipeline(external_tools=[tool])
        kinds = [type(s) for s in pipeline.stages]
        assert ExternalToolStage in kinds
        assert kinds.index(ExternalToolStage) == kinds.index(ReconStage) + 1

    def test_adaptive_mission_runs_external_tools(self):
        tool = _FakeTool(
            "wpscan",
            ToolResult(tool="wpscan", available=True, returncode=0, parsed={"count": 1}),
            findings=[{"type": "WordPress_Vuln", "module": "wpscan"}],
        )
        # No AI client -> planner/exploit skip; external recon still runs.
        ctx = run_adaptive_mission("https://wp.test/", external_tools=[tool])
        assert any(f["module"] == "wpscan" for f in ctx.findings)
        assert tool.received_kwargs is not None
