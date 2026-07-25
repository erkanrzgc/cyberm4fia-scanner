"""Tests for the adaptive LLM-driven orchestration layer.

Covers ``PlannerStage`` (state -> next in-scope intents) and the adaptive
loop that chains Plan -> Exploit rounds with scope + budget guards.
"""

from __future__ import annotations

import json

import pytest

from utils.agent_orchestrator import (
    MissionContext,
    PlannerStage,
    run_adaptive_loop,
)

pytestmark = pytest.mark.unit


# ─── Test doubles ────────────────────────────────────────────────────────────


class FakeAI:
    """Returns canned generate() responses in order; '[]' once exhausted."""

    def __init__(self, responses=None, available=True):
        self.available = available
        self._responses = list(responses or [])
        self.calls = []

    def generate(self, prompt, system="", temperature=0.3, **kw):
        self.calls.append({"prompt": prompt, "system": system})
        return self._responses.pop(0) if self._responses else "[]"


class FakeScope:
    """Allows a URL only if its host substring is in the allowlist."""

    def __init__(self, allowed_substrings):
        self._allowed = list(allowed_substrings)
        self.active = True

    def is_allowed(self, url):
        return any(s in url for s in self._allowed)


def _intents_json(*intents):
    return json.dumps(list(intents))


# ─── PlannerStage ────────────────────────────────────────────────────────────


class TestPlannerStage:
    def test_appends_in_scope_intents_from_llm(self):
        ctx = MissionContext(target_url="https://app.test/")
        ai = FakeAI([_intents_json(
            {"vuln_type": "sqli", "param": "id", "target_url": "https://app.test/p", "goal": "dump"},
            {"vuln_type": "xss", "param": "q", "target_url": "https://app.test/s", "goal": "alert"},
        )])
        scope = FakeScope(["app.test"])

        PlannerStage(ai_client=ai, scope=scope).run(ctx)

        assert len(ctx.intents) == 2
        assert {i["vuln_type"] for i in ctx.intents} == {"sqli", "xss"}

    def test_drops_out_of_scope_intents(self):
        ctx = MissionContext(target_url="https://app.test/")
        ai = FakeAI([_intents_json(
            {"vuln_type": "sqli", "param": "id", "target_url": "https://app.test/p", "goal": "g"},
            {"vuln_type": "ssrf", "param": "u", "target_url": "https://evil.com/x", "goal": "g"},
        )])
        scope = FakeScope(["app.test"])

        PlannerStage(ai_client=ai, scope=scope).run(ctx)

        assert len(ctx.intents) == 1
        assert ctx.intents[0]["vuln_type"] == "sqli"

    def test_dedupes_against_existing_intents(self):
        ctx = MissionContext(target_url="https://app.test/")
        ctx.add_intent({"vuln_type": "sqli", "param": "id",
                        "target_url": "https://app.test/p", "goal": "dump"})
        ai = FakeAI([_intents_json(
            {"vuln_type": "sqli", "param": "id", "target_url": "https://app.test/p", "goal": "dump"},
            {"vuln_type": "xss", "param": "q", "target_url": "https://app.test/s", "goal": "alert"},
        )])
        scope = FakeScope(["app.test"])

        PlannerStage(ai_client=ai, scope=scope).run(ctx)

        # Only the genuinely-new xss intent is added (sqli already present).
        assert len(ctx.intents) == 2
        assert sum(1 for i in ctx.intents if i["vuln_type"] == "sqli") == 1

    def test_respects_max_intents_per_round(self):
        ctx = MissionContext(target_url="https://app.test/")
        many = [{"vuln_type": f"v{n}", "param": "p", "target_url": "https://app.test/", "goal": "g"}
                for n in range(5)]
        ai = FakeAI([_intents_json(*many)])
        scope = FakeScope(["app.test"])

        PlannerStage(ai_client=ai, scope=scope, max_intents_per_round=2).run(ctx)

        assert len(ctx.intents) == 2

    def test_skips_when_ai_unavailable(self):
        ctx = MissionContext(target_url="https://app.test/")
        ai = FakeAI(available=False)

        PlannerStage(ai_client=ai, scope=FakeScope(["app.test"])).run(ctx)

        assert ctx.intents == []
        assert ai.calls == []
        assert ctx.stage_results[-1].get("skipped")

    def test_handles_malformed_llm_output(self):
        ctx = MissionContext(target_url="https://app.test/")
        ai = FakeAI(["not json at all <<<"])

        PlannerStage(ai_client=ai, scope=FakeScope(["app.test"])).run(ctx)

        assert ctx.intents == []


# ─── Adaptive loop ───────────────────────────────────────────────────────────


class _AddingPlanner:
    """Planner double that appends `per_round` unique intents each call,
    up to `rounds_with_output` calls, then nothing."""
    name = "plan"

    def __init__(self, rounds_with_output, per_round=1):
        self.rounds_with_output = rounds_with_output
        self.per_round = per_round
        self.calls = 0

    def run(self, ctx):
        self.calls += 1
        if self.calls <= self.rounds_with_output:
            for n in range(self.per_round):
                ctx.add_intent({"vuln_type": f"r{self.calls}_v{n}",
                                "target_url": ctx.target_url, "goal": "g"})


class _RecordingExploit:
    """Exploit double: turns every queued intent into a finding."""
    name = "exploit"

    def __init__(self):
        self.runs = 0

    def run(self, ctx):
        self.runs += 1
        for intent in ctx.intents:
            ctx.add_finding({"type": intent["vuln_type"], "module": "fake"})


class TestAdaptiveLoop:
    def test_stops_when_no_new_intents(self):
        ctx = MissionContext(target_url="https://app.test/")
        planner = _AddingPlanner(rounds_with_output=0)
        exploit = _RecordingExploit()

        run_adaptive_loop(ctx, planner, exploit, max_rounds=3)

        assert exploit.runs == 0
        assert ctx.stage_results[-1] == {"stage": "adaptive_loop", "rounds": 0}

    def test_respects_max_rounds_budget(self):
        ctx = MissionContext(target_url="https://app.test/")
        planner = _AddingPlanner(rounds_with_output=99)  # would never converge
        exploit = _RecordingExploit()

        run_adaptive_loop(ctx, planner, exploit, max_rounds=2)

        assert planner.calls == 2
        assert exploit.runs == 2
        assert ctx.stage_results[-1]["rounds"] == 2

    def test_chains_until_convergence(self):
        ctx = MissionContext(target_url="https://app.test/")
        planner = _AddingPlanner(rounds_with_output=2)  # rounds 1,2 add; round 3 empty
        exploit = _RecordingExploit()

        run_adaptive_loop(ctx, planner, exploit, max_rounds=5)

        assert exploit.runs == 2
        assert len(ctx.findings) == 2
        assert ctx.stage_results[-1]["rounds"] == 2

    def test_drains_intents_between_rounds(self):
        # Each round must only exploit that round's freshly-planned intents,
        # never re-running prior rounds' work.
        ctx = MissionContext(target_url="https://app.test/")

        class CountingExploit:
            name = "exploit"

            def __init__(self):
                self.seen_per_run = []

            def run(self, ctx):
                self.seen_per_run.append(len(ctx.intents))

        planner = _AddingPlanner(rounds_with_output=3, per_round=1)
        exploit = CountingExploit()

        run_adaptive_loop(ctx, planner, exploit, max_rounds=3)

        assert exploit.seen_per_run == [1, 1, 1]

    def test_default_scope_is_derived_from_target_host(self):
        # No explicit scope: planner must reject intents pointing off-host.
        from utils.agent_orchestrator import _resolve_default_scope
        scope = _resolve_default_scope("https://app.test/sub/")
        assert scope.is_allowed("https://app.test/x") is True
        assert scope.is_allowed("https://evil.example/x") is False

    def test_budget_exceeded_halts_loop_gracefully(self):
        # Planner raises BudgetExceeded mid-loop -> loop records halt + exits.
        from utils.llm_budget import BudgetExceeded
        ctx = MissionContext(target_url="https://app.test/")

        class _BudgetPlanner:
            name = "plan"

            def __init__(self):
                self.calls = 0

            def run(self, ctx):
                self.calls += 1
                if self.calls == 1:
                    ctx.add_intent({"vuln_type": "v1", "target_url": ctx.target_url, "goal": "g"})
                else:
                    raise BudgetExceeded("test cap reached")

        planner = _BudgetPlanner()
        exploit = _RecordingExploit()
        run_adaptive_loop(ctx, planner, exploit, max_rounds=5)

        assert exploit.runs == 1
        assert ctx.stage_results[-1]["halted"]

    def test_real_planner_dedup_prevents_infinite_rerun(self):
        # A planner that keeps proposing the SAME intent must converge once
        # the signature is already known, even if max_rounds is generous.
        ctx = MissionContext(target_url="https://app.test/")
        same = {"vuln_type": "sqli", "param": "id",
                "target_url": "https://app.test/p", "goal": "dump"}
        ai = FakeAI([_intents_json(same), _intents_json(same), _intents_json(same)])
        planner = PlannerStage(ai_client=ai, scope=FakeScope(["app.test"]))
        exploit = _RecordingExploit()

        run_adaptive_loop(ctx, planner, exploit, max_rounds=5)

        assert exploit.runs == 1
        assert ctx.stage_results[-1]["rounds"] == 1
