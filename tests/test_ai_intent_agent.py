"""Tests for utils/ai_intent_agent — intent-driven, self-healing exploit agent."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from utils.ai_intent_agent import (
    Intent,
    IntentAgent,
    _extract_python_block,
)


pytestmark = pytest.mark.unit


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _client(responses: list[str]) -> MagicMock:
    """Mock NvidiaApiClient that returns scripted responses in order."""
    cli = MagicMock()
    cli.available = True
    cli.generate = MagicMock(side_effect=responses)
    return cli


def _fence(body: str) -> str:
    return f"```python\n{body}\n```"


# ─── Python-block extraction ─────────────────────────────────────────────────


class TestExtractPythonBlock:
    def test_pulls_fenced_python_block(self):
        text = "Sure, here:\n```python\nresult = {'ok': True}\n```\nDone."
        assert _extract_python_block(text) == "result = {'ok': True}"

    def test_pulls_unlabelled_fence(self):
        text = "```\nresult = {'ok': True}\n```"
        assert _extract_python_block(text) == "result = {'ok': True}"

    def test_returns_empty_for_prose_only(self):
        assert _extract_python_block("nothing useful here") == ""

    def test_falls_back_to_plain_python_if_no_fence(self):
        assert _extract_python_block("import json\nresult = {}").startswith("import")


# ─── Outcome paths ───────────────────────────────────────────────────────────


class TestRunOutcomes:
    def test_no_client_returns_skipped_outcome(self):
        agent = IntentAgent(ai_client=None)
        out = agent.run(Intent(goal="x", target_url="http://t/"))
        assert out.success is False
        assert "not available" in out.summary

    def test_first_try_confirmation_short_circuits_loop(self):
        # First response: a script that confirms the bug.
        body = (
            "result = {"
            "'confirmed': True, 'confidence': 95, "
            "'evidence': 'reflected', 'payload': '<svg/onload=1>', "
            "'notes': 'ok'}"
        )
        client = _client([_fence(body)])
        agent = IntentAgent(client, max_iterations=3, sandbox_timeout=5)

        out = agent.run(Intent(
            goal="Confirm reflected XSS",
            target_url="http://example.invalid/",
            param="q",
            vuln_type="XSS",
        ))

        assert out.success is True
        assert out.iterations_used == 1
        assert out.confidence == 95.0
        assert out.evidence == "reflected"
        # The LLM should only have been called once.
        assert client.generate.call_count == 1

    def test_self_healing_loop_recovers_after_runtime_error(self):
        # First response raises at runtime; second confirms.
        broken = "raise RuntimeError('first attempt died')"
        good = (
            "result = {"
            "'confirmed': True, 'confidence': 80, "
            "'evidence': 'sql error visible', 'payload': \"' OR 1=1 -- \", "
            "'notes': 'mysql error reflected'}"
        )
        client = _client([_fence(broken), _fence(good)])
        agent = IntentAgent(client, max_iterations=3, sandbox_timeout=5)

        out = agent.run(Intent(
            goal="Find SQLi",
            target_url="http://example.invalid/",
            param="id",
            vuln_type="SQLi",
        ))

        assert out.success is True
        assert out.iterations_used == 2
        # First attempt failed with a runtime error.
        first = out.attempts[0]
        assert first.confirmed is False
        assert first.execution.exception_type == "RuntimeError"
        # Second attempt confirms.
        assert out.attempts[1].confirmed is True
        # Repair prompt was issued (second LLM call).
        assert client.generate.call_count == 2

    def test_low_confidence_is_treated_as_unconfirmed(self):
        body = (
            "result = {'confirmed': True, 'confidence': 30, "
            "'evidence': 'maybe', 'payload': 'x', 'notes': 'shaky'}"
        )
        # All 3 attempts return the same low-confidence "confirmation".
        client = _client([_fence(body)] * 3)
        agent = IntentAgent(client, max_iterations=3, sandbox_timeout=5)

        out = agent.run(Intent(
            goal="Probe",
            target_url="http://example.invalid/",
            param="x",
            vuln_type="XSS",
        ))

        assert out.success is False
        assert out.iterations_used == 3
        assert "no confirmed exploit" in out.summary
        for attempt in out.attempts:
            assert attempt.confirmed is False
            assert "below 60" in attempt.fail_reason

    def test_empty_llm_response_is_skipped_not_crashed(self):
        client = _client(["", "no code here at all", ""])
        agent = IntentAgent(client, max_iterations=3, sandbox_timeout=5)

        out = agent.run(Intent(
            goal="x",
            target_url="http://t/",
            vuln_type="XSS",
        ))

        assert out.success is False
        # Each "empty" response just skips, so no attempts recorded.
        assert out.iterations_used == 0
        assert client.generate.call_count == 3
