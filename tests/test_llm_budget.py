"""Tests for the LLM-call budget guard.

The adaptive orchestration loop calls the AI client repeatedly (planner +
intent-agent retries). The budget wrapper caps total calls so a runaway
loop can't drain the NVIDIA NIM quota.
"""

from __future__ import annotations

import pytest

from utils.llm_budget import BudgetExceeded, LLMBudgetClient

pytestmark = pytest.mark.unit


class _FakeAI:
    def __init__(self, available=True):
        self.available = available
        self.calls = 0

    def generate(self, prompt, system="", **kw):
        self.calls += 1
        return "OK"


class TestLLMBudgetClient:
    def test_passes_calls_through_when_under_budget(self):
        inner = _FakeAI()
        client = LLMBudgetClient(inner, max_calls=3)

        assert client.generate("a") == "OK"
        assert client.generate("b") == "OK"
        assert client.calls_made == 2
        assert client.remaining == 1

    def test_blocks_call_that_would_exceed_budget(self):
        inner = _FakeAI()
        client = LLMBudgetClient(inner, max_calls=2)
        client.generate("a")
        client.generate("b")

        with pytest.raises(BudgetExceeded):
            client.generate("c")
        # Inner client must not have been invoked for the over-budget call.
        assert inner.calls == 2

    def test_propagates_available_attribute(self):
        client = LLMBudgetClient(_FakeAI(available=False), max_calls=10)
        assert client.available is False

    def test_zero_or_negative_budget_means_no_cap(self):
        # 0/-1 = "unlimited" — useful for opting out without changing call sites.
        client = LLMBudgetClient(_FakeAI(), max_calls=0)
        for _ in range(20):
            client.generate("x")
        assert client.calls_made == 20
