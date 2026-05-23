"""LLM call budget guard for adaptive orchestration.

Wraps any AI client (``NvidiaApiClient``, ``DualModelAI``, fakes) with a
``generate``-call counter and a hard cap. When the cap is exhausted the
wrapper raises :class:`BudgetExceeded` — the orchestrator catches this and
exits the loop cleanly so a runaway planner/intent-agent never drains the
NVIDIA NIM quota.

A cap of ``0`` (or negative) means "no limit" — callers can opt out without
restructuring code paths.
"""

from __future__ import annotations

from typing import Any


class BudgetExceeded(RuntimeError):
    """Raised when an additional ``generate`` call would breach the budget."""


class LLMBudgetClient:
    """AI-client proxy that counts ``generate`` calls and enforces a cap."""

    def __init__(self, inner: Any, *, max_calls: int):
        self._inner = inner
        self._max = int(max_calls)
        self._count = 0

    @property
    def available(self) -> bool:
        return bool(getattr(self._inner, "available", False))

    @property
    def calls_made(self) -> int:
        return self._count

    @property
    def remaining(self) -> int:
        if self._max <= 0:
            return -1   # unlimited
        return max(0, self._max - self._count)

    def generate(self, prompt: str, system: str = "", **kwargs) -> Any:
        if self._max > 0 and self._count >= self._max:
            raise BudgetExceeded(
                f"LLM call budget exhausted ({self._count}/{self._max})"
            )
        self._count += 1
        return self._inner.generate(prompt, system=system, **kwargs)

    def __getattr__(self, name: str) -> Any:
        # Pass through any other attributes/methods (e.g. get_client_for_role).
        return getattr(self._inner, name)
