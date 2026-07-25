"""Tests for utils/scan_executor — phase-aware concurrent module fan-out."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable

import pytest

from utils.scan_executor import ScanExecutor, run_phase_concurrent


pytestmark = pytest.mark.unit


# ─── Fixtures ────────────────────────────────────────────────────────────────


@dataclass
class _FakeSpec:
    """Minimal stand-in for PhaseModuleSpec — same attribute surface."""

    id: str
    runner: Callable[[dict], Any]
    name: str = ""
    option_key: str | None = None
    phase: str = "pre_scan"
    requires_forms: bool = False
    collect_results: bool = True


def _patch_iter(monkeypatch, specs: list[_FakeSpec]) -> None:
    """Force iter_phase_module_specs to yield our fake specs verbatim."""
    monkeypatch.setattr(
        "utils.scan_executor.iter_phase_module_specs",
        lambda phase, options: iter(specs),
    )


# ─── Sequential path ─────────────────────────────────────────────────────────


def test_sequential_run_collects_results_in_order(monkeypatch):
    calls: list[str] = []

    def make_runner(name: str, result: list):
        def _run(state: dict) -> list:
            calls.append(name)
            return result
        return _run

    specs = [
        _FakeSpec(id="a", runner=make_runner("a", [{"type": "X", "marker": "a"}])),
        _FakeSpec(id="b", runner=make_runner("b", [{"type": "Y", "marker": "b"}])),
    ]
    _patch_iter(monkeypatch, specs)

    state: dict = {}
    executor = ScanExecutor(max_workers=4)
    collected = executor.run_phase("pre_scan", options={}, state=state)

    assert calls == ["a", "b"]  # registry order preserved
    assert [v["marker"] for v in collected] == ["a", "b"]
    assert state["all_vulns"] == collected


def test_runner_crash_is_isolated(monkeypatch):
    def boom(_state):
        raise RuntimeError("module crashed")

    specs = [
        _FakeSpec(id="ok", runner=lambda s: [{"type": "X"}]),
        _FakeSpec(id="bad", runner=boom),
        _FakeSpec(id="ok2", runner=lambda s: [{"type": "Y"}]),
    ]
    _patch_iter(monkeypatch, specs)

    state: dict = {}
    collected = ScanExecutor().run_phase("pre_scan", options={}, state=state)

    # The crash must not abort the phase — neighbours still emit findings.
    types = sorted(v["type"] for v in collected)
    assert types == ["X", "Y"]
    report = state["_phase_reports"][-1]
    assert "bad" in report.crashed


def test_requires_forms_skipped_without_forms(monkeypatch):
    calls: list[str] = []
    specs = [
        _FakeSpec(
            id="form_only",
            runner=lambda s: calls.append("form_only") or [],
            requires_forms=True,
        ),
        _FakeSpec(id="always", runner=lambda s: calls.append("always") or []),
    ]
    _patch_iter(monkeypatch, specs)

    ScanExecutor().run_phase("pre_scan", options={}, state={})
    assert calls == ["always"]


# ─── Concurrent path ────────────────────────────────────────────────────────


def test_parallel_ids_actually_run_concurrently(monkeypatch):
    """Four 200ms sleep specs should finish closer to 200ms than 800ms.

    Sequential would take ~800ms (4 × 200ms). With max_workers=4 it should
    finish in well under half that — we assert <500ms to absorb CI jitter.
    """
    def slow_runner(name: str):
        def _run(_state):
            time.sleep(0.2)
            return [{"type": "Slow", "name": name}]
        return _run

    specs = [
        _FakeSpec(id=f"slow_{i}", runner=slow_runner(f"slow_{i}"))
        for i in range(4)
    ]
    _patch_iter(monkeypatch, specs)

    parallel_ids = {f"slow_{i}" for i in range(4)}
    state: dict = {}

    t0 = time.monotonic()
    collected = ScanExecutor(max_workers=4).run_phase(
        "pre_scan", options={}, state=state, parallel_ids=parallel_ids,
    )
    elapsed = time.monotonic() - t0

    assert len(collected) == 4
    assert len(state["all_vulns"]) == 4
    # Sequential would be ~0.8s; with fan-out we expect well under 0.5s.
    assert elapsed < 0.5, (
        f"parallel fan-out did not happen: elapsed={elapsed:.3f}s"
    )


def test_parallel_crash_does_not_kill_phase(monkeypatch):
    def boom(_state):
        raise ValueError("kaboom")

    specs = [
        _FakeSpec(id="p1", runner=lambda s: [{"type": "A"}]),
        _FakeSpec(id="p2", runner=boom),
        _FakeSpec(id="p3", runner=lambda s: [{"type": "C"}]),
    ]
    _patch_iter(monkeypatch, specs)

    state: dict = {}
    collected = ScanExecutor().run_phase(
        "pre_scan",
        options={},
        state=state,
        parallel_ids={"p1", "p2", "p3"},
    )

    types = sorted(v["type"] for v in collected)
    assert types == ["A", "C"]
    report = state["_phase_reports"][-1]
    assert "p2" in report.crashed


def test_run_phase_concurrent_helper(monkeypatch):
    specs = [_FakeSpec(id="x", runner=lambda s: [{"type": "X"}])]
    _patch_iter(monkeypatch, specs)
    out = run_phase_concurrent("pre_scan", options={}, state={}, parallel_ids={"x"})
    assert out == [{"type": "X"}]


def test_collect_results_false_does_not_extend_state(monkeypatch):
    specs = [
        _FakeSpec(
            id="silent",
            runner=lambda s: [{"type": "Ignored"}],
            collect_results=False,
        ),
    ]
    _patch_iter(monkeypatch, specs)

    state: dict = {}
    collected = ScanExecutor().run_phase("pre_scan", options={}, state=state)
    assert collected == []
    assert "all_vulns" not in state
