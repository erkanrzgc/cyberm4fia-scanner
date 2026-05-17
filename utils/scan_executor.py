"""Concurrent phase-module executor.

Drop-in companion to :func:`core.module_registry.execution.run_phase_modules`.
Where the sequential runner walks specs one at a time, ``ScanExecutor`` fans
opt-in specs out across a thread pool while keeping the rest sequential.

Design constraints honoured:

* ``PhaseModuleSpec`` is frozen — paralelizm whitelist'i **id bazlı** dışarıdan
  geçirilir, dataclass'a yeni alan eklenmez.
* Hata izolasyonu ``run_phase_modules`` ile birebir aynı: tek bir modül crash
  ederse scan ölmez, ``log_error`` yazar.
* ``state['all_vulns']`` tek bir bütünleşik liste olarak güncellenir — paralel
  worker'lar ``state.lock`` üzerinden serileştirilir.
* Sync runner'lar için thread-pool yeterlidir (asyncio gereksiz; modüller
  bloklayan I/O yapıyor ve scanner.py top-level sync).

Typical use::

    parallel_pre_scan = {
        "osint", "osint_identity", "osint_breach", "osint_sector",
        "dorking", "wayback", "urlscan",
    }
    executor = ScanExecutor(max_workers=8)
    executor.run_phase("pre_scan", options, state, parallel_ids=parallel_pre_scan)
"""

from __future__ import annotations

import concurrent.futures
import threading
from dataclasses import dataclass, field
from typing import Iterable

from core.module_registry.execution import iter_phase_module_specs
from core.module_registry.types import PhaseModuleSpec
from utils.colors import log_error, log_info
from utils.request import ScanCancelled, get_thread_count


@dataclass
class PhaseExecutionReport:
    """Telemetry from a single phase execution."""

    phase: str
    sequential_count: int = 0
    parallel_count: int = 0
    crashed: list[str] = field(default_factory=list)
    collected_count: int = 0


class ScanExecutor:
    """Thread-pool fan-out for opt-in phase modules.

    Whitelist'te (``parallel_ids``) yer alan modüller eş zamanlı çalışır;
    diğerleri sırayla. Bağımsız I/O-bound modüller için 3-5x hız beklenir
    (OSINT, dorking, wayback, urlscan gibi).
    """

    def __init__(self, max_workers: int | None = None):
        self.max_workers = max_workers or get_thread_count()
        self._results_lock = threading.Lock()

    # ── Public API ──────────────────────────────────────────────────────────

    def run_phase(
        self,
        phase: str,
        options: dict,
        state: dict,
        parallel_ids: Iterable[str] | None = None,
    ) -> list:
        """Execute every enabled spec for ``phase``.

        Specs whose ``id`` is in ``parallel_ids`` are dispatched to the thread
        pool together; the rest run sequentially in registry order. Results
        from collect-enabled specs are merged into ``state['all_vulns']`` and
        returned to the caller for downstream chaining.

        Returns the flat list of newly collected vulns from this phase
        (same shape as :func:`run_phase_modules`).
        """
        parallel_set = set(parallel_ids or [])
        report = PhaseExecutionReport(phase=phase)

        sequential_specs: list[PhaseModuleSpec] = []
        parallel_specs: list[PhaseModuleSpec] = []
        for spec in iter_phase_module_specs(phase, options):
            if spec.requires_forms and not state.get("forms"):
                continue
            if spec.id in parallel_set:
                parallel_specs.append(spec)
            else:
                sequential_specs.append(spec)

        collected: list = []

        # Sequential first — preserves dependency order for non-parallel specs.
        for spec in sequential_specs:
            collected.extend(self._run_one(spec, state, report))
            report.sequential_count += 1

        # Parallel fan-out for I/O-bound bağımsız modüller.
        if parallel_specs:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.max_workers
            ) as pool:
                futures = {
                    pool.submit(self._run_one_isolated, spec, state): spec
                    for spec in parallel_specs
                }
                try:
                    for future in concurrent.futures.as_completed(futures):
                        spec = futures[future]
                        try:
                            spec_result = future.result()
                        except ScanCancelled:
                            raise
                        except Exception as exc:  # noqa: BLE001
                            report.crashed.append(spec.name or spec.id)
                            log_error(
                                f"Module '{spec.name or spec.id}' crashed: "
                                f"{type(exc).__name__}: {exc}"
                            )
                            continue
                        if spec.collect_results and spec_result:
                            with self._results_lock:
                                state["all_vulns"] = list(
                                    state.get("all_vulns", [])
                                ) + list(spec_result)
                            collected.extend(spec_result)
                        report.parallel_count += 1
                except ScanCancelled:
                    log_info(
                        "[-] Scan cancelled during concurrent phase; "
                        "stopping workers..."
                    )
                    for pending in futures:
                        pending.cancel()
                    raise

        report.collected_count = len(collected)
        state.setdefault("_phase_reports", []).append(report)
        return collected

    # ── Internal helpers ────────────────────────────────────────────────────

    def _run_one(
        self,
        spec: PhaseModuleSpec,
        state: dict,
        report: PhaseExecutionReport,
    ) -> list:
        """Sequential runner — mirrors run_phase_modules exception policy."""
        try:
            result = spec.runner(state)
        except ScanCancelled:
            raise
        except Exception as exc:  # noqa: BLE001
            report.crashed.append(spec.name or spec.id)
            log_error(
                f"Module '{spec.name or spec.id}' crashed: "
                f"{type(exc).__name__}: {exc}"
            )
            return []
        if spec.collect_results and result:
            state["all_vulns"] = list(state.get("all_vulns", [])) + list(result)
            return list(result)
        return []

    def _run_one_isolated(self, spec: PhaseModuleSpec, state: dict) -> list:
        """Thread-worker variant — no shared-state write here.

        State mutation happens in the futures-completion loop under the lock,
        avoiding interleaved appends to ``state['all_vulns']``.
        """
        result = spec.runner(state)
        return list(result) if result else []


def run_phase_concurrent(
    phase: str,
    options: dict,
    state: dict,
    parallel_ids: Iterable[str] | None = None,
    max_workers: int | None = None,
) -> list:
    """One-shot convenience: build a ScanExecutor and run a single phase."""
    return ScanExecutor(max_workers=max_workers).run_phase(
        phase, options, state, parallel_ids=parallel_ids
    )
