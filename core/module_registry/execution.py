"""Registry iteration and execution helpers."""

from __future__ import annotations

from .async_modules import ASYNC_MODULES
from .phase_modules import PHASE_MODULES

def iter_async_module_specs(options: dict):
    """Yield enabled async module specs in registry order."""
    for spec in ASYNC_MODULES:
        if options.get(spec.option_key):
            yield spec


def iter_phase_module_specs(phase: str, options: dict):
    """Yield enabled scanner phase specs in registry order."""
    for spec in PHASE_MODULES:
        if spec.phase != phase:
            continue
        if spec.option_key is None or options.get(spec.option_key):
            yield spec


def run_phase_modules(phase: str, options: dict, state: dict):
    """Run sequential registry-backed modules for a given scanner phase."""
    from utils.colors import log_error

    collected = []
    for spec in iter_phase_module_specs(phase, options):
        if spec.requires_forms and not state.get("forms"):
            continue
        try:
            result = spec.runner(state)
            if spec.collect_results and result:
                collected.extend(result)
                state["all_vulns"] = list(state.get("all_vulns", [])) + list(result)
        except Exception as e:  # noqa: BLE001 — never let a single module kill the scan
            mod_name = spec.name or spec.option_key or "unknown"
            log_error(f"Module '{mod_name}' crashed: {type(e).__name__}: {e}")
    return collected
