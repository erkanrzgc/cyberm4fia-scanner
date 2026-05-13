"""Module registry metadata and runners.

Replaces the former 988-LOC ``core/module_registry.py`` with cohesive
submodules while preserving the public import surface.
"""

from .async_modules import ASYNC_MODULES
from .execution import (
    iter_async_module_specs,
    iter_phase_module_specs,
    run_phase_modules,
)
from .phase_modules import PHASE_MODULES
from .types import AsyncModuleSpec, PhaseModuleSpec
from .urls import canonicalize_scan_url, canonicalize_scan_urls

__all__ = [
    "AsyncModuleSpec",
    "PhaseModuleSpec",
    "canonicalize_scan_url",
    "canonicalize_scan_urls",
    "ASYNC_MODULES",
    "PHASE_MODULES",
    "iter_async_module_specs",
    "iter_phase_module_specs",
    "run_phase_modules",
]
