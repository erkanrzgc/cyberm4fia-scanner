"""Registry metadata dataclasses."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

@dataclass(frozen=True)
class AsyncModuleSpec:
    """Metadata for concurrent per-page modules."""

    id: str
    option_key: str
    name: str
    phase: str
    requires_forms: bool
    loader: Callable[[], Callable]
    args_factory: Callable[[str, list, float, dict], tuple]

    def build_args(
        self,
        scan_url: str,
        forms: list,
        delay: float,
        options: dict | None = None,
    ) -> tuple:
        return self.args_factory(scan_url, forms, delay, options or {})


@dataclass(frozen=True)
class PhaseModuleSpec:
    """Metadata for scanner pipeline phases executed sequentially."""

    id: str
    option_key: str | None
    name: str
    phase: str
    requires_forms: bool
    collect_results: bool
    runner: Callable[[dict], Any]
