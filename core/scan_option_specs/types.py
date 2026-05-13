"""Declarative scan-option metadata types."""

from __future__ import annotations

from dataclasses import dataclass

@dataclass(frozen=True)
class ArgumentSpec:
    """Declarative argparse metadata."""

    flags: tuple[str, ...]
    kwargs: dict


@dataclass(frozen=True)
class InteractivePromptSpec:
    """Declarative interactive prompt metadata."""

    option_key: str
    prompt: str
    default: str = "N"
    value_type: str = "bool"
    skip_if_truthy: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScanModeSpec:
    """Runtime and documentation metadata for scan modes."""

    key: str
    label: str
    runtime_mode: str
    delay: float
    threads: int
    description: str
    cli_aliases: tuple[str, ...] = ()
    interactive_choice: str | None = None


@dataclass(frozen=True)
class AttackProfileSpec:
    """Interactive and documentation metadata for attack profiles."""

    choice: str
    label: str
    description: str
    option_keys: frozenset[str]
    interactive_label: str
    recommended_prompt_specs: tuple[InteractivePromptSpec, ...] = ()
