"""Scan-mode runtime and documentation specs."""

from __future__ import annotations

from utils.request import get_request_delay, get_stealth_delay

from .types import ScanModeSpec

SCAN_MODE_SPECS = (
    ScanModeSpec(
        key="normal",
        label="Normal",
        runtime_mode="normal",
        delay=get_request_delay(),
        threads=10,
        description="Balanced default mode for most targets.",
        cli_aliases=("1", "2"),
        interactive_choice="1",
    ),
    ScanModeSpec(
        key="stealth",
        label="Stealth",
        runtime_mode="stealth",
        delay=get_stealth_delay(),
        threads=1,
        description="Slow, low-noise mode for cautious testing.",
        cli_aliases=("4",),
        interactive_choice="2",
    ),
    ScanModeSpec(
        key="lab",
        label="Lab",
        runtime_mode="lab",
        delay=0.05,
        threads=30,
        description="High-noise mode for local labs, staging, and CTF environments only.",
        cli_aliases=("3",),
    ),
)

SCAN_MODE_MAP = {spec.key: spec for spec in SCAN_MODE_SPECS}
SCAN_MODE_ALIAS_MAP = {
    alias: spec.key for spec in SCAN_MODE_SPECS for alias in spec.cli_aliases
}
INTERACTIVE_SCAN_MODE_SPECS = tuple(
    spec for spec in SCAN_MODE_SPECS if spec.interactive_choice
)
