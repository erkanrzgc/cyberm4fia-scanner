"""Coverage guard: every attack/recon module must resolve to a SKILL.md.

Utility modules (reporting, payload data, tool runners) are exempt. This test
fails if a new module is added without wiring a skill, or if a mapped skill
file goes missing.
"""

from __future__ import annotations

import os

import pytest

from utils.ai import _load_skill_for_vuln

pytestmark = pytest.mark.unit

_MODULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "modules"
)

# Modules that are infrastructure/utilities, not attack techniques.
_UTILITY_MODULES = {
    "__init__", "compare", "guaranteed_checks", "nuclei_runner", "payloads",
    "poc_generator", "proxy_interceptor", "report",
}


def _attack_modules() -> list[str]:
    names = []
    for fn in os.listdir(_MODULES_DIR):
        if not fn.endswith(".py"):
            continue
        stem = fn[:-3]
        if stem in _UTILITY_MODULES:
            continue
        names.append(stem)
    return sorted(names)


@pytest.mark.parametrize("module", _attack_modules())
def test_every_attack_module_resolves_to_a_skill(module):
    skill = _load_skill_for_vuln(module)
    assert skill, f"module '{module}' has no skill wired in _SKILL_MAP"
    assert "EXPERT SKILL KNOWLEDGE BASE" in skill
