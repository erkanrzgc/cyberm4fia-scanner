"""Tests for the AI skill loader (utils.ai._load_skill_for_vuln).

The loader maps a vuln_type/module name to a SKILL.md, searching our own
``offensive-*`` skills first, then the imported ``hack-skills`` library.
"""

from __future__ import annotations

import pytest

from utils.ai import (
    _load_skill_for_vuln,
    _resolve_skill_file,
    skill_slug_for_vuln,
)

pytestmark = pytest.mark.unit


class TestSkillLoaderMechanism:
    def test_known_offensive_type_loads_content(self):
        out = _load_skill_for_vuln("sqli")
        assert out
        assert "EXPERT SKILL KNOWLEDGE BASE" in out

    def test_imported_hackskill_is_reachable_via_fallback(self):
        # prototype-pollution-advanced lives only in imported/hack-skills.
        path = _resolve_skill_file("prototype-pollution-advanced")
        assert path is not None
        assert path.endswith("SKILL.md")

    def test_unknown_type_returns_empty(self):
        assert _load_skill_for_vuln("totally_unknown_vuln") == ""

    def test_empty_type_returns_empty(self):
        assert _load_skill_for_vuln("") == ""

    def test_nosql_does_not_collide_with_sqli(self):
        # "sql" is a substring of "nosql"; precedence must pick the NoSQL skill.
        assert skill_slug_for_vuln("nosql_exploit") != "offensive-sqli"

    def test_proto_pollution_maps_to_imported_slug(self):
        assert skill_slug_for_vuln("proto_pollution") == "prototype-pollution-advanced"
