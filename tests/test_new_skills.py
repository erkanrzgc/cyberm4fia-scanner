"""Tests for the 5 new SKILL.md files (defensive FP filter + 4 offensive).

Each skill must be loadable by ``utils.ai._load_skill_for_vuln`` either via
its slug lookup keyword or via explicit ``skill_slug=`` override. Frontmatter
must be present and the body must contain expected section headers.
"""

from __future__ import annotations

import os

import pytest

from utils.ai import _load_skill_for_vuln, _resolve_skill_file, skill_slug_for_vuln

pytestmark = pytest.mark.unit


NEW_SKILLS = {
    "offensive-clickjacking": ("clickjacking", "X-Frame-Options"),
    "offensive-hsts-downgrade": ("hsts_downgrade", "Strict-Transport-Security"),
    "offensive-mime-confusion": ("mime_confusion", "nosniff"),
    "offensive-referrer-policy-leak": ("referrer_leak", "Referrer-Policy"),
    "defensive-false-positive-filter": ("false_positive", "spa_fallback"),
}


class TestSkillFilesExist:
    @pytest.mark.parametrize("slug", list(NEW_SKILLS.keys()))
    def test_file_resolves(self, slug):
        path = _resolve_skill_file(slug)
        assert path is not None, f"{slug} not found on disk"
        assert path.endswith("SKILL.md")
        assert os.path.exists(path)


class TestSlugLookup:
    @pytest.mark.parametrize("slug,keyword", [(s, k[0]) for s, k in NEW_SKILLS.items()])
    def test_keyword_maps_to_slug(self, slug, keyword):
        assert skill_slug_for_vuln(keyword) == slug


class TestSkillContent:
    @pytest.mark.parametrize("slug,bodymark", [(s, k[1]) for s, k in NEW_SKILLS.items()])
    def test_body_contains_expected_marker(self, slug, bodymark):
        path = _resolve_skill_file(slug)
        with open(path) as f:
            content = f.read()
        # Frontmatter present
        assert content.startswith("---\n")
        assert "\nname:" in content
        assert "\ndescription:" in content
        # Domain-specific marker
        assert bodymark.lower() in content.lower(), f"{slug} body missing {bodymark!r}"


class TestExplicitSlugOverride:
    """Findings enriched by header_exploit_map carry skill_slug — that path
    must work even if the type doesn't match any substring in _SKILL_MAP."""

    def test_explicit_slug_loads(self):
        out = _load_skill_for_vuln(
            "Missing_Security_Header", skill_slug="offensive-clickjacking"
        )
        assert out
        assert "EXPERT SKILL KNOWLEDGE BASE" in out
        assert "Clickjacking" in out
