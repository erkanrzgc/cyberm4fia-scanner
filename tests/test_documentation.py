"""
Tests for documentation generation and sync.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.documentation import (  # noqa: E402
    DOC_TARGETS,
    GENERATED_SECTION_RENDERERS,
    render_attack_profiles_markdown,
    render_cli_flags_markdown,
    render_feature_tables_markdown,
    render_scan_modes_markdown,
)
from core.scan_options import SCAN_MODE_SPECS


def _extract_generated_section(text: str, section_name: str):
    start_marker = f"<!-- BEGIN GENERATED: {section_name} -->"
    end_marker = f"<!-- END GENERATED: {section_name} -->"
    start = text.index(start_marker) + len(start_marker)
    end = text.index(end_marker)
    return text[start:end].strip()


class TestDocumentation:
    def test_feature_tables_include_registry_and_auto_features(self):
        markdown = render_feature_tables_markdown()

        assert "### Web Application Scanning" in markdown
        assert "| Secrets Scan | `--secrets` |" in markdown
        assert "| Proxy Interceptor | `--proxy-listen PORT` |" in markdown
        assert "| PoC Generator | `(auto)` |" in markdown

    def test_cli_flags_include_generated_groups(self):
        markdown = render_cli_flags_markdown()

        assert "### Scan Modules" in markdown
        assert "| `--api-scan` | API security scan" in markdown
        assert "| `--proxy-listen PORT` | Start local MITM proxy" in markdown
        assert "| `--ai-model AI_MODEL` | Ollama model" in markdown

    def test_scan_modes_and_attack_profiles_render_from_metadata(self):
        mode_markdown = render_scan_modes_markdown()
        profile_markdown = render_attack_profiles_markdown()

        normal_mode = SCAN_MODE_SPECS[0]
        stealth_mode = SCAN_MODE_SPECS[1]
        lab_mode = SCAN_MODE_SPECS[2]

        assert (
            f"| `{normal_mode.key}` |" in mode_markdown
        )
        assert normal_mode.description in mode_markdown
        assert (
            f"| `{stealth_mode.key}` |" in mode_markdown
        )
        assert stealth_mode.description in mode_markdown
        assert f"| `{lab_mode.key}` |" in mode_markdown
        assert lab_mode.description in mode_markdown
        assert "| `1-Fast Recon` | Recon, subdomain discovery" in profile_markdown
        assert "`manual selection`" in profile_markdown
        assert "`(auto via --all)`" in profile_markdown
        assert "`--crawl`" in profile_markdown
        assert "`--wordlist`" in profile_markdown

    def test_repo_docs_match_generated_sections(self):
        for path, section_names in DOC_TARGETS.items():
            text = Path(path).read_text(encoding="utf-8")
            for section_name in section_names:
                expected = GENERATED_SECTION_RENDERERS[section_name]().strip()
                actual = _extract_generated_section(text, section_name)
                assert actual == expected
