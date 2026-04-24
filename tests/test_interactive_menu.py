"""
Tests for interactive menu prompt generation.
"""

import json

import pytest

import scanner
from core import interactive as interactive_mod
from core.scan_options import (
    API_SPEC_PROMPT,
    INTERACTIVE_CUSTOM_PROMPT_GROUPS,
    get_attack_profile_recommended_prompt_specs,
    get_interactive_runtime_prompt_specs,
)

@pytest.fixture(autouse=True)
def reset_json_output():
    original = scanner.Config.JSON_OUTPUT
    yield
    scanner.Config.JSON_OUTPUT = original

class TestInteractiveMenu:
    def test_profile_preset_applies_recommended_extras(self, monkeypatch):
        prompt_log = []
        answers = {
            "\n[?] Target URL:": "example.com",
            "[?] Resume session file (leave empty to configure a new scan)": "",
            "[?] Choice [1]:": "1",
            "[?] Choice [4]:": "1",
            "[?] Recommended: crawl the site too? (Y/n)": "y",
            "[?] Recommended: enable OSINT enrichment? (y/N)": "y",
            "[?] Recommended: use headless SPA discovery? (y/N)": "n",
            "[?] Proxy URL (leave empty for none)": "127.0.0.1:8080",
            "[?] Scope include patterns (comma-separated, leave empty for none)": "*.example.com",
            "[?] Session save file (leave empty to disable)": "sessions/recon.json",
        }

        def fake_get_input(prompt, default=""):
            prompt_log.append(prompt)
            return answers.get(prompt, default)

        monkeypatch.setattr(interactive_mod, "get_input", fake_get_input)
        monkeypatch.setattr(scanner.console, "print", lambda *args, **kwargs: None)

        _, _, _, options = scanner.interactive_menu()

        assert options["recon"] is True
        assert options["subdomain"] is True
        assert options["fuzz"] is True
        assert options["tech"] is True
        assert options["passive"] is True
        assert options["crawl"] is True
        assert options["osint"] is True
        assert options["headless"] is False
        assert options["proxy_url"] == "http://127.0.0.1:8080"
        assert options["scope"] == "*.example.com"
        assert options["session"] == "sessions/recon.json"

        for spec in get_attack_profile_recommended_prompt_specs("1"):
            assert spec.prompt in prompt_log

        for spec in get_interactive_runtime_prompt_specs("normal", "1"):
            assert spec.prompt in prompt_log

    def test_resume_session_restores_saved_config_early(self, monkeypatch, tmp_path):
        session_path = tmp_path / "resume.json"
        session_path.write_text(
            json.dumps(
                {
                    "target": "https://saved.example.com",
                    "mode": "stealth",
                    "options": {
                        "xss": True,
                        "proxy_url": "http://saved:8080",
                        "json_output": True,
                        "threads": 1,
                    },
                    "scanned_urls": ["https://saved.example.com/a"],
                    "pending_urls": [],
                }
            )
        )

        prompt_log = []
        answers = {
            "\n[?] Target URL:": "",
            "[?] Resume session file (leave empty to configure a new scan)": str(session_path),
        }

        def fake_get_input(prompt, default=""):
            prompt_log.append(prompt)
            return answers.get(prompt, default)

        summary_calls = []
        monkeypatch.setattr(interactive_mod, "get_input", fake_get_input)
        monkeypatch.setattr(scanner.console, "print", lambda *args, **kwargs: None)
        monkeypatch.setattr(
            interactive_mod,
            "print_restored_config_summary",
            lambda target, mode, options, provided_dests=None: summary_calls.append(
                {
                    "target": target,
                    "mode": mode,
                    "options": dict(options),
                    "provided_dests": provided_dests,
                }
            ),
        )

        url, mode, delay, options = scanner.interactive_menu()

        assert url == "https://saved.example.com"
        assert mode == "stealth"
        assert delay == scanner.Config.STEALTH_DELAY
        assert options["xss"] is True
        assert options["proxy_url"] == "http://saved:8080"
        assert options["json_output"] is True
        assert options["resume"] == str(session_path)
        assert scanner.Config.JSON_OUTPUT is True
        assert "[?] Choice [1]:" not in prompt_log
        assert summary_calls == [
            {
                "target": "https://saved.example.com",
                "mode": "stealth",
                "options": dict(options),
                "provided_dests": None,
            }
        ]

    def test_custom_profile_uses_metadata_prompts_and_conditional_api_spec(
        self, monkeypatch
    ):
        prompt_log = []
        answers = {
            "\n[?] Target URL:": "example.com",
            "[?] Resume session file (leave empty to configure a new scan)": "",
            "[?] Choice [1]:": "1",
            "[?] Choice [4]:": "5",
            "[?] Test XSS? (y/N)": "y",
            "[?] Run API Security Scan? (y/N)": "y",
            API_SPEC_PROMPT.prompt: "openapi.yaml",
            "[?] Cookie (leave empty for none)": "sid=1",
            "[?] Session save file (leave empty to disable)": "session.json",
            "[?] Enable AI Vulnerability Analysis (NVIDIA API)? (y/N)": "y",
            "[?] Generate HTML report? (y/N)": "y",
            "[?] Save JSON? (y/N)": "y",
        }

        def fake_get_input(prompt, default=""):
            prompt_log.append(prompt)
            return answers.get(prompt, default)

        monkeypatch.setattr(interactive_mod, "get_input", fake_get_input)
        monkeypatch.setattr(scanner.console, "print", lambda *args, **kwargs: None)

        url, mode, delay, options = scanner.interactive_menu()

        assert url == "http://example.com"
        assert mode == "normal"
        assert delay == scanner.Config.REQUEST_DELAY
        assert options["recon"] is True
        assert options["xss"] is True
        assert options["api_scan"] is True
        assert options["api_spec"] == "openapi.yaml"
        assert options["cookie"] == "sid=1"
        assert options["resume"] == ""
        assert options["session"] == "session.json"
        assert options["ai"] is True
        assert options["html"] is True
        assert scanner.Config.JSON_OUTPUT is True

        for _, prompt_specs in INTERACTIVE_CUSTOM_PROMPT_GROUPS:
            for spec in prompt_specs:
                assert spec.prompt in prompt_log

        for spec in get_interactive_runtime_prompt_specs("normal", "5"):
            assert spec.prompt in prompt_log

        assert API_SPEC_PROMPT.prompt in prompt_log

    def test_custom_profile_skips_api_spec_prompt_without_api_scan(self, monkeypatch):
        prompt_log = []
        answers = {
            "\n[?] Target URL:": "example.com",
            "[?] Resume session file (leave empty to configure a new scan)": "",
            "[?] Choice [1]:": "1",
            "[?] Choice [4]:": "5",
        }

        def fake_get_input(prompt, default=""):
            prompt_log.append(prompt)
            return answers.get(prompt, default)

        monkeypatch.setattr(interactive_mod, "get_input", fake_get_input)
        monkeypatch.setattr(scanner.console, "print", lambda *args, **kwargs: None)

        _, _, _, options = scanner.interactive_menu()

        assert options["api_scan"] is False
        assert options["api_spec"] == ""
        assert API_SPEC_PROMPT.prompt not in prompt_log
