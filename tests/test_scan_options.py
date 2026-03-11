"""
Tests for core/scan_options.py
"""

import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scan_options import (
    ATTACK_PROFILE_SPECS,
    ALL_ENABLED_OPTION_KEYS,
    DEFAULT_AI_MODEL,
    InteractivePromptSpec,
    SCAN_MODE_SPECS,
    apply_profile_preset,
    apply_interactive_prompt_specs,
    build_cli_scan_options,
    build_default_scan_options,
    get_attack_profile_recommended_prompt_specs,
    get_attack_profile_spec,
    get_interactive_runtime_prompt_specs,
    get_scan_mode_runtime,
    resolve_interactive_prompt_value,
)


def _make_args(**overrides):
    base = {
        "all": False,
        "recon": False,
        "subdomain": False,
        "fuzz": False,
        "crawl": False,
        "xss": False,
        "sqli": False,
        "lfi": False,
        "rfi": False,
        "cmdi": False,
        "dom_xss": False,
        "secrets": False,
        "oob": False,
        "ssrf": False,
        "csrf": False,
        "cors": False,
        "header_inject": False,
        "cloud": False,
        "takeover": False,
        "tech": False,
        "api_scan": False,
        "api_spec": "",
        "ssti": False,
        "xxe": False,
        "redirect": False,
        "spray": False,
        "email": False,
        "passive": False,
        "jwt": False,
        "race": False,
        "smuggle": False,
        "proto": False,
        "deser": False,
        "bizlogic": False,
        "osint": False,
        "chain": False,
        "wordlist": False,
        "headless": False,
        "cookie": "",
        "html": False,
        "sarif": False,
        "ai": False,
        "ai_model": DEFAULT_AI_MODEL,
        "proxy_listen": False,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


class TestScanOptions:
    def test_default_options_include_expected_runtime_defaults(self):
        options = build_default_scan_options(threads=33)

        assert options["threads"] == 33
        assert options["ai_model"] == DEFAULT_AI_MODEL
        assert options["xss"] is False
        assert options["api_spec"] == ""
        assert options["cookie"] == ""
        assert options["request_timeout"] > 0
        assert "logout" in options["path_blacklist"]

    def test_profile_presets_preserve_expected_groups(self):
        recon_options = build_default_scan_options()
        apply_profile_preset(recon_options, "1")
        assert recon_options["recon"] is True
        assert recon_options["subdomain"] is True
        assert recon_options["fuzz"] is True
        assert recon_options["tech"] is True
        assert recon_options["passive"] is True
        assert recon_options["xss"] is False

        all_options = build_default_scan_options()
        apply_profile_preset(all_options, "4")
        assert all_options["templates"] is True
        assert all_options["html"] is True
        assert all_options["wordlist"] is False
        assert all_options["api_spec"] == ""

    def test_cli_builder_preserves_use_all_behavior(self):
        options = build_cli_scan_options(_make_args(all=True), threads=25)

        for key in ALL_ENABLED_OPTION_KEYS:
            assert options[key] is True, key

        assert options["templates"] is True
        assert options["wordlist"] is False
        assert options["sarif"] is False
        assert options["ai"] is False
        assert options["threads"] == 25

    def test_cli_builder_preserves_explicit_values_without_all(self):
        args = _make_args(
            xss=True,
            api_scan=True,
            api_spec="spec.yaml",
            wordlist=True,
            cookie="sid=1",
            sarif=True,
            ai=True,
            ai_model="custom-model",
            html=True,
            tamper="space2comment",
            proxy_url="http://127.0.0.1:8080",
            scope="*.example.com",
            exclude="/logout",
            session="scan.json",
            resume="resume.json",
            exploit=True,
            max_requests=150,
            request_timeout=4.5,
            max_host_concurrency=2,
            path_blacklist="/logout,/checkout",
        )
        options = build_cli_scan_options(args, threads=12)

        assert options["xss"] is True
        assert options["api_scan"] is True
        assert options["api_spec"] == "spec.yaml"
        assert options["wordlist"] is True
        assert options["cookie"] == "sid=1"
        assert options["sarif"] is True
        assert options["ai"] is True
        assert options["ai_model"] == "custom-model"
        assert options["html"] is True
        assert options["tamper"] == "space2comment"
        assert options["proxy_url"] == "http://127.0.0.1:8080"
        assert options["scope"] == "*.example.com"
        assert options["exclude"] == "/logout"
        assert options["session"] == "scan.json"
        assert options["resume"] == "resume.json"
        assert options["exploit"] is True
        assert options["max_requests"] == 150
        assert options["request_timeout"] == 4.5
        assert options["max_host_concurrency"] == 2
        assert options["path_blacklist"] == "/logout,/checkout"
        assert options["templates"] is False
        assert options["threads"] == 12

    def test_cli_builder_normalizes_proxy_urls_without_scheme(self):
        args = _make_args(proxy_url="127.0.0.1:8080")

        options = build_cli_scan_options(args, threads=10)

        assert options["proxy_url"] == "http://127.0.0.1:8080"

    def test_interactive_prompt_resolution_preserves_yes_no_defaults(self):
        yes_default = InteractivePromptSpec("recon", "Recon?", "Y")
        no_default = InteractivePromptSpec("xss", "XSS?", "N")

        assert resolve_interactive_prompt_value(yes_default, "") is True
        assert resolve_interactive_prompt_value(yes_default, "n") is False
        assert resolve_interactive_prompt_value(no_default, "") is False
        assert resolve_interactive_prompt_value(no_default, "yes") is True

    def test_interactive_prompt_application_updates_target_dict(self):
        prompts = (
            InteractivePromptSpec("cookie", "Cookie?", "", value_type="text"),
            InteractivePromptSpec("html", "HTML?", "N"),
        )

        target = {}
        answers = {"Cookie?": "sid=1", "HTML?": "y"}

        apply_interactive_prompt_specs(
            target,
            prompts,
            lambda prompt, default: answers.get(prompt, default),
        )

        assert target == {"cookie": "sid=1", "html": True}

    def test_interactive_text_prompt_normalizes_proxy_and_discards_yes_for_session(self):
        proxy_prompt = InteractivePromptSpec(
            "proxy_url",
            "Proxy?",
            "",
            value_type="text",
        )
        session_prompt = InteractivePromptSpec(
            "session",
            "Session?",
            "",
            value_type="text",
        )

        assert (
            resolve_interactive_prompt_value(proxy_prompt, "127.0.0.1:8080")
            == "http://127.0.0.1:8080"
        )
        assert resolve_interactive_prompt_value(session_prompt, "y") == ""

    def test_scan_mode_runtime_uses_metadata_and_default_fallback(self):
        assert [spec.key for spec in SCAN_MODE_SPECS] == ["normal", "stealth", "lab"]
        assert get_scan_mode_runtime("lab") == ("lab", 0.05, 30)
        assert get_scan_mode_runtime("3") == ("lab", 0.05, 30)
        assert get_scan_mode_runtime("4") == (
            SCAN_MODE_SPECS[1].runtime_mode,
            SCAN_MODE_SPECS[1].delay,
            SCAN_MODE_SPECS[1].threads,
        )
        assert get_scan_mode_runtime("unknown") == (
            SCAN_MODE_SPECS[0].runtime_mode,
            SCAN_MODE_SPECS[0].delay,
            SCAN_MODE_SPECS[0].threads,
        )

    def test_attack_profile_lookup_uses_custom_fallback(self):
        assert ATTACK_PROFILE_SPECS[0].choice == "1"
        assert get_attack_profile_spec("2").label == "Core Web Vulns"
        assert get_attack_profile_spec("missing").choice == "5"

    def test_attack_profile_recommendations_filter_already_enabled_options(self):
        recommended = get_attack_profile_recommended_prompt_specs("1")
        filtered = get_attack_profile_recommended_prompt_specs(
            "1",
            {"crawl": True, "osint": False, "headless": False},
        )

        assert [spec.option_key for spec in recommended] == [
            "crawl",
            "osint",
            "headless",
        ]
        assert [spec.option_key for spec in filtered] == ["osint", "headless"]

    def test_interactive_runtime_prompts_adapt_to_mode_and_profile(self):
        prompts = get_interactive_runtime_prompt_specs("stealth", "1")
        filtered = get_interactive_runtime_prompt_specs(
            "stealth",
            "2",
            {"cookie": "sid=1", "resume": "resume.json"},
        )

        assert [spec.option_key for spec in prompts] == [
            "proxy_url",
            "scope",
            "exclude",
            "session",
            "exploit",
            "ai",
            "proxy_listen",
            "html",
            "sarif",
        ]
        assert [spec.option_key for spec in filtered] == [
            "tamper",
            "proxy_url",
            "scope",
            "exclude",
            "exploit",
            "ai",
            "proxy_listen",
            "html",
            "sarif",
        ]
