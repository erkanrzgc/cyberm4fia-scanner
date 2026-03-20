"""
Tests for parser generation from core.scan_options metadata.
"""

import argparse
import json
import sys

import pytest

import scanner
from core.session import ScanSession
from core.scan_options import DEFAULT_AI_MODEL, add_parser_arguments

@pytest.fixture(autouse=True)
def reset_json_output():
    original = scanner.Config.JSON_OUTPUT
    yield
    scanner.Config.JSON_OUTPUT = original

class TestParser:
    def test_parse_args_accepts_generated_cli_flags(self):
        args = scanner.parse_args(
            [
                "-u",
                "example.com",
                "--api-scan",
                "--api-spec",
                "openapi.yaml",
                "--csrf",
                "--proxy-listen",
                "8081",
                "--scope-proxy",
                "example.com",
                "--ai",
                "--exploit",
                "--max-requests",
                "50",
                "--request-timeout",
                "4.5",
                "--max-host-concurrency",
                "2",
            ]
        )

        assert args.url == "example.com"
        assert args.api_scan is True
        assert args.api_spec == "openapi.yaml"
        assert args.csrf is True
        assert args.proxy_listen == 8081
        assert args.scope_proxy == "example.com"
        assert args.ai is True
        assert args.exploit is True
        assert args.max_requests == 50
        assert args.request_timeout == 4.5
        assert args.max_host_concurrency == 2
        assert args.ai_model == DEFAULT_AI_MODEL
        assert args.mode == "normal"
        assert {"url", "api_scan", "api_spec", "csrf", "proxy_listen", "scope_proxy", "ai", "exploit", "max_requests", "request_timeout", "max_host_concurrency"} <= args._provided_dests

    def test_generated_help_contains_key_metadata_options(self):
        parser = argparse.ArgumentParser(description="cyberm4fia-scanner")
        add_parser_arguments(parser)

        help_text = parser.format_help()

        assert "--api-scan" in help_text
        assert "--api-spec FILE" in help_text
        assert "--proxy-listen PORT" in help_text
        assert "--scope-proxy DOMAIN" in help_text
        assert "--ai-model AI_MODEL" in help_text
        assert "--mode MODE" in help_text
        assert "--exploit" in help_text
        assert "--max-requests N" in help_text
        assert "--request-timeout SECONDS" in help_text

    def test_resume_restore_helper_preserves_explicit_overrides(self):
        session = ScanSession("resume.json")
        session.set_target(
            "https://saved.example.com",
            "stealth",
            {
                "xss": True,
                "threads": 1,
                "proxy_url": "http://saved:8080",
                "json_output": True,
            },
        )

        target, mode, delay, options = scanner.restore_resume_scan_state(
            session,
            {
                "threads": 30,
                "proxy_url": "http://override:8080",
                "json_output": False,
                "ai_model": DEFAULT_AI_MODEL,
            },
            provided_dests={"threads", "proxy_url", "json", "mode"},
            mode_override="lab",
        )

        assert target == "https://saved.example.com"
        assert mode == "lab"
        assert delay == 0.05
        assert options["xss"] is True
        assert options["threads"] == 30
        assert options["proxy_url"] == "http://override:8080"
        assert options["json_output"] is False

    def test_summarize_restored_config_includes_overrides_and_reports(self):
        summary = scanner.summarize_restored_config(
            "https://saved.example.com",
            "lab",
            {
                "xss": True,
                "sqli": True,
                "threads": 30,
                "proxy_url": "http://override:8080",
                "scope": "*.example.com",
                "exclude": "/logout",
                "cookie": "sid=1",
                "tamper": "space2comment",
                "resume": "resume.json",
                "json_output": True,
                "html": True,
                "ai": True,
            },
            provided_dests={"mode", "proxy_url", "json"},
        )

        assert summary["Target"] == "https://saved.example.com"
        assert summary["Mode"] == "lab"
        assert summary["Threads"] == "30"
        assert summary["Enabled Checks"] == "2"
        assert summary["Sample Checks"] == "sqli, xss"
        assert summary["Proxy"] == "http://override:8080"
        assert summary["Scope"] == "*.example.com"
        assert summary["Exclude"] == "/logout"
        assert summary["Cookie"] == "set"
        assert summary["Tamper"] == "space2comment"
        assert summary["Session File"] == "resume.json"
        assert summary["Reports"] == "json, html"
        assert summary["AI"] == "enabled"
        assert summary["CLI Overrides"] == "json_output, proxy_url, threads"

    def test_main_cli_resume_prints_restored_summary(self, monkeypatch, tmp_path):
        session_path = tmp_path / "resume.json"
        session_path.write_text(
            json.dumps(
                {
                    "target": "https://saved.example.com",
                    "mode": "stealth",
                    "options": {
                        "xss": True,
                        "threads": 1,
                        "proxy_url": "http://saved:8080",
                    },
                }
            )
        )

        summary_calls = []
        scan_calls = []

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "scanner.py",
                "--resume",
                str(session_path),
                "--mode",
                "lab",
                "--proxy",
                "http://override:8080",
            ],
        )
        monkeypatch.setattr(scanner, "print_gradient_banner", lambda: None)
        monkeypatch.setattr(
            scanner,
            "print_restored_config_summary",
            lambda target, mode, options, provided_dests=None: summary_calls.append(
                {
                    "target": target,
                    "mode": mode,
                    "options": dict(options),
                    "provided_dests": set(provided_dests or set()),
                }
            ),
        )
        monkeypatch.setattr(
            scanner,
            "scan_target",
            lambda url, mode, delay, options, runtime_options, **kwargs: scan_calls.append(
                {
                    "url": url,
                    "mode": mode,
                    "delay": delay,
                    "options": dict(options),
                    "runtime_options": dict(runtime_options),
                }
            ),
        )

        scanner.main()

        assert len(summary_calls) == 1
        assert summary_calls[0]["target"] == "https://saved.example.com"
        assert summary_calls[0]["mode"] == "lab"
        assert summary_calls[0]["provided_dests"] == {"resume", "mode", "proxy_url"}
        assert summary_calls[0]["options"]["xss"] is True
        assert summary_calls[0]["options"]["proxy_url"] == "http://override:8080"
        assert summary_calls[0]["options"]["resume"] == str(session_path)
        assert len(scan_calls) == 1
        assert scan_calls[0]["url"] == "https://saved.example.com"
        assert scan_calls[0]["mode"] == "lab"
        assert scan_calls[0]["delay"] == 0.05
        assert scan_calls[0]["options"]["proxy_url"] == "http://override:8080"
        assert scan_calls[0]["runtime_options"]["proxy_url"] == "http://override:8080"

    def test_main_target_list_uses_target_specific_session_files(
        self, monkeypatch, tmp_path
    ):
        target_list = tmp_path / "targets.txt"
        target_list.write_text("example.com\napi.example.com\n")
        session_path = tmp_path / "scan.json"

        scan_calls = []

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "scanner.py",
                "-l",
                str(target_list),
                "--session",
                str(session_path),
                "--xss",
            ],
        )
        monkeypatch.setattr(scanner, "print_gradient_banner", lambda: None)
        monkeypatch.setattr(
            scanner,
            "scan_target",
            lambda url, mode, delay, options, runtime_options, **kwargs: scan_calls.append(
                {
                    "url": url,
                    "session_file": kwargs["session"].session_file,
                    "options": dict(options),
                }
            ),
        )

        scanner.main()

        assert [call["url"] for call in scan_calls] == [
            "http://example.com",
            "http://api.example.com",
        ]
        assert scan_calls[0]["session_file"].endswith("scan__example_com.json")
        assert scan_calls[1]["session_file"].endswith("scan__api_example_com.json")
        assert scan_calls[0]["options"]["session"].endswith("scan__example_com.json")
        assert scan_calls[1]["options"]["session"].endswith(
            "scan__api_example_com.json"
        )

    def test_main_target_list_resume_restores_target_specific_sessions(
        self, monkeypatch, tmp_path
    ):
        target_list = tmp_path / "targets.txt"
        target_list.write_text("example.com\napi.example.com\n")
        resume_path = tmp_path / "resume.json"
        (tmp_path / "resume__example_com.json").write_text(
            json.dumps(
                {
                    "target": "http://example.com",
                    "mode": "stealth",
                    "options": {"xss": True, "threads": 1},
                }
            )
        )
        (tmp_path / "resume__api_example_com.json").write_text(
            json.dumps(
                {
                    "target": "http://api.example.com",
                    "mode": "lab",
                    "options": {"sqli": True, "threads": 30},
                }
            )
        )

        scan_calls = []

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "scanner.py",
                "-l",
                str(target_list),
                "--resume",
                str(resume_path),
            ],
        )
        monkeypatch.setattr(scanner, "print_gradient_banner", lambda: None)
        monkeypatch.setattr(
            scanner,
            "scan_target",
            lambda url, mode, delay, options, runtime_options, **kwargs: scan_calls.append(
                {
                    "url": url,
                    "mode": mode,
                    "options": dict(options),
                }
            ),
        )

        scanner.main()

        assert scan_calls[0]["url"] == "http://example.com"
        assert scan_calls[0]["mode"] == "stealth"
        assert scan_calls[0]["options"]["xss"] is True
        assert scan_calls[0]["options"]["resume"].endswith(
            "resume__example_com.json"
        )
        assert scan_calls[1]["url"] == "http://api.example.com"
        assert scan_calls[1]["mode"] == "lab"
        assert scan_calls[1]["options"]["sqli"] is True
        assert scan_calls[1]["options"]["resume"].endswith(
            "resume__api_example_com.json"
        )
