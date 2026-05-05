"""Tests for modules.nuclei_runner — Nuclei JSONL output parser + subprocess wrapper.

The nuclei binary is not invoked in tests; subprocess.run is mocked.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest


pytestmark = pytest.mark.unit


SAMPLE_RECORD = {
    "template-id": "cve-2021-44228",
    "info": {
        "name": "Log4Shell RCE",
        "severity": "critical",
        "description": "Apache Log4j2 JNDI RCE",
        "tags": ["cve", "rce", "log4j"],
        "classification": {"cve-id": ["CVE-2021-44228"]},
    },
    "matched-at": "https://target.example.com/api",
    "matcher-name": "word-match",
    "extracted-results": ["jndi-leak"],
    "curl-command": "curl -X POST https://target.example.com/api -d 'x'",
}


class TestObservationParser:
    def test_basic_fields(self):
        from modules.nuclei_runner import _to_observation

        obs = _to_observation(SAMPLE_RECORD, "https://target.example.com/")
        assert obs.observation_type == "cve-2021-44228"
        assert obs.severity == "critical"
        assert obs.confidence == "high"
        assert obs.url == "https://target.example.com/api"
        assert obs.module == "nuclei_runner"
        assert "Log4Shell" in obs.description
        assert "CVE-2021-44228" in obs.tags

    def test_unknown_severity_defaults_to_info(self):
        from modules.nuclei_runner import _to_observation

        record = {
            "template-id": "x", "info": {"severity": "weird"}, "matched-at": "u",
        }
        obs = _to_observation(record, "u")
        assert obs.severity == "info"
        assert obs.confidence == "medium"

    def test_tags_string_form_is_split(self):
        from modules.nuclei_runner import _to_observation

        record = {
            "template-id": "t",
            "info": {"name": "n", "severity": "low", "tags": "a, b ,c"},
            "matched-at": "u",
        }
        obs = _to_observation(record, "u")
        assert obs.tags == ["a", "b", "c"]


class TestJsonlParser:
    def test_skips_blank_and_invalid_lines(self):
        from modules.nuclei_runner import _parse_jsonl

        stdout = "\n".join([
            json.dumps(SAMPLE_RECORD),
            "",
            "not-json-here",
            json.dumps({"template-id": "x", "info": {"severity": "low"}, "matched-at": "u"}),
        ])
        records = list(_parse_jsonl(stdout))
        assert len(records) == 2
        assert records[0]["template-id"] == "cve-2021-44228"


class TestRunNuclei:
    def test_returns_empty_when_binary_missing(self):
        from modules import nuclei_runner

        with patch("modules.nuclei_runner.shutil.which", return_value=None):
            assert nuclei_runner.run_nuclei("https://x.test") == []

    def test_invokes_subprocess_and_parses_output(self):
        from modules import nuclei_runner

        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = json.dumps(SAMPLE_RECORD)
        proc.stderr = ""

        with patch("modules.nuclei_runner.shutil.which", return_value="/usr/bin/nuclei"), \
             patch("modules.nuclei_runner.subprocess.run", return_value=proc) as run_mock:
            obs_list = nuclei_runner.run_nuclei(
                "https://target.example.com/",
                severity=["high", "critical"],
                tags=["cve"],
                rate_limit=10,
                concurrency=5,
            )

        assert len(obs_list) == 1
        assert obs_list[0].severity == "critical"
        called_cmd = run_mock.call_args[0][0]
        assert "-jsonl" in called_cmd
        assert "high,critical" in called_cmd
        assert "cve" in called_cmd
        assert "-rate-limit" in called_cmd

    def test_timeout_returns_empty(self):
        from modules import nuclei_runner
        import subprocess

        with patch("modules.nuclei_runner.shutil.which", return_value="/usr/bin/nuclei"), \
             patch(
                 "modules.nuclei_runner.subprocess.run",
                 side_effect=subprocess.TimeoutExpired(cmd="nuclei", timeout=1),
             ):
            assert nuclei_runner.run_nuclei("https://x.test", timeout=1) == []


class TestScanWithNucleiEntrypoint:
    def test_passes_options_to_run_nuclei(self):
        from modules import nuclei_runner

        with patch("modules.nuclei_runner.run_nuclei", return_value=[]) as run_mock:
            nuclei_runner.scan_with_nuclei(
                "https://x.test",
                {"nuclei_severity": ["high"], "nuclei_tags": ["cve"]},
            )
        run_mock.assert_called_once()
        kwargs = run_mock.call_args.kwargs
        assert kwargs["severity"] == ["high"]
        assert kwargs["tags"] == ["cve"]
