"""Tests for the unified external-tool adapter layer (utils/external_tools).

``ExternalTool`` gives every battle-tested CLI scanner one contract:
availability check -> build command -> run with timeout -> structured parse.
``MasscanTool`` is the first concrete wrapper (fast network port scanning).
"""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from utils.external_tools.base import ExternalTool, ToolResult
from utils.external_tools.masscan import MasscanTool

pytestmark = pytest.mark.unit


# ─── A minimal concrete tool used to exercise the base contract ───────────────


class _EchoTool(ExternalTool):
    binary = "echotool"

    def get_command(self, target, **kwargs):
        return [self.binary, target]

    def parse_output(self, stdout, stderr, returncode):
        return {"echo": stdout.strip()}


def _completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(args=["x"], returncode=returncode,
                                       stdout=stdout, stderr=stderr)


# ─── Base contract ────────────────────────────────────────────────────────────


class TestExternalToolBase:
    def test_skips_when_binary_missing(self):
        with patch("utils.external_tools.base.shutil.which", lambda _: None):
            result = _EchoTool().run("t")
        assert result.available is False
        assert result.succeeded is False
        assert "PATH" in result.error

    def test_executes_and_parses_on_success(self):
        with patch("utils.external_tools.base.shutil.which", lambda _: "/usr/bin/echotool"), \
             patch("utils.external_tools.base.subprocess.run",
                   return_value=_completed(stdout="hello", returncode=0)):
            result = _EchoTool().run("t")
        assert result.succeeded is True
        assert result.parsed == {"echo": "hello"}
        assert result.raw_stdout == "hello"

    def test_timeout_is_reported_not_raised(self):
        def boom(*a, **k):
            raise subprocess.TimeoutExpired(cmd="echotool", timeout=1)

        with patch("utils.external_tools.base.shutil.which", lambda _: "/usr/bin/echotool"), \
             patch("utils.external_tools.base.subprocess.run", side_effect=boom):
            result = _EchoTool().run("t", timeout=1)
        assert result.error == "timeout"
        assert result.succeeded is False

    def test_parse_failure_is_captured_with_raw_output_preserved(self):
        class _BrokenTool(_EchoTool):
            def parse_output(self, stdout, stderr, returncode):
                raise ValueError("bad data")

        with patch("utils.external_tools.base.shutil.which", lambda _: "/usr/bin/echotool"), \
             patch("utils.external_tools.base.subprocess.run",
                   return_value=_completed(stdout="raw", returncode=0)):
            result = _BrokenTool().run("t")
        assert result.error.startswith("parse failed")
        assert result.raw_stdout == "raw"
        assert result.succeeded is False

    def test_nonzero_returncode_is_not_success(self):
        with patch("utils.external_tools.base.shutil.which", lambda _: "/usr/bin/echotool"), \
             patch("utils.external_tools.base.subprocess.run",
                   return_value=_completed(stdout="", stderr="err", returncode=1)):
            result = _EchoTool().run("t")
        assert result.returncode == 1
        assert result.succeeded is False


# ─── Masscan wrapper ──────────────────────────────────────────────────────────


class TestMasscanTool:
    def test_command_carries_ports_and_rate(self):
        cmd = MasscanTool().get_command("1.2.3.4", ports="80,443", rate=5000)
        assert "1.2.3.4" in cmd
        assert "80,443" in cmd
        assert "5000" in cmd
        # list output to stdout so we can parse it
        assert "-oL" in cmd and "-" in cmd

    def test_parses_open_ports_from_list_output(self):
        out = (
            "#masscan\n"
            "open tcp 443 192.0.2.1 1620000000\n"
            "open tcp 22 192.0.2.1 1620000000\n"
            "# end\n"
        )
        parsed = MasscanTool().parse_output(out, "", 0)
        assert parsed["count"] == 2
        ports = {p["port"] for p in parsed["open_ports"]}
        assert ports == {443, 22}
        assert parsed["open_ports"][0]["ip"] == "192.0.2.1"
        assert parsed["open_ports"][0]["proto"] == "tcp"

    def test_ignores_comments_and_blank_lines(self):
        parsed = MasscanTool().parse_output("#masscan\n\n# end\n", "", 0)
        assert parsed["count"] == 0
        assert parsed["open_ports"] == []

    def test_run_skips_cleanly_when_masscan_absent(self):
        with patch("utils.external_tools.base.shutil.which", lambda _: None):
            result = MasscanTool().run("1.2.3.4")
        assert isinstance(result, ToolResult)
        assert result.available is False
        assert result.tool == "masscan"
