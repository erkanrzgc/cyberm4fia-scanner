"""Tests for utils/recon_tools — subfinder/amass/assetfinder/puredns wrappers."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from utils.recon_tools import (
    ReconToolResult,
    parse_ffuf_json,
    parse_gobuster_lines,
    parse_lines,
    parse_subfinder_jsonl,
    run_amass,
    run_assetfinder,
    run_ffuf,
    run_gobuster,
    run_puredns_resolve,
    run_subfinder,
)


pytestmark = pytest.mark.unit


# ── Pure parsers ─────────────────────────────────────────────────────────────


def test_parse_lines_normalises_and_dedupes():
    raw = "API.example.COM\napi.example.com\n\napi.example.com.\n"
    assert parse_lines(raw) == frozenset({"api.example.com"})


def test_parse_lines_drops_bogus_entries():
    raw = "*.example.com\n  \npath/with/slash\nspaced entry\nok.example.com"
    assert parse_lines(raw) == frozenset({"ok.example.com"})


def test_parse_subfinder_jsonl_extracts_host_field():
    raw = (
        '{"host":"a.example.com","source":"crtsh"}\n'
        '{"host":"b.example.com","source":"alienvault"}\n'
        '{"unrelated":"x"}\n'
        'not-json-at-all\n'
    )
    assert parse_subfinder_jsonl(raw) == frozenset(
        {"a.example.com", "b.example.com"}
    )


def test_parse_subfinder_jsonl_capitalised_field():
    raw = '{"Host":"X.example.com"}'
    assert parse_subfinder_jsonl(raw) == frozenset({"x.example.com"})


# ── Runner: binary missing ───────────────────────────────────────────────────


def _no_binary(*_args, **_kwargs):
    return None


@pytest.mark.parametrize(
    "runner,tool",
    [
        (run_subfinder, "subfinder"),
        (run_amass, "amass"),
        (run_assetfinder, "assetfinder"),
    ],
)
def test_runner_returns_diagnostic_when_binary_missing(runner, tool):
    with patch("utils.recon_tools.shutil.which", _no_binary):
        result = runner("example.com")
    assert isinstance(result, ReconToolResult)
    assert result.tool == tool
    assert result.subdomains == frozenset()
    assert result.succeeded is False
    assert "PATH" in result.error


def test_puredns_returns_diagnostic_when_binary_missing(tmp_path):
    wordlist = tmp_path / "candidates.txt"
    wordlist.write_text("a.example.com\nb.example.com\n")
    with patch("utils.recon_tools.shutil.which", _no_binary):
        result = run_puredns_resolve(str(wordlist))
    assert result.tool == "puredns"
    assert result.subdomains == frozenset()
    assert result.succeeded is False


# ── Runner: binary present (mocked subprocess) ───────────────────────────────


def _fake_proc(stdout: str, returncode: int = 0, stderr: str = "") -> SimpleNamespace:
    return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


def test_run_subfinder_success_parses_jsonl():
    with patch("utils.recon_tools.shutil.which", lambda _: "/usr/bin/subfinder"), \
         patch(
             "utils.recon_tools.subprocess.run",
             return_value=_fake_proc(
                 stdout='{"host":"a.example.com"}\n{"host":"b.example.com"}\n',
             ),
         ):
        result = run_subfinder("example.com")
    assert result.succeeded is True
    assert result.subdomains == frozenset({"a.example.com", "b.example.com"})


def test_run_subfinder_failure_returncode_carries_stderr():
    with patch("utils.recon_tools.shutil.which", lambda _: "/usr/bin/subfinder"), \
         patch(
             "utils.recon_tools.subprocess.run",
             return_value=_fake_proc(stdout="", returncode=2, stderr="auth error"),
         ):
        result = run_subfinder("example.com")
    assert result.succeeded is False
    assert "auth error" in result.error


def test_run_amass_passive_flag_in_cmd():
    captured: dict = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _fake_proc(stdout="a.example.com\nb.example.com\n")

    with patch("utils.recon_tools.shutil.which", lambda _: "/usr/bin/amass"), \
         patch("utils.recon_tools.subprocess.run", side_effect=fake_run):
        result = run_amass("example.com", passive=True)
    assert "-passive" in captured["cmd"]
    assert result.subdomains == frozenset({"a.example.com", "b.example.com"})


def test_run_assetfinder_subs_only_flag():
    captured: dict = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _fake_proc(stdout="ok.example.com\n")

    with patch("utils.recon_tools.shutil.which", lambda _: "/usr/bin/assetfinder"), \
         patch("utils.recon_tools.subprocess.run", side_effect=fake_run):
        run_assetfinder("example.com")
    assert "--subs-only" in captured["cmd"]


def test_run_subfinder_timeout_returns_none_result():
    def boom(*_a, **_kw):
        raise subprocess.TimeoutExpired(cmd="subfinder", timeout=1)

    with patch("utils.recon_tools.shutil.which", lambda _: "/usr/bin/subfinder"), \
         patch("utils.recon_tools.subprocess.run", side_effect=boom):
        result = run_subfinder("example.com", timeout=1)
    assert result.succeeded is False
    assert result.subdomains == frozenset()
    assert "timeout" in result.error.lower()


# ── ffuf parser + runner ──────────────────────────────────────────────────────


def test_parse_ffuf_json_extracts_results():
    raw = """
    {
      "results": [
        {"url": "https://t/admin", "status": 200, "length": 1234, "words": 50, "lines": 10},
        {"url": "https://t/api",   "status": 401, "length": 88,   "words": 5,  "lines": 1}
      ]
    }
    """
    hits = parse_ffuf_json(raw)
    assert len(hits) == 2
    assert hits[0].url == "https://t/admin"
    assert hits[0].status == 200
    assert hits[1].status == 401


def test_parse_ffuf_json_empty_or_malformed():
    assert parse_ffuf_json("") == ()
    assert parse_ffuf_json("{") == ()
    assert parse_ffuf_json('{"results":[]}') == ()


def test_run_ffuf_requires_fuzz_keyword_in_url():
    with patch("utils.recon_tools.shutil.which", lambda _: "/usr/bin/ffuf"):
        result = run_ffuf("https://t/admin", "wordlist.txt")
    assert result.succeeded is False
    assert "FUZZ" in result.error


def test_run_ffuf_binary_missing_returns_diagnostic():
    with patch("utils.recon_tools.shutil.which", _no_binary):
        result = run_ffuf("https://t/FUZZ", "wordlist.txt")
    assert result.tool == "ffuf"
    assert result.succeeded is False
    assert "PATH" in result.error


def test_run_ffuf_success_parses_hits():
    fake_json = (
        '{"results":[{"url":"https://t/admin","status":200,'
        '"length":1234,"words":50,"lines":10}]}'
    )
    with patch("utils.recon_tools.shutil.which", lambda _: "/usr/bin/ffuf"), \
         patch(
             "utils.recon_tools.subprocess.run",
             return_value=_fake_proc(stdout=fake_json),
         ):
        result = run_ffuf("https://t/FUZZ", "/tmp/words.txt")
    assert result.succeeded is True
    assert len(result.hits) == 1
    assert result.hits[0].url == "https://t/admin"


# ── gobuster parser + runner ──────────────────────────────────────────────────


def test_parse_gobuster_lines():
    raw = (
        "/admin                (Status: 200) [Size: 1234]\n"
        "/api                  (Status: 401) [Size: 88]\n"
        "garbage line that should be skipped\n"
        "/no-size              (Status: 403)\n"
    )
    hits = parse_gobuster_lines(raw)
    assert len(hits) == 3
    assert hits[0].url == "/admin"
    assert hits[0].length == 1234
    assert hits[2].length == 0  # missing Size


def test_run_gobuster_binary_missing():
    with patch("utils.recon_tools.shutil.which", _no_binary):
        result = run_gobuster("https://t/", "wordlist.txt")
    assert result.tool == "gobuster"
    assert result.succeeded is False


def test_run_gobuster_success_parses_lines():
    with patch("utils.recon_tools.shutil.which", lambda _: "/usr/bin/gobuster"), \
         patch(
             "utils.recon_tools.subprocess.run",
             return_value=_fake_proc(
                 stdout="/admin (Status: 200) [Size: 100]\n"
             ),
         ):
        result = run_gobuster("https://t/", "/tmp/words.txt")
    assert result.succeeded is True
    assert result.hits[0].url == "/admin"
