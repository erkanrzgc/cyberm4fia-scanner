"""Tests for modules.git_history_scan — git history secret scan + exposed .git probe."""

from __future__ import annotations

import os
import subprocess
from unittest.mock import MagicMock, patch

import pytest


pytestmark = pytest.mark.unit


def _resp(status_code=200, body="", json_body=None):
    r = MagicMock()
    r.status_code = status_code
    r.text = body
    if json_body is not None:
        r.json = MagicMock(return_value=json_body)
    return r


class TestScanBlob:
    def test_finds_real_secret_and_drops_placeholder(self):
        from modules.git_history_scan import _scan_blob_for_secrets

        # Build secret-shaped fixtures at runtime — keeps the literal patterns
        # out of source code so GitHub push-protection / GitGuardian don't
        # flag the test file as containing real secrets.
        sk_prefix = "sk_" + "live_"
        real = sk_prefix + "abcdefghijklmnopqrstuvwx"
        placeholder = sk_prefix + "yourplaceholderkeyhere"
        text = (
            f'const real = "{real}";\n'
            f'const fake = "{placeholder}";\n'
            'aws = process.env.AWS_KEY;  AKIA1234567890ABCDEF\n'
        )
        hits = _scan_blob_for_secrets(text, source="repo")
        types = [h["secret_type"] for h in hits]
        assert "Stripe Standard API Key" in types
        # placeholder Stripe key dropped
        assert sum(1 for t in types if t == "Stripe Standard API Key") == 1
        # AWS dropped due to env-ref context
        assert "AWS Access Key ID" not in types

    def test_empty_text_returns_no_hits(self):
        from modules.git_history_scan import _scan_blob_for_secrets

        assert _scan_blob_for_secrets("", "x") == []


class TestScanLocalRepo:
    def test_skips_when_git_missing(self):
        from modules import git_history_scan

        with patch("modules.git_history_scan.shutil.which", return_value=None):
            assert git_history_scan.scan_local_repo("/some/path") == []

    def test_skips_when_not_a_git_repo(self, tmp_path):
        from modules import git_history_scan

        with patch("modules.git_history_scan.shutil.which", return_value="/usr/bin/git"):
            assert git_history_scan.scan_local_repo(str(tmp_path)) == []

    def test_finds_secrets_via_git_log(self, tmp_path):
        from modules import git_history_scan

        # fake out is_git_repo() and the subprocess.run() call
        proc = MagicMock()
        proc.returncode = 0
        sk_prefix = "sk_" + "live_"
        leaked = sk_prefix + "abcdefghijklmnopqrstuvwx"
        proc.stdout = (
            "commit abc\n"
            "diff --git a/foo b/foo\n"
            f'+const k = "{leaked}";\n'
        )
        proc.stderr = ""

        with patch("modules.git_history_scan.shutil.which", return_value="/usr/bin/git"), \
             patch("modules.git_history_scan.is_git_repo", return_value=True), \
             patch("modules.git_history_scan.subprocess.run", return_value=proc):
            obs_list = git_history_scan.scan_local_repo(str(tmp_path))

        assert len(obs_list) == 1
        ob = obs_list[0]
        assert ob.severity == "high"
        assert "Stripe" in ob.observation_type
        assert "git-history" in ob.tags

    def test_timeout_returns_empty(self, tmp_path):
        from modules import git_history_scan

        with patch("modules.git_history_scan.shutil.which", return_value="/usr/bin/git"), \
             patch("modules.git_history_scan.is_git_repo", return_value=True), \
             patch(
                 "modules.git_history_scan.subprocess.run",
                 side_effect=subprocess.TimeoutExpired(cmd="git", timeout=1),
             ):
            assert git_history_scan.scan_local_repo(str(tmp_path), timeout=1) == []


class TestExposedDotGit:
    def test_detects_exposed_head(self):
        from modules import git_history_scan

        head_resp = _resp(200, "ref: refs/heads/main\n")
        config_resp = _resp(404, "")

        with patch(
            "modules.git_history_scan.smart_request",
            side_effect=[head_resp, config_resp],
        ):
            obs_list = git_history_scan.check_exposed_dotgit("https://target.example.com")

        assert len(obs_list) == 1
        assert obs_list[0].severity == "critical"
        assert obs_list[0].observation_type == "exposed_dotgit"
        assert "git-dumper" in obs_list[0].description.lower()

    def test_ignores_html_404_pages(self):
        from modules import git_history_scan

        # 200 status but body looks like HTML, not git
        html_resp = _resp(200, "<html><body>Not Found</body></html>")
        with patch(
            "modules.git_history_scan.smart_request",
            return_value=html_resp,
        ):
            obs_list = git_history_scan.check_exposed_dotgit("https://target.example.com")
        assert obs_list == []

    def test_skips_non_200(self):
        from modules import git_history_scan

        with patch(
            "modules.git_history_scan.smart_request",
            return_value=_resp(404, ""),
        ):
            assert git_history_scan.check_exposed_dotgit("https://x.test") == []


class TestEntrypoint:
    def test_white_box_path_dispatches_to_local_scan(self):
        from modules import git_history_scan

        with patch(
            "modules.git_history_scan.scan_local_repo", return_value=[]
        ) as local_mock:
            git_history_scan.scan_git_history(
                "https://x.test",
                options={"git_history_path": "/path/to/repo", "git_history_max_commits": 100},
            )
        local_mock.assert_called_once()
        assert local_mock.call_args.args == ("/path/to/repo",)
        assert local_mock.call_args.kwargs["max_commits"] == 100

    def test_default_dispatches_to_dotgit_probe(self):
        from modules import git_history_scan

        with patch(
            "modules.git_history_scan.check_exposed_dotgit", return_value=[]
        ) as probe_mock:
            git_history_scan.scan_git_history("https://target.example.com")
        probe_mock.assert_called_once()
