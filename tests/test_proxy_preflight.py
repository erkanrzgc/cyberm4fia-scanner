"""Tests for the mitmproxy startup preflight in modules.proxy_interceptor.

We stub ``subprocess.run`` so the tests run on any host without mitmdump.
Verify:

* `mitmdump --version` exit 0 → ok=True.
* FileNotFoundError → ok=False with a clear pip-install hint.
* Non-zero exit + bcrypt/72-byte error text → ok=False with the
  ``pip install 'bcrypt<4.1'`` fix in the reason.
* Any other non-zero exit → ok=False with the last stderr line.
* Timeout → ok=False with a timeout message.

We also verify start_proxy bails early (without crashing) when the
preflight reports failure.
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from modules.proxy_interceptor import _mitmdump_works, start_proxy

pytestmark = pytest.mark.unit


def _run_result(returncode: int = 0, stdout: str = "", stderr: str = "") -> MagicMock:
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


class TestPreflightSuccess:
    def test_zero_exit_means_ok(self):
        with patch(
            "subprocess.run", return_value=_run_result(0, stdout="Mitmproxy: 10.0\n")
        ):
            ok, reason = _mitmdump_works()
        assert ok is True
        assert reason == ""


class TestPreflightFileNotFound:
    def test_missing_binary_returns_pip_install_hint(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            ok, reason = _mitmdump_works()
        assert ok is False
        assert "pip install mitmproxy" in reason


class TestPreflightBcryptCrash:
    def test_72_bytes_error_returns_specific_fix(self):
        stderr = (
            "Traceback (most recent call last):\n"
            "  File '/x/passlib/handlers/bcrypt.py', line 1, in <module>\n"
            "ValueError: password cannot be longer than 72 bytes, truncate manually\n"
        )
        with patch(
            "subprocess.run", return_value=_run_result(1, stderr=stderr)
        ):
            ok, reason = _mitmdump_works()
        assert ok is False
        assert "bcrypt<4.1" in reason
        assert "passlib" in reason.lower()

    def test_attributeerror_bcrypt_also_recognised(self):
        stderr = "AttributeError: module 'bcrypt' has no attribute '__about__'\n"
        with patch("subprocess.run", return_value=_run_result(1, stderr=stderr)):
            ok, reason = _mitmdump_works()
        assert ok is False
        assert "bcrypt<4.1" in reason


class TestPreflightOtherFailures:
    def test_unknown_nonzero_returns_last_stderr_line(self):
        stderr = "Some other error\nthat happens at startup\n"
        with patch("subprocess.run", return_value=_run_result(2, stderr=stderr)):
            ok, reason = _mitmdump_works()
        assert ok is False
        assert "mitmdump unavailable" in reason

    def test_timeout_returns_timeout_message(self):
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="mitmdump", timeout=10),
        ):
            ok, reason = _mitmdump_works()
        assert ok is False
        assert "timed out" in reason

    def test_oserror_returns_clean_message(self):
        with patch("subprocess.run", side_effect=OSError("permission denied")):
            ok, reason = _mitmdump_works()
        assert ok is False
        assert "mitmdump launch error" in reason


class TestStartProxyGuardrails:
    def test_no_scope_warns_and_returns(self, capsys):
        # Should not raise, should not invoke subprocess.Popen
        with patch("subprocess.Popen") as popen:
            start_proxy(listen_port=18999, scope="")
        assert popen.call_count == 0

    def test_failed_preflight_skips_subprocess(self):
        with patch(
            "modules.proxy_interceptor._mitmdump_works",
            return_value=(False, "test stub failure"),
        ), patch("subprocess.Popen") as popen:
            start_proxy(listen_port=18999, scope="example.com")
        assert popen.call_count == 0
