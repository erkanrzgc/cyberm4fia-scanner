"""Tests for utils/code_executor — sandboxed Python executor."""

from __future__ import annotations

import sys

import pytest

from utils.code_executor import (
    DEFAULT_ALLOWED_MODULES,
    ExecutionResult,
    execute_python,
)


pytestmark = pytest.mark.unit


# ─── Smoke / happy path ──────────────────────────────────────────────────────


class TestHappyPath:
    def test_simple_arithmetic_returns_result_dict(self):
        out = execute_python(
            "result = {'value': 2 + 2, 'ok': True}",
            timeout=5,
        )
        assert out.success is True
        assert out.exit_code == 0
        assert out.return_value == {"value": 4, "ok": True}
        assert out.exception_type == ""

    def test_stdout_is_captured(self):
        out = execute_python(
            "print('hello sandbox'); result = {'ok': True}",
            timeout=5,
        )
        assert out.success is True
        assert "hello sandbox" in out.stdout

    def test_no_result_var_still_succeeds_with_none(self):
        out = execute_python("x = 1 + 1", timeout=5)
        assert out.success is True
        assert out.return_value is None


# ─── Module whitelist ────────────────────────────────────────────────────────


class TestImportWhitelist:
    def test_allowed_module_imports_fine(self):
        out = execute_python(
            "import json, base64\nresult = {'ok': True}",
            timeout=5,
        )
        assert out.success is True

    def test_blocked_module_raises_import_error(self):
        # `os` is intentionally NOT in DEFAULT_ALLOWED_MODULES.
        out = execute_python(
            "import os\nresult = {'ok': True}",
            timeout=5,
        )
        assert out.success is False
        assert out.exception_type == "ImportError"
        assert "not in the allowed list" in out.exception_message

    def test_extra_modules_can_be_added(self):
        out = execute_python(
            "import os\nresult = {'pid': bool(os.getpid())}",
            timeout=5,
            extra_modules={"os"},
        )
        assert out.success is True
        assert out.return_value == {"pid": True}


# ─── Failure modes ───────────────────────────────────────────────────────────


class TestFailureModes:
    def test_runtime_error_is_captured(self):
        out = execute_python(
            "raise ValueError('boom')",
            timeout=5,
        )
        assert out.success is False
        assert out.exception_type == "ValueError"
        assert "boom" in out.exception_message
        assert "ValueError" in out.traceback

    def test_short_error_message(self):
        out = execute_python("raise RuntimeError('x')", timeout=5)
        assert "RuntimeError" in out.short_error()

    def test_timeout_kills_long_running(self):
        # Don't import time inside the user code — busy-loop instead.
        code = "while True:\n    pass\n"
        out = execute_python(code, timeout=1)
        assert out.killed_by_timeout is True
        assert out.success is False
        assert out.has_error is True

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="RLIMIT_AS not enforced on Windows",
    )
    def test_memory_limit_blocks_huge_alloc(self):
        # Try to allocate ~1 GiB while the cap is 64 MiB. Should fail.
        code = "x = bytearray(1024 * 1024 * 1024); result = {'len': len(x)}"
        out = execute_python(code, timeout=5, max_memory_mb=64)
        assert out.success is False


# ─── Default whitelist sanity ────────────────────────────────────────────────


class TestDefaults:
    def test_default_allowlist_includes_http_libs(self):
        assert "requests" in DEFAULT_ALLOWED_MODULES
        assert "httpx" in DEFAULT_ALLOWED_MODULES
        assert "json" in DEFAULT_ALLOWED_MODULES

    def test_execution_result_short_error_for_clean_run(self):
        ok = ExecutionResult(success=True, exit_code=0)
        assert ok.short_error() == ""
        assert ok.has_error is False
