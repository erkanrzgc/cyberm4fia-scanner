"""
cyberm4fia-scanner — Sandboxed Python Executor

Runs AI-generated exploit scripts in an isolated subprocess with:
- CPU time limit
- Memory limit (RLIMIT_AS)
- File-size limit
- Wall-clock timeout
- Module whitelist (enforced via a custom __import__)
- Captured stdout/stderr
- Structured result extraction via __RESULT__ marker

Threat model
------------
This is *best-effort* process isolation, not a hard security boundary.
It is meant to keep AI-generated payload code from corrupting the scanner
process or running for too long. Do not run hostile third-party code on a
production host with this alone — wrap it in Docker / firejail / nsjail
for real isolation.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass, field
from typing import Optional


# ─── Defaults ────────────────────────────────────────────────────────────────

DEFAULT_TIMEOUT = 15
DEFAULT_MAX_MEMORY_MB = 256
DEFAULT_MAX_OUTPUT_BYTES = 256 * 1024
RESULT_MARKER = "__CYBERM4FIA_RESULT__"

# Modules the AI exploit code is allowed to import. Anything else raises ImportError
# inside the sandbox. Keep this tight — only what payload work genuinely needs.
DEFAULT_ALLOWED_MODULES = frozenset({
    # stdlib data + protocol primitives
    "base64", "binascii", "hashlib", "hmac", "json", "math", "random",
    "re", "string", "struct", "time", "uuid",
    "urllib", "urllib.parse", "urllib.request", "urllib.error",
    "html", "html.parser", "xml", "xml.etree", "xml.etree.ElementTree",
    "io", "itertools", "functools", "collections", "dataclasses",
    "typing", "enum",
    # 3rd-party HTTP — what the scanner already depends on
    "requests", "httpx",
})


# ─── Result type ─────────────────────────────────────────────────────────────


@dataclass
class ExecutionResult:
    """Outcome of running a code snippet in the sandbox."""
    success: bool                       # process exited 0 AND no exception inside
    return_value: object = None         # parsed from RESULT_MARKER line (any JSON-serialisable)
    stdout: str = ""
    stderr: str = ""
    exception_type: str = ""
    exception_message: str = ""
    traceback: str = ""
    duration_seconds: float = 0.0
    killed_by_timeout: bool = False
    exit_code: int = 0
    extra: dict = field(default_factory=dict)

    @property
    def has_error(self) -> bool:
        return bool(self.exception_type) or self.exit_code != 0 or self.killed_by_timeout

    def short_error(self) -> str:
        if self.killed_by_timeout:
            return f"TIMEOUT after {self.duration_seconds:.2f}s"
        if self.exception_type:
            return f"{self.exception_type}: {self.exception_message}"
        if self.exit_code != 0:
            return f"exit_code={self.exit_code}; stderr={self.stderr[:200]}"
        return ""


# ─── Sandbox harness (runs inside the child process) ─────────────────────────

# This string is the *child* program. The parent writes the user code into
# a temp file and execs this harness with the file path + a JSON config
# passed via stdin. We keep it as a string so it stays self-contained.
_HARNESS = r'''
import builtins, json, sys, traceback

_cfg = json.loads(sys.stdin.read())
_allowed = set(_cfg["allowed_modules"])
_user_code_path = _cfg["code_path"]
_max_output = int(_cfg["max_output_bytes"])
_marker = _cfg["result_marker"]

# Apply resource limits (Linux/macOS only — Windows has no `resource`)
try:
    import resource
    cpu = int(_cfg["cpu_seconds"])
    mem = int(_cfg["max_memory_bytes"])
    fsz = int(_cfg["max_file_bytes"])
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    if mem > 0:
        try:
            resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
        except (ValueError, OSError):
            pass
    resource.setrlimit(resource.RLIMIT_FSIZE, (fsz, fsz))
    try:
        resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    except (ValueError, OSError, AttributeError):
        pass
except ImportError:
    pass

# Pre-warm every allowed module BEFORE installing the import hook.
# This pulls in their transitive deps (socket, ssl, _io, _struct, ...) so that
# user code which only imports allow-listed names still works, while user code
# trying to import a non-allow-listed name is rejected by the hook below.
for _modname in _allowed:
    try:
        __import__(_modname)
    except Exception:
        pass

_real_import = builtins.__import__

def _guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
    root = name.split(".")[0]
    if root not in _allowed and name not in _allowed:
        raise ImportError(
            f"sandbox: module '{name}' is not in the allowed list"
        )
    return _real_import(name, globals, locals, fromlist, level)

builtins.__import__ = _guarded_import

# Read user code
with open(_user_code_path, "r", encoding="utf-8") as _fh:
    _user_code = _fh.read()

_g = {"__name__": "__sandbox__", "__builtins__": builtins}

_result_payload = {"ok": False, "value": None, "exc": None}
try:
    exec(compile(_user_code, "<sandbox>", "exec"), _g)
    if "result" in _g:
        try:
            json.dumps(_g["result"])
            _result_payload["value"] = _g["result"]
        except (TypeError, ValueError):
            _result_payload["value"] = repr(_g["result"])
    _result_payload["ok"] = True
except SystemExit as e:
    _result_payload["ok"] = (e.code in (0, None))
    _result_payload["exc"] = {
        "type": "SystemExit",
        "msg": str(e.code),
        "tb": "",
    }
except BaseException as e:
    _result_payload["ok"] = False
    _result_payload["exc"] = {
        "type": type(e).__name__,
        "msg": str(e),
        "tb": traceback.format_exc(limit=8),
    }

sys.stdout.flush()
sys.stderr.flush()
print(_marker + json.dumps(_result_payload))
'''


# ─── Public API ──────────────────────────────────────────────────────────────


def execute_python(
    code: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_memory_mb: int = DEFAULT_MAX_MEMORY_MB,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    allowed_modules: Optional[frozenset[str]] = None,
    extra_modules: Optional[set[str]] = None,
    env: Optional[dict[str, str]] = None,
) -> ExecutionResult:
    """Run a Python snippet in a subprocess sandbox.

    Parameters
    ----------
    code : str
        The Python source to execute. If it sets a top-level variable named
        ``result`` that is JSON-serialisable, the value is returned in
        ``ExecutionResult.return_value``.
    timeout : float
        Wall-clock timeout in seconds. Process is killed past this.
    max_memory_mb : int
        Address-space cap (RLIMIT_AS). Set to 0 to disable.
    allowed_modules : frozenset[str]
        Whitelist of importable modules. Defaults to ``DEFAULT_ALLOWED_MODULES``.
    extra_modules : set[str]
        Additional modules to allow on top of the default whitelist.
    env : dict[str, str]
        Extra environment variables for the child. Network is *not* blocked.
    """
    if allowed_modules is None:
        allowed_modules = DEFAULT_ALLOWED_MODULES
    if extra_modules:
        allowed_modules = frozenset(allowed_modules | set(extra_modules))

    # CPU rlimit lives slightly above the wall-clock timeout so the parent's
    # subprocess.run() timeout fires first (cleaner stdout/stderr capture).
    # The CPU rlimit is just the safety net for runaway native loops.
    cpu_budget = int(max(2, timeout + 3))
    cfg = {
        "allowed_modules": sorted(allowed_modules),
        "max_output_bytes": int(max_output_bytes),
        "result_marker": RESULT_MARKER,
        "cpu_seconds": cpu_budget,
        "max_memory_bytes": int(max_memory_mb * 1024 * 1024) if max_memory_mb else 0,
        "max_file_bytes": 64 * 1024 * 1024,  # 64 MiB scratch cap
    }

    # Persist user code to a temp file so the child can read it cleanly.
    code_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as fh:
            fh.write(textwrap.dedent(code))
            code_path = fh.name
        cfg["code_path"] = code_path

        child_env = os.environ.copy()
        # Don't inherit secrets the child doesn't need.
        for sensitive in ("NVIDIA_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
            child_env.pop(sensitive, None)
        if env:
            child_env.update(env)

        start = time.monotonic()
        try:
            proc = subprocess.run(
                [sys.executable, "-I", "-c", _HARNESS],
                input=json.dumps(cfg),
                capture_output=True,
                text=True,
                timeout=timeout,
                env=child_env,
                check=False,
            )
        except subprocess.TimeoutExpired as te:
            duration = time.monotonic() - start
            return ExecutionResult(
                success=False,
                stdout=(te.stdout or b"").decode("utf-8", errors="replace") if isinstance(te.stdout, bytes) else (te.stdout or ""),
                stderr=(te.stderr or b"").decode("utf-8", errors="replace") if isinstance(te.stderr, bytes) else (te.stderr or ""),
                exception_type="TimeoutError",
                exception_message=f"sandbox exceeded {timeout}s wall-clock",
                duration_seconds=duration,
                killed_by_timeout=True,
                exit_code=-1,
            )

        duration = time.monotonic() - start

        stdout = (proc.stdout or "")[-max_output_bytes:]
        stderr = (proc.stderr or "")[-max_output_bytes:]

        # Parse the marker line.
        payload = _extract_marker(stdout)
        # Negative exit code on POSIX = killed by signal (e.g. RLIMIT_CPU/AS).
        # Treat as a resource-limit timeout so callers don't need to dig.
        killed_by_signal = proc.returncode < 0
        if payload is None:
            return ExecutionResult(
                success=(proc.returncode == 0),
                stdout=stdout,
                stderr=stderr,
                exception_type=(
                    "TimeoutError" if killed_by_signal
                    else ("HarnessError" if proc.returncode != 0 else "")
                ),
                exception_message=(
                    f"sandbox killed by signal {-proc.returncode} "
                    f"(likely RLIMIT_CPU/AS)"
                    if killed_by_signal
                    else (
                        "child exited without emitting result marker"
                        if proc.returncode != 0
                        else ""
                    )
                ),
                duration_seconds=duration,
                killed_by_timeout=killed_by_signal,
                exit_code=proc.returncode,
            )

        # Strip marker from visible stdout for cleaner logs.
        clean_stdout = _strip_marker(stdout)
        exc = payload.get("exc") or {}
        return ExecutionResult(
            success=bool(payload.get("ok") and proc.returncode == 0),
            return_value=payload.get("value"),
            stdout=clean_stdout,
            stderr=stderr,
            exception_type=str(exc.get("type") or ""),
            exception_message=str(exc.get("msg") or ""),
            traceback=str(exc.get("tb") or ""),
            duration_seconds=duration,
            exit_code=proc.returncode,
        )
    finally:
        if code_path and os.path.exists(code_path):
            try:
                os.unlink(code_path)
            except OSError:
                pass


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _extract_marker(stdout: str) -> Optional[dict]:
    """Find the last RESULT_MARKER line and parse its JSON payload."""
    if not stdout or RESULT_MARKER not in stdout:
        return None
    # Walk lines from the end — marker is emitted last.
    for line in reversed(stdout.splitlines()):
        idx = line.find(RESULT_MARKER)
        if idx < 0:
            continue
        raw = line[idx + len(RESULT_MARKER):].strip()
        if not raw:
            continue
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            return None
    return None


def _strip_marker(stdout: str) -> str:
    """Remove the marker line so callers can show clean stdout."""
    if not stdout or RESULT_MARKER not in stdout:
        return stdout
    kept = [ln for ln in stdout.splitlines() if RESULT_MARKER not in ln]
    return "\n".join(kept)
