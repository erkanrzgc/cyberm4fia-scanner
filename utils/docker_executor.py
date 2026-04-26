"""
cyberm4fia-scanner — Docker-Based Sandbox Executor

Stronger isolation than `utils.code_executor`: runs AI-generated Python
inside a one-shot Docker container with network on a default bridge,
read-only rootfs, no Linux capabilities, dropped privileges, a memory cap,
and a wall-clock timeout enforced by `docker run --stop-timeout`.

When to use this vs the subprocess sandbox
------------------------------------------
* `code_executor.execute_python` → fast, no daemon required, best-effort.
* `docker_executor.execute_python_docker` → kernel-level isolation, costs
  ~1–2s per call for container spin-up, requires Docker daemon.

Both implement the same `ExecutionResult` contract so callers can swap
backends without changing downstream code.

Image
-----
By default uses ``python:3.11-slim``; override with ``image=`` or set
``CYBERM4FIA_SANDBOX_IMAGE`` in the environment. The image must have
``python3`` on PATH and ideally ``requests`` / ``httpx`` preinstalled —
otherwise the AI-generated payload code can't import them. A tiny custom
image (`Dockerfile.sandbox`) is recommended for production.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import textwrap
import time
import uuid
from typing import Optional

from utils.code_executor import (
    DEFAULT_ALLOWED_MODULES,
    DEFAULT_MAX_MEMORY_MB,
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_TIMEOUT,
    RESULT_MARKER,
    ExecutionResult,
    _extract_marker,
    _strip_marker,
)


DEFAULT_IMAGE = os.environ.get("CYBERM4FIA_SANDBOX_IMAGE", "python:3.11-slim")
DEFAULT_NETWORK = os.environ.get("CYBERM4FIA_SANDBOX_NETWORK", "bridge")


# ─── Capability discovery ────────────────────────────────────────────────────


def docker_available() -> bool:
    """True if a usable Docker daemon is reachable.

    Checks both that the binary is on PATH *and* that ``docker info`` returns
    successfully (which catches "binary present, daemon down" cases).
    """
    if not shutil.which("docker"):
        return False
    try:
        proc = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, timeout=3, check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return proc.returncode == 0


# ─── Public API ──────────────────────────────────────────────────────────────


def execute_python_docker(
    code: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_memory_mb: int = DEFAULT_MAX_MEMORY_MB,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    allowed_modules: Optional[frozenset[str]] = None,
    extra_modules: Optional[set[str]] = None,
    image: str = DEFAULT_IMAGE,
    network: str = DEFAULT_NETWORK,
    env: Optional[dict[str, str]] = None,
) -> ExecutionResult:
    """Run a Python snippet inside a one-shot Docker container.

    Returns an `ExecutionResult` with the same shape as the subprocess
    sandbox. If Docker isn't available, returns a failed result with a
    ``DockerUnavailableError`` exception type — callers can fall back to
    `utils.code_executor.execute_python`.
    """
    if not docker_available():
        return ExecutionResult(
            success=False,
            exception_type="DockerUnavailableError",
            exception_message=(
                "Docker daemon not reachable. Use utils.code_executor as fallback "
                "or start Docker."
            ),
            exit_code=-1,
        )

    if allowed_modules is None:
        allowed_modules = DEFAULT_ALLOWED_MODULES
    if extra_modules:
        allowed_modules = frozenset(allowed_modules | set(extra_modules))

    cfg = {
        "allowed_modules": sorted(allowed_modules),
        "max_output_bytes": int(max_output_bytes),
        "result_marker": RESULT_MARKER,
        "cpu_seconds": int(max(2, timeout + 3)),
        "max_memory_bytes": int(max_memory_mb * 1024 * 1024) if max_memory_mb else 0,
        "max_file_bytes": 64 * 1024 * 1024,
    }

    # Persist the AI-generated code outside the container, then bind-mount it
    # read-only at /sandbox/user.py.
    workdir = tempfile.mkdtemp(prefix="cyberm4fia-docker-")
    container_name = f"cyberm4fia-sandbox-{uuid.uuid4().hex[:8]}"
    try:
        code_path = os.path.join(workdir, "user.py")
        with open(code_path, "w", encoding="utf-8") as fh:
            fh.write(textwrap.dedent(code))
        cfg["code_path"] = "/sandbox/user.py"

        harness_path = os.path.join(workdir, "harness.py")
        with open(harness_path, "w", encoding="utf-8") as fh:
            fh.write(_DOCKER_HARNESS)

        # Container runs as `nobody` (uid 65534); make sure that user can
        # read the bind-mounted workdir + files.
        os.chmod(workdir, 0o755)
        os.chmod(code_path, 0o644)
        os.chmod(harness_path, 0o644)

        cmd = _build_docker_cmd(
            image=image,
            network=network,
            container_name=container_name,
            workdir=workdir,
            timeout=timeout,
            max_memory_mb=max_memory_mb,
            extra_env=env or {},
        )

        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                input=json.dumps(cfg),
                capture_output=True,
                text=True,
                timeout=timeout + 10,  # docker overhead grace
                check=False,
            )
        except subprocess.TimeoutExpired:
            duration = time.monotonic() - start
            _force_kill(container_name)
            return ExecutionResult(
                success=False,
                exception_type="TimeoutError",
                exception_message=f"docker container exceeded {timeout}s wall-clock",
                duration_seconds=duration,
                killed_by_timeout=True,
                exit_code=-1,
            )

        duration = time.monotonic() - start
        stdout = (proc.stdout or "")[-max_output_bytes:]
        stderr = (proc.stderr or "")[-max_output_bytes:]

        payload = _extract_marker(stdout)
        killed_by_signal = proc.returncode < 0 or proc.returncode == 137  # OOM-kill
        if payload is None:
            return ExecutionResult(
                success=False,
                stdout=stdout,
                stderr=stderr,
                exception_type=(
                    "TimeoutError" if killed_by_signal
                    else "HarnessError"
                ),
                exception_message=(
                    "container exited without emitting result marker "
                    f"(exit_code={proc.returncode})"
                ),
                duration_seconds=duration,
                killed_by_timeout=killed_by_signal,
                exit_code=proc.returncode,
                extra={"container_name": container_name, "image": image},
            )

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
            extra={"container_name": container_name, "image": image},
        )
    finally:
        # Remove the workdir; container is auto-removed via --rm.
        try:
            shutil.rmtree(workdir, ignore_errors=True)
        except OSError:
            pass


# ─── Internals ───────────────────────────────────────────────────────────────


def _build_docker_cmd(
    *,
    image: str,
    network: str,
    container_name: str,
    workdir: str,
    timeout: float,
    max_memory_mb: int,
    extra_env: dict[str, str],
) -> list[str]:
    """Compose the `docker run` command line for a one-shot sandbox."""
    cmd = [
        "docker", "run",
        "--rm",
        "--name", container_name,
        "--network", network,
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--user", "65534:65534",                      # nobody
        "--pids-limit", "128",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        "--stop-timeout", str(int(max(1, timeout))),
        "-i",
        "-v", f"{workdir}:/sandbox:ro",
    ]
    if max_memory_mb:
        cmd += ["--memory", f"{max_memory_mb}m", "--memory-swap", f"{max_memory_mb}m"]
    for key, value in extra_env.items():
        cmd += ["-e", f"{key}={value}"]
    cmd += [image, "python3", "/sandbox/harness.py"]
    return cmd


def _force_kill(container_name: str) -> None:
    """Best-effort kill if our wall-clock fired before docker stopped it."""
    try:
        subprocess.run(
            ["docker", "kill", container_name],
            capture_output=True, timeout=5, check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        pass


# Harness that runs INSIDE the container. Reads JSON config from stdin, sets
# up resource limits + import whitelist (same shape as the subprocess sandbox),
# execs the user code, prints the RESULT_MARKER line.
_DOCKER_HARNESS = r'''
import builtins, json, sys, traceback

_cfg = json.loads(sys.stdin.read())
_allowed = set(_cfg["allowed_modules"])
_user_code_path = _cfg["code_path"]
_marker = _cfg["result_marker"]

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
except Exception:
    pass

# Pre-warm allow-listed modules before installing the import hook.
for _modname in _allowed:
    try:
        __import__(_modname)
    except Exception:
        pass

_real_import = builtins.__import__

def _guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
    root = name.split(".")[0]
    if root not in _allowed and name not in _allowed:
        raise ImportError(f"sandbox: module '{name}' is not in the allowed list")
    return _real_import(name, globals, locals, fromlist, level)

builtins.__import__ = _guarded_import

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
    _result_payload["exc"] = {"type": "SystemExit", "msg": str(e.code), "tb": ""}
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


# ─── Backend dispatch helper ─────────────────────────────────────────────────


def execute_python_auto(code: str, **kwargs):
    """Try Docker first; fall back to the subprocess sandbox if it isn't there.

    Use this when you want the strongest isolation available without forcing
    Docker as a hard dependency.
    """
    if docker_available():
        result = execute_python_docker(code, **kwargs)
        # Only consider Docker "broken" (and fall back) if the binary truly
        # rejected us — propagate user-code errors normally.
        if result.exception_type != "DockerUnavailableError":
            return result

    from utils.code_executor import execute_python
    # Strip Docker-only kwargs so the subprocess backend doesn't choke.
    for docker_only in ("image", "network"):
        kwargs.pop(docker_only, None)
    return execute_python(code, **kwargs)
