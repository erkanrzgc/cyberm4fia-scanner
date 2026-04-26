"""Tests for utils/docker_executor — sandbox layer that wraps Docker.

These tests deliberately avoid spawning real containers (CI doesn't always
have Docker) and instead exercise the dispatch + fallback logic via mocks.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from utils.docker_executor import (
    _build_docker_cmd,
    docker_available,
    execute_python_auto,
    execute_python_docker,
)


pytestmark = pytest.mark.unit


# ─── Capability check ────────────────────────────────────────────────────────


class TestDockerAvailable:
    def test_returns_false_when_binary_missing(self):
        with patch("utils.docker_executor.shutil.which", return_value=None):
            assert docker_available() is False

    def test_returns_false_when_info_command_fails(self):
        # Binary is on PATH, but daemon is unreachable.
        class FakeProc:
            returncode = 1

        with patch("utils.docker_executor.shutil.which", return_value="/usr/bin/docker"), \
             patch("utils.docker_executor.subprocess.run", return_value=FakeProc()):
            assert docker_available() is False


# ─── Command builder ─────────────────────────────────────────────────────────


class TestBuildDockerCmd:
    def test_includes_isolation_flags(self):
        cmd = _build_docker_cmd(
            image="python:3.11-slim",
            network="bridge",
            container_name="cyberm4fia-sandbox-test",
            workdir="/tmp/work",
            timeout=10,
            max_memory_mb=128,
            extra_env={},
        )
        # Standard hardening flags must be present.
        assert "--rm" in cmd
        assert "--read-only" in cmd
        assert "--cap-drop" in cmd and "ALL" in cmd
        assert "--security-opt" in cmd
        assert "--pids-limit" in cmd
        # Memory caps applied.
        assert "--memory" in cmd
        assert "128m" in cmd
        # Bind-mount of the workdir is read-only.
        assert any(arg.endswith(":/sandbox:ro") for arg in cmd)
        # Image and python entrypoint at the end.
        assert "python:3.11-slim" in cmd
        assert "python3" in cmd

    def test_no_memory_flag_when_limit_zero(self):
        cmd = _build_docker_cmd(
            image="x",
            network="bridge",
            container_name="x",
            workdir="/tmp",
            timeout=5,
            max_memory_mb=0,
            extra_env={},
        )
        assert "--memory" not in cmd

    def test_extra_env_appended_as_e_flags(self):
        cmd = _build_docker_cmd(
            image="x", network="bridge", container_name="x", workdir="/tmp",
            timeout=5, max_memory_mb=64,
            extra_env={"FOO": "bar", "BAZ": "qux"},
        )
        joined = " ".join(cmd)
        assert "FOO=bar" in joined
        assert "BAZ=qux" in joined


# ─── Graceful failure when Docker is missing ─────────────────────────────────


class TestExecutePythonDockerWithoutDaemon:
    def test_returns_unavailable_result(self):
        with patch("utils.docker_executor.docker_available", return_value=False):
            result = execute_python_docker("result = {'x': 1}", timeout=2)
        assert result.success is False
        assert result.exception_type == "DockerUnavailableError"
        assert "Docker daemon" in result.exception_message


# ─── Auto-fallback dispatcher ────────────────────────────────────────────────


class TestExecutePythonAutoFallback:
    def test_uses_subprocess_sandbox_when_docker_unavailable(self):
        # docker_available → False, so auto should fall through to the
        # subprocess sandbox (which we mock here to return a sentinel).
        sentinel = object()

        def fake_subprocess(code, **kwargs):
            assert "result = {'x': 1}" in code
            assert "image" not in kwargs    # docker-only kwarg stripped
            assert "network" not in kwargs
            return sentinel

        with patch("utils.docker_executor.docker_available", return_value=False), \
             patch("utils.code_executor.execute_python", side_effect=fake_subprocess):
            out = execute_python_auto("result = {'x': 1}", timeout=2,
                                      image="ignored", network="ignored")
        assert out is sentinel

    def test_uses_docker_when_daemon_present(self):
        # docker_available → True. We don't actually run docker; we just
        # verify the dispatch picked the docker path by mocking it.
        from utils.code_executor import ExecutionResult

        ok_result = ExecutionResult(success=True, return_value={"ok": True})

        with patch("utils.docker_executor.docker_available", return_value=True), \
             patch("utils.docker_executor.execute_python_docker", return_value=ok_result) as m:
            out = execute_python_auto("result = {'ok': True}", timeout=2)
        assert out is ok_result
        assert m.called


# ─── Live Docker run (only when daemon AND image are available) ─────────────


def _image_present(image: str) -> bool:
    """True only if the image is already pulled locally — avoids requiring
    network access for the live smoke test."""
    if not docker_available():
        return False
    import subprocess
    try:
        proc = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True, timeout=5, check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return proc.returncode == 0


_LIVE_IMAGE = "python:3.11-slim"


@pytest.mark.skipif(
    not _image_present(_LIVE_IMAGE),
    reason=f"Docker image {_LIVE_IMAGE} not pulled locally",
)
class TestExecutePythonDockerLive:
    """Smoke test against a real Docker daemon, skipped otherwise."""

    def test_simple_arithmetic(self):
        out = execute_python_docker(
            "result = {'value': 2 + 2}",
            timeout=30,
            max_memory_mb=128,
            image=_LIVE_IMAGE,
        )
        assert out.success is True, out.short_error()
        assert out.return_value == {"value": 4}
