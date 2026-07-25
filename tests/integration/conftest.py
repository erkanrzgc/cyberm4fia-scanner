"""Integration-test infrastructure.

Provides skip decorators so each tool's integration test reports a clear
"missing X" reason instead of a hard failure when the local environment isn't
configured. Also auto-tags every test under this directory with
``@pytest.mark.integration`` so a top-level ``pytest`` run skips them.
"""

from __future__ import annotations

import os
import shutil
import socket

import pytest


def requires_binary(name: str):
    """Skip if ``name`` is not on PATH."""
    return pytest.mark.skipif(
        shutil.which(name) is None,
        reason=f"integration: binary '{name}' not installed",
    )


def requires_env(var: str):
    """Skip if env var ``var`` is unset or empty."""
    return pytest.mark.skipif(
        not os.environ.get(var),
        reason=f"integration: environment variable {var} not set",
    )


def requires_service(host: str, port: int):
    """Skip if no TCP listener is reachable at ``host:port``."""
    def _reachable() -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.connect((host, port))
                return True
        except OSError:
            return False
    return pytest.mark.skipif(
        not _reachable(),
        reason=f"integration: no listener on {host}:{port}",
    )


def pytest_collection_modifyitems(config, items):
    """Auto-mark everything under tests/integration/ as `integration`."""
    integration_root = os.path.join("tests", "integration")
    for item in items:
        if integration_root in str(item.fspath):
            item.add_marker(pytest.mark.integration)
