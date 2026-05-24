"""Real-binary integration test: WpscanTool.

Targets the WordPress container from docker-compose.integration.yml on
127.0.0.1:8080. Requires WPSCAN_API_TOKEN to be set — wpscan's vuln database
checks no-op without it. Skipped otherwise.
"""

from __future__ import annotations

import os

import pytest

from tests.integration.conftest import requires_binary, requires_env, requires_service
from utils.external_tools.wpscan import WpscanTool

pytestmark = [
    requires_binary("wpscan"),
    requires_env("WPSCAN_API_TOKEN"),
    requires_service("127.0.0.1", 8080),
]


def test_wpscan_runs_against_fixture_wordpress():
    token = os.environ["WPSCAN_API_TOKEN"]
    result = WpscanTool().run(
        "http://127.0.0.1:8080/",
        api_token=token,
        extra_args=["--disable-tls-checks"],
        timeout=600,
    )
    # Some wpscan runs return a non-zero exit when issues are found — that's
    # fine; the parser handles it. We only assert structure of the output.
    assert isinstance(result.parsed.get("vulnerabilities"), list), (
        f"unexpected wpscan parsed shape: {result.parsed!r} stderr={result.raw_stderr[:200]!r}"
    )
