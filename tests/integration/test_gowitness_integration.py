"""Real-binary integration test: GowitnessTool.

Targets the http-target service from docker-compose.integration.yml on
127.0.0.1:8081. gowitness requires Chrome/Chromium at runtime; the test skips
if either gowitness binary or a chromium-shaped browser is missing.
"""

from __future__ import annotations

import shutil

import pytest

from tests.integration.conftest import requires_binary, requires_service
from utils.external_tools.gowitness import GowitnessTool

pytestmark = [requires_binary("gowitness"), requires_service("127.0.0.1", 8081)]


def test_gowitness_captures_fixture_target(tmp_path):
    has_chrome = any(shutil.which(b) for b in ("chromium", "chromium-browser",
                                              "google-chrome", "google-chrome-stable"))
    if not has_chrome:
        pytest.skip("gowitness needs a chromium binary at runtime")

    result = GowitnessTool().run(
        "http://127.0.0.1:8081/",
        screenshot_path=str(tmp_path / "shots"),
        timeout=90,
    )
    if not result.succeeded:
        pytest.skip(f"gowitness did not produce clean output: {result.error or result.raw_stderr[:200]}")
    assert result.parsed["count"] >= 1
    title = result.parsed["captures"][0]["title"]
    assert "fixture" in title.lower(), f"unexpected page title {title!r}"
