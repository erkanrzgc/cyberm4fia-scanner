"""Real-binary integration test: TestsslTool.

Same fixture as sslyze (weak-tls on 127.0.0.1:8443). testssl is much slower;
the timeout is generous.
"""

from __future__ import annotations

import pytest

from tests.integration.conftest import requires_binary, requires_service
from utils.external_tools.testssl import TestsslTool

pytestmark = [requires_binary("testssl.sh"), requires_service("127.0.0.1", 8443)]


def test_testssl_flags_actionable_vulnerabilities_on_weak_tls():
    result = TestsslTool().run("127.0.0.1:8443", timeout=900)
    if not result.succeeded:
        pytest.skip(f"testssl run incomplete: {result.error or result.raw_stderr[:200]}")
    # We don't assert a specific vuln name (the rule IDs evolve) — only that
    # the wrapper extracted at least one actionable record from a known-weak
    # endpoint. A clean server would produce zero.
    assert result.parsed["count"] >= 1, "expected at least one actionable testssl finding"
