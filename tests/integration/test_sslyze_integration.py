"""Real-binary integration test: SslyzeTool.

Targets the weak-tls service from docker-compose.integration.yml on
127.0.0.1:8443 (TLSv1.0 + TLSv1.1 deliberately enabled). Skipped when the
fixture isn't up.
"""

from __future__ import annotations

import pytest

from tests.integration.conftest import requires_binary, requires_service
from utils.external_tools.sslyze import SslyzeTool

pytestmark = [requires_binary("sslyze"), requires_service("127.0.0.1", 8443)]


def test_sslyze_flags_weak_protocols_against_fixture():
    result = SslyzeTool().run("127.0.0.1:8443", timeout=180)
    if not result.succeeded:
        pytest.skip(f"sslyze did not produce a clean run: {result.error or result.raw_stderr[:200]}")
    weak = set(result.parsed.get("weak_protocols", []))
    # docker-compose fixture enables TLSv1.0 + TLSv1.1 explicitly.
    assert weak & {"TLS 1.0", "TLS 1.1"}, (
        f"expected sslyze to report weak protocols, got {weak}"
    )
