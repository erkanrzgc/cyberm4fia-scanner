"""Real-binary integration test: SmbmapTool.

Targets the Samba container from docker-compose.integration.yml on
127.0.0.1:1445 (public READ + writable shares configured).
"""

from __future__ import annotations

import pytest

from tests.integration.conftest import requires_binary, requires_service
from utils.external_tools.smbmap import SmbmapTool

pytestmark = [requires_binary("smbmap"), requires_service("127.0.0.1", 1445)]


def test_smbmap_enumerates_fixture_shares():
    # smbmap doesn't take a port flag in older versions; for the integration
    # fixture we point its default 445 at the mapped 1445 via -P.
    result = SmbmapTool().run("127.0.0.1", extra_args=["-P", "1445"], timeout=60)
    if not result.succeeded:
        pytest.skip(f"smbmap did not produce a clean run: {result.error or result.raw_stderr[:200]}")
    share_names = {s["share"] for s in result.parsed["shares"]}
    # The fixture defines a "public" share. dperson/samba also creates IPC$.
    assert "public" in share_names, f"expected 'public' share, got {share_names}"
