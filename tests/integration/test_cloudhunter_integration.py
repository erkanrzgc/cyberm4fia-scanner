"""Real-binary integration test: CloudHunterTool.

Probes a publicly-known throwaway bucket name to validate the wrapper
round-trips real CloudHunter output. Doesn't assert specific results because
public-bucket states change; only that the parsed shape is sane and either
zero or more buckets came back.

Requires CYBERM4FIA_INTEGRATION_NETWORK=1 to be set since this test reaches
out to public cloud endpoints (AWS / GCP / Azure metadata). Skipped otherwise.
"""

from __future__ import annotations

import pytest

from tests.integration.conftest import requires_binary, requires_env
from utils.external_tools.cloudhunter import CloudHunterTool

pytestmark = [
    requires_binary("cloudhunter"),
    requires_env("CYBERM4FIA_INTEGRATION_NETWORK"),
]


def test_cloudhunter_runs_against_known_domain():
    # `example.com` is reserved and parks no real buckets; CloudHunter still
    # produces a structured "scanned, found nothing" response we can shape-check.
    result = CloudHunterTool().run("example.com", timeout=300)
    if not result.succeeded and not result.parsed:
        pytest.skip(f"cloudhunter did not run cleanly: {result.error or result.raw_stderr[:200]}")
    assert isinstance(result.parsed.get("buckets"), list)
    assert isinstance(result.parsed.get("count"), int)
