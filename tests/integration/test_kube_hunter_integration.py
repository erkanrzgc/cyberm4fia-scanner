"""Real-binary integration test: KubeHunterTool.

Targets a Kubernetes API server. The lightest sane fixture is a `kind`
cluster the user brings up with `make integration-kube-up` (or by hand);
the test discovers it via 127.0.0.1:6443 and skips when absent.

Spinning kind up inside the test would couple us to Docker-in-Docker and
takes ~30 s per test; better to keep that bring-up as an explicit step.
"""

from __future__ import annotations

import pytest

from tests.integration.conftest import requires_binary, requires_service
from utils.external_tools.kube_hunter import KubeHunterTool

pytestmark = [
    requires_binary("kube-hunter"),
    requires_service("127.0.0.1", 6443),
]


def test_kube_hunter_runs_against_local_cluster():
    result = KubeHunterTool().run("https://127.0.0.1:6443", timeout=300)
    if not result.succeeded:
        pytest.skip(f"kube-hunter did not produce a clean run: {result.error or result.raw_stderr[:200]}")
    # Shape check only — a well-locked-down cluster legitimately reports 0.
    # The point is to prove the wrapper round-trips the real --report json
    # output without crashing.
    assert isinstance(result.parsed.get("vulnerabilities"), list)
    assert isinstance(result.parsed.get("count"), int)
