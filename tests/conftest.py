"""Shared pytest fixtures for deterministic test isolation."""

import os

import pytest

# Strip ambient proxy env at collection time. Several tests build httpx clients
# that fail under `HTTP(S)_PROXY=socks5h://...` because httpx has no native
# socks scheme support. Production code uses its own configured transport, so
# clearing these only affects the test sandbox.
for _var in (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
):
    os.environ.pop(_var, None)


@pytest.fixture(autouse=True)
def reset_waf_detector_state():
    """Keep global WAF fingerprint state from leaking across tests."""
    from utils.waf import waf_detector

    waf_detector.detected_waf = None
    yield
    waf_detector.detected_waf = None
