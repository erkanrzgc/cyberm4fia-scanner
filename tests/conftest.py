"""Shared pytest fixtures for deterministic test isolation."""

import pytest


@pytest.fixture(autouse=True)
def reset_waf_detector_state():
    """Keep global WAF fingerprint state from leaking across tests."""
    from utils.waf import waf_detector

    waf_detector.detected_waf = None
    yield
    waf_detector.detected_waf = None
