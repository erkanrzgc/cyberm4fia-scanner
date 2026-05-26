"""Tests for the new missing-header → exploit promotion chains in
``utils.ai_exploit_agent.chain_detector.ExploitChainDetector``.
"""

from __future__ import annotations

import pytest

from utils.ai_exploit_agent.chain_detector import ExploitChainDetector

pytestmark = pytest.mark.unit


@pytest.fixture
def detector():
    return ExploitChainDetector(ai_client=None)


def _chain_names(chains: list) -> set[str]:
    return {c["chain_name"] for c in chains}


class TestNewChains:
    def test_missing_csp_plus_xss(self, detector):
        chains = detector.detect_chains(
            [
                {"type": "Missing_Security_Header", "param": "Content-Security-Policy"},
                {"type": "XSS_Param", "url": "http://x/q", "payload": "<svg>"},
            ]
        )
        names = _chain_names(chains)
        assert "Missing CSP + Reflected Input → Stored XSS Exfil" in names

    def test_missing_hsts_plus_insecure_cookie(self, detector):
        chains = detector.detect_chains(
            [
                {"type": "Missing_Security_Header", "param": "Strict-Transport-Security"},
                {"type": "Insecure_Cookie", "url": "http://x/", "param": "PHPSESSID"},
            ]
        )
        names = _chain_names(chains)
        assert "Missing HSTS + Insecure Cookie → SSL Strip Session Hijack" in names

    def test_missing_xct_plus_file_upload(self, detector):
        chains = detector.detect_chains(
            [
                {"type": "Missing_Security_Header", "param": "X-Content-Type-Options"},
                {"type": "File_Upload", "url": "http://x/upload"},
            ]
        )
        names = _chain_names(chains)
        assert "Missing X-Content-Type-Options + File Upload → MIME-Confusion XSS" in names

    def test_cookie_theft_chain(self, detector):
        chains = detector.detect_chains(
            [
                {"type": "Insecure_Cookie", "url": "http://x/", "param": "PHPSESSID"},
                {"type": "XSS_Param", "url": "http://x/q", "payload": "<svg>"},
            ]
        )
        names = _chain_names(chains)
        assert "Insecure Cookie (no HttpOnly) + XSS → Full Account Takeover" in names


class TestNoFalseChains:
    def test_lonely_missing_header_does_not_promote(self, detector):
        """Missing header alone (no chainable primitive) shouldn't trigger
        the chain promotions."""
        chains = detector.detect_chains(
            [{"type": "Missing_Security_Header", "param": "Content-Security-Policy"}]
        )
        names = _chain_names(chains)
        assert "Missing CSP + Reflected Input → Stored XSS Exfil" not in names

    def test_lonely_xss_does_not_promote_csp_chain(self, detector):
        chains = detector.detect_chains(
            [{"type": "XSS_Param", "url": "http://x/q", "payload": "<svg>"}]
        )
        names = _chain_names(chains)
        assert "Missing CSP + Reflected Input → Stored XSS Exfil" not in names
