"""Tests for utils.finding.promoted_dedup.

Each promoted active-verifier finding should collapse the legacy emit on
the same URL. Unrelated findings stay untouched.
"""

from __future__ import annotations

import pytest

from utils.finding.promoted_dedup import collapse_promoted_siblings

pytestmark = pytest.mark.unit


class TestClickjackingCollapse:
    def test_collapses_legacy_clickjacking_vulnerable(self):
        findings = [
            {"type": "Clickjacking_Vulnerable", "url": "https://x/"},
            {"type": "Clickjacking_Exploitable", "url": "https://x/"},
        ]
        out = collapse_promoted_siblings(findings)
        types = [f["type"] for f in out]
        assert types == ["Clickjacking_Exploitable"]

    def test_does_not_collapse_when_no_promoted_sibling(self):
        findings = [{"type": "Clickjacking_Vulnerable", "url": "https://x/"}]
        out = collapse_promoted_siblings(findings)
        assert len(out) == 1
        assert out[0]["type"] == "Clickjacking_Vulnerable"

    def test_url_match_is_required(self):
        findings = [
            {"type": "Clickjacking_Vulnerable", "url": "https://x/page-a"},
            {"type": "Clickjacking_Exploitable", "url": "https://x/page-b"},
        ]
        out = collapse_promoted_siblings(findings)
        # Different URLs — both survive
        assert len(out) == 2

    def test_trailing_slash_treated_as_same_url(self):
        findings = [
            {"type": "Clickjacking_Vulnerable", "url": "https://x"},
            {"type": "Clickjacking_Exploitable", "url": "https://x/"},
        ]
        out = collapse_promoted_siblings(findings)
        assert len(out) == 1
        assert out[0]["type"] == "Clickjacking_Exploitable"


class TestHSTSCollapse:
    def test_collapses_legacy_weak_hsts(self):
        findings = [
            {"type": "Weak_HSTS", "url": "https://x/"},
            {"type": "HSTS_Downgrade_Exploitable", "url": "https://x/"},
        ]
        out = collapse_promoted_siblings(findings)
        types = [f["type"] for f in out]
        assert types == ["HSTS_Downgrade_Exploitable"]

    def test_weak_hsts_survives_without_promotion(self):
        findings = [{"type": "Weak_HSTS", "url": "https://x/"}]
        out = collapse_promoted_siblings(findings)
        assert len(out) == 1


class TestCSPCollapse:
    def test_legacy_csp_missing_collapsed_by_header_finding(self):
        findings = [
            {"type": "CSP_Bypass", "weakness": "missing_csp", "url": "https://x/"},
            {
                "type": "Missing_Security_Header",
                "param": "Content-Security-Policy",
                "url": "https://x/",
            },
        ]
        out = collapse_promoted_siblings(findings)
        types = [f["type"] for f in out]
        assert "CSP_Bypass" not in types
        assert "Missing_Security_Header" in types

    def test_csp_bypass_with_real_weakness_survives(self):
        """A real CSP weakness like unsafe-inline is NOT a duplicate of the
        missing-header finding — keep it."""
        findings = [
            {"type": "CSP_Bypass", "weakness": "unsafe-inline", "url": "https://x/"},
            {
                "type": "Missing_Security_Header",
                "param": "Content-Security-Policy",
                "url": "https://x/",
            },
        ]
        out = collapse_promoted_siblings(findings)
        types = [f["type"] for f in out]
        # Both stay — unsafe-inline is a separate signal
        assert "CSP_Bypass" in types
        assert "Missing_Security_Header" in types


class TestUnrelatedFindings:
    def test_xss_untouched(self):
        findings = [
            {"type": "XSS_Param", "url": "https://x/q", "payload": "<svg>"},
            {"type": "Clickjacking_Exploitable", "url": "https://x/"},
            {"type": "Clickjacking_Vulnerable", "url": "https://x/"},
        ]
        out = collapse_promoted_siblings(findings)
        # XSS_Param + the promoted Clickjacking survive
        assert len(out) == 2
        types = {f["type"] for f in out}
        assert "XSS_Param" in types
        assert "Clickjacking_Exploitable" in types

    def test_empty_input(self):
        assert collapse_promoted_siblings([]) == []


class TestRealWorldBatch:
    """Replays the foremyurtdisidanismanlik.com pattern."""

    def test_typical_post_verifier_batch(self):
        findings = [
            # Promoted by active verifiers
            {"type": "Clickjacking_Exploitable", "url": "https://x/"},
            {"type": "Clickjacking_Exploitable", "url": "https://x/"},  # sibling promo
            {"type": "HSTS_Downgrade_Exploitable", "url": "https://x/"},
            {"type": "Permissions_Policy_Abuse", "url": "https://x/"},
            # Legacy duplicates that should be dropped
            {"type": "Clickjacking_Vulnerable", "url": "https://x/"},
            {"type": "Weak_HSTS", "url": "https://x/"},
            {"type": "CSP_Bypass", "weakness": "missing_csp", "url": "https://x/"},
            # Unrelated
            {"type": "Version_Disclosure", "url": "https://x/"},
            {
                "type": "Missing_Security_Header",
                "param": "Content-Security-Policy",
                "url": "https://x/",
            },
        ]
        out = collapse_promoted_siblings(findings)
        types = [f["type"] for f in out]
        # 3 legacy dups dropped: Clickjacking_Vulnerable, Weak_HSTS, CSP_Bypass
        assert "Clickjacking_Vulnerable" not in types
        assert "Weak_HSTS" not in types
        assert "CSP_Bypass" not in types
        # Promoted + unrelated survive
        assert types.count("Clickjacking_Exploitable") == 2
        assert "HSTS_Downgrade_Exploitable" in types
        assert "Permissions_Policy_Abuse" in types
        assert "Version_Disclosure" in types
