"""Tests for the active verifier subsystem.

Network calls are stubbed out so the tests run offline. We verify:

* Each verifier's ``applies_to`` predicate matches the right finding types.
* When the header-only signals say "exploitable", findings are promoted to
  their ``*_Exploitable`` registry type and ``verified=True``.
* When defences are present (e.g. proper HSTS, frame-ancestors none), the
  finding stays suspected.
* ``run_all_verifiers`` composes them in order without raising on empty.
* Clickjacking sibling-promotion: when XFO is found exploitable, the CSP
  Missing_Security_Header on the same URL is promoted alongside.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from modules.active_verifiers import (
    ClickjackingVerifier,
    HSTSVerifier,
    MIMEConfusionVerifier,
    ReferrerLeakVerifier,
    run_all_verifiers,
    verify_clickjacking,
)
from modules.active_verifiers.base import (
    VerificationOutcome,
    apply_outcome,
)

pytestmark = pytest.mark.unit


def _mh(param: str, url: str = "https://target.tld/") -> dict:
    return {"type": "Missing_Security_Header", "url": url, "param": param}


# ── Clickjacking ─────────────────────────────────────────────────────────


class TestClickjacking:
    def test_applies_to_xfo_and_csp(self):
        v = ClickjackingVerifier()
        assert v.applies_to(_mh("X-Frame-Options"))
        assert v.applies_to(_mh("content-security-policy"))
        assert not v.applies_to(_mh("Referrer-Policy"))
        assert not v.applies_to({"type": "XSS_Param"})

    def test_xfo_deny_blocks_promotion(self, monkeypatch):
        monkeypatch.setattr(
            ClickjackingVerifier,
            "_fetch_headers",
            staticmethod(lambda url: {"x-frame-options": "DENY"}),
        )
        # browser probe should not be hit when header check already passes
        monkeypatch.setattr(ClickjackingVerifier, "_verify_in_browser", staticmethod(lambda u: ""))
        out = ClickjackingVerifier().verify(_mh("X-Frame-Options"), "https://target.tld/")
        assert out.verified is False
        assert "xfo_ok=True" in out.evidence

    def test_csp_frame_ancestors_none_blocks_promotion(self, monkeypatch):
        monkeypatch.setattr(
            ClickjackingVerifier,
            "_fetch_headers",
            staticmethod(lambda url: {"content-security-policy": "frame-ancestors 'none'"}),
        )
        monkeypatch.setattr(ClickjackingVerifier, "_verify_in_browser", staticmethod(lambda u: ""))
        out = ClickjackingVerifier().verify(_mh("content-security-policy"), "https://target.tld/")
        assert out.verified is False
        assert "csp_ok=True" in out.evidence

    def test_no_protection_promotes(self, monkeypatch):
        monkeypatch.setattr(
            ClickjackingVerifier,
            "_fetch_headers",
            staticmethod(lambda url: {"server": "nginx"}),
        )
        monkeypatch.setattr(ClickjackingVerifier, "_verify_in_browser", staticmethod(lambda u: ""))
        out = ClickjackingVerifier().verify(_mh("X-Frame-Options"), "https://target.tld/")
        assert out.verified is True
        assert out.promoted_type == "Clickjacking_Exploitable"
        assert out.cvss_override == 5.4

    def test_sibling_promotion(self, monkeypatch):
        """When XFO promotes, the sibling CSP Missing_Security_Header on the
        same URL is promoted in the same pass."""
        monkeypatch.setattr(
            ClickjackingVerifier,
            "_fetch_headers",
            staticmethod(lambda url: {}),  # both headers absent
        )
        monkeypatch.setattr(ClickjackingVerifier, "_verify_in_browser", staticmethod(lambda u: ""))
        findings = [
            _mh("X-Frame-Options", "https://target.tld/"),
            _mh("Content-Security-Policy", "https://target.tld/"),
        ]
        out = verify_clickjacking(findings, "https://target.tld/")
        assert all(f["verified"] for f in out)
        assert all(f["type"] == "Clickjacking_Exploitable" for f in out)


# ── HSTS ─────────────────────────────────────────────────────────────────


class TestHSTS:
    def test_applies_to_hsts_only(self):
        v = HSTSVerifier()
        assert v.applies_to(_mh("Strict-Transport-Security"))
        assert not v.applies_to(_mh("X-Frame-Options"))

    def test_absent_hsts_promotes(self, monkeypatch):
        monkeypatch.setattr(HSTSVerifier, "_fetch_headers", staticmethod(lambda url: {}))
        monkeypatch.setattr(HSTSVerifier, "_check_preload", staticmethod(lambda host: ""))
        monkeypatch.setattr(HSTSVerifier, "_first_hit_downgrade", staticmethod(lambda url: ""))
        out = HSTSVerifier().verify(_mh("Strict-Transport-Security"), "https://target.tld/")
        assert out.verified is True
        assert out.promoted_type == "HSTS_Downgrade_Exploitable"
        assert "absent" in out.evidence

    def test_strong_hsts_blocks_promotion(self, monkeypatch):
        monkeypatch.setattr(
            HSTSVerifier,
            "_fetch_headers",
            staticmethod(lambda url: {"strict-transport-security":
                "max-age=63072000; includeSubDomains; preload"}),
        )
        monkeypatch.setattr(HSTSVerifier, "_check_preload", staticmethod(lambda host: "preloaded"))
        monkeypatch.setattr(HSTSVerifier, "_first_hit_downgrade", staticmethod(lambda url: ""))
        out = HSTSVerifier().verify(_mh("Strict-Transport-Security"), "https://target.tld/")
        assert out.verified is False

    def test_weak_max_age_promotes(self, monkeypatch):
        monkeypatch.setattr(
            HSTSVerifier,
            "_fetch_headers",
            staticmethod(lambda url: {"strict-transport-security": "max-age=3600"}),
        )
        monkeypatch.setattr(HSTSVerifier, "_check_preload", staticmethod(lambda host: ""))
        monkeypatch.setattr(HSTSVerifier, "_first_hit_downgrade", staticmethod(lambda url: ""))
        out = HSTSVerifier().verify(_mh("Strict-Transport-Security"), "https://target.tld/")
        assert out.verified is True
        assert "max-age=3600" in out.evidence

    def test_first_hit_downgrade_promotes(self, monkeypatch):
        monkeypatch.setattr(
            HSTSVerifier,
            "_fetch_headers",
            staticmethod(lambda url: {"strict-transport-security":
                "max-age=63072000; includeSubDomains; preload"}),
        )
        monkeypatch.setattr(HSTSVerifier, "_check_preload", staticmethod(lambda host: "preloaded"))
        monkeypatch.setattr(
            HSTSVerifier,
            "_first_hit_downgrade",
            staticmethod(lambda url: "HTTP→HTTPS redirect carries no HSTS"),
        )
        out = HSTSVerifier().verify(_mh("Strict-Transport-Security"), "https://target.tld/")
        assert out.verified is True


# ── MIME ─────────────────────────────────────────────────────────────────


class TestMIME:
    def test_applies_to_xct_only(self):
        v = MIMEConfusionVerifier()
        assert v.applies_to(_mh("X-Content-Type-Options"))
        assert not v.applies_to(_mh("X-Frame-Options"))

    def test_both_signals_promote(self, monkeypatch):
        v = MIMEConfusionVerifier()
        monkeypatch.setattr(v, "_find_upload_endpoint", lambda url: "https://target.tld/upload")
        monkeypatch.setattr(v, "_find_weak_content_type", lambda url: "weak Content-Type at /uploads/: (absent)")
        out = v.verify(_mh("X-Content-Type-Options"), "https://target.tld/")
        assert out.verified is True
        assert out.promoted_type == "MIME_Confusion_Exploitable"

    def test_only_upload_no_promotion(self, monkeypatch):
        v = MIMEConfusionVerifier()
        monkeypatch.setattr(v, "_find_upload_endpoint", lambda url: "https://target.tld/upload")
        monkeypatch.setattr(v, "_find_weak_content_type", lambda url: "")
        out = v.verify(_mh("X-Content-Type-Options"), "https://target.tld/")
        assert out.verified is False
        assert "need both" in out.evidence

    def test_neither_signal_no_promotion(self, monkeypatch):
        v = MIMEConfusionVerifier()
        monkeypatch.setattr(v, "_find_upload_endpoint", lambda url: "")
        monkeypatch.setattr(v, "_find_weak_content_type", lambda url: "")
        out = v.verify(_mh("X-Content-Type-Options"), "https://target.tld/")
        assert out.verified is False


# ── Referrer ─────────────────────────────────────────────────────────────


class TestReferrer:
    def test_applies_to_referrer_only(self):
        v = ReferrerLeakVerifier()
        assert v.applies_to(_mh("Referrer-Policy"))
        assert not v.applies_to(_mh("X-Frame-Options"))

    def test_safe_policy_blocks_promotion(self, monkeypatch):
        page = SimpleNamespace(
            headers={"referrer-policy": "no-referrer"},
            text="<html><body>safe</body></html>",
        )
        monkeypatch.setattr(ReferrerLeakVerifier, "_fetch", staticmethod(lambda url: page))
        out = ReferrerLeakVerifier().verify(_mh("Referrer-Policy"), "https://target.tld/")
        assert out.verified is False
        assert "safe Referrer-Policy" in out.evidence

    def test_sensitive_url_plus_third_party_promotes(self, monkeypatch):
        page = SimpleNamespace(
            headers={"referrer-policy": ""},
            text=(
                '<html><body>'
                'Reset link: /reset?reset_token=AAA-BBB-CCC '
                '<img src="https://cdn.attacker.tld/logo.png">'
                '<link href="https://fonts.evil.tld/font.woff2">'
                '</body></html>'
            ),
        )
        monkeypatch.setattr(ReferrerLeakVerifier, "_fetch", staticmethod(lambda url: page))
        out = ReferrerLeakVerifier().verify(_mh("Referrer-Policy"), "https://target.tld/reset")
        assert out.verified is True
        assert out.promoted_type == "Referrer_Leak_Exploitable"

    def test_neither_signal_no_promotion(self, monkeypatch):
        page = SimpleNamespace(
            headers={"referrer-policy": ""},
            text="<html><body>nothing interesting</body></html>",
        )
        monkeypatch.setattr(ReferrerLeakVerifier, "_fetch", staticmethod(lambda url: page))
        out = ReferrerLeakVerifier().verify(_mh("Referrer-Policy"), "https://target.tld/")
        assert out.verified is False


# ── Composition ──────────────────────────────────────────────────────────


class TestRunAllVerifiers:
    def test_empty_findings_passthrough(self):
        assert run_all_verifiers([], "https://target.tld/") == []

    def test_non_header_findings_untouched(self):
        findings = [{"type": "XSS_Param", "url": "https://target.tld/q", "payload": "<svg>"}]
        out = run_all_verifiers(list(findings), "https://target.tld/")
        # XSS_Param should be untouched (no verifier claims it)
        assert out[0]["type"] == "XSS_Param"
        assert "verified" not in out[0]


class TestApplyOutcome:
    def test_verified_outcome_promotes_type(self):
        f = _mh("X-Frame-Options")
        out = VerificationOutcome(
            verified=True,
            promoted_type="Clickjacking_Exploitable",
            evidence="evidence text",
            severity_override="medium",
            cvss_override=5.4,
        )
        apply_outcome(f, out)
        assert f["verified"] is True
        assert f["verification_state"] == "verified"
        assert f["type"] == "Clickjacking_Exploitable"
        assert f["severity"] == "MEDIUM"
        assert f["cvss"] == 5.4
        assert "evidence text" in f["evidence"]

    def test_unverified_outcome_keeps_type(self):
        f = _mh("X-Frame-Options")
        out = VerificationOutcome(verified=False, evidence="probe failed")
        apply_outcome(f, out)
        assert f["verified"] is False
        assert f["type"] == "Missing_Security_Header"
        assert "probe failed" in f["evidence"]
