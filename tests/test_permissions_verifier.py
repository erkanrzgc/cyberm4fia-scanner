"""Tests for the Permissions-Policy active verifier."""

from __future__ import annotations

import pytest

from modules.active_verifiers import (
    PermissionsPolicyVerifier,
    run_all_verifiers,
)
from modules.active_verifiers.permissions import (
    _is_directive_restrictive,
    _parse_permissions_policy,
)

pytestmark = pytest.mark.unit


def _mh(url: str = "https://target.tld/") -> dict:
    return {"type": "Missing_Security_Header", "url": url, "param": "Permissions-Policy"}


class TestParser:
    def test_empty_string(self):
        assert _parse_permissions_policy("") == {}

    def test_single_directive(self):
        assert _parse_permissions_policy("camera=()") == {"camera": "()"}

    def test_multiple_directives(self):
        out = _parse_permissions_policy("camera=(), microphone=(self), geolocation=*")
        assert out == {"camera": "()", "microphone": "(self)", "geolocation": "*"}

    def test_strips_whitespace(self):
        out = _parse_permissions_policy("  camera  =  ()  ,  microphone=(self)  ")
        assert out["camera"] == "()"
        assert out["microphone"] == "(self)"


class TestRestrictive:
    @pytest.mark.parametrize("directive", ["()", "(  )", "(none)"])
    def test_empty_is_restrictive(self, directive):
        assert _is_directive_restrictive(directive)

    @pytest.mark.parametrize("directive", ["(self)", "*", '("https://attacker.tld")', "(self https://x.tld)"])
    def test_with_origins_is_not_restrictive(self, directive):
        assert not _is_directive_restrictive(directive)


class TestVerifier:
    def test_applies_only_to_permissions_policy(self):
        v = PermissionsPolicyVerifier()
        assert v.applies_to(_mh())
        assert not v.applies_to({"type": "Missing_Security_Header", "url": "x", "param": "X-Frame-Options"})

    def test_missing_header_plus_framable_promotes(self, monkeypatch):
        monkeypatch.setattr(
            PermissionsPolicyVerifier, "_fetch_headers", staticmethod(lambda u: {})
        )
        out = PermissionsPolicyVerifier().verify(_mh(), "https://target.tld/")
        assert out.verified is True
        assert out.promoted_type == "Permissions_Policy_Abuse"
        assert out.cvss_override == 5.4
        assert "absent" in out.evidence

    def test_strict_policy_blocks_promotion(self, monkeypatch):
        # All sensitive features denied = no abuse vector
        strict = ", ".join(
            f"{f}=()" for f in
            ("camera", "microphone", "geolocation", "payment", "usb", "midi",
             "serial", "hid", "fullscreen", "display-capture", "publickey-credentials-get")
        )
        monkeypatch.setattr(
            PermissionsPolicyVerifier,
            "_fetch_headers",
            staticmethod(lambda u: {"permissions-policy": strict}),
        )
        out = PermissionsPolicyVerifier().verify(_mh(), "https://target.tld/")
        assert out.verified is False
        assert "0 sensitive feature" in out.evidence

    def test_partial_policy_promotes_unrestricted_features(self, monkeypatch):
        # Only camera is restricted; everything else inherits permissive default
        monkeypatch.setattr(
            PermissionsPolicyVerifier,
            "_fetch_headers",
            staticmethod(lambda u: {"permissions-policy": "camera=()"}),
        )
        out = PermissionsPolicyVerifier().verify(_mh(), "https://target.tld/")
        assert out.verified is True
        assert "microphone" in out.evidence or "geolocation" in out.evidence

    def test_framing_blocked_kills_abuse_vector(self, monkeypatch):
        # No Permissions-Policy but page is XFO: DENY → abuse impossible
        monkeypatch.setattr(
            PermissionsPolicyVerifier,
            "_fetch_headers",
            staticmethod(lambda u: {"x-frame-options": "DENY"}),
        )
        out = PermissionsPolicyVerifier().verify(_mh(), "https://target.tld/")
        assert out.verified is False
        assert "NOT framable" in out.evidence

    def test_csp_frame_ancestors_none_kills_abuse_vector(self, monkeypatch):
        monkeypatch.setattr(
            PermissionsPolicyVerifier,
            "_fetch_headers",
            staticmethod(lambda u: {"content-security-policy": "frame-ancestors 'none'"}),
        )
        out = PermissionsPolicyVerifier().verify(_mh(), "https://target.tld/")
        assert out.verified is False
        assert "NOT framable" in out.evidence

    def test_csp_frame_ancestors_wildcard_does_not_block(self, monkeypatch):
        monkeypatch.setattr(
            PermissionsPolicyVerifier,
            "_fetch_headers",
            staticmethod(lambda u: {"content-security-policy": "frame-ancestors *"}),
        )
        out = PermissionsPolicyVerifier().verify(_mh(), "https://target.tld/")
        assert out.verified is True
        assert "framable" not in out.evidence  # framing succeeded; framable wording absent

    def test_fetch_failure_returns_unverified(self, monkeypatch):
        monkeypatch.setattr(
            PermissionsPolicyVerifier, "_fetch_headers", staticmethod(lambda u: None)
        )
        out = PermissionsPolicyVerifier().verify(_mh(), "https://target.tld/")
        assert out.verified is False
        assert "active probe failed" in out.evidence


class TestComposition:
    def test_run_all_verifiers_includes_permissions(self, monkeypatch):
        # Stub every verifier's _fetch_headers / _fetch so the composition runs offline.
        monkeypatch.setattr(
            PermissionsPolicyVerifier,
            "_fetch_headers",
            staticmethod(lambda u: {}),
        )
        # Stub the other verifiers so they don't try real network.
        from modules.active_verifiers import (
            ClickjackingVerifier,
            HSTSVerifier,
            MIMEConfusionVerifier,
            ReferrerLeakVerifier,
        )
        monkeypatch.setattr(ClickjackingVerifier, "_fetch_headers", staticmethod(lambda u: {}))
        monkeypatch.setattr(ClickjackingVerifier, "_verify_in_browser", staticmethod(lambda u: ""))
        monkeypatch.setattr(HSTSVerifier, "_fetch_headers", staticmethod(lambda u: {}))
        monkeypatch.setattr(HSTSVerifier, "_check_preload", staticmethod(lambda h: ""))
        monkeypatch.setattr(HSTSVerifier, "_first_hit_downgrade", staticmethod(lambda u: ""))
        monkeypatch.setattr(MIMEConfusionVerifier, "_try_get", staticmethod(lambda u: None))
        from types import SimpleNamespace
        monkeypatch.setattr(
            ReferrerLeakVerifier, "_fetch",
            staticmethod(lambda u: SimpleNamespace(headers={"referrer-policy": ""}, text="")),
        )

        findings = [_mh()]
        out = run_all_verifiers(findings, "https://target.tld/")
        assert out[0]["verified"] is True
        assert out[0]["type"] == "Permissions_Policy_Abuse"
