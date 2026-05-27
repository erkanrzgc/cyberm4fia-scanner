"""Tests for modules.poc_generator promoted-type dispatch.

Before the fix, active verifiers replaced ``Missing_Security_Header`` with
``Clickjacking_Exploitable`` / ``HSTS_Downgrade_Exploitable`` / etc. before
the reporting phase. The PoC generator's dispatch loop only handled
``Missing_Security_Header``, so promoted findings silently skipped PoC
generation. These tests pin that regression closed.
"""

from __future__ import annotations

import glob
import os
import tempfile

import pytest

from modules.poc_generator import (
    _PROMOTED_TYPE_TO_POC_KIND,
    generate_pocs,
)

pytestmark = pytest.mark.unit


def _pocs_in(d: str) -> list[str]:
    return sorted(os.path.basename(p) for p in glob.glob(os.path.join(d, "pocs", "*.html")))


class TestPromotedTypeMap:
    def test_all_active_verifier_outputs_covered(self):
        """Every promoted type our active verifiers emit must map to a
        concrete PoC kind."""
        promoted_emitted_by_verifiers = {
            "Clickjacking_Exploitable",
            "HSTS_Downgrade_Exploitable",
            "MIME_Confusion_Exploitable",
            "Referrer_Leak_Exploitable",
            "Permissions_Policy_Abuse",
        }
        for promoted_type in promoted_emitted_by_verifiers:
            assert promoted_type in _PROMOTED_TYPE_TO_POC_KIND, (
                f"{promoted_type} is emitted by a verifier but has no PoC mapping"
            )

    def test_csp_bypass_also_routed(self):
        """CSP_Bypass is emitted by modules.csp_bypass, not a verifier, but
        its exploit primitive is the same XSS — route it too."""
        assert _PROMOTED_TYPE_TO_POC_KIND.get("CSP_Bypass") == "csp_xss"


class TestPromotedDispatch:
    @pytest.mark.parametrize("promoted_type,expected_prefix", [
        ("Clickjacking_Exploitable", "clickjacking_"),
        ("HSTS_Downgrade_Exploitable", "hsts_downgrade_"),
        ("MIME_Confusion_Exploitable", "mime_confusion_"),
        ("Referrer_Leak_Exploitable", "referrer_leak_"),
        ("Permissions_Policy_Abuse", "permissions_abuse_"),
    ])
    def test_each_promoted_type_produces_poc(self, promoted_type, expected_prefix):
        with tempfile.TemporaryDirectory() as d:
            generate_pocs(
                [{"type": promoted_type, "url": "https://target.tld/"}],
                d,
            )
            assert any(f.startswith(expected_prefix) for f in _pocs_in(d)), \
                f"{promoted_type} did not produce a {expected_prefix} PoC"

    def test_mixed_batch_produces_all_pocs(self):
        """A realistic batch with both Missing_Security_Header *and* promoted
        findings should still produce one PoC per unique (kind, url)."""
        with tempfile.TemporaryDirectory() as d:
            generate_pocs(
                [
                    {"type": "Clickjacking_Exploitable", "url": "https://x/a"},
                    {"type": "HSTS_Downgrade_Exploitable", "url": "https://x/b"},
                    {"type": "Missing_Security_Header", "url": "https://x/c",
                     "param": "Referrer-Policy", "poc_kind": "referrer_leak"},
                    {"type": "Permissions_Policy_Abuse", "url": "https://x/d"},
                ],
                d,
            )
            files = _pocs_in(d)
            assert any(f.startswith("clickjacking_") for f in files)
            assert any(f.startswith("hsts_downgrade_") for f in files)
            assert any(f.startswith("referrer_leak_") for f in files)
            assert any(f.startswith("permissions_abuse_") for f in files)

    def test_promoted_and_legacy_on_same_url_deduped(self):
        """A finding with both the legacy Missing_Security_Header form and
        the promoted form on the same URL should only emit one PoC per kind."""
        with tempfile.TemporaryDirectory() as d:
            generate_pocs(
                [
                    {"type": "Missing_Security_Header", "url": "https://x/",
                     "param": "X-Frame-Options", "poc_kind": "clickjacking"},
                    {"type": "Clickjacking_Exploitable", "url": "https://x/"},
                ],
                d,
            )
            clickjacking_files = [
                f for f in _pocs_in(d) if f.startswith("clickjacking_")
            ]
            assert len(clickjacking_files) == 1


class TestCSPBypassDispatch:
    def test_csp_bypass_produces_csp_xss_poc(self):
        with tempfile.TemporaryDirectory() as d:
            generate_pocs(
                [{"type": "CSP_Bypass", "url": "https://x/", "weakness": "missing_csp"}],
                d,
            )
            files = _pocs_in(d)
            assert any(f.startswith("csp_xss_") for f in files), files
