"""Tests for the expanded modules.poc_generator pipeline.

Verifies that each missing-header finding (CSP, XFO, HSTS, XCT, Referrer,
Permissions) produces the right PoC file, that the cookie-theft chain only
fires when both Insecure_Cookie and an XSS are present, and that the CSRF
PoC still works.
"""

from __future__ import annotations

import glob
import os
import tempfile

import pytest

from modules.poc_generator import generate_pocs

pytestmark = pytest.mark.unit


def _enriched_missing_header(url: str, header: str, poc_kind: str) -> dict:
    return {
        "type": "Missing_Security_Header",
        "url": url,
        "param": header,
        "poc_kind": poc_kind,
    }


def _pocs_in(d: str) -> list[str]:
    return sorted(
        os.path.basename(p) for p in glob.glob(os.path.join(d, "pocs", "*.html"))
    )


class TestHeaderPoCs:
    def test_csp_xss_poc(self):
        with tempfile.TemporaryDirectory() as d:
            generate_pocs(
                [_enriched_missing_header("http://x/login", "Content-Security-Policy", "csp_xss")],
                d,
            )
            files = _pocs_in(d)
            assert any(f.startswith("csp_xss_") for f in files), files

    def test_clickjacking_poc(self):
        with tempfile.TemporaryDirectory() as d:
            generate_pocs(
                [_enriched_missing_header("http://x/account", "X-Frame-Options", "clickjacking")],
                d,
            )
            files = _pocs_in(d)
            assert any(f.startswith("clickjacking_") for f in files), files

    def test_hsts_downgrade_poc(self):
        with tempfile.TemporaryDirectory() as d:
            generate_pocs(
                [_enriched_missing_header("https://x/login", "Strict-Transport-Security", "hsts_downgrade")],
                d,
            )
            files = _pocs_in(d)
            assert any(f.startswith("hsts_downgrade_") for f in files), files

    def test_mime_confusion_poc(self):
        with tempfile.TemporaryDirectory() as d:
            generate_pocs(
                [_enriched_missing_header("http://x/avatar", "X-Content-Type-Options", "mime_confusion")],
                d,
            )
            files = _pocs_in(d)
            assert any(f.startswith("mime_confusion_") for f in files), files

    def test_referrer_leak_poc(self):
        with tempfile.TemporaryDirectory() as d:
            generate_pocs(
                [_enriched_missing_header("http://x/reset", "Referrer-Policy", "referrer_leak")],
                d,
            )
            files = _pocs_in(d)
            assert any(f.startswith("referrer_leak_") for f in files), files

    def test_permissions_abuse_poc(self):
        with tempfile.TemporaryDirectory() as d:
            generate_pocs(
                [_enriched_missing_header("http://x/", "Permissions-Policy", "permissions_abuse")],
                d,
            )
            files = _pocs_in(d)
            assert any(f.startswith("permissions_abuse_") for f in files), files

    def test_unenriched_header_uses_lookup_fallback(self):
        """A finding from legacy code without ``poc_kind`` should still
        produce a PoC if the header is in HEADER_EXPLOIT_MAP."""
        with tempfile.TemporaryDirectory() as d:
            generate_pocs(
                [{"type": "Missing_Security_Header", "url": "http://x/", "param": "X-Frame-Options"}],
                d,
            )
            assert any(f.startswith("clickjacking_") for f in _pocs_in(d))


class TestChainedPoCs:
    def test_cookie_theft_only_with_xss(self):
        # Without XSS — no cookie theft PoC
        with tempfile.TemporaryDirectory() as d:
            generate_pocs(
                [{"type": "Insecure_Cookie", "url": "http://x/", "param": "PHPSESSID"}],
                d,
            )
            assert not any(f.startswith("cookie_theft_") for f in _pocs_in(d))

        # With XSS in same batch — cookie theft fires
        with tempfile.TemporaryDirectory() as d:
            generate_pocs(
                [
                    {"type": "Insecure_Cookie", "url": "http://x/", "param": "PHPSESSID"},
                    {"type": "XSS_Param", "url": "http://x/q", "payload": "<svg>"},
                ],
                d,
            )
            assert any(f.startswith("cookie_theft_") for f in _pocs_in(d))


class TestCsrfPoC:
    def test_csrf_emits_auto_submit_form(self):
        with tempfile.TemporaryDirectory() as d:
            generate_pocs(
                [
                    {
                        "type": "CSRF",
                        "url": "http://x/account/email",
                        "method": "POST",
                        "form_fields": {"email": "attacker@evil.tld"},
                    }
                ],
                d,
            )
            files = _pocs_in(d)
            assert any(f.startswith("csrf_") for f in files), files
            # Verify the form body actually contains an auto-submit
            poc_path = next(
                os.path.join(d, "pocs", f) for f in files if f.startswith("csrf_")
            )
            content = open(poc_path).read()
            assert "submit()" in content
            assert 'name="email"' in content


class TestDeduplication:
    def test_same_kind_same_url_only_once(self):
        with tempfile.TemporaryDirectory() as d:
            generate_pocs(
                [
                    _enriched_missing_header("http://x/", "X-Frame-Options", "clickjacking"),
                    _enriched_missing_header("http://x/", "X-Frame-Options", "clickjacking"),
                    _enriched_missing_header("http://x/", "X-Frame-Options", "clickjacking"),
                ],
                d,
            )
            files = [f for f in _pocs_in(d) if f.startswith("clickjacking_")]
            assert len(files) == 1


class TestEmptyInput:
    def test_no_findings_writes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            generate_pocs([], d)
            assert not os.path.exists(os.path.join(d, "pocs"))
