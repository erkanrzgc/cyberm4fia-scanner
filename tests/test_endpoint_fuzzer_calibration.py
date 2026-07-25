"""Tests for the strengthened modules.endpoint_fuzzer calibration logic.

Replays the narinkaucuk.com.tr pattern: a SPA returns its homepage template
(with the requested URL embedded in <base href>) for every unknown path. The
new fingerprint-aware calibration must mark all such hits as soft-404.
"""

from __future__ import annotations

import asyncio

import pytest

from modules.endpoint_fuzzer import EndpointFuzzer, _CALIBRATION_TEMPLATES

pytestmark = pytest.mark.unit


HOMEPAGE_TPL = """<!doctype html><html><head>
<title>SiteName</title>
<base href="{url}">
<link rel="canonical" href="{url}">
</head><body><nav>home about products</nav>
<section class="hero">Welcome</section>
<footer>(c) 2026</footer></body></html>"""


class _FakeResp:
    def __init__(self, status: int, body: str, headers: dict | None = None):
        self.status_code = status
        self.text = body
        self.headers = headers or {"Content-Type": "text/html"}


class _SPAFakeClient:
    """Every request returns 200 + the homepage template embedding the URL."""

    async def get(self, url):
        return _FakeResp(200, HOMEPAGE_TPL.format(url=url))


class _WellBehavedClient:
    """Returns 404 for unknown paths — no soft-404."""

    async def get(self, url):
        if url.endswith("/"):
            return _FakeResp(200, "<html><head><title>Real</title></head><body>OK</body></html>")
        return _FakeResp(404, "<html><body>not found</body></html>")


def _fuzzer():
    # Use /dev/null as wordlist; we only need calibration logic
    return EndpointFuzzer("http://example.com", "/dev/null")


class TestCalibration:
    def test_calibration_runs_all_templates(self):
        f = _fuzzer()
        asyncio.run(f._calibrate(_SPAFakeClient()))
        # 8 template probes + 1 homepage probe = up to 9 baseline fingerprints
        assert len(f.soft_404_baseline.fingerprints) >= len(_CALIBRATION_TEMPLATES)

    def test_spa_fallback_endpoint_marked_soft_404(self):
        f = _fuzzer()
        asyncio.run(f._calibrate(_SPAFakeClient()))
        resp = _FakeResp(200, HOMEPAGE_TPL.format(url="http://example.com/wp-admin/"))
        assert f._is_soft_404(resp) is True

    def test_real_different_page_not_soft_404(self):
        f = _fuzzer()
        asyncio.run(f._calibrate(_SPAFakeClient()))
        real = _FakeResp(
            200,
            "<html><head><title>Bayi Girisi</title></head><body><form><input></form></body></html>",
        )
        assert f._is_soft_404(real) is False

    def test_well_behaved_target_no_baseline(self):
        f = _fuzzer()
        asyncio.run(f._calibrate(_WellBehavedClient()))
        # Homepage probe returned 200 once but real 404s came back — baseline
        # may still contain the homepage; whatever it contains, a real 404
        # response shouldn't be flagged as soft-404 because its status is 404.
        not_found = _FakeResp(404, "<html><body>nope</body></html>")
        assert f._is_soft_404(not_found) is False


class TestLegacySignaturesPreserved:
    def test_length_signatures_still_populated(self):
        """External callers may still read soft_404_signatures."""
        f = _fuzzer()
        asyncio.run(f._calibrate(_SPAFakeClient()))
        assert len(f.soft_404_signatures) >= len(_CALIBRATION_TEMPLATES) - 1
