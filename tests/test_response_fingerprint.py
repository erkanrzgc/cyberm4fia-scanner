"""Tests for utils.response_fingerprint.

Covers the SPA/catch-all detection that motivated the module: a site that
returns its homepage template for every unknown URL must be recognised as a
catch-all and discarded by the fuzzer.
"""

from __future__ import annotations

import pytest

from utils.response_fingerprint import (
    BaselineSet,
    ResponseFingerprint,
    compute_baseline_set,
    compute_fingerprint,
    compute_simhash_64,
    hamming_distance,
    is_similar,
)

pytestmark = pytest.mark.unit


HOMEPAGE = """<!doctype html><html><head>
<title>Narin Kauçuk</title>
<base href="https://www.narinkaucuk.com.tr/">
<link rel="canonical" href="https://www.narinkaucuk.com.tr/">
</head><body><nav>home about products bayi contact</nav>
<section class="hero">Welcome to Narin Kauçuk</section>
<footer>(c) 2026 narinkaucuk</footer></body></html>"""

# Same SPA template — only the URL inside <base href>/<canonical> changes.
SPA_FALLBACK = """<!doctype html><html><head>
<title>Narin Kauçuk</title>
<base href="https://www.narinkaucuk.com.tr/en/package.json">
<link rel="canonical" href="https://www.narinkaucuk.com.tr/en/package.json">
</head><body><nav>home about products bayi contact</nav>
<section class="hero">Welcome to Narin Kauçuk</section>
<footer>(c) 2026 narinkaucuk</footer></body></html>"""

# A genuinely different page with its own title + structure.
REAL_BAYI_PAGE = """<!doctype html><html><head>
<title>Bayi Girisi - Narin Kaucuk</title></head><body>
<form action="/bayi/login" method="post">
<input name="user"><input name="pass" type="password">
<button>Giris</button></form></body></html>"""


class TestFingerprintBasics:
    def test_fingerprint_fields_are_stable(self):
        fp1 = compute_fingerprint(HOMEPAGE)
        fp2 = compute_fingerprint(HOMEPAGE)
        assert fp1 == fp2

    def test_empty_body_does_not_raise(self):
        fp = compute_fingerprint("")
        assert fp.length == 0
        assert fp.simhash_64 == 0

    def test_content_type_is_captured(self):
        fp = compute_fingerprint(HOMEPAGE, {"Content-Type": "text/html; charset=utf-8"})
        assert "text/html" in fp.content_type

    def test_title_hash_matches_when_titles_identical(self):
        fp_home = compute_fingerprint(HOMEPAGE)
        fp_spa = compute_fingerprint(SPA_FALLBACK)
        assert fp_home.title_hash == fp_spa.title_hash

    def test_dom_skeleton_matches_when_tag_sequence_identical(self):
        fp_home = compute_fingerprint(HOMEPAGE)
        fp_spa = compute_fingerprint(SPA_FALLBACK)
        assert fp_home.dom_skeleton_hash == fp_spa.dom_skeleton_hash


class TestSimilarity:
    def test_spa_fallback_is_similar_to_homepage(self):
        fp_home = compute_fingerprint(HOMEPAGE)
        fp_spa = compute_fingerprint(SPA_FALLBACK)
        assert is_similar(fp_home, fp_spa) is True

    def test_real_different_page_is_not_similar(self):
        fp_home = compute_fingerprint(HOMEPAGE)
        fp_real = compute_fingerprint(REAL_BAYI_PAGE)
        assert is_similar(fp_home, fp_real) is False

    def test_identical_body_short_circuits(self):
        fp = compute_fingerprint(HOMEPAGE)
        assert is_similar(fp, fp) is True

    def test_different_title_blocks_similarity_even_when_length_close(self):
        a = "<html><head><title>One</title></head><body>" + "x" * 1000 + "</body></html>"
        b = "<html><head><title>Two</title></head><body>" + "x" * 1000 + "</body></html>"
        fa = compute_fingerprint(a)
        fb = compute_fingerprint(b)
        # Same tag skeleton would otherwise short-circuit; force a structural
        # difference so we exercise the title gate.
        fb_no_dom = ResponseFingerprint(
            length=fb.length,
            sha256=fb.sha256,
            title_hash=fb.title_hash,
            dom_skeleton_hash="zzz",
            simhash_64=fb.simhash_64,
        )
        fa_no_dom = ResponseFingerprint(
            length=fa.length,
            sha256=fa.sha256,
            title_hash=fa.title_hash,
            dom_skeleton_hash="qqq",
            simhash_64=fa.simhash_64,
        )
        assert is_similar(fa_no_dom, fb_no_dom) is False


class TestBaselineSet:
    def test_baseline_matches_spa_fallback(self):
        baseline = compute_baseline_set([(HOMEPAGE, {}), (SPA_FALLBACK, {})])
        fp_spa = compute_fingerprint(SPA_FALLBACK)
        assert baseline.matches(fp_spa) is True

    def test_baseline_rejects_real_page(self):
        baseline = compute_baseline_set([(HOMEPAGE, {}), (SPA_FALLBACK, {})])
        fp_real = compute_fingerprint(REAL_BAYI_PAGE)
        assert baseline.matches(fp_real) is False

    def test_empty_baseline_matches_nothing(self):
        baseline = BaselineSet(fingerprints=())
        assert baseline.matches(compute_fingerprint(REAL_BAYI_PAGE)) is False


class TestSimhash:
    def test_hamming_distance_self_is_zero(self):
        h = compute_simhash_64(HOMEPAGE)
        assert hamming_distance(h, h) == 0

    def test_small_change_keeps_distance_low(self):
        a = compute_simhash_64(HOMEPAGE)
        b = compute_simhash_64(HOMEPAGE.replace("Welcome", "Hosgeldiniz"))
        assert hamming_distance(a, b) <= 16  # template-similar pages stay close

    def test_unrelated_bodies_diverge(self):
        a = compute_simhash_64(HOMEPAGE)
        b = compute_simhash_64(REAL_BAYI_PAGE)
        assert hamming_distance(a, b) > 16
