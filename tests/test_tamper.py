"""
Tests for utils/tamper.py — Tamper Script Engine
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.tamper import (
    TamperChain,
    BUILTIN_TAMPERS,
    list_tampers,
    _space2comment,
    _randomcase,
    _doubleurlencode,
    _nullbyte,
    _charencode,
    _base64encode,
    _commentbeforeparentheses,
    _concat,
    _multiline,
)


class TestBuiltinTampers:
    """Test individual tamper functions."""

    def test_space2comment(self):
        assert _space2comment("SELECT * FROM users") == "SELECT/**/*/**/FROM/**/users"

    def test_randomcase(self):
        result = _randomcase("select")
        assert result.lower() == "select"
        assert len(result) == 6

    def test_doubleurlencode(self):
        result = _doubleurlencode("<script>")
        assert "<" not in result
        assert "%" in result

    def test_nullbyte(self):
        assert _nullbyte("../../etc/passwd") == "../../etc/passwd%00"

    def test_charencode(self):
        result = _charencode("abc")
        assert result == "CHAR(97,98,99)"

    def test_base64encode(self):
        result = _base64encode("test")
        assert result == "dGVzdA=="

    def test_commentbeforeparentheses(self):
        assert _commentbeforeparentheses("SLEEP(5)") == "SLEEP/**/(5)"

    def test_concat(self):
        result = _concat("admin")
        assert "||" in result

    def test_multiline(self):
        result = _multiline("SELECT * FROM users")
        assert "\n" in result


class TestTamperChain:
    """Test TamperChain class."""

    def test_empty_chain(self):
        chain = TamperChain()
        assert not chain.active
        assert chain.apply("test") == "test"

    def test_single_tamper(self):
        chain = TamperChain(["space2comment"])
        assert chain.active
        assert "/**/" in chain.apply("SELECT * FROM users")

    def test_multiple_tampers(self):
        chain = TamperChain(["space2comment", "nullbyte"])
        result = chain.apply("SELECT * FROM users")
        assert "/**/" in result
        assert "%00" in result

    def test_apply_list_adds_variants(self):
        chain = TamperChain(["nullbyte"])
        original = ["../../etc/passwd", "../etc/shadow"]
        result = chain.apply_list(original)
        # Should contain originals + tampered
        assert len(result) > len(original)
        assert "../../etc/passwd" in result
        assert "../../etc/passwd%00" in result

    def test_apply_list_no_duplicates(self):
        chain = TamperChain(["space2comment"])
        # Payload without spaces won't change
        original = ["nospaces"]
        result = chain.apply_list(original)
        assert len(result) == 1  # No duplicate added

    def test_all_keyword(self):
        chain = TamperChain(["all"])
        assert chain.active
        assert len(chain.functions) == len(BUILTIN_TAMPERS)

    def test_invalid_tamper_name(self):
        chain = TamperChain(["nonexistent_tamper_xyz"])
        assert not chain.active

    def test_chain_preserves_originals(self):
        chain = TamperChain(["base64encode"])
        original = ["<script>alert(1)</script>"]
        result = chain.apply_list(original)
        assert original[0] in result  # Original preserved


class TestTamperRegistry:
    """Test tamper registry and listing."""

    def test_minimum_builtin_count(self):
        assert len(BUILTIN_TAMPERS) >= 15

    def test_all_have_required_fields(self):
        for name, info in BUILTIN_TAMPERS.items():
            assert "fn" in info, f"{name} missing fn"
            assert "tags" in info, f"{name} missing tags"
            assert "description" in info, f"{name} missing description"
            assert callable(info["fn"]), f"{name} fn not callable"

    def test_list_tampers_all(self):
        result = list_tampers()
        assert len(result) >= 15

    def test_list_tampers_by_tag(self):
        sqli_tampers = list_tampers(tag="sqli")
        xss_tampers = list_tampers(tag="xss")
        assert len(sqli_tampers) >= 5
        assert len(xss_tampers) >= 3

    def test_list_tampers_lfi_tag(self):
        lfi_tampers = list_tampers(tag="lfi")
        assert len(lfi_tampers) >= 2
        names = [t["name"] for t in lfi_tampers]
        assert "nullbyte" in names
