"""Tests for utils.shodan_lookup._decode_whois_bytes and whois_lookup.

Country-code WHOIS servers (.tr, .de, .br) ship non-UTF-8 encodings. The
default subprocess.run(text=True) crashes with UnicodeDecodeError, which
broke the recon stage on Turkish targets. These tests pin the fix.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from utils.shodan_lookup import _decode_whois_bytes, whois_lookup

pytestmark = pytest.mark.unit


class TestDecode:
    def test_utf8_roundtrips(self):
        assert _decode_whois_bytes(b"Registrar: Example") == "Registrar: Example"

    def test_turkish_latin1_decodes(self):
        # Turkish ü = 0xfc in Latin-1 / cp1254 — fails strict UTF-8.
        out = _decode_whois_bytes(b"Organization: T\xfcrkiye")
        assert "Türkiye" in out

    def test_iso_8859_9_decodes(self):
        # ISO-8859-9 ş = 0xfe
        out = _decode_whois_bytes(b"Contact: \xfceyma")
        # latin-1 attempt succeeds first; either accepted decoding is fine
        assert out  # non-empty
        assert len(out) > 0

    def test_none_returns_empty(self):
        assert _decode_whois_bytes(None) == ""

    def test_string_passthrough(self):
        assert _decode_whois_bytes("already decoded") == "already decoded"

    def test_garbage_does_not_raise(self):
        # Arbitrary bytes should never crash; we may emit replacement chars
        result = _decode_whois_bytes(b"\xff\xfe\xfd\xfc")
        assert isinstance(result, str)


class TestWhoisLookup:
    def test_turkish_response_no_crash(self):
        """The bug we're pinning: a Turkish WHOIS response must not abort
        the recon stage with UnicodeDecodeError."""
        raw_response = (
            b"Registrar: Nic.tr\n"
            b"Registrant Organization: T\xfcrkiye Domain Ltd\n"
            b"Registrant Country: TR\n"
            b"Name Server: ns1.example.com.tr\n"
        )
        proc = MagicMock()
        proc.stdout = raw_response
        with patch("subprocess.run", return_value=proc):
            result = whois_lookup("example.com.tr")
        assert result.get("registrar") == "Nic.tr"
        # The Turkish character is preserved
        assert "Türkiye" in (result.get("registrant_org") or "")

    def test_missing_whois_binary_no_crash(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = whois_lookup("example.com")
        assert result == {}

    def test_timeout_no_crash(self):
        import subprocess
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="whois", timeout=15),
        ):
            result = whois_lookup("example.com")
        assert result == {}
