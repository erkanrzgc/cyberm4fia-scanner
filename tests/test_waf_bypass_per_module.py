"""Tests for the per-module 3-tier WAF bypass entry points wired into
cmdi / lfi / ssrf / xxe.

Each module exposes a private ``_run_waf_bypass_chain_for_*`` that:
  1. Returns ``None`` when ``waf_detector.detected_waf`` is empty
     (conservative gate — never spend AI tokens on non-WAF targets).
  2. Delegates to ``utils.waf_evasion.apply_waf_bypass_chain`` and
     returns its finding.

These tests verify both branches without making real HTTP, AI, or
``apply`` calls.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlparse, parse_qs

import pytest


# ─────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────


def _params_for(url: str):
    parsed = urlparse(url)
    return parse_qs(parsed.query), parsed


def _stub_response(status: int = 403, text: str = "blocked") -> SimpleNamespace:
    return SimpleNamespace(status_code=status, text=text)


# ─────────────────────────────────────────────────────────────────────────
# CMDi
# ─────────────────────────────────────────────────────────────────────────


class TestCmdiWafBypassEntry:
    def test_returns_none_when_no_waf_detected(self):
        from modules.cmdi import _run_waf_bypass_chain_for_cmdi

        params, parsed = _params_for("http://example.com/?q=test")

        with patch("utils.waf.waf_detector") as waf:
            waf.detected_waf = ""
            assert _run_waf_bypass_chain_for_cmdi(params, parsed, delay=0) is None

    def test_delegates_to_chain_helper_when_waf_present(self):
        from modules.cmdi import _run_waf_bypass_chain_for_cmdi

        params, parsed = _params_for("http://example.com/?q=test")

        finding = {"type": "CMDi_Param", "param": "q"}

        with patch("utils.waf.waf_detector") as waf, \
             patch("modules.cmdi.smart_request", return_value=_stub_response()), \
             patch("utils.waf_evasion.apply_waf_bypass_chain", return_value=finding) as chain:
            waf.detected_waf = "Cloudflare"
            result = _run_waf_bypass_chain_for_cmdi(params, parsed, delay=0)

        assert result is finding
        assert chain.called
        kwargs = chain.call_args.kwargs
        assert kwargs["waf_name"] == "Cloudflare"
        assert kwargs["vuln_label"] == "Command Injection"
        assert kwargs["payload"] == "; id"


# ─────────────────────────────────────────────────────────────────────────
# LFI
# ─────────────────────────────────────────────────────────────────────────


class TestLfiWafBypassEntry:
    def test_returns_none_when_no_waf_detected(self):
        from modules.lfi import _run_waf_bypass_chain_for_lfi

        params, parsed = _params_for("http://example.com/?file=index.php")

        with patch("utils.waf.waf_detector") as waf:
            waf.detected_waf = ""
            assert _run_waf_bypass_chain_for_lfi(params, parsed, delay=0) is None

    def test_delegates_to_chain_helper_when_waf_present(self):
        from modules.lfi import _run_waf_bypass_chain_for_lfi

        params, parsed = _params_for("http://example.com/?file=index.php")

        finding = {"type": "LFI_Param", "param": "file"}

        with patch("utils.waf.waf_detector") as waf, \
             patch("modules.lfi.smart_request", return_value=_stub_response()), \
             patch("utils.waf_evasion.apply_waf_bypass_chain", return_value=finding) as chain:
            waf.detected_waf = "Akamai"
            result = _run_waf_bypass_chain_for_lfi(params, parsed, delay=0)

        assert result is finding
        kwargs = chain.call_args.kwargs
        assert kwargs["waf_name"] == "Akamai"
        assert kwargs["vuln_label"] == "LFI"
        assert "etc/passwd" in kwargs["payload"]


# ─────────────────────────────────────────────────────────────────────────
# SSRF
# ─────────────────────────────────────────────────────────────────────────


class TestSsrfWafBypassEntry:
    def test_returns_none_when_no_waf_detected(self):
        from modules.ssrf import _run_waf_bypass_chain_for_ssrf

        params, parsed = _params_for("http://example.com/?url=foo")

        with patch("utils.waf.waf_detector") as waf:
            waf.detected_waf = ""
            assert _run_waf_bypass_chain_for_ssrf(
                params, parsed, delay=0, baseline_text="", baseline_len=0
            ) is None

    def test_delegates_to_chain_helper_when_waf_present(self):
        from modules.ssrf import _run_waf_bypass_chain_for_ssrf

        params, parsed = _params_for("http://example.com/?url=foo")

        finding = {"type": "SSRF", "param": "url"}

        with patch("utils.waf.waf_detector") as waf, \
             patch("modules.ssrf.smart_request", return_value=_stub_response()), \
             patch("utils.waf_evasion.apply_waf_bypass_chain", return_value=finding) as chain:
            waf.detected_waf = "AWS WAF"
            result = _run_waf_bypass_chain_for_ssrf(
                params, parsed, delay=0, baseline_text="", baseline_len=0
            )

        assert result is finding
        kwargs = chain.call_args.kwargs
        assert kwargs["waf_name"] == "AWS WAF"
        assert kwargs["vuln_label"] == "SSRF"
        assert "169.254.169.254" in kwargs["payload"]


# ─────────────────────────────────────────────────────────────────────────
# XXE
# ─────────────────────────────────────────────────────────────────────────


class TestXxeWafBypassEntry:
    def test_returns_none_when_no_waf_detected(self):
        from modules.xxe import _run_waf_bypass_chain_for_xxe

        with patch("utils.waf.waf_detector") as waf:
            waf.detected_waf = ""
            assert _run_waf_bypass_chain_for_xxe(
                [{"url": "http://example.com/api"}], delay=0
            ) is None

    def test_delegates_to_chain_helper_when_waf_present(self):
        from modules.xxe import _run_waf_bypass_chain_for_xxe

        finding = {"type": "XXE", "kind": "linux-file-read"}

        with patch("utils.waf.waf_detector") as waf, \
             patch("modules.xxe.smart_request", return_value=_stub_response()), \
             patch("utils.waf_evasion.apply_waf_bypass_chain", return_value=finding) as chain:
            waf.detected_waf = "ModSecurity"
            result = _run_waf_bypass_chain_for_xxe(
                [{"url": "http://example.com/api"}], delay=0
            )

        assert result is finding
        kwargs = chain.call_args.kwargs
        assert kwargs["waf_name"] == "ModSecurity"
        assert kwargs["vuln_label"] == "XXE"
        # XXE must disable Tier-1 (auto-tamper) — XML body would corrupt.
        assert kwargs["enable_tamper"] is False


# ─────────────────────────────────────────────────────────────────────────
# Cross-module sanity: every entry honors the conservative gate
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("module_name,helper_name,extra_args", [
    ("modules.cmdi", "_run_waf_bypass_chain_for_cmdi", ()),
    ("modules.lfi", "_run_waf_bypass_chain_for_lfi", ()),
    ("modules.ssrf", "_run_waf_bypass_chain_for_ssrf", ("", 0)),  # baseline_text, baseline_len
])
def test_param_helpers_return_none_without_waf(module_name, helper_name, extra_args):
    """Pure regression guard: the conservative gate must never call into
    the chain helper when no specific WAF was fingerprinted."""
    import importlib

    module = importlib.import_module(module_name)
    helper = getattr(module, helper_name)
    params, parsed = _params_for("http://example.com/?q=test")

    with patch("utils.waf.waf_detector") as waf, \
         patch("utils.waf_evasion.apply_waf_bypass_chain") as chain:
        waf.detected_waf = ""
        result = helper(params, parsed, 0, *extra_args)

    assert result is None
    assert not chain.called
