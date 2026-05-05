"""Unit tests for utils.waf_evasion.apply_waf_bypass_chain.

The chain has three tiers (auto-tamper, AI evolution, protocol evasion).
We exercise every short-circuit path and the tier-by-tier fallthrough
without touching real WAFs, AI clients, or HTTP machinery.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from utils.waf_evasion import apply_waf_bypass_chain


def _resp(status: int = 403, text: str = "blocked by WAF") -> SimpleNamespace:
    """Return a stub response object with the attrs the chain reads."""
    return SimpleNamespace(status_code=status, text=text)


@pytest.fixture(autouse=True)
def _patch_logging():
    # Silence colored logging during the tests.
    with patch("utils.waf_evasion.__name__", "utils.waf_evasion"):
        yield


def _make_request_fn(responses_by_payload, calls):
    """Build a request_fn that records every call and replays canned responses.

    ``responses_by_payload`` keys may be exact payload strings *or* the
    sentinel ``"__evasion_{level}__"`` for Tier-3 calls.
    """
    def request_fn(payload, *, evasion_level=0):
        calls.append((payload, evasion_level))
        if evasion_level:
            return responses_by_payload.get(
                f"__evasion_{evasion_level}__", _resp(403, "still blocked")
            )
        return responses_by_payload.get(payload, _resp(403, "still blocked"))
    return request_fn


def test_tier1_autotamper_finds_finding():
    """Auto-tamper produces a vuln on the first tampered request."""
    calls = []
    finding = {"type": "XSS", "source": "tier1"}

    request_fn = _make_request_fn(
        {"TAMPERED(<svg>)": _resp(200, "alert ran")}, calls
    )

    def check_fn(response, payload, source):
        if source == "⚡ Auto-Tamper" and response.status_code == 200:
            return finding
        return None

    with patch("utils.waf.waf_detector") as waf, \
         patch("utils.tamper.TamperChain") as TamperChain:
        waf.get_recommended_tampers.return_value = ["space2comment"]
        waf.is_waf_block.return_value = False
        TamperChain.return_value.apply.side_effect = lambda p: f"TAMPERED({p})"

        result = apply_waf_bypass_chain(
            payload="<svg>",
            blocked_response=_resp(403, "blocked"),
            request_fn=request_fn,
            check_fn=check_fn,
            waf_name="Cloudflare",
            vuln_label="XSS",
        )

    assert result is finding
    assert calls == [("TAMPERED(<svg>)", 0)]


def test_no_recommended_tampers_skips_to_ai():
    """If waf_detector recommends nothing, Tier 1 is silently skipped and
    AI engine takes over."""
    calls = []
    found = {"type": "SQLi", "tier": "ai"}

    request_fn = _make_request_fn({"AI_PAYLOAD_1": _resp(200, "ok")}, calls)

    def check_fn(response, payload, source):
        if "AI Gen-1" in source and response.status_code == 200:
            return found
        return None

    with patch("utils.waf.waf_detector") as waf, \
         patch("utils.ai.get_ai") as get_ai_mock, \
         patch("utils.ai.EvolvingWAFBypassEngine") as Engine:
        waf.get_recommended_tampers.return_value = []
        waf.is_waf_block.return_value = True
        ai_client = SimpleNamespace(available=True)
        get_ai_mock.return_value = ai_client
        engine_instance = Engine.return_value
        engine_instance.mutate.return_value = ["AI_PAYLOAD_1"]

        result = apply_waf_bypass_chain(
            payload="' OR 1=1--",
            blocked_response=_resp(403, "WAF blocked"),
            request_fn=request_fn,
            check_fn=check_fn,
            waf_name="ModSecurity",
            vuln_label="SQL Injection",
        )

    assert result is found
    assert calls == [("AI_PAYLOAD_1", 0)]


def test_falls_through_to_protocol_evasion_level1():
    """Tier 1 + Tier 2 exhaust, Tier 3 (Unicode evasion) succeeds."""
    calls = []
    found = {"type": "XSS", "tier": "protocol"}

    request_fn = _make_request_fn(
        {
            "tampered": _resp(403, "blocked"),
            "__evasion_1__": _resp(200, "ok"),
        },
        calls,
    )

    def check_fn(response, payload, source):
        if source == "🛡️ Unicode Evasion" and response.status_code == 200:
            return found
        return None

    with patch("utils.waf.waf_detector") as waf, \
         patch("utils.tamper.TamperChain") as TamperChain, \
         patch("utils.ai.get_ai") as get_ai_mock:
        waf.get_recommended_tampers.return_value = ["base64encode"]
        # Always blocked → forces fall-through past tampers and AI.
        waf.is_waf_block.return_value = True
        TamperChain.return_value.apply.return_value = "tampered"
        get_ai_mock.return_value = None  # no AI available

        result = apply_waf_bypass_chain(
            payload="<script>",
            blocked_response=_resp(403, "blocked"),
            request_fn=request_fn,
            check_fn=check_fn,
            waf_name="Akamai",
            vuln_label="XSS",
        )

    assert result is found
    # tier-1 call + tier-3 level 1 call (level 2/3 not reached)
    assert ("tampered", 0) in calls
    assert ("<script>", 1) in calls
    assert all(level <= 1 for _p, level in calls)


def test_request_fn_without_evasion_level_short_circuits_tier3():
    """If request_fn doesn't accept evasion_level, the protocol tier
    breaks out cleanly instead of crashing."""
    calls = []

    def legacy_request_fn(payload):
        # NOTE: no evasion_level kwarg — TypeError on tier-3.
        calls.append(payload)
        return _resp(403, "still blocked")

    def check_fn(response, payload, source):
        return None

    with patch("utils.waf.waf_detector") as waf, \
         patch("utils.tamper.TamperChain") as TamperChain, \
         patch("utils.ai.get_ai") as get_ai_mock:
        waf.get_recommended_tampers.return_value = []
        waf.is_waf_block.return_value = True
        TamperChain.return_value.apply.return_value = "x"
        get_ai_mock.return_value = None

        result = apply_waf_bypass_chain(
            payload="orig",
            blocked_response=_resp(403, "blocked"),
            request_fn=legacy_request_fn,
            check_fn=check_fn,
            waf_name="None",
            vuln_label="XSS",
        )

    assert result is None  # no finding, no crash


def test_disabled_tiers_are_not_invoked():
    """All tiers off → returns None without calling request_fn."""
    calls = []

    def request_fn(payload, *, evasion_level=0):
        calls.append((payload, evasion_level))
        return _resp(200, "ok")

    def check_fn(*a, **kw):
        return None

    result = apply_waf_bypass_chain(
        payload="orig",
        blocked_response=_resp(403, "blocked"),
        request_fn=request_fn,
        check_fn=check_fn,
        waf_name="X",
        vuln_label="Y",
        enable_tamper=False,
        enable_ai=False,
        enable_protocol=False,
    )
    assert result is None
    assert calls == []


def test_initial_response_not_blocked_returns_early_after_tamper():
    """If the post-tamper response is no longer a WAF block, the chain
    bails out before AI/protocol tiers."""
    calls = []
    request_fn = _make_request_fn(
        {"tampered": _resp(200, "looks fine but no vuln")}, calls
    )

    def check_fn(response, payload, source):
        return None  # tamper hit didn't expose a vuln

    with patch("utils.waf.waf_detector") as waf, \
         patch("utils.tamper.TamperChain") as TamperChain:
        waf.get_recommended_tampers.return_value = ["t"]
        # First call (after tamper) -> no longer blocked -> early return
        waf.is_waf_block.return_value = False
        TamperChain.return_value.apply.return_value = "tampered"

        result = apply_waf_bypass_chain(
            payload="orig",
            blocked_response=_resp(403, "blocked"),
            request_fn=request_fn,
            check_fn=check_fn,
            waf_name="Cloudflare",
            vuln_label="XSS",
        )

    assert result is None
    # only the tier-1 call happened
    assert calls == [("tampered", 0)]
