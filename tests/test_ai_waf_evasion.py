"""Tests for utils/ai_waf_evasion — LLM-driven WAF evasion chains."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from utils.ai_waf_evasion import (
    EvasionResult,
    _parse_payload_array,
    ai_evasion_chain,
)


pytestmark = pytest.mark.unit


# ── Output parser ────────────────────────────────────────────────────────────


def test_parse_clean_json_array():
    raw = '["aaa", "bbb", "ccc"]'
    assert _parse_payload_array(raw) == ["aaa", "bbb", "ccc"]


def test_parse_array_wrapped_in_prose():
    raw = (
        "Here are five candidates that should bypass the filter:\n"
        '[" %3Cscript%3E ", "<scr%0aipt>", "<%73cript>", "<scrIPT>", "<scri\\u0070t>"]\n'
        "Use them in order of decreasing aggression."
    )
    out = _parse_payload_array(raw)
    assert len(out) == 5


def test_parse_extracts_array_even_when_wrapped_in_object():
    """If the model returns ``{"alternatives": [...]}`` we still extract the
    inner array. Pragmatic — real LLM outputs vary in framing."""
    out = _parse_payload_array('{"alternatives": ["a", "b"]}')
    assert out == ["a", "b"]


def test_parse_drops_non_string_entries():
    raw = '["good", 42, null, "also good"]'
    assert _parse_payload_array(raw) == ["good", "also good"]


def test_parse_empty_or_malformed_returns_list():
    assert _parse_payload_array("") == []
    assert _parse_payload_array("not even json") == []
    assert _parse_payload_array("[broken") == []


def test_parse_drops_overlong_entries():
    huge = "x" * 5_000
    raw = json.dumps(["normal", huge])
    assert _parse_payload_array(raw) == ["normal"]


# ── ai_evasion_chain end-to-end ──────────────────────────────────────────────


def _stub_ai_client(returns: str = "", available: bool = True):
    client = MagicMock()
    client.available = available
    client.generate.return_value = returns
    return client


def test_cache_hit_short_circuits_ai_call():
    cache = {}
    cache_key = "ai_waf_evasion::Cloudflare::PAYLOAD"
    cache[cache_key] = json.dumps(["alt1", "alt2", "alt3"])

    class DictCache:
        def __init__(self, store): self.store = store
        def get(self, k): return self.store.get(k)
        def set(self, k, v): self.store[k] = v

    ai = _stub_ai_client('["MUST_NOT_BE_USED"]')
    result = ai_evasion_chain(
        "PAYLOAD",
        waf_name="Cloudflare",
        blocked_response="blocked",
        ai_client=ai,
        cache=DictCache(cache),
    )
    assert result.cache_hit
    assert result.candidates == ["alt1", "alt2", "alt3"]
    ai.generate.assert_not_called()


def test_cache_miss_calls_ai_and_caches_result():
    cache_store: dict = {}

    class DictCache:
        def __init__(self, store): self.store = store
        def get(self, k): return self.store.get(k)
        def set(self, k, v): self.store[k] = v

    ai = _stub_ai_client(returns='["a", "b", "c", "d", "e"]')
    cache = DictCache(cache_store)
    result = ai_evasion_chain(
        "PAYLOAD",
        waf_name="AWS WAF",
        blocked_response="REQUEST BLOCKED",
        ai_client=ai,
        cache=cache,
    )
    assert not result.cache_hit
    assert result.candidates == ["a", "b", "c", "d", "e"]
    ai.generate.assert_called_once()
    # Cached for next lookup.
    assert cache_store["ai_waf_evasion::AWS WAF::PAYLOAD"]


def test_ai_unavailable_returns_empty():
    ai = _stub_ai_client(returns='["x"]', available=False)
    result = ai_evasion_chain("p", waf_name="W", ai_client=ai)
    assert result.candidates == []
    ai.generate.assert_not_called()


def test_no_ai_client_returns_empty():
    result = ai_evasion_chain("p", waf_name="W")
    assert result.candidates == []
    assert result.cache_hit is False


def test_ai_exception_is_absorbed():
    ai = MagicMock(available=True)
    ai.generate.side_effect = RuntimeError("upstream 500")
    result = ai_evasion_chain("p", waf_name="W", ai_client=ai)
    assert result.candidates == []


def test_garbage_ai_response_yields_no_candidates():
    ai = _stub_ai_client(returns="I refuse to answer this query.")
    result = ai_evasion_chain("p", waf_name="W", ai_client=ai)
    assert result.candidates == []


def test_limit_caps_returned_candidates():
    ai = _stub_ai_client(returns='["a","b","c","d","e","f","g","h"]')
    result = ai_evasion_chain("p", waf_name="W", ai_client=ai, limit=3)
    assert result.candidates == ["a", "b", "c"]


def test_truncation_protects_prompt_budget():
    """Very long blocked response should not crash the chain."""
    ai = _stub_ai_client(returns='["a","b","c","d","e"]')
    result = ai_evasion_chain(
        "p" * 1000,
        waf_name="W",
        blocked_response="x" * 10_000,
        ai_client=ai,
    )
    assert result.candidates == ["a", "b", "c", "d", "e"]
    args, kwargs = ai.generate.call_args
    # The prompt that reached the model must be smaller than the raw inputs.
    prompt_text = kwargs.get("prompt", "")
    assert len(prompt_text) < 11_000


def test_corrupt_cache_falls_back_to_ai():
    class BrokenCache:
        def get(self, k): raise IOError("disk failure")
        def set(self, k, v): pass

    ai = _stub_ai_client(returns='["a","b","c","d","e"]')
    result = ai_evasion_chain(
        "p", waf_name="W", ai_client=ai, cache=BrokenCache()
    )
    # The exception from cache.get is swallowed; AI was still called.
    assert result.candidates == ["a", "b", "c", "d", "e"]
    ai.generate.assert_called_once()
