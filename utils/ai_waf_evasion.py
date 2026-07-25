"""LLM-driven WAF evasion — give the model a blocked payload, get back
five alternative encodings to try.

``utils.waf_evasion`` already ships rule-based transforms (Unicode
homoglyphs, chunked transfer, case mutation). When those run out we ask
the model: "this payload was blocked by {WAF}, here's the rejection
response — produce five alternative encodings that preserve the
semantics." Results are cached in :class:`utils.payload_memory` so we
don't burn tokens re-deriving the same chain twice.

Design constraints:

* **NVIDIA NIM only.** No alternate provider abstractions
  (project-wide rule).
* **Cache-first.** ``payload_memory`` lookup before the AI call —
  cheap and deterministic for repeated payload/WAF pairs.
* **Strict parsing.** Model output is expected as a JSON array of
  strings. We extract the array safely; anything malformed yields
  an empty list rather than raising.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


_SYSTEM_PROMPT = (
    "You are a web-app security expert specialised in WAF evasion. "
    "Given a payload that was blocked by a named WAF and the rejection "
    "response, return five alternative payloads that preserve the original "
    "semantics but bypass naive signature-based filters. Use techniques "
    "appropriate to the target context: URL encoding, double encoding, "
    "Unicode homoglyphs, comment insertion, case shuffling, whitespace "
    "tricks, character/keyword substitution. Reply with a JSON array of "
    "exactly five strings — no explanation, no fences, no trailing text."
)


_USER_TEMPLATE = (
    "PAYLOAD (blocked):\n{payload}\n\n"
    "WAF:\n{waf}\n\n"
    "REJECTION RESPONSE (truncated to 800 chars):\n{response}\n\n"
    "Produce the JSON array now."
)


def _truncate(text: str, limit: int = 800) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


_JSON_ARRAY_RE = re.compile(r"\[[\s\S]*\]")


def _parse_payload_array(raw: str) -> list[str]:
    """Extract a JSON array of strings from the model's output.

    The model sometimes wraps the JSON in stray prose / code fences;
    we strip those before parsing. Anything that isn't a list of strings
    of length 1..2000 each is discarded.
    """
    if not raw:
        return []
    match = _JSON_ARRAY_RE.search(raw)
    if not match:
        return []
    try:
        parsed = json.loads(match.group(0))
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    out: list[str] = []
    for entry in parsed:
        if not isinstance(entry, str):
            continue
        entry = entry.strip()
        if 1 <= len(entry) <= 2000:
            out.append(entry)
    return out


@dataclass
class EvasionResult:
    """One AI evasion call's outcome."""

    payload: str
    waf: str
    cache_hit: bool
    candidates: list[str] = field(default_factory=list)


def _cache_key(payload: str, waf: str) -> str:
    return f"ai_waf_evasion::{waf}::{payload}"


def ai_evasion_chain(
    payload: str,
    *,
    waf_name: str = "",
    blocked_response: str = "",
    ai_client: Any = None,
    cache: Any = None,
    temperature: float = 0.5,
    limit: int = 5,
) -> EvasionResult:
    """Request ``limit`` alternative payloads from the AI.

    Cache layer (when supplied) is queried first; on miss the AI is
    called and the response stored back. ``ai_client`` should expose
    a NVIDIA NIM-shaped ``generate(prompt, system=..., temperature=...)``
    method (``utils.ai.NvidiaApiClient``).
    """
    result = EvasionResult(payload=payload, waf=waf_name, cache_hit=False)

    if cache is not None:
        try:
            cached = cache.get(_cache_key(payload, waf_name))
        except Exception:  # noqa: BLE001
            cached = None
        if cached:
            try:
                payloads = json.loads(cached) if isinstance(cached, str) else list(cached)
            except (TypeError, ValueError):
                payloads = []
            if payloads:
                result.cache_hit = True
                result.candidates = [str(p) for p in payloads][:limit]
                return result

    if ai_client is None or not getattr(ai_client, "available", False):
        return result

    user_prompt = _USER_TEMPLATE.format(
        payload=_truncate(payload, 500),
        waf=waf_name or "unknown",
        response=_truncate(blocked_response, 800),
    )

    try:
        raw = ai_client.generate(
            prompt=user_prompt,
            system=_SYSTEM_PROMPT,
            temperature=temperature,
        )
    except Exception:  # noqa: BLE001
        return result

    candidates = _parse_payload_array(raw)[:limit]
    result.candidates = candidates

    if candidates and cache is not None:
        try:
            cache.set(_cache_key(payload, waf_name), json.dumps(candidates))
        except Exception:  # noqa: BLE001
            pass

    return result


__all__ = [
    "EvasionResult",
    "ai_evasion_chain",
    "_parse_payload_array",
]
