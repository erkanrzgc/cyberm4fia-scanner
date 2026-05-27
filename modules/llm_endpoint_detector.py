"""LLM endpoint detector — find chatbot / completion / agent surfaces on a target.

Modern web apps embed LLM-powered features behind paths like ``/api/chat``,
``/v1/chat/completions``, ``/api/generate`` (Ollama), ``/api/v1/generate``
(vLLM). Detecting these is the prerequisite for routing the target into
``utils.external_tools.GarakTool`` for jailbreak / prompt-injection /
data-leakage probing.

Heuristic — no exploitation, just identification:

1. **Path probe** — issue ``POST {path} {"message": "ping"}`` /
   ``{"prompt": "ping"}`` / ``{"model":"...","messages":[...]}`` against a
   well-known catalogue of endpoints and look for OpenAI / Ollama / vLLM /
   Anthropic response shapes.
2. **Response shape match** — keys like ``choices[].message.content``,
   ``choices[].text``, ``model``, ``id`` starting with ``chatcmpl-``,
   ``response``, ``message.content``.
3. **Server / header fingerprint** — ``Server: vllm``, ``Server: tgi``,
   ``X-OpenAI-*``, ``X-AI-*``, ``Anthropic-*``, ``OpenAI-*``.
4. **HTML fingerprint** — script src / fetch URLs that point at OpenAI /
   Anthropic / Mistral / together.ai / replicate / api.cohere /
   build.nvidia.com, plus visible widget markers (Intercom / Drift /
   Crisp AI assistants).

Findings emit type ``LLM_Endpoint_Discovered`` so downstream stages can
route them into the garak adapter via ``--llm-probe``.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


# ── Catalogue of well-known LLM endpoint paths ─────────────────────────
_PROBE_PATHS = (
    "/v1/chat/completions",       # OpenAI compatible (Together, Groq, NIM, …)
    "/v1/completions",
    "/v1/messages",               # Anthropic Messages API
    "/api/chat",                  # generic / Vercel AI SDK
    "/api/chat/completions",
    "/api/v1/chat/completions",
    "/api/generate",              # Ollama
    "/api/v1/generate",           # vLLM
    "/generate",
    "/chat",
    "/chatbot",
    "/api/ai/chat",
    "/api/copilot",
    "/api/assistant",
    "/inference",
    "/api/inference",
    "/llm",
    "/api/llm",
)

# ── Sample request bodies — one per vendor flavour ─────────────────────
_PROBE_BODIES = [
    # OpenAI / NIM / Together / Groq / Mistral / Anthropic-compatible
    {"model": "test", "messages": [{"role": "user", "content": "ping"}]},
    # Ollama
    {"model": "test", "prompt": "ping"},
    # vLLM legacy completion
    {"prompt": "ping", "max_tokens": 4},
    # Generic chatbot
    {"message": "ping"},
    # Anthropic Messages API
    {"model": "claude-3", "messages": [{"role": "user", "content": "ping"}], "max_tokens": 4},
]

# Response-shape signatures (any one match is enough to confirm).
_RESPONSE_SIGNATURES = (
    "choices[*].message.content",
    "choices[*].text",
    "completion",
    "response",
    "generated_text",
    "content[*].text",  # Anthropic
    "data.response",
    "outputs[*].text",  # vLLM
)

# Header fingerprints — case-insensitive substring match against header name+value.
_HEADER_FINGERPRINTS = (
    ("server", "vllm"),
    ("server", "tgi"),
    ("server", "ollama"),
    ("server", "text-generation-inference"),
    ("server", "litellm"),
    ("x-openai-version", ""),
    ("x-anthropic-version", ""),
    ("openai-version", ""),
    ("openai-organization", ""),
    ("anthropic-version", ""),
    ("x-ai-", ""),
    ("x-model", ""),
)

# HTML body fingerprints — script tags / fetch URLs pointing at LLM providers.
_HTML_FINGERPRINTS = re.compile(
    r"(api\.openai\.com|api\.anthropic\.com|api\.mistral\.ai|api\.cohere\.ai|"
    r"api\.together\.xyz|api\.groq\.com|api\.replicate\.com|"
    r"integrate\.api\.nvidia\.com|api\.deepseek\.com|api\.perplexity\.ai|"
    r"intercom\.io.*ai|drift\.com.*ai|crisp\.chat.*ai)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class LLMEndpoint:
    """One detected LLM endpoint with supporting evidence."""

    url: str
    confidence: str        # "high" | "medium" | "low"
    evidence: str
    suggested_target_type: str  # garak --target_type hint


def _check_response_for_llm(body: str | None) -> tuple[bool, str]:
    if not body:
        return False, ""
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return False, ""

    # Walk a small set of well-known paths.
    if isinstance(data, dict):
        if "choices" in data and isinstance(data["choices"], list) and data["choices"]:
            first = data["choices"][0]
            if isinstance(first, dict) and ("message" in first or "text" in first):
                return True, "choices[].message|text"
        for key in ("completion", "response", "generated_text", "answer"):
            if key in data and isinstance(data[key], str):
                return True, f"flat key: {key}"
        if "content" in data and isinstance(data["content"], list) and data["content"]:
            # Anthropic Messages
            return True, "content[].text (Anthropic)"
        if "outputs" in data and isinstance(data["outputs"], list):
            return True, "outputs[].text (vLLM)"
        # Common OpenAI-compatible identifiers
        if isinstance(data.get("id"), str) and data["id"].startswith(("chatcmpl-", "cmpl-")):
            return True, "id prefix: chatcmpl-"
        if isinstance(data.get("object"), str) and data["object"] in (
            "chat.completion", "text_completion", "message",
        ):
            return True, f"object={data['object']}"
    return False, ""


def _check_headers_for_llm(headers: dict | None) -> tuple[bool, str]:
    if not headers:
        return False, ""
    lower = {k.lower(): str(v).lower() for k, v in headers.items()}
    for header_name, value_match in _HEADER_FINGERPRINTS:
        if header_name in lower:
            if not value_match or value_match in lower[header_name]:
                return True, f"{header_name}={lower[header_name][:40]}"
    return False, ""


def _check_html_for_llm(body: str | None) -> tuple[bool, str]:
    if not body:
        return False, ""
    m = _HTML_FINGERPRINTS.search(body)
    if m:
        return True, f"3rd-party LLM provider referenced: {m.group(0)}"
    return False, ""


def _probe_endpoint(target: str, path: str) -> LLMEndpoint | None:
    """Send each probe body to a candidate path and return the strongest match."""
    try:
        import httpx
    except ImportError:
        return None

    full_url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
    best: LLMEndpoint | None = None
    for body in _PROBE_BODIES:
        try:
            r = httpx.post(full_url, json=body, timeout=8.0, follow_redirects=False, verify=False)
        except Exception as exc:  # noqa: BLE001
            logger.debug("LLM probe %s failed: %s", full_url, exc)
            continue

        text = r.text or ""
        headers = dict(r.headers)

        # Strongest signal: response body looks like an LLM API response.
        is_llm_body, body_evidence = _check_response_for_llm(text)
        is_llm_header, header_evidence = _check_headers_for_llm(headers)

        if is_llm_body and is_llm_header:
            return LLMEndpoint(
                url=full_url, confidence="high",
                evidence=f"body shape ({body_evidence}) + header ({header_evidence})",
                suggested_target_type="rest",
            )
        if is_llm_body:
            best = LLMEndpoint(
                url=full_url, confidence="high",
                evidence=f"body shape: {body_evidence}",
                suggested_target_type="rest",
            )
        elif is_llm_header and best is None:
            best = LLMEndpoint(
                url=full_url, confidence="medium",
                evidence=f"header: {header_evidence}",
                suggested_target_type="rest",
            )
    return best


def detect_llm_endpoints(target_url: str, *, response_bodies: Iterable[str] = ()) -> list[LLMEndpoint]:
    """Find LLM endpoints on the target.

    ``response_bodies`` is an optional iterable of already-fetched HTML
    bodies (e.g. from the crawler) so the HTML fingerprint pass doesn't
    re-fetch.
    """
    endpoints: list[LLMEndpoint] = []

    # 1) Path probing
    seen_urls: set[str] = set()
    for path in _PROBE_PATHS:
        ep = _probe_endpoint(target_url, path)
        if ep and ep.url not in seen_urls:
            endpoints.append(ep)
            seen_urls.add(ep.url)

    # 2) HTML fingerprint (passive — uses caller-provided bodies)
    for body in response_bodies:
        ok, evidence = _check_html_for_llm(body)
        if ok:
            endpoints.append(LLMEndpoint(
                url=target_url, confidence="low",
                evidence=evidence,
                suggested_target_type="rest",
            ))
            break  # one HTML signal is enough; don't duplicate

    return endpoints


def endpoints_to_findings(endpoints: list[LLMEndpoint]) -> list[dict]:
    """Convert LLM endpoint discoveries into scanner finding dicts.

    These are *advisory* findings — severity info — that downstream stages
    use to route the URL into the garak adapter when ``--llm-probe`` is on.
    """
    out = []
    for ep in endpoints:
        out.append({
            "type": "LLM_Endpoint_Discovered",
            "url": ep.url,
            "severity": "INFO",
            "evidence": ep.evidence,
            "param": ep.suggested_target_type,
            "confidence": ep.confidence,
            "payload": "(advisory) consider --llm-probe to run garak against this endpoint",
            "module": "llm_endpoint_detector",
        })
    return out


def scan_llm_endpoints(target_url: str, *, response_bodies: Iterable[str] = ()) -> list[dict]:
    """Public entry point: returns finding dicts ready to merge into all_vulns."""
    return endpoints_to_findings(detect_llm_endpoints(target_url, response_bodies=response_bodies))
