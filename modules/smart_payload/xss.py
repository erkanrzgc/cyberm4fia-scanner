"""XSS Smart Probe — public ``probe_xss_context`` orchestrator.

Drives the 4-layer XSS detection (context, char filter, keyword filter,
WAF syntax fuzz) and emits a list of context-targeted + mutation-bypass
payloads back to ``modules.xss``.
"""

from __future__ import annotations

from utils.colors import log_info, log_warning
from utils.request import ScanExceptions, smart_request

from ._xss_detection import (
    CHAR_PROBE,
    COMBINED_KEYWORD_PROBE,
    PROBE_STRING,
    WAF_FUZZES,
    _detect_char_filters,
    _detect_contexts,
    _detect_keyword_filters,
    _detect_waf,
)
from ._xss_payloads import _apply_mutations, _generate_payloads_for_context


def probe_xss_context(url, param, params, method="get", form_data=None, delay=0):
    """3-layer intelligent probe + WAF fuzzing + context-aware payload generation."""
    from urllib.parse import urlencode, urlparse, urlunparse

    result = {
        "contexts": [],
        "allowed_chars": {},
        "keyword_filters": {},
        "waf_blocks": {},
        "smart_payloads": [],
        "probe_reflected": False,
        "waf_detected": False,
    }

    def _send_probe(value):
        if method == "get":
            tp = params.copy()
            tp[param] = value
            parsed = urlparse(url)
            turl = urlunparse(parsed._replace(query=urlencode(tp)))
            return smart_request("get", turl, delay=delay)
        else:
            data = form_data.copy() if form_data else {}
            data[param] = value
            return smart_request("post", url, data=data, delay=delay)

    try:
        # ── Layer 1: Context Detection ──
        resp = _send_probe(PROBE_STRING)

        if _detect_waf(resp):
            result["waf_detected"] = True
            log_warning(f"  ⚠️  WAF detected for [{param}]!")

        if PROBE_STRING not in resp.text:
            return result

        result["probe_reflected"] = True
        contexts = _detect_contexts(resp.text, PROBE_STRING)
        result["contexts"] = contexts

        # ── Layer 2: Character Filter Detection ──
        resp2 = _send_probe(CHAR_PROBE)
        allowed = _detect_char_filters(resp2.text, PROBE_STRING)
        result["allowed_chars"] = allowed

        # ── Layer 3: Keyword Filter Detection ──
        resp3 = _send_probe(COMBINED_KEYWORD_PROBE)
        kw_allowed = _detect_keyword_filters(resp3.text, PROBE_STRING)
        result["keyword_filters"] = kw_allowed

        # ── Layer 4: WAF Syntax Fuzzing ──
        waf_blocks = {}
        if (
            result["waf_detected"]
            or not all(kw_allowed.values())
            or not allowed.get("lt", True)
        ):
            for fuzz_name, fuzz_payload in WAF_FUZZES.items():
                fuzz_resp = _send_probe(fuzz_payload)
                waf_blocks[fuzz_name] = _detect_waf(fuzz_resp)
        result["waf_blocks"] = waf_blocks

        # ── Generate Payloads ──
        all_payloads = []
        seen = set()

        for ctx in contexts:
            ctx_type = ctx["type"]
            base_payloads = _generate_payloads_for_context(
                ctx_type, ctx, allowed, kw_allowed, waf_blocks
            )
            for p in base_payloads:
                if p not in seen:
                    seen.add(p)
                    all_payloads.append(p)

        # ── Apply Mutations for blocked keywords ──
        mutations = _apply_mutations(all_payloads, kw_allowed)
        for m in mutations:
            if m not in seen:
                seen.add(m)
                all_payloads.append(m)

        result["smart_payloads"] = all_payloads

        # ── Logging ──
        if contexts:
            ctx_names = []
            for c in contexts:
                name = c["type"]
                if "tag" in c:
                    name += f" ({c['tag']})"
                if "bad_tag" in c:
                    name += f" [BAD_TAG: {c['bad_tag']}]"
                ctx_names.append(name)

            log_info(
                f"  🧠 Smart Probe [{param}]: "
                f"context={', '.join(ctx_names)} | "
                f"{len(all_payloads)} targeted payloads"
            )

            allowed_list = [n for n, ok in allowed.items() if ok]
            blocked_list = [n for n, ok in allowed.items() if not ok]
            if allowed_list:
                log_info(f"     ✅ Chars: {', '.join(allowed_list)}")
            if blocked_list:
                log_info(f"     ❌ Chars: {', '.join(blocked_list)}")

            kw_blocked = [n for n, ok in kw_allowed.items() if not ok]
            if kw_blocked:
                log_warning(f"     🚫 Keywords blocked: {', '.join(kw_blocked)}")
                log_info(f"     🔄 Generated {len(mutations)} mutation bypass payloads")

            syntax_blocked = [n for n, blocked in waf_blocks.items() if blocked]
            if syntax_blocked:
                log_warning(f"     🛡️  WAF Syntax Blocks: {', '.join(syntax_blocked)}")

    except ScanExceptions:
        pass  # Probe failure — fall back to static payloads

    return result
