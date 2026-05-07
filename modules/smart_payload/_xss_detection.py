"""XSS Smart Payload — probe constants + 4-layer detection helpers.

This module groups the XSS probe primitives that operate on response
text:

  Layer 1 — context detection (where does the input land?)
  Layer 2 — character-filter detection (which special chars survive?)
  Layer 3 — keyword-filter detection (which words are stripped?)
  Layer 4 — WAF detection / syntax fuzzing (which HTML structures drop?)
"""

from __future__ import annotations

import re

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

# WAF syntax-fuzz probes — detect exactly which HTML structures the WAF blocks
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
    bad_tags = ["title", "textarea", "iframe", "noscript", "noembed", "template", "xmp"]
    temp_before = before_lower
    while True:
        last_open_bracket = temp_before.rfind("<")
        if last_open_bracket == -1:
            break

        if temp_before[last_open_bracket : last_open_bracket + 2] == "</":
            temp_before = temp_before[:last_open_bracket]
            continue

        match = re.match(r"<([a-z0-9]+)", temp_before[last_open_bracket:])
        if match:
            found_tag = match.group(1)
            if found_tag in bad_tags:
                return {"type": "HTML_BODY", "bad_tag": found_tag}
            break

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
# KEYWORD FILTER DETECTION (Layer 3)
# ══════════════════════════════════════════

def _detect_keyword_filters(response_text, probe):
    """Detect which XSS keywords are filtered/stripped."""
    allowed = {}
    for keyword, keyword_probe in KEYWORD_PROBES.items():
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
# WAF DETECTION
# ══════════════════════════════════════════

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
