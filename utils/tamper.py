"""
cyberm4fia-scanner — Tamper Script Engine

sqlmap-style payload transformation system for WAF bypass.
Each tamper script is a Python file with a tamper(payload) function
that transforms the payload to evade filters.

Usage:
    python3 scanner.py -u https://target.com --xss --tamper space2comment,randomcase
    python3 scanner.py -u https://target.com --sqli --tamper all

Built-in tampers are in payloads/tampers/*.py
Custom tampers can be added to the same directory.
"""

import os
import importlib.util
from utils.colors import log_info, log_warning, log_success
from utils.request import ScanExceptions


# ──────────────────────────────────────────────
#  Built-in Tamper Functions
# ──────────────────────────────────────────────


def _space2comment(payload: str) -> str:
    """Replace spaces with inline comments /**/"""
    return payload.replace(" ", "/**/")


def _space2plus(payload: str) -> str:
    """Replace spaces with + signs"""
    return payload.replace(" ", "+")


def _space2tab(payload: str) -> str:
    """Replace spaces with tab characters"""
    return payload.replace(" ", "\t")


def _randomcase(payload: str) -> str:
    """Randomly change character case: SeLeCt → bypass case-sensitive filters"""
    import random

    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)


def _doubleurlencode(payload: str) -> str:
    """Double URL-encode special characters"""
    from urllib.parse import quote

    return quote(quote(payload, safe=""), safe="")


def _urlencode(payload: str) -> str:
    """URL-encode the entire payload"""
    from urllib.parse import quote

    return quote(payload, safe="")


def _htmlencode(payload: str) -> str:
    """HTML entity encode: < → &lt; (useful for stored XSS in attributes)"""
    replacements = {
        "<": "&#60;",
        ">": "&#62;",
        '"': "&#34;",
        "'": "&#39;",
        "/": "&#47;",
    }
    for char, entity in replacements.items():
        payload = payload.replace(char, entity)
    return payload


def _unicodeencode(payload: str) -> str:
    """Unicode escape: < → \\u003c"""
    return "".join(f"\\u{ord(c):04x}" if not c.isalnum() else c for c in payload)


def _charencode(payload: str) -> str:
    """SQL CHAR() encoding: abc → CHAR(97,98,99)"""
    return "CHAR(" + ",".join(str(ord(c)) for c in payload) + ")"


def _between(payload: str) -> str:
    """Replace > with NOT BETWEEN 0 AND, = with BETWEEN X AND X (SQLi bypass)"""
    return payload.replace("=", " BETWEEN 1 AND 1--").replace(
        ">", " NOT BETWEEN 0 AND "
    )


def _concat(payload: str) -> str:
    """Break strings with concatenation: 'admin' → 'ad'||'min'"""
    if len(payload) > 4:
        mid = len(payload) // 2
        return f"'{payload[:mid]}'||'{payload[mid:]}'"
    return payload


def _commentbeforeparentheses(payload: str) -> str:
    """Insert comments before parentheses: SLEEP(5) → SLEEP/**/(5)"""
    return payload.replace("(", "/**/(")


def _nullbyte(payload: str) -> str:
    """Append null byte: bypass extension checks in LFI"""
    return payload + "%00"


def _appendnullbyte(payload: str) -> str:
    """Prepend and append null bytes"""
    return "%00" + payload + "%00"


def _base64encode(payload: str) -> str:
    """Base64 encode the payload"""
    import base64

    return base64.b64encode(payload.encode()).decode()


def _jsontamper(payload: str) -> str:
    """Wrap payload in JSON format for API testing"""
    return '{"input":"' + payload.replace('"', '\\"') + '"}'


def _multiline(payload: str) -> str:
    """Break payload across multiple lines (bypasses single-line regex filters)"""
    return payload.replace(" ", "\n")


# ──────────────────────────────────────────────
#  Registry
# ──────────────────────────────────────────────

BUILTIN_TAMPERS = {
    "space2comment": {
        "fn": _space2comment,
        "tags": ["sqli", "generic"],
        "description": "Replace spaces with /**/ comments",
    },
    "space2plus": {
        "fn": _space2plus,
        "tags": ["sqli", "generic"],
        "description": "Replace spaces with + signs",
    },
    "space2tab": {
        "fn": _space2tab,
        "tags": ["sqli", "generic"],
        "description": "Replace spaces with tab characters",
    },
    "randomcase": {
        "fn": _randomcase,
        "tags": ["sqli", "xss", "generic"],
        "description": "Randomly change character case",
    },
    "doubleurlencode": {
        "fn": _doubleurlencode,
        "tags": ["xss", "sqli", "lfi", "generic"],
        "description": "Double URL-encode special characters",
    },
    "urlencode": {
        "fn": _urlencode,
        "tags": ["xss", "sqli", "lfi", "generic"],
        "description": "URL-encode the entire payload",
    },
    "htmlencode": {
        "fn": _htmlencode,
        "tags": ["xss"],
        "description": "HTML entity encode special characters",
    },
    "unicodeencode": {
        "fn": _unicodeencode,
        "tags": ["xss", "generic"],
        "description": "Unicode escape non-alphanumeric characters",
    },
    "charencode": {
        "fn": _charencode,
        "tags": ["sqli"],
        "description": "Convert to SQL CHAR() encoding",
    },
    "between": {
        "fn": _between,
        "tags": ["sqli"],
        "description": "Replace = and > with BETWEEN syntax",
    },
    "concat": {
        "fn": _concat,
        "tags": ["sqli"],
        "description": "Break strings with || concatenation",
    },
    "commentbeforeparentheses": {
        "fn": _commentbeforeparentheses,
        "tags": ["sqli"],
        "description": "Insert /**/ before parentheses",
    },
    "nullbyte": {
        "fn": _nullbyte,
        "tags": ["lfi", "rfi"],
        "description": "Append %00 null byte",
    },
    "appendnullbyte": {
        "fn": _appendnullbyte,
        "tags": ["lfi", "rfi"],
        "description": "Prepend and append %00 null bytes",
    },
    "base64encode": {
        "fn": _base64encode,
        "tags": ["generic"],
        "description": "Base64 encode the payload",
    },
    "jsontamper": {
        "fn": _jsontamper,
        "tags": ["api", "generic"],
        "description": "Wrap payload in JSON format",
    },
    "multiline": {
        "fn": _multiline,
        "tags": ["generic"],
        "description": "Break payload across multiple lines",
    },
}


class TamperChain:
    """
    Chain of tamper functions to apply to payloads.

    Usage:
        chain = TamperChain(["space2comment", "randomcase"])
        tampered = chain.apply("SELECT * FROM users")
        # → "SeLeCt/**/*/FrOm/**/uSeRs"

        # Apply to entire payload list:
        tampered_list = chain.apply_list(["payload1", "payload2"])
    """

    def __init__(self, tamper_names: list = None):
        self.functions = []
        self.names = []

        if not tamper_names:
            return

        for name in tamper_names:
            name = name.strip().lower()

            if name == "all":
                # Load all built-in tampers
                for tname, tinfo in BUILTIN_TAMPERS.items():
                    self.functions.append(tinfo["fn"])
                    self.names.append(tname)
                break

            if name in BUILTIN_TAMPERS:
                self.functions.append(BUILTIN_TAMPERS[name]["fn"])
                self.names.append(name)
            else:
                # Try loading from payloads/tampers/ directory
                custom_fn = _load_custom_tamper(name)
                if custom_fn:
                    self.functions.append(custom_fn)
                    self.names.append(f"custom:{name}")
                else:
                    log_warning(f"Tamper script not found: {name}")

        if self.names:
            log_info(f"Tamper chain: {' → '.join(self.names)}")

    def apply(self, payload: str) -> str:
        """Apply all tamper functions in chain order."""
        for fn in self.functions:
            try:
                payload = fn(payload)
            except ScanExceptions:
                pass  # Skip failed tamper, use untampered
        return payload

    def apply_list(self, payloads: list) -> list:
        """
        Apply tamper chain to a list of payloads.
        Returns BOTH original and tampered versions for maximum coverage.
        """
        if not self.functions:
            return payloads

        result = list(payloads)  # Keep originals
        seen = set(payloads)

        for payload in payloads:
            tampered = self.apply(payload)
            if tampered not in seen:
                result.append(tampered)
                seen.add(tampered)

        log_success(
            f"Tamper: {len(payloads)} → {len(result)} payloads (+{len(result) - len(payloads)} variants)"
        )
        return result

    @property
    def active(self) -> bool:
        """Whether any tamper scripts are loaded."""
        return len(self.functions) > 0


def _load_custom_tamper(name: str):
    """Load a custom tamper script from payloads/tampers/ directory."""
    tamper_dir = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "payloads", "tampers"
    )
    tamper_file = os.path.join(tamper_dir, f"{name}.py")

    if not os.path.isfile(tamper_file):
        return None

    try:
        spec = importlib.util.spec_from_file_location(f"tamper_{name}", tamper_file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        if hasattr(module, "tamper"):
            log_info(f"Loaded custom tamper: {name}")
            return module.tamper
        else:
            log_warning(f"Custom tamper {name}.py has no tamper() function")
            return None
    except ScanExceptions as e:
        log_warning(f"Failed to load custom tamper {name}: {e}")
        return None


def list_tampers(tag: str = None) -> list:
    """List available tamper scripts, optionally filtered by tag."""
    results = []
    for name, info in BUILTIN_TAMPERS.items():
        if tag and tag not in info["tags"]:
            continue
        results.append(
            {
                "name": name,
                "tags": info["tags"],
                "description": info["description"],
            }
        )
    return results


# Global tamper chain (set by scanner.py at startup)
_active_chain = TamperChain()


def get_tamper_chain() -> TamperChain:
    """Get the currently active tamper chain."""
    return _active_chain


def set_tamper_chain(chain: TamperChain):
    """Set the active tamper chain."""
    global _active_chain
    _active_chain = chain
