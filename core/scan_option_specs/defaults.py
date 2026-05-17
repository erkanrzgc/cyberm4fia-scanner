"""Scan option defaults, derived option-key sets, and profile presets."""

from __future__ import annotations

import os

# Defensive .env load. utils.request also calls load_dotenv(); multiple calls
# are idempotent and this guards against future import-order changes.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from core.module_registry import ASYNC_MODULES, PHASE_MODULES
from utils.request import get_default_timeout, get_path_blacklist

DEFAULT_AI_MODEL = "meta/llama-3.3-70b-instruct"
# Read from env. Never hardcode an API key in source — keys committed to git
# are leaked permanently in history. Set NVIDIA_API_KEY in .env or your shell.
DEFAULT_NVIDIA_API_KEY = os.environ.get("NVIDIA_API_KEY", "")


SCAN_OPTION_DEFAULTS = {
    "recon": False,
    "subdomain": False,
    "fuzz": False,
    "crawl": False,
    "xss": False,
    "sqli": False,
    "lfi": False,
    "rfi": False,
    "cmdi": False,
    "dom_xss": False,
    "secrets": False,
    "oob": False,
    "ssrf": False,
    "csrf": False,
    "cors": False,
    "header_inject": False,
    "templates": False,
    "cloud": False,
    "takeover": False,
    "tech": False,
    "api_scan": False,
    "api_spec": "",
    "ssti": False,
    "xxe": False,
    "redirect": False,
    "spray": False,
    "email": False,
    "passive": False,
    "jwt": False,
    "race": False,
    "smuggle": False,
    "proto": False,
    "deser": False,
    "bizlogic": False,
    "forbidden_bypass": False,
    "file_upload": False,
    "ato": False,
    "auth_bypass": False,
    "osint": False,
    "chain": False,
    "wordlist": False,
    "headless": False,
    "har_output": False,
    "exploit": False,
    "cookie": "",
    "tamper": "",
    "proxy_url": "",
    "scope": "",
    "exclude": "",
    "session": "",
    "resume": "",
    "max_requests": 0,
    "request_timeout": get_default_timeout(),
    "max_host_concurrency": 0,
    "path_blacklist": ",".join(get_path_blacklist()),
    "wordlist_file": "wordlists/api_endpoints.txt",
    "json_output": False,
    "html": False,
    "sarif": False,
    "threads": 10,
    "ai": False,
    "ai_model": DEFAULT_AI_MODEL,
    "nvidia_api_key": DEFAULT_NVIDIA_API_KEY,
    "agent": False,
    "agent_mode": "legacy",
    "auth_flow": None,
    "auth_url": "",
    "auth_form_url": "",
    "auth_fields": "",
    "auth_success": "",
    "accounts": "",
    "brute": False,
    "sploitus": False,
    "history": False,
    "proxy_listen": False,
    "dorking": False,
    "wayback": False,
    "urlscan": False,
    "rotate_proxy": False,
    "nuclei": False,
    "asset_search": False,
    "git_history": False,
    "git_history_path": "",
}

BOOL_OPTION_KEYS = frozenset(
    key for key, value in SCAN_OPTION_DEFAULTS.items() if isinstance(value, bool)
)

REGISTRY_OPTION_KEYS = frozenset(
    [spec.option_key for spec in ASYNC_MODULES if spec.option_key]
    + [spec.option_key for spec in PHASE_MODULES if spec.option_key]
)

ALL_ENABLED_OPTION_KEYS = frozenset(
    REGISTRY_OPTION_KEYS
    | {
        "recon",
        "fuzz",
        "crawl",
        "secrets",
        "oob",
        "csrf",
        "tech",
        "osint",
        "headless",
        "html",
        "passive",
        "dorking",
        "wayback",
        "urlscan",
        "nuclei",
        "asset_search",
        "git_history",
    }
) - {"wordlist", "sarif", "ai", "proxy_listen", "exploit"}

API_MODULE_OPTION_KEYS = (
    REGISTRY_OPTION_KEYS | {"recon"}
) - {"html", "sarif", "ai"}

PROFILE_PRESETS = {
    "1": frozenset({"recon", "subdomain", "fuzz", "tech", "passive"}),
    "2": frozenset(
        {"xss", "sqli", "lfi", "rfi", "cmdi", "csrf", "cors", "header_inject", "passive", "dom_xss"}
    ),
    "3": frozenset(
        {
            "jwt",
            "deser",
            "ssti",
            "race",
            "proto",
            "ssrf",
            "bizlogic",
            "redirect",
            "smuggle",
            "xxe",
            "api_scan",
            "oob",
            "forbidden_bypass",
            "file_upload",
            "ato",
            "auth_bypass",
        }
    ),
    "4": ALL_ENABLED_OPTION_KEYS,
    # Profile 6 — Web Recon + Audit (OctoScan `web` chain analogue)
    # Tech intel + nuclei community templates + endpoint discovery + asset
    # search across 7 OSINT providers + passive checks. Useful as a
    # focused-but-noisy follow-up to Profile 1.
    "6": frozenset({
        "recon", "subdomain", "tech", "fuzz", "crawl",
        "nuclei", "asset_search", "passive",
        "csp_bypass", "cookie", "cors", "header_inject",
    }),
}
