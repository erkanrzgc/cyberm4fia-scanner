"""Concurrent per-page module specs."""

from __future__ import annotations

from .types import AsyncModuleSpec

def _load_xss():
    from modules.xss import scan_xss

    return scan_xss


def _load_sqli():
    from modules.sqli import scan_sqli

    return scan_sqli


def _load_lfi():
    from modules.lfi import async_scan_lfi

    return async_scan_lfi


def _load_rfi():
    from modules.rfi import scan_rfi

    return scan_rfi


def _load_cmdi():
    from modules.cmdi import async_scan_cmdi

    return async_scan_cmdi


def _load_ssrf():
    from modules.ssrf import async_scan_ssrf

    return async_scan_ssrf


def _load_ssti():
    from modules.ssti import async_scan_ssti

    return async_scan_ssti


def _load_xxe():
    from modules.xxe import async_scan_xxe

    return async_scan_xxe


def _load_dom_xss():
    from modules.dom_xss import scan_dom_xss

    return scan_dom_xss


def _load_templates():
    from modules.template_engine import run_templates

    return run_templates


ASYNC_MODULES = (
    AsyncModuleSpec(
        id="xss",
        option_key="xss",
        name="XSS",
        phase="page_scan",
        requires_forms=True,
        loader=_load_xss,
        args_factory=lambda scan_url, forms, delay, options: (scan_url, forms, delay),
    ),
    AsyncModuleSpec(
        id="sqli",
        option_key="sqli",
        name="SQLi",
        phase="page_scan",
        requires_forms=True,
        loader=_load_sqli,
        args_factory=lambda scan_url, forms, delay, options: (scan_url, forms, delay, options),
    ),
    AsyncModuleSpec(
        id="lfi",
        option_key="lfi",
        name="LFI",
        phase="page_scan",
        requires_forms=True,
        loader=_load_lfi,
        args_factory=lambda scan_url, forms, delay, options: (scan_url, forms, delay, options),
    ),
    AsyncModuleSpec(
        id="rfi",
        option_key="rfi",
        name="RFI",
        phase="page_scan",
        requires_forms=True,
        loader=_load_rfi,
        args_factory=lambda scan_url, forms, delay, options: (scan_url, forms, delay), # doesn't need context yet
    ),
    AsyncModuleSpec(
        id="cmdi",
        option_key="cmdi",
        name="CMDi",
        phase="page_scan",
        requires_forms=True,
        loader=_load_cmdi,
        args_factory=lambda scan_url, forms, delay, options: (scan_url, forms, delay, options),
    ),
    AsyncModuleSpec(
        id="ssrf",
        option_key="ssrf",
        name="SSRF",
        phase="page_scan",
        requires_forms=True,
        loader=_load_ssrf,
        args_factory=lambda scan_url, forms, delay, options: (scan_url, forms, delay), # doesn't need context yet
    ),
    AsyncModuleSpec(
        id="ssti",
        option_key="ssti",
        name="SSTI",
        phase="page_scan",
        requires_forms=False,
        loader=_load_ssti,
        args_factory=lambda scan_url, forms, delay, options: (scan_url, delay), # Doesn't currently accept forms
    ),
    AsyncModuleSpec(
        id="xxe",
        option_key="xxe",
        name="XXE",
        phase="page_scan",
        requires_forms=False,
        loader=_load_xxe,
        args_factory=lambda scan_url, forms, delay, options: (scan_url, delay),
    ),
    AsyncModuleSpec(
        id="dom_xss",
        option_key="dom_xss",
        name="DOM-XSS",
        phase="browser_scan",
        requires_forms=False,
        loader=_load_dom_xss,
        args_factory=lambda scan_url, forms, delay, options: (scan_url,),
    ),
    AsyncModuleSpec(
        id="templates",
        option_key="templates",
        name="Templates",
        phase="template_scan",
        requires_forms=False,
        loader=_load_templates,
        args_factory=lambda scan_url, forms, delay, options: (scan_url, delay),
    ),
)
