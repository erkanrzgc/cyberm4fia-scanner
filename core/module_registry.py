"""
cyberm4fia-scanner - Module registry metadata and runners.
"""

from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


@dataclass(frozen=True)
class AsyncModuleSpec:
    """Metadata for concurrent per-page modules."""

    id: str
    option_key: str
    name: str
    phase: str
    requires_forms: bool
    loader: Callable[[], Callable]
    args_factory: Callable[[str, list, float, dict], tuple]

    def build_args(
        self,
        scan_url: str,
        forms: list,
        delay: float,
        options: dict | None = None,
    ) -> tuple:
        return self.args_factory(scan_url, forms, delay, options or {})


@dataclass(frozen=True)
class PhaseModuleSpec:
    """Metadata for scanner pipeline phases executed sequentially."""

    id: str
    option_key: str | None
    name: str
    phase: str
    requires_forms: bool
    collect_results: bool
    runner: Callable[[dict], Any]


_NOISE_QUERY_KEYS = {
    "_rsc",
    "__nextdatareq",
    "fbclid",
    "gclid",
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
}


def canonicalize_scan_url(url: str) -> str:
    """Normalize scan URLs to reduce duplicate work on fragments/noise params."""
    if not url:
        return url

    parsed = urlparse(url)
    query_pairs = [
        (key, value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        if key.lower() not in _NOISE_QUERY_KEYS
    ]
    query_pairs.sort()
    normalized = parsed._replace(
        query=urlencode(query_pairs, doseq=True),
        fragment="",
    )
    return urlunparse(normalized)


def canonicalize_scan_urls(urls: list[str]) -> list[str]:
    """Deduplicate scan URLs after canonicalization while preserving order."""
    seen = set()
    normalized = []

    for url in urls:
        candidate = canonicalize_scan_url(url)
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        normalized.append(candidate)

    return normalized


def _load_xss():
    from modules.xss import scan_xss

    return scan_xss


def _load_sqli():
    from modules.sqli import scan_sqli

    return scan_sqli


def _load_lfi():
    from modules.lfi import scan_lfi

    return scan_lfi


def _load_rfi():
    from modules.rfi import scan_rfi

    return scan_rfi


def _load_cmdi():
    from modules.cmdi import scan_cmdi

    return scan_cmdi


def _load_ssrf():
    from modules.ssrf import scan_ssrf

    return scan_ssrf


def _load_ssti():
    from modules.ssti import scan_ssti

    return scan_ssti


def _load_xxe():
    from modules.xxe import scan_xxe

    return scan_xxe


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


# Runner functions live in core.module_runners to keep this module focused on
# metadata and spec definitions.
from core.module_runners import (  # noqa: E402, F401
    _run_ai_analysis,
    _run_api_scan,
    _run_autopwn_postprocess,
    _run_business_logic,
    _run_chain_analysis,
    _run_cloud_storage,
    _run_cmdi_postprocess,
    _run_cookie_hsts_hook,
    _run_cors,
    _run_crawl_discovery,
    _run_credential_spray,
    _run_csrf_exploit,
    _run_csrf_hook,
    _run_csp_bypass_hook,
    _run_deduplicate_results,
    _run_deserialization,
    _run_email_harvest,
    _run_findings_json,
    _run_fuzzer_discovery,
    _run_header_inject,
    _run_headless_discovery,
    _run_html_report,
    _run_json_report,
    _run_jwt_scan,
    _run_markdown_report,
    _run_normalize_findings,
    _run_open_redirect,
    _run_osint,
    _run_passive_hook,
    _run_payload_report,
    _run_poc_generation,
    _run_proto_pollution,
    _run_race_condition,
    _run_recon,
    _run_sarif_report,
    _run_scan_summary,
    _run_secrets_hook,
    _run_severity_summary,
    _run_smuggling,
    _run_sqli_postprocess,
    _run_subdomain_scan,
    _run_subdomain_takeover,
    _run_tech_intel,
    _run_wordlist_generation,
    _run_xss_postprocess,
)


PHASE_MODULES = (
    PhaseModuleSpec(
        id="recon",
        option_key=None,
        name="Recon",
        phase="pre_scan",
        requires_forms=False,
        collect_results=False,
        runner=_run_recon,
    ),
    PhaseModuleSpec(
        id="osint",
        option_key="osint",
        name="OSINT",
        phase="pre_scan",
        requires_forms=False,
        collect_results=False,
        runner=_run_osint,
    ),
    PhaseModuleSpec(
        id="tech",
        option_key="tech",
        name="Technology Intel",
        phase="pre_scan",
        requires_forms=False,
        collect_results=True,
        runner=_run_tech_intel,
    ),
    PhaseModuleSpec(
        id="cloud",
        option_key="cloud",
        name="Cloud Storage",
        phase="phase4_target",
        requires_forms=False,
        collect_results=True,
        runner=_run_cloud_storage,
    ),
    PhaseModuleSpec(
        id="takeover",
        option_key="takeover",
        name="Subdomain Takeover",
        phase="phase4_target",
        requires_forms=False,
        collect_results=True,
        runner=_run_subdomain_takeover,
    ),
    PhaseModuleSpec(
        id="api_scan",
        option_key="api_scan",
        name="API Scan",
        phase="phase4_target",
        requires_forms=False,
        collect_results=True,
        runner=_run_api_scan,
    ),
    PhaseModuleSpec(
        id="subdomain",
        option_key="subdomain",
        name="Subdomain Discovery",
        phase="phase4_target",
        requires_forms=False,
        collect_results=False,
        runner=_run_subdomain_scan,
    ),
    PhaseModuleSpec(
        id="cors",
        option_key="cors",
        name="CORS",
        phase="target_checks",
        requires_forms=False,
        collect_results=True,
        runner=_run_cors,
    ),
    PhaseModuleSpec(
        id="header_inject",
        option_key="header_inject",
        name="Header Injection",
        phase="target_checks",
        requires_forms=False,
        collect_results=True,
        runner=_run_header_inject,
    ),
    PhaseModuleSpec(
        id="fuzz",
        option_key="fuzz",
        name="Endpoint Fuzzer",
        phase="discovery_seed",
        requires_forms=False,
        collect_results=False,
        runner=_run_fuzzer_discovery,
    ),
    PhaseModuleSpec(
        id="headless",
        option_key="headless",
        name="Headless Discovery",
        phase="discovery_expand",
        requires_forms=False,
        collect_results=False,
        runner=_run_headless_discovery,
    ),
    PhaseModuleSpec(
        id="crawl",
        option_key="crawl",
        name="Crawler Discovery",
        phase="discovery_expand",
        requires_forms=False,
        collect_results=False,
        runner=_run_crawl_discovery,
    ),
    PhaseModuleSpec(
        id="passive",
        option_key="passive",
        name="Passive Scan",
        phase="page_hooks",
        requires_forms=False,
        collect_results=True,
        runner=_run_passive_hook,
    ),
    PhaseModuleSpec(
        id="secrets",
        option_key="secrets",
        name="Secrets Scan",
        phase="page_hooks",
        requires_forms=False,
        collect_results=True,
        runner=_run_secrets_hook,
    ),
    PhaseModuleSpec(
        id="csrf",
        option_key="csrf",
        name="CSRF",
        phase="page_hooks",
        requires_forms=True,
        collect_results=True,
        runner=_run_csrf_hook,
    ),
    PhaseModuleSpec(
        id="csp_bypass",
        option_key="passive",
        name="CSP Bypass",
        phase="page_hooks",
        requires_forms=False,
        collect_results=True,
        runner=_run_csp_bypass_hook,
    ),
    PhaseModuleSpec(
        id="cookie_hsts",
        option_key="passive",
        name="Cookie & HSTS Audit",
        phase="page_hooks",
        requires_forms=False,
        collect_results=True,
        runner=_run_cookie_hsts_hook,
    ),
    PhaseModuleSpec(
        id="xss_postprocess",
        option_key="xss",
        name="XSS Postprocess",
        phase="result_processors",
        requires_forms=False,
        collect_results=False,
        runner=_run_xss_postprocess,
    ),
    PhaseModuleSpec(
        id="csrf_exploit",
        option_key="csrf",
        name="CSRF Exploit",
        phase="result_processors",
        requires_forms=False,
        collect_results=False,
        runner=_run_csrf_exploit,
    ),
    PhaseModuleSpec(
        id="sqli_postprocess",
        option_key="sqli",
        name="SQLi Postprocess",
        phase="result_processors",
        requires_forms=False,
        collect_results=True,
        runner=_run_sqli_postprocess,
    ),
    PhaseModuleSpec(
        id="cmdi_postprocess",
        option_key="cmdi",
        name="CMDi Postprocess",
        phase="result_processors",
        requires_forms=False,
        collect_results=False,
        runner=_run_cmdi_postprocess,
    ),
    PhaseModuleSpec(
        id="autopwn_postprocess",
        option_key="exploit",
        name="Auto-Pwn Bridge",
        phase="result_processors",
        requires_forms=False,
        collect_results=False,
        runner=_run_autopwn_postprocess,
    ),
    PhaseModuleSpec(
        id="redirect",
        option_key="redirect",
        name="Open Redirect",
        phase="post_scan",
        requires_forms=False,
        collect_results=True,
        runner=_run_open_redirect,
    ),
    PhaseModuleSpec(
        id="spray",
        option_key="spray",
        name="Credential Spray",
        phase="post_scan",
        requires_forms=False,
        collect_results=True,
        runner=_run_credential_spray,
    ),
    PhaseModuleSpec(
        id="email",
        option_key="email",
        name="Email Harvest",
        phase="post_scan",
        requires_forms=False,
        collect_results=False,
        runner=_run_email_harvest,
    ),
    PhaseModuleSpec(
        id="wordlist",
        option_key="wordlist",
        name="Wordlist Generation",
        phase="post_scan",
        requires_forms=False,
        collect_results=False,
        runner=_run_wordlist_generation,
    ),
    PhaseModuleSpec(
        id="jwt",
        option_key="jwt",
        name="JWT",
        phase="post_scan",
        requires_forms=False,
        collect_results=True,
        runner=_run_jwt_scan,
    ),
    PhaseModuleSpec(
        id="race",
        option_key="race",
        name="Race Condition",
        phase="post_scan",
        requires_forms=False,
        collect_results=True,
        runner=_run_race_condition,
    ),
    PhaseModuleSpec(
        id="smuggle",
        option_key="smuggle",
        name="HTTP Smuggling",
        phase="post_scan",
        requires_forms=False,
        collect_results=True,
        runner=_run_smuggling,
    ),
    PhaseModuleSpec(
        id="proto",
        option_key="proto",
        name="Prototype Pollution",
        phase="post_scan",
        requires_forms=False,
        collect_results=True,
        runner=_run_proto_pollution,
    ),
    PhaseModuleSpec(
        id="deser",
        option_key="deser",
        name="Deserialization",
        phase="post_scan",
        requires_forms=False,
        collect_results=True,
        runner=_run_deserialization,
    ),
    PhaseModuleSpec(
        id="bizlogic",
        option_key="bizlogic",
        name="Business Logic",
        phase="post_scan",
        requires_forms=False,
        collect_results=True,
        runner=_run_business_logic,
    ),
    PhaseModuleSpec(
        id="chain",
        option_key="chain",
        name="Chain Analysis",
        phase="post_scan",
        requires_forms=False,
        collect_results=False,
        runner=_run_chain_analysis,
    ),
    PhaseModuleSpec(
        id="dedupe",
        option_key=None,
        name="Deduplicate Findings",
        phase="result_cleanup",
        requires_forms=False,
        collect_results=False,
        runner=_run_deduplicate_results,
    ),
    PhaseModuleSpec(
        id="ai_analysis",
        option_key="ai",
        name="AI Analysis",
        phase="analysis",
        requires_forms=False,
        collect_results=False,
        runner=_run_ai_analysis,
    ),
    PhaseModuleSpec(
        id="summary",
        option_key=None,
        name="Summary",
        phase="reporting",
        requires_forms=False,
        collect_results=False,
        runner=_run_scan_summary,
    ),
    PhaseModuleSpec(
        id="html_report",
        option_key="html",
        name="HTML Report",
        phase="reporting",
        requires_forms=False,
        collect_results=False,
        runner=_run_html_report,
    ),
    PhaseModuleSpec(
        id="payload_report",
        option_key=None,
        name="Payload Report",
        phase="reporting",
        requires_forms=False,
        collect_results=False,
        runner=_run_payload_report,
    ),
    PhaseModuleSpec(
        id="markdown_report",
        option_key=None,
        name="Markdown Report",
        phase="reporting",
        requires_forms=False,
        collect_results=False,
        runner=_run_markdown_report,
    ),
    PhaseModuleSpec(
        id="poc_generation",
        option_key=None,
        name="PoC Generation",
        phase="reporting",
        requires_forms=False,
        collect_results=False,
        runner=_run_poc_generation,
    ),
    PhaseModuleSpec(
        id="normalize_findings",
        option_key=None,
        name="Normalize Findings",
        phase="reporting",
        requires_forms=False,
        collect_results=False,
        runner=_run_normalize_findings,
    ),
    PhaseModuleSpec(
        id="json_report",
        option_key=None,
        name="JSON Report",
        phase="reporting",
        requires_forms=False,
        collect_results=False,
        runner=_run_json_report,
    ),
    PhaseModuleSpec(
        id="sarif_report",
        option_key="sarif",
        name="SARIF Report",
        phase="reporting",
        requires_forms=False,
        collect_results=False,
        runner=_run_sarif_report,
    ),
    PhaseModuleSpec(
        id="findings_json",
        option_key=None,
        name="Enhanced Findings JSON",
        phase="reporting",
        requires_forms=False,
        collect_results=False,
        runner=_run_findings_json,
    ),
    PhaseModuleSpec(
        id="severity_summary",
        option_key=None,
        name="Severity Summary",
        phase="reporting",
        requires_forms=False,
        collect_results=False,
        runner=_run_severity_summary,
    ),
)


def iter_async_module_specs(options: dict):
    """Yield enabled async module specs in registry order."""
    for spec in ASYNC_MODULES:
        if options.get(spec.option_key):
            yield spec


def iter_phase_module_specs(phase: str, options: dict):
    """Yield enabled scanner phase specs in registry order."""
    for spec in PHASE_MODULES:
        if spec.phase != phase:
            continue
        if spec.option_key is None or options.get(spec.option_key):
            yield spec


def run_phase_modules(phase: str, options: dict, state: dict):
    """Run sequential registry-backed modules for a given scanner phase."""
    collected = []
    for spec in iter_phase_module_specs(phase, options):
        if spec.requires_forms and not state.get("forms"):
            continue
        result = spec.runner(state)
        if spec.collect_results and result:
            collected.extend(result)
            state["all_vulns"] = list(state.get("all_vulns", [])) + list(result)
    return collected
