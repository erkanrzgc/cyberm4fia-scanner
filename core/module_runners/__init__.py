"""Phase-module runner functions.

Each ``_run_*`` function is called by the ``PHASE_MODULES`` registry
defined in ``core.module_registry``.

Replaces the former 1374-LOC ``core/module_runners.py`` with six
phase-aligned sub-modules. Public surface preserved verbatim — every
existing ``from core.module_runners import _run_X`` keeps working.

Sub-modules:
  - discovery   → pre-scan recon + crawl + fuzzer (~360 LOC)
  - page_hooks  → passive / secrets / csrf / csp / hsts hooks (~50 LOC)
  - postprocess → result-processor exploit runners (~380 LOC)
  - post_scan   → vuln scanners + analysis (~250 LOC)
  - reporting   → HTML / JSON / SARIF / Markdown / PoC (~155 LOC)
  - extras      → param discovery / API / GraphQL / HAR / nuclei /
                  git history / asset search / guaranteed checks (~190 LOC)
"""

from .discovery import (  # noqa: F401
    _run_api_scan,
    _run_brute_force,
    _run_cicd_exposure,
    _run_cloud_storage,
    _run_container_registry,
    _run_cors,
    _run_crawl_discovery,
    _run_fuzzer_discovery,
    _run_google_dorker,
    _run_header_inject,
    _run_headless_discovery,
    _run_osint,
    _run_osint_breach,
    _run_osint_identity,
    _run_osint_sector,
    _run_recon,
    _run_sploitus_search,
    _run_subdomain_scan,
    _run_subdomain_takeover,
    _run_tech_intel,
    _run_urlscan_passive,
    _run_wayback_harvester,
)
from .extras import (  # noqa: F401
    _run_api_injection,
    _run_asset_search,
    _run_git_history,
    _run_graphql_audit,
    _run_guaranteed_checks,
    _run_har_analysis,
    _run_nuclei,
    _run_param_discovery,
)
from .page_hooks import (  # noqa: F401
    _csp_checked_hosts,
    _hsts_checked_hosts,
    _run_cookie_hsts_hook,
    _run_csp_bypass_hook,
    _run_csrf_hook,
    _run_passive_hook,
    _run_secrets_hook,
)
from .post_scan import (  # noqa: F401
    _run_account_takeover,
    _run_active_verifiers,
    _run_ai_analysis,
    _run_auth_bypass,
    _run_business_logic,
    _run_chain_analysis,
    _run_credential_spray,
    _run_deduplicate_results,
    _run_deserialization,
    _run_email_harvest,
    _run_file_upload,
    _run_forbidden_bypass,
    _run_jwt_scan,
    _run_open_redirect,
    _run_proto_pollution,
    _run_race_condition,
    _run_smuggling,
    _run_wordlist_generation,
)
from .postprocess import (  # noqa: F401
    _run_autopwn_postprocess,
    _run_cmdi_postprocess,
    _run_csrf_exploit,
    _run_lfi_postprocess,
    _run_sqli_postprocess,
    _run_ssrf_postprocess,
    _run_xss_postprocess,
)
from .reporting import (  # noqa: F401
    _run_burp_xml_report,
    _run_findings_json,
    _run_html_report,
    _run_json_report,
    _run_markdown_report,
    _run_normalize_findings,
    _run_payload_report,
    _run_poc_generation,
    _run_sarif_report,
    _run_scan_history,
    _run_scan_summary,
    _run_severity_summary,
)

__all__ = [
    # discovery
    "_run_api_scan",
    "_run_brute_force",
    "_run_cicd_exposure",
    "_run_cloud_storage",
    "_run_container_registry",
    "_run_cors",
    "_run_crawl_discovery",
    "_run_fuzzer_discovery",
    "_run_google_dorker",
    "_run_header_inject",
    "_run_headless_discovery",
    "_run_osint",
    "_run_osint_breach",
    "_run_osint_identity",
    "_run_osint_sector",
    "_run_recon",
    "_run_sploitus_search",
    "_run_subdomain_scan",
    "_run_subdomain_takeover",
    "_run_tech_intel",
    "_run_urlscan_passive",
    "_run_wayback_harvester",
    # extras
    "_run_api_injection",
    "_run_asset_search",
    "_run_git_history",
    "_run_graphql_audit",
    "_run_guaranteed_checks",
    "_run_har_analysis",
    "_run_nuclei",
    "_run_param_discovery",
    # page_hooks
    "_csp_checked_hosts",
    "_hsts_checked_hosts",
    "_run_cookie_hsts_hook",
    "_run_csp_bypass_hook",
    "_run_csrf_hook",
    "_run_passive_hook",
    "_run_secrets_hook",
    # post_scan
    "_run_account_takeover",
    "_run_active_verifiers",
    "_run_ai_analysis",
    "_run_auth_bypass",
    "_run_business_logic",
    "_run_chain_analysis",
    "_run_credential_spray",
    "_run_deduplicate_results",
    "_run_deserialization",
    "_run_email_harvest",
    "_run_file_upload",
    "_run_forbidden_bypass",
    "_run_jwt_scan",
    "_run_open_redirect",
    "_run_proto_pollution",
    "_run_race_condition",
    "_run_smuggling",
    "_run_wordlist_generation",
    # postprocess
    "_run_autopwn_postprocess",
    "_run_cmdi_postprocess",
    "_run_csrf_exploit",
    "_run_lfi_postprocess",
    "_run_sqli_postprocess",
    "_run_ssrf_postprocess",
    "_run_xss_postprocess",
    # reporting
    "_run_burp_xml_report",
    "_run_findings_json",
    "_run_html_report",
    "_run_json_report",
    "_run_markdown_report",
    "_run_normalize_findings",
    "_run_payload_report",
    "_run_poc_generation",
    "_run_sarif_report",
    "_run_scan_history",
    "_run_scan_summary",
    "_run_severity_summary",
]
