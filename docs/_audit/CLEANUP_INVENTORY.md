# Cleanup Inventory — auto-generated

_Run: `python3 scripts/inventory_audit.py`_

## 1. Orphan Modules (defined but never imported anywhere)

- `core/ai_skills/imported/claude-osint/skills/offensive-osint/scripts/secret_scan.py`
- `core/ai_skills/imported/reverse-api-engineer/interfaces/auto_engineer.py`
- `core/ai_skills/imported/reverse-api-engineer/interfaces/native_host.py`
- `core/ai_skills/imported/reverse-api-engineer/interfaces/playwright_codegen.py`
- `modules/subdomain.py`
- `utils/ai_waf_agent.py`
- `utils/template_manager.py`

## 2. Stub / Empty / NotImpl Functions (excluding tests/)

- `modules/browser_exploit.py:138` — `auto_exploit_csrf` (PASS_ONLY)
- `utils/colors.py:87` — `_write_log` (PASS_ONLY)
- `utils/oob.py:37` — `start` (PASS_ONLY)
- `utils/oob.py:40` — `stop` (PASS_ONLY)
- `utils/oob.py:43` — `poll` (RETURN_EMPTY_COLL)

## 3. Unused Imports (heuristic, F401-style)

Total files with ≥1 unused import: **25**

Top offenders (≥3 unused):

- `modules/__init__.py`: 27 unused → `BLIND_SQLI_PAYLOADS, BLIND_SQLI_THRESHOLD, BlindSQLiExploit, CMDI_PAYLOADS, CMDI_SIGNATURES, LFI_PAYLOADS, LFI_SIGNATURES, PayloadEncoder`…
- `utils/__init__.py`: 18 unused → `Colors, Config, LOG_FILE, Stats, USER_AGENTS, _get_session, _global_headers, lock`…
- `modules/api_scanner.py`: 16 unused → `_build_auth_placeholders, _build_endpoint_url, _describe_auth_scheme, _extract_auth_schemes, _extract_request_body, _first_example_value, _flatten_form_payload, _guess_parameter_value`…
- `core/scan_options.py`: 9 unused → `API_SPEC_PROMPT, ATTACK_PROFILE_SPECS, ArgumentSpec, AttackProfileSpec, INTERACTIVE_CUSTOM_PROMPT_GROUPS, INTERACTIVE_RESUME_PROMPT, JSON_OUTPUT_PROMPT, SCAN_MODE_SPECS`…
- `utils/qishing.py`: 4 unused → `log_info, log_warning, re, urljoin`
- `modules/google_dorker.py`: 4 unused → `log_error, log_warning, quote_plus, re`
- `modules/smart_payload.py`: 3 unused → `probe_cmdi_context, probe_lfi_context, probe_sqli_context`

## 4. Suspect Duplicate Pairs — function-name overlap

| A | B | LOC A | LOC B | overlap fns | %A | %B |
|---|---|---|---|---|---|---|
| `modules/sqli.py` | `modules/sqli_exploit.py` | 471 | 1056 | 0 | 0.0 | 0.0 |
| `modules/lfi.py` | `modules/lfi_exploit.py` | 499 | 305 | 0 | 0.0 | 0.0 |
| `modules/cmdi.py` | `modules/cmdi_shell.py` | 644 | 386 | 0 | 0.0 | 0.0 |
| `modules/ssrf.py` | `modules/ssrf_exploit.py` | 529 | 317 | 0 | 0.0 | 0.0 |
| `modules/xss.py` | `modules/xss_exploit.py` | 284 | 476 | 0 | 0.0 | 0.0 |
| `modules/crawler.py` | `modules/dynamic_crawler.py` | 276 | 155 | 0 | 0.0 | 0.0 |
| `modules/payloads.py` | `modules/smart_payload.py` | 408 | 942 | 0 | 0.0 | 0.0 |
| `modules/smart_payload.py` | `modules/smart_payload_inject.py` | 942 | 449 | 0 | 0.0 | 0.0 |
| `utils/agent_framework.py` | `utils/agent_orchestrator.py` | 1019 | 308 | 1 | 3.2 | 12.5 |
| `utils/ai.py` | `utils/ai_exploit_agent.py` | 633 | 1024 | 3 | 13.0 | 8.1 |
| `utils/ai_intent_agent.py` | `utils/ai_waf_agent.py` | 357 | 334 | 1 | 9.1 | 16.7 |
| `utils/waf.py` | `utils/waf_evasion.py` | 257 | 327 | 0 | 0.0 | 0.0 |
| `utils/waf_evasion.py` | `utils/waf_exhaustion.py` | 327 | 67 | 0 | 0.0 | 0.0 |

Overlap names per pair (first 10):

- `utils/agent_framework.py` ↔ `utils/agent_orchestrator.py`: `run_mission`
- `utils/ai.py` ↔ `utils/ai_exploit_agent.py`: `__init__, _extract_json, available`
- `utils/ai_intent_agent.py` ↔ `utils/ai_waf_agent.py`: `__init__`

## 5. Module Reachability Map

Legend: R=registry, U=module_runners, S=scanner.py, A=api_server.py, T=test file

| File | R | U | S | A | T |
|---|---|---|---|---|---|
| `modules/account_takeover.py` | ✓ | ✓ |   |   |   |
| `modules/api_inject.py` | ✓ | ✓ |   |   |   |
| `modules/api_scanner.py` |   | ✓ |   |   | ✓ |
| `modules/api_spec_parser.py` |   |   |   |   |   |
| `modules/auth_bypass.py` | ✓ | ✓ |   |   |   |
| `modules/baas_audit.py` |   |   |   |   | ✓ |
| `modules/browser_exploit.py` |   | ✓ |   |   |   |
| `modules/brute_force.py` | ✓ | ✓ |   |   | ✓ |
| `modules/business_logic.py` | ✓ | ✓ |   |   |   |
| `modules/cloud_enum.py` |   | ✓ |   |   |   |
| `modules/cmdi.py` | ✓ | ✓ | ✓ |   | ✓ |
| `modules/cmdi_shell.py` |   | ✓ |   |   |   |
| `modules/cms_enum.py` |   |   |   |   |   |
| `modules/compare.py` |   |   | ✓ | ✓ |   |
| `modules/cookie_hsts_audit.py` |   | ✓ |   |   |   |
| `modules/cors.py` | ✓ | ✓ |   | ✓ |   |
| `modules/crawler.py` |   | ✓ |   |   |   |
| `modules/crlf.py` |   |   |   |   |   |
| `modules/csp_bypass.py` | ✓ | ✓ |   |   |   |
| `modules/csrf.py` | ✓ | ✓ |   |   |   |
| `modules/deserialization.py` | ✓ | ✓ |   |   | ✓ |
| `modules/dom_xss.py` | ✓ |   |   |   |   |
| `modules/dynamic_crawler.py` |   | ✓ |   |   |   |
| `modules/email_harvest.py` | ✓ | ✓ |   |   |   |
| `modules/endpoint_fuzzer.py` |   | ✓ |   |   |   |
| `modules/file_upload.py` | ✓ | ✓ |   |   |   |
| `modules/forbidden_bypass.py` | ✓ | ✓ |   |   | ✓ |
| `modules/git_history_scan.py` |   | ✓ |   |   | ✓ |
| `modules/google_dorker.py` | ✓ | ✓ |   |   |   |
| `modules/graphql_audit.py` | ✓ | ✓ |   |   | ✓ |
| `modules/guaranteed_checks.py` | ✓ | ✓ |   |   |   |
| `modules/header_inject.py` | ✓ | ✓ |   |   |   |
| `modules/http_methods.py` |   |   |   |   |   |
| `modules/jwt_attack.py` |   | ✓ |   |   |   |
| `modules/ldap.py` |   |   |   |   |   |
| `modules/lfi.py` | ✓ | ✓ |   | ✓ | ✓ |
| `modules/lfi_exploit.py` |   | ✓ |   |   |   |
| `modules/log4shell.py` |   |   |   |   |   |
| `modules/nuclei_runner.py` |   | ✓ |   |   | ✓ |
| `modules/open_redirect.py` | ✓ | ✓ |   |   |   |
| `modules/osint_breach.py` | ✓ | ✓ |   |   |   |
| `modules/osint_identity.py` | ✓ | ✓ |   |   |   |
| `modules/osint_sector.py` | ✓ | ✓ |   |   |   |
| `modules/osv_scanner.py` |   |   |   |   | ✓ |
| `modules/param_discovery.py` | ✓ | ✓ |   |   |   |
| `modules/passive.py` | ✓ | ✓ |   |   |   |
| `modules/payloads.py` |   |   | ✓ |   |   |
| `modules/poc_generator.py` |   | ✓ |   |   |   |
| `modules/privesc_scanner.py` |   | ✓ |   |   |   |
| `modules/proto_pollution.py` | ✓ | ✓ |   |   |   |
| `modules/proxy_interceptor.py` |   |   | ✓ |   |   |
| `modules/race_condition.py` | ✓ | ✓ |   |   |   |
| `modules/recon.py` | ✓ | ✓ | ✓ |   | ✓ |
| `modules/report.py` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `modules/rfi.py` | ✓ |   |   |   |   |
| `modules/secrets_scanner.py` |   | ✓ |   |   |   |
| `modules/shellshock.py` |   |   |   |   |   |
| `modules/smart_payload.py` |   |   |   |   |   |
| `modules/smart_payload_inject.py` |   |   |   |   |   |
| `modules/smuggling.py` | ✓ | ✓ |   |   | ✓ |
| `modules/spray.py` | ✓ | ✓ |   |   |   |
| `modules/sqli.py` | ✓ | ✓ | ✓ | ✓ |   |
| `modules/sqli_exploit.py` |   | ✓ |   |   |   |
| `modules/ssrf.py` | ✓ | ✓ |   |   | ✓ |
| `modules/ssrf_exploit.py` |   | ✓ |   |   |   |
| `modules/ssti.py` | ✓ |   |   |   | ✓ |
| `modules/subdomain.py` | ✓ | ✓ |   |   |   |
| `modules/subdomain_takeover.py` | ✓ | ✓ |   |   |   |
| `modules/tech_detect.py` |   | ✓ |   |   |   |
| `modules/template_engine.py` | ✓ |   |   |   |   |
| `modules/urlscan_passive.py` | ✓ | ✓ |   |   |   |
| `modules/wayback_harvester.py` | ✓ | ✓ |   |   |   |
| `modules/xss.py` | ✓ | ✓ | ✓ | ✓ |   |
| `modules/xss_exploit.py` |   | ✓ |   |   |   |
| `modules/xxe.py` | ✓ |   |   |   | ✓ |
| `utils/agent_framework.py` |   |   | ✓ |   | ✓ |
| `utils/agent_orchestrator.py` |   |   |   |   | ✓ |
| `utils/ai.py` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `utils/ai_exploit_agent.py` |   |   |   |   |   |
| `utils/ai_intent_agent.py` |   |   |   |   | ✓ |
| `utils/ai_waf_agent.py` |   |   |   |   |   |
| `utils/asset_search.py` | ✓ | ✓ |   |   | ✓ |
| `utils/async_request.py` |   |   |   |   |   |
| `utils/attack_mapping.py` |   |   |   |   | ✓ |
| `utils/auth.py` | ✓ |   |   |   | ✓ |
| `utils/autopwn.py` | ✓ | ✓ |   |   |   |
| `utils/brand_protection.py` |   |   |   |   |   |
| `utils/campaign_manager.py` |   |   | ✓ |   | ✓ |
| `utils/code_executor.py` |   |   |   |   | ✓ |
| `utils/colors.py` | ✓ | ✓ | ✓ | ✓ |   |
| `utils/concurrency.py` |   |   |   | ✓ |   |
| `utils/cve_feed.py` |   | ✓ |   |   | ✓ |
| `utils/docker_executor.py` |   |   |   |   | ✓ |
| `utils/exploit_finder.py` |   |   |   |   |   |
| `utils/finding.py` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `utils/har_analyzer.py` |   | ✓ |   |   |   |
| `utils/loot_manager.py` |   | ✓ |   |   |   |
| `utils/mcp_server.py` |   |   |   |   | ✓ |
| `utils/meta_tools.py` |   |   |   |   | ✓ |
| `utils/oob.py` |   |   | ✓ |   |   |
| `utils/payload_filter.py` |   |   |   |   | ✓ |
| `utils/payload_memory.py` |   | ✓ |   |   | ✓ |
| `utils/proxy_rotator.py` |   |   |   |   |   |
| `utils/qishing.py` |   |   |   |   |   |
| `utils/request.py` |   | ✓ | ✓ | ✓ | ✓ |
| `utils/reverse_listener.py` |   | ✓ |   |   |   |
| `utils/revshell.py` |   | ✓ |   |   |   |
| `utils/scan_history.py` | ✓ | ✓ |   |   | ✓ |
| `utils/scan_intelligence.py` |   | ✓ | ✓ |   | ✓ |
| `utils/shodan_lookup.py` |   | ✓ |   |   |   |
| `utils/sploitus_search.py` | ✓ | ✓ |   |   |   |
| `utils/tamper.py` |   |   | ✓ |   | ✓ |
| `utils/target_profiler.py` |   |   |   |   | ✓ |
| `utils/template_manager.py` |   |   |   |   |   |
| `utils/validation_pipeline.py` |   |   | ✓ |   | ✓ |
| `utils/vuln_chain.py` |   | ✓ |   |   |   |
| `utils/waf.py` |   |   | ✓ |   | ✓ |
| `utils/waf_evasion.py` |   |   |   |   |   |
| `utils/waf_exhaustion.py` |   |   |   |   |   |
| `utils/wordlist_gen.py` | ✓ | ✓ |   |   |   |

## 6. Cleanup Decision Hints

### 6a. TRULY ORPHAN — no entry point AND no inter-module importers

Top candidates for orphan removal (still verify with `grep -r`):

- `utils/ai_waf_agent.py`
- `utils/template_manager.py`

### 6b. INDIRECTLY REACHED — no direct entry, but other modules import it

- `modules/api_spec_parser.py` ← imported by: `modules/api_scanner.py, tests/test_integration_api_scanner.py`
- `modules/baas_audit.py` ← imported by: `tests/test_baas_audit.py`
- `modules/cms_enum.py` ← imported by: `tests/test_new_vuln_modules.py`
- `modules/crlf.py` ← imported by: `tests/test_new_vuln_modules.py`
- `modules/http_methods.py` ← imported by: `tests/test_new_vuln_modules.py`
- `modules/ldap.py` ← imported by: `tests/test_new_vuln_modules.py`
- `modules/log4shell.py` ← imported by: `tests/test_new_vuln_modules.py`
- `modules/osv_scanner.py` ← imported by: `modules/guaranteed_checks.py, tests/test_osv_scanner.py`
- `modules/shellshock.py` ← imported by: `tests/test_new_vuln_modules.py`
- `modules/smart_payload.py` ← imported by: `modules/cmdi.py, modules/lfi.py, modules/sqli.py, modules/xss.py`
- `modules/smart_payload_inject.py` ← imported by: `modules/smart_payload.py`
- `utils/agent_orchestrator.py` ← imported by: `tests/test_agent_orchestrator.py`
- `utils/ai_exploit_agent.py` ← imported by: `modules/cmdi.py, modules/deserialization.py, modules/lfi.py, modules/sqli.py, modules/ssrf.py` …
- `utils/ai_intent_agent.py` ← imported by: `tests/test_ai_intent_agent.py, tests/test_mcp_server.py, utils/agent_orchestrator.py, utils/mcp_server.py`
- `utils/async_request.py` ← imported by: `modules/cmdi.py, modules/deserialization.py, modules/lfi.py, modules/ssrf.py, modules/ssti.py` …
- `utils/attack_mapping.py` ← imported by: `tests/test_attack_mapping.py, utils/agent_orchestrator.py`
- `utils/brand_protection.py` ← imported by: `modules/guaranteed_checks.py, tests/test_brand_qishing.py`
- `utils/code_executor.py` ← imported by: `tests/test_code_executor.py, tests/test_docker_executor.py, utils/ai_intent_agent.py, utils/docker_executor.py`
- `utils/docker_executor.py` ← imported by: `tests/test_docker_executor.py`
- `utils/exploit_finder.py` ← imported by: `utils/cve_feed.py`
- `utils/mcp_server.py` ← imported by: `tests/test_mcp_server.py`
- `utils/meta_tools.py` ← imported by: `tests/test_meta_tools.py, utils/agent_orchestrator.py, utils/mcp_server.py`
- `utils/payload_filter.py` ← imported by: `modules/cmdi.py, modules/lfi.py, modules/sqli.py, modules/ssrf.py, modules/xss.py` …
- `utils/proxy_rotator.py` ← imported by: `core/scan_options.py, utils/request.py`
- `utils/qishing.py` ← imported by: `modules/guaranteed_checks.py, tests/test_brand_qishing.py`
- `utils/target_profiler.py` ← imported by: `tests/test_target_profiler.py, utils/agent_framework.py`
- `utils/waf_evasion.py` ← imported by: `modules/cmdi.py, modules/lfi.py, modules/sqli.py, modules/ssrf.py, modules/ssti.py` …
- `utils/waf_exhaustion.py` ← imported by: `utils/waf_evasion.py`

### 6c. ZERO IMPORTERS WITH TEST FILE (test-only orphans?)

_None._
