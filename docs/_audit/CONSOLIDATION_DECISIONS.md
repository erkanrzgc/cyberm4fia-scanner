# Cleanup Decisions — Faz 1 Output

Date: 2026-05-06
Status: **Decisions locked.** Subsequent phases execute these.

## A. Truly Orphan (DELETE in Faz 2)

These have **zero importers** anywhere in the project (verified by AST scan
of inter-module imports + manual `grep -r` over docs/json/yaml).

| File | LOC | Notes |
|---|---|---|
| `utils/ai_waf_agent.py` | 334 | Early WAF-evasion experiment; never wired in. The shipped 3-tier WAF chain uses `utils/waf_evasion.py`. Not referenced by `agent_framework.py` tool-table either. |
| `utils/template_manager.py` | (~100) | YAML template manager CLI helper; never imported. No CLI subcommand exposes it. |

**Action:** delete both files, delete any stale references in
`utils/__init__.py` if they exist, run pytest.

## B. Apparent Orphans, Actually Reachable (KEEP)

`modules/subdomain.py` was flagged orphan by my first pass; verified reachable
via string-based tool dispatch in `utils/agent_framework.py:385`:

```python
"subdomain": ("modules.subdomain", "scan_subdomains", False),
```

Static AST scan misses runtime `importlib`-style dispatch. **KEEP.**

## C. Dormant Subsystem — KEEP with explicit docs

These have tests but **no production caller** today. Memory note:
*"Full Cairn-inspired autonomy stack landed (intent agent + sandbox +
self-healing + meta-tools + MCP) on 2026-05-01"*. They are intentional —
they expose hooks for an external agent runner to drive the scanner.

| File | Importers (excl. tests) |
|---|---|
| `utils/mcp_server.py` | (only tests) |
| `utils/agent_orchestrator.py` | (only tests) |
| `utils/meta_tools.py` | `utils/agent_orchestrator.py`, `utils/mcp_server.py` |
| `utils/code_executor.py` | `utils/ai_intent_agent.py`, `utils/docker_executor.py` |
| `utils/docker_executor.py` | (only tests) |
| `utils/ai_intent_agent.py` | `utils/agent_orchestrator.py`, `utils/mcp_server.py` |
| `utils/ai_exploit_agent.py` | `modules/cmdi.py`, `modules/deserialization.py`, `modules/lfi.py`, `modules/sqli.py`, `modules/ssrf.py` (real prod use) |
| `utils/ai_intent_agent.py` ↔ `utils/ai_waf_agent.py` overlap | only `__init__` |

**Action:** add a one-line docstring at the top of each file marking it
as "agent-harness entry point — invoked externally, not from scanner.py".
No code change.

## D. Suspect Duplicate Pairs — Final Decision Matrix

| Pair | Decision | Rationale |
|---|---|---|
| `modules/sqli.py` ↔ `modules/sqli_exploit.py` | **KEEP-BOTH** | 0% fn-name overlap. detect vs exploit. |
| `modules/lfi.py` ↔ `modules/lfi_exploit.py` | **KEEP-BOTH** | 0% overlap. |
| `modules/cmdi.py` ↔ `modules/cmdi_shell.py` | **KEEP-BOTH** | 0% overlap. cmdi=detect, cmdi_shell=interactive. |
| `modules/ssrf.py` ↔ `modules/ssrf_exploit.py` | **KEEP-BOTH** | 0% overlap. |
| `modules/xss.py` ↔ `modules/xss_exploit.py` | **KEEP-BOTH** | 0% overlap. |
| `modules/crawler.py` ↔ `modules/dynamic_crawler.py` | **KEEP-BOTH** | crawler=static link extraction, dynamic_crawler=Playwright headless. Distinct dependencies (Playwright optional). |
| `modules/payloads.py` ↔ `modules/smart_payload.py` | **KEEP-BOTH** | payloads=static constants (used by scanner.py CLI listing), smart_payload=AI-mutated runtime. |
| `modules/smart_payload.py` ↔ `modules/smart_payload_inject.py` | **KEEP-BOTH** | inject is reachable via smart_payload. Possibly merge in Faz 6 split if cohesion warrants. |
| `utils/agent_framework.py` ↔ `utils/agent_orchestrator.py` | **KEEP-BOTH** | only `run_mission` overlap (3.2%). agent_framework=tool dispatch, agent_orchestrator=multi-agent coordination. |
| `utils/ai.py` ↔ `utils/ai_exploit_agent.py` | **KEEP-BOTH** | 8-13% overlap (`__init__`, `_extract_json`, `available`). Different LLM client roles. Could extract `_extract_json` to a shared util in Faz 6. |
| `utils/ai_intent_agent.py` ↔ `utils/ai_waf_agent.py` | **DELETE ai_waf_agent** | covered in section A. |
| `utils/waf.py` ↔ `utils/waf_evasion.py` | **KEEP-BOTH** | 0% overlap. waf=fingerprint/detect, waf_evasion=3-tier bypass chain. |
| `utils/waf_evasion.py` ↔ `utils/waf_exhaustion.py` | **KEEP-BOTH** | 0% overlap. exhaustion is a 67-LOC tactic file imported by waf_evasion. |

## E. Stub Functions — Faz 4 plan

| Location | Function | Plan |
|---|---|---|
| `modules/browser_exploit.py:138` | `auto_exploit_csrf` (PASS_ONLY) | Called by `core/module_runners.py:470`. Either implement or remove the runner call + this stub. **Investigate runtime path first.** |
| `utils/colors.py:87` | `_write_log` (PASS_ONLY) | Likely intentional placeholder for log file backend. Add docstring; keep. |
| `utils/oob.py:37/40/43` | `start`, `stop`, `poll` | This is a no-op `OutOfBandServer` placeholder. The class exists but does nothing. Either remove the file (and any callers), or implement it. **Investigate.** |

## F. Unused Imports — Faz 2 plan

102 unused imports total across 25 files. Special-case handling:

- `modules/__init__.py` (27 unused) and `utils/__init__.py` (18 unused) are
  **public re-exports** — if pylint/ruff flag them, add them to `__all__`
  instead of removing.
- `core/scan_options.py` (9 unused) — same situation; review before delete.
- `modules/api_scanner.py` (16 unused) — `_build_*` private helpers used as
  re-exports. **Review one-by-one** before deletion.

For clean files (`utils/qishing.py`, `modules/google_dorker.py`, etc. —
3-4 unused imports each), `ruff check --fix --select F401` is safe.

## G. Big Files — Faz 6 plan

| File | LOC | Split target |
|---|---|---|
| `utils/finding.py` | 1169 | `Finding` dataclass · `Severity`/`Category` enums · serializers · dedup helpers → 4 files |
| `modules/sqli_exploit.py` | 1056 | `BlindSQLiExploit` · `TimeBasedExploit` · `ErrorBasedExploit` · `Dumper` → 4 files |
| `utils/ai_exploit_agent.py` | 1024 | agent class · prompt builders · response parsers → 3 files |
| `utils/agent_framework.py` | 1019 | tool registry · executor · result types → 3 files |
| `modules/smart_payload.py` | 942 | mutator · encoder · context-prober → 3 files |

## H. Out of Scope (this cleanup)

- Slow tests (~190s of real-network tests in ssrf/ssti/xxe/vuln_checklist) —
  separate **test-quality** task, not architecture cleanup.
- Vendored `tools/mcp-for-security/` — read-only, do not modify.
- AI provider abstraction — NIM-only is locked per memory.
- Agent harness API — frozen per memory; do not refactor agent_orchestrator
  or meta_tools internals.
