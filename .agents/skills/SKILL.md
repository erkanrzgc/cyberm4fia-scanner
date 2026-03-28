---
name: cyberm4fia
description: >
  Complete architecture guide for the cyberm4fia-scanner project.
  Covers the module registry system, scan pipeline, AI/Multi-Agent integration,
  WAF bypass, exploit chaining, payload generation, reporting, and test infrastructure.
  Triggers: cyberm4fia, scanner, module, exploit, recon, pentest,
  payload, agent, ai, waf, fuzzer, brute, CVE, finding, report.
---

# cyberm4fia-scanner — Comprehensive Development Guide

You are the coding assistant for **Erkan**, the lead developer of cyberm4fia-scanner.
You have deep architectural knowledge of the project: a Python-based, modular,
AI-powered next-generation pentest/recon tool.

---

## 1. Project Identity

| Field | Detail |
|-------|--------|
| **Language** | Python 3.11+ |
| **Environment** | Kali Linux (primary), Windows (secondary) |
| **Architecture** | Modular Pipeline + Async Hybrid (threading + asyncio) |
| **Interface** | `rich` CLI dashboard + REST API (`api_server.py`) |
| **AI** | Local LLM server (OpenAI-compatible `base_url`) |
| **Testing** | pytest (284+ tests, asyncio, mock) |
| **Repository** | github.com/erkanrzgc/cyberm4fia-scanner |

---

## 2. Directory Structure & Responsibilities

```
cyberm4fia-scanner/
├── scanner.py              ← CLI entry point, main scan loop
├── api_server.py           ← REST API server
│
├── core/                   ← Scanner engine core
│   ├── module_registry.py  ← AsyncModuleSpec / PhaseModuleSpec registrations
│   ├── module_runners.py   ← Runner functions for each module
│   ├── scan_context.py     ← ScanContext: per-scan isolation
│   ├── scan_options.py     ← CLI/API argument → options dict conversion
│   ├── scan_option_specs.py← All flag definitions, profiles, defaults
│   ├── engine.py           ← Async module execution engine
│   ├── interactive.py      ← Interactive menu and prompt management
│   ├── session.py          ← Scan session save/load (resume support)
│   ├── scope.py            ← Scope enforcement and URL filtering
│   ├── output.py           ← Output formatter
│   ├── cli.py              ← Argparse wrapper
│   └── documentation.py    ← Auto-generates README.md / usagewithai.md
│
├── modules/                ← Scanning and exploit modules (50+)
│   ├── recon.py            ← OSINT, Shodan, subdomain, tech detection
│   ├── xss.py / xss_exploit.py
│   ├── sqli.py / sqli_exploit.py
│   ├── cmdi.py / cmdi_shell.py
│   ├── ssrf.py / ssrf_exploit.py
│   ├── lfi.py / lfi_exploit.py
│   ├── ssti.py, xxe.py, csrf.py, cors.py
│   ├── jwt_attack.py, deserialization.py
│   ├── race_condition.py, smuggling.py
│   ├── header_inject.py, open_redirect.py
│   ├── business_logic.py, proto_pollution.py
│   ├── brute_force.py, subdomain_takeover.py
│   ├── smart_payload.py / smart_payload_inject.py
│   ├── template_engine.py  ← Nuclei-style YAML template engine
│   ├── report.py           ← HTML/MD/SARIF report generation
│   ├── api_scanner.py / api_spec_parser.py
│   ├── crawler.py / dynamic_crawler.py
│   └── payloads.py         ← Payload bank and generation functions
│
├── utils/                  ← Helper libraries (30+)
│   ├── finding.py          ← Finding / Observation / AttackPath dataclasses
│   ├── ai.py               ← LLM client, prompt dispatch, JSON parsing
│   ├── ai_exploit_agent.py ← AI-powered exploit generation agent
│   ├── ai_waf_agent.py     ← AI-powered WAF bypass agent
│   ├── agent_framework.py  ← Multi-Agent orchestration (Recon/Exploit/Report)
│   ├── request.py          ← HTTP request manager (session, retry, stats)
│   ├── async_request.py    ← Async HTTP requests
│   ├── waf.py              ← WAF detection and fingerprinting
│   ├── waf_evasion.py      ← Adaptive WAF bypass strategies
│   ├── tamper.py           ← Payload mutation functions
│   ├── payload_filter.py   ← WAF/context-based payload filtering
│   ├── payload_memory.py   ← AI payload memory (SQLite)
│   ├── scan_history.py     ← Scan drift detection (SQLite)
│   ├── cve_feed.py         ← NVD CVE feed
│   ├── sploitus_search.py  ← Sploitus exploit search
│   ├── exploit_finder.py   ← Exploit discovery and selection engine
│   ├── vuln_chain.py       ← Vulnerability chaining engine
│   ├── oob.py              ← Out-of-Band callback server
│   ├── auth.py             ← Authentication manager
│   ├── shodan_lookup.py    ← Shodan API integration
│   ├── autopwn.py          ← Automated exploitation orchestrator
│   ├── revshell.py         ← Reverse shell generator
│   └── colors.py           ← Rich console + log manager
│
├── payloads/               ← Static payload files
│   ├── xss.txt, sqli.txt, cmdi.txt, lfi.txt, ssrf.txt
│   └── tampers/            ← Tamper scripts
│
├── templates/              ← Nuclei-style YAML scan templates
├── wordlists/              ← Brute-force and fuzzing dictionaries
├── data/                   ← Static data files
├── memory/                 ← AI payload memory database (SQLite)
├── scans/                  ← Scan outputs (per-target directories)
├── scripts/                ← Helper scripts (generate_docs.py)
└── tests/                  ← Pytest test suite (284+ tests, 40 files)
```

---

## 3. Architecture Concepts

### 3.1 Scan Pipeline (Phases)

Scanner modules are registered by **phase** in `core/module_registry.py`:

| Phase | Description | Registration Type |
|-------|-------------|-------------------|
| `pre_scan` | OSINT, Shodan, tech detection | `PhaseModuleSpec` |
| `discovery` | Crawling, subdomain, endpoint fuzzing | `PhaseModuleSpec` |
| `target` | Per-page async scans (XSS, SQLi...) | `AsyncModuleSpec` |
| `page_hook` | Passive hooks on every page (CSP, cookie, secrets) | `AsyncModuleSpec` |
| `post_scan` | Brute-force, template engine, sploitus | `PhaseModuleSpec` |
| `analysis` | AI analysis, drift detection, confidence scoring | `PhaseModuleSpec` |
| `reporting` | HTML/MD/SARIF report generation | `PhaseModuleSpec` |

### 3.2 Core Data Structures

```python
# Module registration — core/module_registry.py
AsyncModuleSpec(id, option_key, name, phase, requires_forms, loader, args_factory)
PhaseModuleSpec(id, option_key, name, phase, requires_forms, collect_results, runner)

# Findings — utils/finding.py
Observation(id, observation_type, url, module, ...)   # Raw observation
Finding(id, vuln_type, url, severity, confidence_score, verification_state, ...)
AttackPath(id, name, severity, finding_refs, steps)   # Chaining scenario
```

### 3.3 ScanContext Lifecycle

`core/scan_context.py` → Isolated runtime per scan:

```python
with ScanContext(target, mode, delay, options).activate():
    # All global state (proxy, cookie, OOB, stats) is isolated here
    # Automatically restored to previous state when scan completes
```

### 3.4 Multi-Agent Architecture

`utils/agent_framework.py` contains 3 agents + 1 orchestrator:

| Agent | Responsibility |
|-------|---------------|
| `ReconAgent` | Target discovery, tech stack, subdomains |
| `ExploitAgent` | Vulnerability detection, exploit selection |
| `ReportAgent` | Findings reporting |
| `AgentOrchestrator` | Manages agents sequentially (`--agent` flag) |

---

## 4. Coding Rules

### 4.1 General Standards
- **Docstrings:** Required for every function and class.
- **Type Hints:** Mandatory. Example: `def scan(host: str, port: int) -> list[Finding]:`
- **Exceptions:** `except Exception:` is **FORBIDDEN**. Catch specific errors (`KeyError`, `httpx.TimeoutException`, etc.).
- **No magic numbers:** Constants must be defined at the top of the file.
- **Function length:** Max 25 lines. Split into helpers if larger.
- **Import order:** stdlib → third-party → local (blank line between each group).

### 4.2 Security
- `subprocess` → always use `shell=False` with list arguments.
- Network connections → always include `timeout` parameter (default: 5-10s).
- User input / DOM data → always sanitize.
- Sensitive data (passwords, tokens, cookies) → mask before logging (e.g., `admin:p***123`).
- Rate limiting → require explicit flags like `--brute` for aggressive operations.

### 4.3 Output & UI
- `print()` is **FORBIDDEN**. Always use `rich.console.Console` or `utils.colors`.
- Tables → `rich.table.Table`, warnings → `rich.panel.Panel`.
- Long-running operations → show `rich.progress` or `rich.status` (spinner).

### 4.4 AI Integration
- All AI communication → through `utils/ai.py`. Never hardcode API keys.
- Model name and base_url → must come from environment or CLI arguments.
- Always parse AI responses with `json.loads()` + `try-except` (hallucination guard).
- Always specify the expected JSON schema in AI prompts.

---

## 5. Adding a New Module

1. Check if a similar module already exists in `modules/` or `utils/`.
2. Write the runner function in `core/module_runners.py`.
3. Register it in `core/module_registry.py` under the appropriate phase (`AsyncModuleSpec` or `PhaseModuleSpec`).
4. Convert output to `Finding` dataclass — otherwise reporting breaks.
5. Add a new CLI flag in `core/scan_option_specs.py`.
6. Run `python3 scripts/generate_docs.py` → updates README/usagewithai automatically.
7. Write at least one unit test under `tests/`.

### Recommended Scan Order

When advising users or building scan profiles, follow this logical order:

```
 1. RECON + OSINT    → Port scan, Shodan, WHOIS, ASN
 2. TECH DETECT      → Technology fingerprinting (WordPress, Nginx, React, etc.)
 3. CLOUD + TAKEOVER → S3 bucket enum, subdomain takeover check
 4. FUZZER           → Hidden file/directory discovery
 5. CRAWLER          → Discover all pages and forms
 6. XSS + SQLi       → Most common web vulnerabilities
 7. SSTI + XXE       → Template and XML injection
 8. LFI + CMDi + SSRF→ File read, command execution, internal network
 9. API Scanner      → REST/GraphQL endpoint security
10. REDIRECT + CORS  → Configuration errors
11. SPRAY + EMAIL    → Credential testing + email harvesting
12. CHAIN + REPORT   → Attack chain analysis + report generation
```

### Module Dependency Map

Modules feed data into each other. Know the flow when recommending modules:

| Source Module | Feeds Into | Data Provided |
|---------------|-----------|---------------|
| `recon.py` | All modules | IP, server info, open ports, banners |
| `tech_detect.py` | All modules | Technology info → target-specific payloads |
| `crawler.py` | XSS, SQLi, LFI, CMDi, SSRF, CSRF, SSTI | Discovered URLs and forms |
| `fuzzer` | All modules | Hidden endpoints (admin panels, phpinfo) |
| `smart_payload.py` | xss, sqli, cmdi, lfi | Context-aware targeted payloads |
| `xss.py` | `xss_exploit.py` | Found XSS → cookie stealer, keylogger |
| `sqli.py` | `sqli_exploit.py` | Found SQLi → DB dump, table extraction |
| `cmdi.py` | `cmdi_shell.py`, `revshell.py` | Found CMDi → interactive/reverse shell |
| `recon.py` | `spray.py` | Open ports → default credential spray |
| `vuln_chain.py` | Reporting | All findings → attack chain analysis |

## 6. Testing Rules

- Framework: `pytest` + `pytest-asyncio`.
- **Global state cleanup:** Modules using global `set` objects (e.g., `_csp_checked_hosts`) must be `.clear()`'d before each test. Otherwise tests contaminate each other.
- **Mocking:** `rich.prompt`, `input()`, network calls → must be mocked with `unittest.mock.patch`. Tests hanging on input is **UNACCEPTABLE**.
- **Async tests:** Use `@pytest.mark.asyncio` decorator.
- Run tests: `pytest` (from root). All tests must pass.
- After documentation changes: run `python3 scripts/generate_docs.py` first, then `pytest tests/test_documentation.py`.

---

## 7. Commit Message Format

```
feat(xss): add DOM-based XSS scanning support
fix(sqli): fix blind SQLi timeout error
refactor(core): migrate module_runners to async
docs(readme): add usage examples for new modules
test(cmdi): add edge case tests
chore: remove temporary debug files
```

---

## 8. Critical File Dependency Map

When modifying a file, be aware of downstream effects:

| Change | Affected Files |
|--------|---------------|
| New module in `modules/` | `module_registry.py`, `module_runners.py`, `scan_option_specs.py`, `tests/` |
| `utils/finding.py` | `report.py`, `scanner.py`, `ai.py`, all exploit modules |
| `scan_option_specs.py` | `scan_options.py`, `test_scan_options.py`, `documentation.py`, `README.md` |
| `module_registry.py` | `test_module_registry.py`, `engine.py`, `scanner.py` |
| `request.py` | All modules (anything making HTTP requests) |
| `ai.py` | `agent_framework.py`, `ai_exploit_agent.py`, `ai_waf_agent.py` |

---

## 9. Important Disclaimer

**This tool is intended for use only on authorized systems, permitted CTF/Pentest platforms, and personal lab environments.**
When developing offensive features or exploit generation, always include this label:
> "This feature must be used within legal boundaries and authorized penetration testing engagements only."
