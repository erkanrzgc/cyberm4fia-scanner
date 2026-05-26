<h1 align="center">cyberm4fia-scanner</h1>

<p align="center">
  <img src="https://img.shields.io/badge/mission-offensive%20security%20via%20AI-red?style=for-the-badge" alt="mission">
</p>

<table align="center"><tr><td valign="middle">
<pre>
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ███╗██╗  ██╗███████╗██╗ █████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗ ████║██║  ██║██╔════╝██║██╔══██╗
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔████╔██║███████║█████╗  ██║███████║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╔╝██║╚════██║██╔══╝  ██║██╔══██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚═╝ ██║     ██║██║     ██║██║  ██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝
</pre>
</td><td valign="middle">
<img src="https://raw.githubusercontent.com/erkanrzgc/ai-house/main/resources/icons/icon_256.png" width="150">
</td></tr></table>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python" alt="python">
  <img src="https://img.shields.io/badge/modules-90+-purple?style=flat-square" alt="modules">
  <img src="https://img.shields.io/badge/skills-93%20AI%20methodologies-9cf?style=flat-square" alt="skills">
  <img src="https://img.shields.io/badge/tests-1250+%20passing-brightgreen?style=flat-square" alt="tests">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="license">
  <img src="https://img.shields.io/badge/AI-dual%20model%20NVIDIA%20NIM-orange?style=flat-square" alt="AI">
  <img src="https://img.shields.io/badge/output-SARIF%20%7C%20Burp%20XML%20%7C%20HTML%20%7C%20JSON-blueviolet?style=flat-square" alt="output">
  <img src="https://img.shields.io/badge/CI%2FCD-severity%20exit%20codes-yellow?style=flat-square" alt="ci">
  <img src="https://img.shields.io/github/last-commit/erkanrzgc/cyberm4fia-scanner?style=flat-square" alt="last commit">
</p>

<p align="center">
  <b>cyberm4fia-scanner</b> is an AI-powered autonomous penetration testing framework for web applications, APIs, networks, and cloud infrastructure.<br>
  <i>nuclei-fast scanning, Burp-deep verification, methodology-driven exploitation, ChatGPT-grade reasoning — in one box.</i>
</p>

---

## Why cyberm4fia-scanner

| What others give you | What cyberm4fia-scanner gives you |
|---|---|
| Template / fingerprint hits | **Verified exploits** — active verifiers (Playwright, preload list, polyglot probe) promote `Missing_*` advisories to `*_Exploitable` only when the bug is actually triggerable |
| A flat finding list | **Attack chain detection** — Missing CSP + reflected input → Stored XSS Exfil; Insecure Cookie + XSS → Cookie Theft Chain (deterministic patterns + AI-discovered chains) |
| 5-line CVE descriptions | **93 AI-loaded methodologies** (`core/ai_skills/`) — every offensive/defensive skill ships its own playbook the AI consults per finding |
| One huge `index.html` | **SARIF + Burp XML + Markdown + HTML + JSON + JSONL** — drop into GitHub Code Scanning, Burp Pro, DefectDojo, Jenkins warnings-ng, GitLab SAST without glue code |
| Hard fails / pass | **Per-severity exit codes** — `0` clean / `1` critical / `2` high / `3` medium / `4` low — gated by `SCAN_EXIT_THRESHOLD` so CI/CD pipelines pick their threshold |
| Vendor lock | **NVIDIA NIM only** — no OpenAI / Anthropic dependency; defaults to `meta/llama-3.3-70b-instruct`, dual-model routing for cost |
| "Re-run from scratch" on crash | **Phase-resume + URL-resume** — checkpoints persist per phase + per URL; resume continues right where you stopped |
| "Trust the results" | **0-day machine validation gates** — every finding traverses `suspected → evidence_confirmed → verified → exploitable` and SPA / catch-all 200s are dropped by a content-fingerprint filter |

### Core capabilities

- **90+ attack modules** spanning web, API, network, cloud, and OSINT — not just an `nmap` / `nuclei` wrapper.
- **Self-healing exploit agent** — the LLM writes exploit code, a sandbox runs it, and errors loop back as repair attempts until it works.
- **Adaptive LLM orchestration** — the planner reacts to recon + findings each round and chains discoveries (e.g. `LFI` → log poisoning → `RCE`) instead of running a fixed checklist.
- **External tool adapter layer** — battle-tested CLIs (`masscan`, `sslyze`, `wpscan`, `arjun`, `nuclei`, `gowitness`, `gitleaks`, `testssl.sh`, `smbmap`, `kube-hunter`, `CloudHunter`) plug in under one `BaseTool` contract.
- **MITRE ATT&CK tagged findings**, scope enforcement, and a sandboxed exploit runner — built for authorized testing, not pranks.

## Comparison vs other scanners

|                                       | **cyberm4fia** | nuclei  | OWASP ZAP | Burp Pro | Acunetix |
|---------------------------------------|:--------------:|:-------:|:---------:|:--------:|:--------:|
| Template-based detection              | ✅             | ✅      | ✅        | ✅       | ✅       |
| AI-driven exploit generation          | ✅             | ❌      | ❌        | ❌       | partial  |
| Skill / methodology-based reasoning   | ✅ (93 skills) | ❌      | ❌        | ❌       | ❌       |
| Multi-stage attack chain detection    | ✅ (det+AI)    | ❌      | ❌        | manual   | partial  |
| Content-fingerprint FP filter         | ✅ (simhash)   | ❌      | partial   | ❌       | ✅       |
| Active exploit verifiers (Playwright) | ✅             | ❌      | ❌        | ✅       | ✅       |
| 0-day validation gates                | ✅             | ❌      | ❌        | ❌       | ❌       |
| SARIF + Burp XML + DefectDojo         | ✅             | partial | partial   | native   | partial  |
| Per-severity CI exit codes            | ✅             | ❌      | partial   | ❌       | partial  |
| Phase-level scan resume               | ✅             | ❌      | ❌        | partial  | ❌       |
| Headless / SPA crawl                  | ✅             | ❌      | ✅        | ✅       | ✅       |
| Open source / self-hostable           | ✅             | ✅      | ✅        | ❌       | ❌       |

Niche: **AI-augmented offensive scanner with verifiable exploits** — between nuclei's template velocity, Burp's manual depth, and an AI assistant's reasoning.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  scanner.py / cyberm4fia CLI / REST API / Interactive wizard / MCP server   │
└────────────────────────────────────────┬────────────────────────────────────┘
                                         │
                       ┌─────────────────┴──────────────────┐
                       │   Phase pipeline (checkpointed)    │
                       └─────────────────┬──────────────────┘
                                         │
   ┌─────────────┬─────────────┬─────────┴────────┬──────────────┬───────────┐
   │   recon     │  discovery  │  per-URL active  │  post-scan   │  reporting│
   │ subdomain   │   crawler   │   XSS/SQLi/LFI   │ auth bypass  │ SARIF     │
   │ tech detect │  fuzzer     │   SSRF/CMDi/SST  │ business log │ Burp XML  │
   │ port scan   │  param disc │   CORS/CSRF/XXE  │ race / jwt   │ HTML/MD   │
   │ wayback     │  api spec   │   passive hooks  │ smuggle/proto│ findings  │
   └──────┬──────┴──────┬──────┴──────────┬───────┴──────┬───────┴───────────┘
          │             │                 │              │
          ▼             ▼                 ▼              ▼
   ┌─────────────────────────────────────────────────────────┐
   │  Cross-cutting: scope enforcement · request budget ·    │
   │  WAF auto-calibration · proxy interceptor · OOB client  │
   └─────────────────────────────────────────────────────────┘
                                         │
                       ┌─────────────────┴──────────────────┐
                       │       Finding pipeline             │
                       └─────────────────┬──────────────────┘
                                         │
        ┌────────────┬──────────┬────────┴────────┬───────────────┬──────────┐
        │ normalize  │  SPA-FP  │ active verifier │ chain detector│ AI:FP    │
        │ +registry  │  filter  │ (CJ/HSTS/MIME/  │ (det patterns │  + remed │
        │ +CVSS/CWE  │ (simhash)│  Referrer/Perm) │  + AI-discov) │  + skill │
        └────────────┴──────────┴─────────────────┴───────────────┴──────────┘
                                         │
                       ┌─────────────────┴──────────────────┐
                       │   Validation gates (0-day machine) │
                       │ suspected → evidence_confirmed →   │
                       │ verified → confirmed → exploitable │
                       └─────────────────┬──────────────────┘
                                         │
                                         ▼
                   ┌──────────────────────────────────────────┐
                   │ scans/<target>/ : report.html, .md,      │
                   │  results.sarif, issues.burp.xml,         │
                   │  findings.json, scan.json, pocs/*.html   │
                   └──────────────────────────────────────────┘
```

## What's new — last 3 sprints

- **`feat(verifiers+ci+exports)`** — 5 active verifiers (Clickjacking, HSTS, MIME, Referrer, Permissions-Policy), Burp Issues XML export, per-severity CI exit codes, GitHub Code Scanning SARIF upload, auth-session audit module, `docs/INTEGRATIONS.md`.
- **`feat(fp+headers)`** — SPA-fallback FP filter (simhash + DOM-skeleton + title hash), `Missing_Security_Header` → real exploit payload + chain promotion, 5 new offensive/defensive SKILL.md (clickjacking, hsts-downgrade, mime-confusion, referrer-policy-leak, defensive-fp-filter), 4 new chain patterns.
- **`feat(hardening)`** — Phase-boundary checkpoints in `ScanSession` (resume skips completed phases + persists mid-pipeline findings), real-binary integration suite for all 10 external tool wrappers, AI budget enforcement, sandboxed exploit runner.

## 60-Second Quick Start

```bash
git clone https://github.com/erkanrzgc/cyberm4fia-scanner.git
cd cyberm4fia-scanner
pip install -r requirements.txt

# Full passive + active scan
python3 scanner.py -u https://your-target.example/ --all

# + AI analysis (set NVIDIA_API_KEY first)
export NVIDIA_API_KEY=nvapi-...
python3 scanner.py -u https://your-target.example/ --all --ai
```

## Demo

<!--
Drop a demo recording here once captured, e.g.:
  ![demo](docs/demo.gif)
  [![asciicast](https://asciinema.org/a/XXXXX.svg)](https://asciinema.org/a/XXXXX)
-->
_Demo recording coming soon — try `python3 scanner.py --help` or jump into Quick Start above._

---

## Features

<!-- BEGIN GENERATED: feature_tables -->
### Web Application Scanning
| Module | Flag | Description |
|---|---|---|
| XSS | `--xss` | Reflected and stored XSS checks with context-aware payload selection. |
| SQLi | `--sqli` | Union-based SQL injection with blind fallback and exploit post-processing. |
| LFI | `--lfi` | Local File Inclusion checks against traversal and wrapper payloads. |
| RFI | `--rfi` | Remote File Inclusion checks for remote fetch and execution sinks. |
| CMDi | `--cmdi` | OS command injection checks with optional interactive shell workflow. |
| SSRF | `--ssrf` | Server-Side Request Forgery checks including cloud metadata probes. |
| CSRF | `--csrf` | CSRF token and form protection checks for discovered forms. |
| CORS | `--cors` | Cross-Origin Resource Sharing misconfiguration checks. |
| Header Injection | `--header-inject` | CRLF and header injection checks. |
| DOM XSS | `--dom-xss` | DOM-based XSS checks with Playwright browser execution. |
| SSTI | `--ssti` | Template injection checks for common server-side template engines. |
| XXE | `--xxe` | XML External Entity injection checks. |
| Open Redirect | `--redirect` | Redirect abuse checks across discovered URLs. |
| Passive Scan | `--passive` | Passive checks for headers, debug leakage, and lightweight disclosures. |
| Secrets Scan | `--secrets` | HTML and JavaScript secret exposure scanning for API keys and tokens. |
| OOB Testing | `--oob` | Out-of-band callback support for blind vulnerability verification. |

### API Security
| Module | Flag | Description |
|---|---|---|
| API Scanner | `--api-scan` | OWASP API tests with OpenAPI import, schema-aware bodies, and auth intel. |

### Network & Infrastructure
| Module | Flag | Description |
|---|---|---|
| Recon | `--recon` | Deep port, DNS, and TLS recon. Lightweight server and header intel runs on every scan. |
| Subdomain Discovery | `--subdomain` | Subdomain enumeration for the target host. |
| Endpoint Fuzzer | `--fuzz` | Directory and API endpoint brute forcing with smart 404 calibration. |
| Crawler | `--crawl` | Recursive crawler with form and link discovery. |
| Headless Discovery | `--headless` | Playwright-based SPA rendering and background endpoint discovery. |
| Cloud Buckets | `--cloud` | Open S3, Azure Blob, and GCP bucket detection. |
| Subdomain Takeover | `--takeover` | Dangling DNS and takeover fingerprint checks. |
| Credential Spray | `--spray` | Default credential checks for exposed services. |

### Intelligence & OSINT
| Module | Flag | Description |
|---|---|---|
| Technology Fingerprinting | `--tech` | Wappalyzer-style technology detection with CVE enrichment. |
| OSINT Enrichment | `--osint` | Shodan InternetDB, WHOIS, and ASN enrichment. |
| Email Harvesting | `--email` | Email discovery from public sources and on-page content. |

### Automation & Reporting
| Module | Flag | Description |
|---|---|---|
| JWT Attack Suite | `--jwt` | Weak secret, algorithm confusion, and claim tampering checks. |
| Race Condition | `--race` | TOCTOU and replay-style concurrency checks. |
| HTTP Smuggling | `--smuggle` | CL.TE and TE.CL request smuggling checks. |
| Prototype Pollution | `--proto` | Node.js prototype pollution probes. |
| Deserialization | `--deser` | Insecure deserialization checks. |
| Business Logic | `--bizlogic` | Multi-step business logic flaw checks. |
| Vulnerability Chaining | `--chain` | Attack path correlation across discovered findings. |
| Wordlist Generation | `--wordlist` | Site-specific password wordlist generation. |
| AI Analysis | `--ai` | Dual-model AI with autonomous exploit agent, PoC generation, and false-positive filtering. |
| Proxy Interceptor | `--proxy-listen PORT` | Built-in MITM proxy to capture traffic and feed scanner workflows. |
| PoC Generator | `(auto)` | Automatic HTML and JSON proof-of-concept generation for findings. |
| Template Engine | `(auto via --all)` | Built-in template-based checks that can be enabled through all-modules mode. |
<!-- END GENERATED: feature_tables -->

---

## Quick Start

The scanner now defaults to a powerful **Interactive Setup Wizard** built with `rich`. You can easily run it from anywhere in your terminal by just passing the target URL:

```bash
# Start Interactive Interface directly with a target
cyberm4fia https://target.com
```

This will instantly display the banner and directly ask you for the scan modes, attack profiles, and runtime behavior!

If you prefer classical CLI usage:

```bash
# Full scan via CLI
python3 scanner.py -u https://target.com --all

# Specific modules
python3 scanner.py -u https://target.com --xss --sqli

# API scan with local OpenAPI spec
python3 scanner.py -u https://api.target.com --api-scan --api-spec openapi.yaml

# Multi-target
python3 scanner.py -l targets.txt --all

# Through proxy
python3 scanner.py -u https://target.com --all --proxy socks5://127.0.0.1:9050

# Session resume
python3 scanner.py --resume scan1.json
```

---

## 🧨 Active Exploitation Framework

cyberm4fia-scanner goes beyond finding vulnerabilities—it verifies and exploits them. By selecting an attack profile that supports it, or simply passing the `--exploit` flag, the scanner activates post-exploitation modules:

- **Interactive Shells:** Catch reverse shells automatically when Command Injection or RCE is discovered.
- **Out-of-Band (OOB) Testing:** Spin up local HTTP listeners to detect blind/asynchronous vulnerabilities (supports auto-port fallback).
- **Automated Looting:** Extract and dump database contents (SQLi) or grab sensitive system files (LFI) directly into a `loot/` directory.
- **Offline PoC Generation:** Generate standalone `.html` or `.json` artifacts that securely demonstrate the exact vulnerability (e.g. Clickjacking, CSRF HTML forms).
- **Auto-Pwn Hand-off:** Automatically generates ready-to-run Nuclei templates or MSF (Metasploit) commands to reproduce and exploit findings.
- **Headless Browser Escalation:** Uses Playwright to drive active DOM XSS or CSRF payload execution directly within a real headless Chromium instance.

---

## 🛡️ Built-in Proxy Interceptor

You can route your manual browser traffic directly through the scanner using the built-in MITM proxy.

```bash
# Starts proxy on port 8081 specifically scoped to target.com
python3 scanner.py --proxy-listen 8081 --scope-proxy target.com
```

Any traffic you generate through your browser will be automatically intercepted, fed into the main scanning engine, and dynamically tested for vulnerabilities in real-time.

---

## Usage with AI

The scanner integrates an **NVIDIA-powered AI system** for autonomous exploit generation, intelligent analysis, and automated PoC creation.

### Prerequisites

You need an **NVIDIA API Key**. Set it as an environment variable:

```bash
export NVIDIA_API_KEY="your_nvapi_key_here"
```

### AI-Powered Scanning

```bash
# Full scan with AI enabled (NVIDIA API)
python3 scanner.py -u https://target.com --all --ai

# AI + specific modules
python3 scanner.py -u https://target.com --xss --sqli --ai

# Run Multi-Agent Autonomous Agent mode
python3 scanner.py -u https://target.com --agent --ai
```

### Unified AI Architecture (70B)

Both exploit and code generation roles now utilize the high-performance **meta/llama-3.3-70b-instruct** model via NVIDIA NIM for maximum fidelity:

| Role | Implementation | What It Does |
|---|---|---|
| 🐇 **Exploit Agent** | Llama 3.3 70B | Payload crafting, WAF bypass, exploit planning, false-positive filtering |
| 🧠 **Code Agent** | Llama 3.3 70B | PoC script writing, remediation code, code analysis |

### AI Exploit Agent

When standard payload lists fail, the **Autonomous AI Exploit Agent** takes over:

```
Static Payloads → Smart Probes → WAF Mutation → AI Exploit Agent
                                                       ↓
                                              Think → Generate → Execute
                                              → Validate → Learn (3 rounds)
                                                       ↓
                                              PoC: cURL + Python + Nuclei
```

**Supported vulnerability types:** XSS, SQLi, LFI, CMDi, SSRF

**Anti-hallucination pipeline:** Every AI-generated exploit is validated with regex checks + AI double-verification. Confidence below 70% is automatically rejected.

### Public Exploit Intelligence

The scanner automatically searches for known public exploits when CVEs are discovered:

```
Technology Detected → SiberAdar CVE Feed → Public Exploit Search
                                                  ↓
                                    ExploitDB (searchsploit) — offline archive
                                    GitHub PoC — starred repositories
                                    sploitscan — multi-source aggregation
                                                  ↓
                                    AI Agent uses real PoCs as templates
```

Optional tools for enhanced coverage:

```bash
# ExploitDB offline archive
sudo apt install exploitdb

# Multi-source exploit search
pip3 install sploitscan
```

### AI Features Summary

| Feature | Description |
|---|---|
| **Autonomous Exploit Agent** | Iterative think→generate→execute→validate→learn loop |
| **Dual-Model Routing** | WhiteRabbitNeo for exploits, Qwen3-Coder for code |
| **Anti-Hallucination** | Regex + AI verification, 70% confidence threshold |
| **PoC Generation** | Auto-generates cURL, Python scripts, Nuclei templates |
| **Exploit Chain Detection** | 7 built-in patterns + AI-discovered chains |
| **Public Exploit Search** | ExploitDB, GitHub, sploitscan integration |
| **WAF Bypass Mutation** | Evolving AI mutation engine for adaptive bypass |
| **False Positive Filtering** | AI-assisted validation reduces noise |
| **Remediation Guidance** | AI-generated code fixes and best practices |
| **Executive Summaries** | AI-written C-level security reports |

---

## Scan Modes

<!-- BEGIN GENERATED: scan_modes -->
| Mode | Delay | Threads | Use Case |
|---|---|---|---|
| `normal` | 0.5s | 10 | Balanced default mode for most targets. |
| `stealth` | 3.0s | 1 | Slow, low-noise mode for cautious testing. |
| `lab` | 0.05s | 30 | High-noise mode for local labs, staging, and CTF environments only. |
<!-- END GENERATED: scan_modes -->

---

## Attack Profiles

<!-- BEGIN GENERATED: attack_profiles -->
| Profile | Coverage | Included Flags | Suggested Extras |
|---|---|---|---|
| `1-Fast Recon` | Recon, subdomain discovery, endpoint fuzzing, technology intel, and passive checks. | `--fuzz`, `--passive`, `--recon`, `--subdomain`, `--tech` | `--crawl`, `--osint`, `--headless` |
| `2-Core Web Vulns` | Core web checks like XSS, SQLi, file inclusion, CMDi, CSRF, CORS, and DOM XSS. | `--cmdi`, `--cors`, `--csrf`, `--dom-xss`, `--header-inject`, `--lfi`, `--passive`, `--rfi`, `--sqli`, `--xss` | `--secrets`, `--oob`, `--headless`, `--exploit` |
| `3-Advanced / Modern` | JWT, deserialization, SSTI, race, prototype pollution, SSRF, business logic, API, OOB, and XXE coverage. | `--api-scan`, `--ato`, `--auth-bypass`, `--bizlogic`, `--deser`, `--file-upload`, `--forbidden-bypass`, `--jwt`, `--oob`, `--proto`, `--race`, `--redirect`, `--smuggle`, `--ssrf`, `--ssti`, `--xxe` | `--tech`, `--passive`, `--chain`, `--exploit` |
| `4-All-In-One` | Enables nearly every scan module except opt-in extras like AI and SARIF. | `(auto via --all)`, `--api-scan`, `--ato`, `--auth-bypass`, `--bizlogic`, `--chain`, `--cloud`, `--cmdi`, `--cors`, `--crawl`, `--csrf`, `--deser`, `--dom-xss`, `--dorking`, `--email`, `--file-upload`, `--forbidden-bypass`, `--fuzz`, `--har-output`, `--header-inject`, `--headless`, `--html`, `--jwt`, `--lfi`, `--oob`, `--osint`, `--passive`, `--proto`, `--race`, `--recon`, `--redirect`, `--rfi`, `--secrets`, `--smuggle`, `--spray`, `--sqli`, `--ssrf`, `--ssti`, `--subdomain`, `--takeover`, `--tech`, `--urlscan`, `--wayback`, `--xss`, `--xxe`, `Git History Secret Scanner (white-box + exposed-.git probe)`, `Multi-Provider Asset Search (Censys/ZoomEye/FOFA/Onyphe/Netlas/FullHunt/LeakIX)`, `Nuclei Community Templates`, `SSH/FTP Brute-Force`, `Scan Drift Detection` | `--wordlist`, `--exploit` |
| `5-Custom Choice` | Ask every module prompt one by one. | `manual selection` | - |
| `6-Web Recon + Audit` | OctoScan-style web chain: tech intel + nuclei community templates + endpoint fuzz + crawl + 7-provider asset search + passive. | `--cookie COOKIE`, `--cors`, `--crawl`, `--fuzz`, `--header-inject`, `--passive`, `--recon`, `--subdomain`, `--tech`, `Multi-Provider Asset Search (Censys/ZoomEye/FOFA/Onyphe/Netlas/FullHunt/LeakIX)`, `Nuclei Community Templates`, `csp_bypass` | `--secrets`, `git_history` |
<!-- END GENERATED: attack_profiles -->

---

## CI/CD & Integrations

Every scan emits **SARIF** (`results.sarif`), **Burp Issues XML** (`issues.burp.xml`), enhanced JSON, HTML, Markdown, and PoC HTMLs. Import targets:

| Target | Format | One-liner |
|---|---|---|
| **GitHub Code Scanning** | SARIF | upload via `github/codeql-action/upload-sarif@v3` (already wired in `.github/workflows/security-scan.yml`) |
| **Burp Suite Pro** | Burp Issues XML | *Project → Import issues → `issues.burp.xml`* |
| **DefectDojo** | SARIF or Burp XML | API: `POST /api/v2/import-scan/` (see `docs/INTEGRATIONS.md`) |
| **Jenkins** | SARIF | `recordIssues(tools: [sarif(pattern: 'scans/**/results.sarif')])` |
| **GitLab Ultimate** | SARIF as SAST | `artifacts.reports.sast: scans/*/results.sarif` |

### Per-severity exit codes for pipeline gating

```bash
python3 scanner.py -u https://my-app/ --xss --sqli --sarif
# exit 0 = clean
# exit 1 = CRITICAL findings
# exit 2 = HIGH findings
# exit 3 = MEDIUM findings
# exit 4 = LOW/INFO findings
# exit 10 = scanner internal error
```

Pick a threshold with `SCAN_EXIT_THRESHOLD=critical|high|medium|low|info|never`. Full mapping table + Burp / DefectDojo / Jenkins / GitLab examples in **[`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md)**.

---

## REST API

The scanner includes a FastAPI-based REST API with auto-generated documentation.

```bash
python3 scanner.py --api --port 8080
```

| Endpoint | Method | Description |
|---|---|---|
| `/api/scan` | POST | Start a new scan |
| `/api/scan/{id}` | GET | Get scan results |
| `/api/scans` | GET | List all scans |
| `/api/report/{id}` | GET | Download HTML report |
| `/api/scan/{id}` | DELETE | Cancel a scan |
| `/docs` | GET | Swagger UI |
| `/redoc` | GET | ReDoc |

---

## Project Structure

```
cyberm4fia-scanner/
├── scanner.py              # main orchestrator
├── api_server.py           # FastAPI REST API
├── modules/                # 40+ scanning modules
├── utils/                  # HTTP client, WAF detection, auth, AI engine
│   ├── ai.py               # dual-model AI client (WhiteRabbitNeo + Qwen3-Coder)
│   ├── ai_exploit_agent.py  # autonomous exploit agent + chain detector
│   └── exploit_finder.py   # ExploitDB, GitHub PoC, sploitscan search
├── payloads/               # XSS, SQLi, LFI, SSRF, CMDi payload files
├── wordlists/              # fuzzer wordlists
├── tests/                  # pytest test suite (470+ tests)
├── .github/workflows/      # CI/CD pipelines
├── .env.example            # environment variable template
└── requirements.txt        # dependencies
```

---

## Configuration

Copy `.env.example` to `.env` and set your values:

```bash
cp .env.example .env
```

| Variable | Description |
|---|---|
| `NVIDIA_API_KEY` | NVIDIA NIM API key for AI-powered scanning |
| `WATCHSTACK_API_KEY` | WatchStack.io API key for verified PoC intelligence (free tier: 30 req/min) |
| `GITHUB_TOKEN` | GitHub API token for higher rate limits on PoC search |
| `SHODAN_API_KEY` | Shodan API key for OSINT enrichment |
| `DEFAULT_THREADS` | Default thread count |
| `DEFAULT_DELAY` | Default request delay |
| `VERIFY_SSL` | SSL verification toggle |
| `HTTP_PROXY` | Proxy URL |

---

## Testing

```bash
pip install pytest
pytest tests/ -v
```

---

## Legal Disclaimer

> **This tool is for authorized security testing and educational purposes only.**
> Unauthorized scanning of systems you do not own or have permission to test is illegal.
> The developers assume no liability for misuse.

---

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
