# cyberm4fia-scanner — AI Advisor Guide

> This file is designed to help an AI assistant understand, correctly use, and advise users on this scanner tool.

---

📌 Overview

cyberm4fia-scanner is a Python-based modular Red Team security scanning platform. It covers web application, network, API, cloud, and OSINT scanning capabilities. The main entry point is `scanner.py`.

**Run via Wizard:** `python3 scanner.py` (Fully interactive setup for target, AI, proxy, and exploit follow-ups)
**Run via CLI:** `python3 scanner.py -u <target> [flags...]`

---

## ⚡ Key Highlights for AI Advisors

When guiding users, emphasize these powerful features:
- **Interactive Setup:** Tell the user to run `python3 scanner.py` without arguments for a guided setup. It asks for attack profiles and handles AI setup.
- **Active Exploitation (`--exploit`):** For RCE/SQLi/XSS, enabling this feature pops interactive shells, generates standalone reverse shells, extracts DB schemas (loot), and outputs standalone offline HTML/JSON PoC exploits into the `pocs/` directory.
- **Auto-Pwn Hand-off:** Automatically generates ready-to-run Nuclei templates and Metasploit commands for discovered vulnerabilities.
- **MITM Proxy Interceptor (`--proxy-listen 8081`):** Captures manual browser traffic and feeds it into the scanner asynchronously.
- **Out-of-Band (OOB):** Automatically starts an auto-incrementing HTTP listener to catch blind SSRF/XSS/RFI callbacks.

---

## 🧩 Module Map

```
scanner.py                          ← Main orchestrator
├── modules/
│   ├── recon.py                    ← Server discovery (asyncio port scan + banner, header, SSL, DNS)
│   ├── subdomain.py                ← Subdomain enumeration
│   ├── fuzzer.py                   ← Directory/file discovery (smart 404 calibration)
│   ├── crawler.py                  ← Sitemap + JS endpoint extraction
│   ├── xss.py                      ← XSS scanning (Reflected + Stored)
│   │   ├── smart_payload.py        ← 🧠 Context-aware payload generator
│   │   └── xss_exploit.py          ← Cookie stealer, keylogger generator
│   ├── sqli.py                     ← SQL Injection (Union + Blind)
│   │   └── sqli_exploit.py         ← DB extraction, table/column dump
│   ├── lfi.py                      ← Local File Inclusion
│   ├── rfi.py                      ← Remote File Inclusion
│   ├── cmdi.py                     ← Command Injection
│   │   └── cmdi_shell.py           ← Interactive shell
│   ├── dom_xss.py                  ← DOM-based XSS (requires Playwright)
│   ├── ssrf.py                     ← Server-Side Request Forgery
│   ├── csrf.py                     ← Cross-Site Request Forgery
│   ├── cors.py                     ← CORS misconfiguration
│   ├── header_inject.py            ← HTTP Header Injection
│   ├── ssti.py                     ← Server-Side Template Injection
│   ├── xxe.py                      ← XML External Entity Injection
│   ├── open_redirect.py            ← Open Redirect Scanner
│   ├── spray.py                    ← Credential Sprayer (SSH/FTP/MySQL/Redis)
│   ├── api_scanner.py              ← API Security (OWASP API Top 10 + OpenAPI import + body/auth extraction + placeholder injection)
│   ├── cloud_enum.py               ← Cloud Bucket Enumeration (S3/Azure/GCP)
│   ├── subdomain_takeover.py       ← Subdomain Takeover Detection
│   ├── tech_detect.py              ← Technology Fingerprinting
│   ├── email_harvest.py            ← Email Harvester
│   ├── race_condition.py           ← Race Condition / TOCTOU Scanner
│   ├── dom_static.py               ← DOM Static Analysis
│   ├── payloads.py                 ← Static payload lists
│   ├── report.py                   ← HTML/JSON/TXT report generator
│   ├── compare.py                  ← Two-scan comparison
│   ├── poc_generator.py            ← Auto-generates exploit PoC HTML/JSON files
│   ├── proxy_interceptor.py        ← MITM Proxy to capture manual browser traffic
│   └── template_engine.py          ← Nuclei-style YAML template runner
└── utils/
    ├── colors.py                   ← Colored logging
    ├── request.py                  ← HTTP request management (httpx, session, proxy, WAF, auth)
    ├── async_request.py            ← Async HTTP with httpx.AsyncClient (HTTP/2)
    ├── auth.py                     ← AuthChain (token, cookie, header auth)
    ├── waf.py                      ← WAF fingerprinting (22 vendors) + adaptive evasion
    ├── oob.py                      ← Out-of-Band callback client
    ├── revshell.py                 ← Reverse Shell payload generator
    ├── vuln_chain.py               ← Vulnerability Chaining engine
    ├── wordlist_gen.py             ← CeWL-style wordlist generator
    └── shodan_lookup.py            ← Shodan/WHOIS/ASN OSINT
```

---

## 🔗 Module Dependencies

### Which modules feed into each other?

| Source Module | Target Module | How? |
|---|---|---|
| `recon.py` | All | IP, server info, open ports, banners |
| `crawler.py` | XSS, SQLi, LFI, CMDi, SSRF, CSRF, SSTI, Redirect | Provides discovered URLs to all modules |
| `fuzzer.py` | All | Hidden endpoints (admin panel, phpinfo) |
| `smart_payload.py` | `xss.py`, `sqli.py`, `cmdi.py`, `lfi.py` | Generates context-aware targeted payloads |
| `xss.py` | `xss_exploit.py` | Found XSS → cookie stealer, keylogger |
| `sqli.py` | `sqli_exploit.py` | Found SQLi → DB dump, table extraction |
| `cmdi.py` | `cmdi_shell.py`, `revshell.py` | Found CMDi → interactive or reverse shell |
| `recon.py` | `spray.py` | Open ports → default credential spray |
| `tech_detect.py` | All | Technology info → target-specific payload strategy |
| `vuln_chain.py` | Reporting | All findings → attack chain analysis |
| `shodan_lookup.py` | Recon | CVE, hostname, ASN info |
| `email_harvest.py` | Spray, OSINT | Email addresses → social engineering |

### Recommended Scan Order

```
1. RECON + OSINT   → Port scan, Shodan, WHOIS, ASN
2. TECH DETECT     → Technology detection (WordPress, Nginx, React, etc.)
3. CLOUD + TAKEOVER→ S3 bucket, subdomain takeover check
4. FUZZER          → Hidden file/directory discovery
5. CRAWLER         → Discover all pages and forms
6. XSS + SQLi      → Most common vulnerabilities
7. SSTI + XXE      → Template and XML injection
8. LFI + CMDi + SSRF → File read, command execution, internal network
9. API Scanner     → REST/GraphQL endpoint security
10. REDIRECT + CORS → Configuration errors
11. SPRAY + EMAIL   → Credential testing + email harvesting
12. WORDLIST + CHAIN → Generate wordlist + attack chain analysis
```

---

## ⚡ Scan Modes

<!-- BEGIN GENERATED: scan_modes -->
| Mode | Delay | Threads | Use Case |
|---|---|---|---|
| `normal` | 0.5s | 10 | Balanced default mode for most targets. |
| `stealth` | 3.0s | 1 | Slow, low-noise mode for cautious testing. |
| `lab` | 0.05s | 30 | High-noise mode for local labs, staging, and CTF environments only. |
<!-- END GENERATED: scan_modes -->

**AI Advice:** Use `stealth` or `normal` on real targets. Use `lab` only on local labs, staging, or CTF-style environments.

---

## 🎛️ Attack Profiles

<!-- BEGIN GENERATED: attack_profiles -->
| Profile | Coverage | Included Flags | Suggested Extras |
|---|---|---|---|
| `1-Fast Recon` | Recon, subdomain discovery, endpoint fuzzing, technology intel, and passive checks. | `--fuzz`, `--passive`, `--recon`, `--subdomain`, `--tech` | `--crawl`, `--osint`, `--headless` |
| `2-Core Web Vulns` | Core web checks like XSS, SQLi, file inclusion, CMDi, CSRF, CORS, and DOM XSS. | `--cmdi`, `--cors`, `--csrf`, `--dom-xss`, `--header-inject`, `--lfi`, `--passive`, `--rfi`, `--sqli`, `--xss` | `--secrets`, `--oob`, `--headless`, `--exploit` |
| `3-Advanced / Modern` | JWT, deserialization, SSTI, race, prototype pollution, SSRF, business logic, API, OOB, and XXE coverage. | `--api-scan`, `--ato`, `--auth-bypass`, `--bizlogic`, `--deser`, `--file-upload`, `--forbidden-bypass`, `--jwt`, `--oob`, `--proto`, `--race`, `--redirect`, `--smuggle`, `--ssrf`, `--ssti`, `--xxe` | `--tech`, `--passive`, `--chain`, `--exploit` |
| `4-All-In-One` | Enables nearly every scan module except opt-in extras like AI and SARIF. | `(auto via --all)`, `--api-scan`, `--ato`, `--auth-bypass`, `--bizlogic`, `--chain`, `--cloud`, `--cmdi`, `--cors`, `--crawl`, `--csrf`, `--deser`, `--dom-xss`, `--email`, `--file-upload`, `--forbidden-bypass`, `--fuzz`, `--header-inject`, `--headless`, `--html`, `--jwt`, `--lfi`, `--oob`, `--osint`, `--passive`, `--proto`, `--race`, `--recon`, `--redirect`, `--rfi`, `--secrets`, `--smuggle`, `--spray`, `--sqli`, `--ssrf`, `--ssti`, `--subdomain`, `--takeover`, `--tech`, `--xss`, `--xxe`, `SSH/FTP Brute-Force`, `Scan Drift Detection` | `--wordlist`, `--exploit` |
| `5-Custom Choice` | Ask every module prompt one by one. | `manual selection` | - |
<!-- END GENERATED: attack_profiles -->

---

## 🍪 Cookie Setup

For targets requiring authentication, set cookies:

```
Cookie (leave empty for none): security=low; PHPSESSID=abc123def456
```

**IMPORTANT:** Cookie format is `key=value; key2=value2`. Do NOT use quotes.

---

## 🎯 CLI Usage Examples

### Full scan (everything enabled)
```bash
python3 scanner.py -u https://target.com --all
```

### XSS + SQLi only
```bash
python3 scanner.py -u https://target.com --xss --sqli --cookie "session=abc123"
```

### OSINT + Cloud + Takeover
```bash
python3 scanner.py -u https://target.com --osint --cloud --takeover --tech
```

### Multi-target scan
```bash
python3 scanner.py -l targets.txt --all
```

### Scan through Tor
```bash
python3 scanner.py -u https://target.com --all --proxy socks5://127.0.0.1:9050
```

### DVWA test
```bash
python3 scanner.py -u http://192.168.1.100/dvwa/ --xss --sqli --lfi --cmdi \
  --cookie "security=low; PHPSESSID=YOUR_SESSION_ID"
```

### API security scan
```bash
python3 scanner.py -u https://api.target.com --api-scan --tech
```

### API security scan with local OpenAPI spec
```bash
python3 scanner.py -u https://api.target.com --api-scan --api-spec openapi.yaml
```

### Two-scan comparison
```bash
python3 scanner.py --compare scans/target_1/ scans/target_2/
```

---

## 📁 Output Files

Each scan creates results under `scans/<target>/`:

| File | Content |
|---|---|
| `scan.txt` | Full scan log (terminal output) |
| `scan_results.json` | Machine-readable results |
| `report.html` | Visual HTML report |
| `payloads.txt` | List of successful payloads |
| `wordlist.txt` | Site-specific wordlist (if wordlist mode enabled) |

---

## 🔧 All CLI Flags

<!-- BEGIN GENERATED: cli_flags -->
### Target & Scope
| Flag | Description |
|---|---|
| `-u URL, --url URL` | Target URL |
| `--compare SCAN1 SCAN2` | Compare two scan dirs |
| `-l TARGET_LIST, --list TARGET_LIST` | File with list of target URLs |
| `--scope SCOPE` | Scope include patterns (comma-separated, e.g. '*.target.com') |
| `--exclude EXCLUDE` | Scope exclude patterns (comma-separated, e.g. '/logout,*.pdf') |
| `--session SESSION` | Session file for save/resume (e.g. scan1.json) |
| `--resume RESUME` | Resume scan from session file |

### Scan Modules
| Flag | Description |
|---|---|
| `--all` | Enable ALL scan modules |
| `--xss` | Enable XSS scan |
| `--sqli` | Enable SQLi scan |
| `--lfi` | Enable LFI scan |
| `--rfi` | Enable RFI scan |
| `--cmdi` | Enable Command Injection scan |
| `--dom-xss` | Enable DOM XSS scan |
| `--secrets` | Scan for Secrets & API Keys in JS/HTML |
| `--recon` | Enable deep server recon (extended port/DNS/TLS checks) |
| `--subdomain` | Enable Subdomain scan |
| `--fuzz` | Enable High-Speed API/Directory Fuzzer |
| `--ssrf` | Enable SSRF scan |
| `--oob` | Enable Out-Of-Band (OOB) testing |
| `--csrf` | Enable CSRF scan |
| `--cors` | Enable CORS check |
| `--header-inject` | Enable Header Injection scan |
| `--crawl` | Enable Crawling |
| `--passive` | Enable passive scanning (header/secret/debug checks) |
| `--cloud` | Scan for open cloud buckets (S3/Azure/GCP) |
| `--takeover` | Scan for subdomain takeover |
| `--tech` | Technology fingerprinting |
| `--api-scan` | API security scan (OWASP API Top 10) |
| `--api-spec FILE` | Local OpenAPI/Swagger JSON or YAML file for API scanning |
| `--ssti` | SSTI (Template Injection) scan |
| `--xxe` | XXE (XML External Entity) scan |
| `--redirect` | Open Redirect scan |
| `--spray` | Default credential spraying |
| `--email` | Email harvesting |
| `--osint` | OSINT enrichment (Shodan/Whois) |
| `--chain` | Vulnerability chaining analysis |
| `--wordlist` | Generate site-specific wordlist |
| `--headless` | Use headless browser for SPA rendering (requires playwright) |
| `--race` | Race condition scanner |
| `--jwt` | JWT attack suite |
| `--smuggle` | HTTP request smuggling scanner (CL.TE/TE.CL) |
| `--proto` | Prototype pollution scanner (Node.js) |
| `--deser` | Insecure deserialization scanner |
| `--bizlogic` | Business logic flaw scanner |

### Runtime & Output
| Flag | Description |
|---|---|
| `-m MODE, --mode MODE` | Scan mode (normal, stealth, lab). Legacy aliases: 1/2=normal, 3=lab, 4=stealth |
| `-c COOKIE, --cookie COOKIE` | Session cookie (e.g. 'PHPSESSID=...') |
| `--quiet, -q` | Quiet mode (only show vulns/errors) |
| `--wordlist-file FILE` | Custom wordlist for Fuzzer |
| `--html` | Generate HTML report |
| `--json` | Save JSON report |
| `--sarif` | Save SARIF report (for GitHub Security tab) |
| `--tamper TAMPER` | Tamper scripts for WAF bypass (comma-separated, e.g. space2comment,randomcase) |
| `-t THREADS, --threads THREADS` | Number of threads |
| `--proxy PROXY_URL` | Proxy URL (http/socks5, e.g. socks5://127.0.0.1:9050) |
| `--ai` | Enable AI analysis (Ollama, local & free). Requires Ollama running. |
| `--ai-model AI_MODEL` | Ollama model (default: WhiteRabbitNeo-Llama-3.1-8B) |
| `--ollama-url OLLAMA_URL` | Ollama server URL (default: http://192.168.6.1:11434) |

### Service Modes
| Flag | Description |
|---|---|
| `--api` | Start REST API server mode |
| `--port PORT` | API server port (default: 8080) |
| `--proxy-listen PORT` | Start local MITM proxy to automatically scan intercepted traffic (e.g., 8081) |
| `--scope-proxy DOMAIN` | Target domain for the proxy interceptor (e.g., wisarc.com) |

### Other
| Flag | Description |
|---|---|
| `-h, --help` | show this help message and exit |
| `--exploit` | Enable exploit follow-up actions/prompts after scan results |
| `--forbidden-bypass` | 403/401 forbidden bypass scanner |
| `--file-upload` | File upload vulnerability scanner |
| `--ato` | Account takeover scanner |
| `--auth-bypass` | 2FA & authentication bypass scanner |
| `--max-requests N` | Stop a scan after N requests (0 disables the budget) |
| `--request-timeout SECONDS` | Default per-request timeout in seconds |
| `--max-host-concurrency N` | Limit simultaneous in-flight requests per host (0 disables the limit) |
| `--path-blacklist PATTERNS` | Comma-separated risky path patterns to skip (e.g. '/logout,/checkout') |
| `--agent` | Run Multi-Agent autonomous pentesting mode (bypasses standard modules) |
<!-- END GENERATED: cli_flags -->

---

## 🧠 Smart Payload Engine — How It Works

```
Step 1: Send harmless probe ("cybm4f1a7357")
         └→ Find where it lands in the response

Step 2: Send character probe (<"'>/()\`&)
         └→ Which characters are filtered?

Step 3: Send keyword probe (script, alert, onerror, img, svg...)
         └→ Which keywords are blocked?

Step 4: Generate targeted payload using context + filter + keyword info
         └→ Apply mutation bypass for blocked keywords

Step 5: Try smart payloads first, fall back to static list if needed
```

---

## 🏗️ Architecture Highlights

- **Single HTTP library:** `httpx` for both sync and async (HTTP/2 support)
- **WAF detection:** 22 vendor fingerprints with adaptive evasion
- **User-Agent rotation:** 22 browser agents (desktop + mobile)
- **Rate limiting:** HTTP 429 auto-backoff with Retry-After support
- **Secret management:** `.env` + `python-dotenv` (never hardcode API keys)
- **API server:** FastAPI with auto-generated Swagger UI (`/docs`) and ReDoc (`/redoc`)
- **Testing:** pytest with 38 unit tests
- **AI Vulnerability Deduplication:** Advanced AI filtering combining duplicated parameter hits and pruning Info/Low findings to optimize execution times.
- **MITM Proxy Interception:** Built on `mitmproxy`, captures and filters in-flight traffic for targeted scoping.
- **PoC Engine:** Produces functional `.html` proof-of-concept exploits (e.g. Clickjacking, MIME sniffing).
- **CI/CD:** GitHub Actions pipeline (lint + test + compile-check)

---

## ⚠️ Known Limitations

1. **RFI:** Won't work if PHP `allow_url_include=Off`
2. **DOM XSS:** Requires Selenium + ChromeDriver
3. **SSRF:** Only tests existing URL parameters
4. **SSH Spray:** Requires `paramiko` library (`pip install paramiko`)
5. **MySQL Spray:** Requires `pymysql` library (`pip install pymysql`)
6. **WHOIS:** Requires `whois` CLI tool (`apt install whois`)

---

## 🔐 CI/CD Integration

GitHub Actions pipelines are included:

- **`.github/workflows/ci.yml`** — Lint (ruff), test (pytest), compile check on every push/PR
- **`.github/workflows/security-scan.yml`** — Automated security scanning with report artifacts

---

*This file is written for cyberm4fia-scanner v5.0. — by Erkan*
