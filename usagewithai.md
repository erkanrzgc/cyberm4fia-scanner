# cyberm4fia-scanner — AI Advisor Guide

> This file is designed to help an AI assistant understand, correctly use, and advise users on this scanner tool.

---

📌 Overview

cyberm4fia-scanner is a Python-based modular Red Team security scanning platform. It covers web application, network, API, cloud, and OSINT scanning capabilities. The main entry point is `scanner.py`.

**Run:** `python3 scanner.py` (interactive) or with CLI arguments (non-interactive)

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
│   ├── dom_xss.py                  ← DOM-based XSS (requires Selenium)
│   ├── ssrf.py                     ← Server-Side Request Forgery
│   ├── csrf.py                     ← Cross-Site Request Forgery
│   ├── cors.py                     ← CORS misconfiguration
│   ├── header_inject.py            ← HTTP Header Injection
│   ├── ssti.py                     ← Server-Side Template Injection
│   ├── xxe.py                      ← XML External Entity Injection
│   ├── open_redirect.py            ← Open Redirect Scanner
│   ├── spray.py                    ← Credential Sprayer (SSH/FTP/MySQL/Redis)
│   ├── api_scanner.py              ← API Security (OWASP API Top 10)
│   ├── cloud_enum.py               ← Cloud Bucket Enumeration (S3/Azure/GCP)
│   ├── subdomain_takeover.py       ← Subdomain Takeover Detection
│   ├── tech_detect.py              ← Technology Fingerprinting
│   ├── email_harvest.py            ← Email Harvester
│   ├── race_condition.py           ← Race Condition / TOCTOU Scanner
│   ├── dom_static.py               ← DOM Static Analysis
│   ├── payloads.py                 ← Static payload lists
│   ├── report.py                   ← HTML/JSON/TXT report generator
│   ├── compare.py                  ← Two-scan comparison
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

| Mode | Delay | Threads | Use Case |
|---|---|---|---|
| `1-Quick` | 0.05s | 10 | Fast general scan |
| `2-Normal` | 0.3s | 10 | Default, balanced |
| `3-Aggressive` | 0.05s | 30 | Full power (may trigger WAF!) |
| `4-Stealth` | 2.0s | 1 | Slow but stealthy, evades WAF/IDS |

**AI Advice:** Use `4-Stealth` or `2-Normal` on real targets. `3-Aggressive` is fine for lab environments (DVWA, Metasploitable).

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

```
Target:
  -u, --url URL           Target URL
  -l, --list FILE         Target list file

Scan Modules:
  --recon                 Network discovery (port scan + banner)
  --subdomain             Subdomain enumeration
  --fuzz                  Directory discovery
  --crawl                 Site crawler
  --xss                   XSS scanning
  --sqli                  SQL Injection
  --lfi                   Local File Inclusion
  --rfi                   Remote File Inclusion
  --cmdi                  Command Injection
  --ssrf                  SSRF scanning
  --ssti                  Template Injection
  --xxe                   XXE scanning
  --redirect              Open Redirect
  --cors                  CORS misconfiguration
  --header-inject         Header Injection
  --dom-xss               DOM-based XSS
  --api-scan              API security scan
  --cloud                 Cloud bucket scan
  --takeover              Subdomain takeover
  --tech                  Technology detection
  --spray                 Credential sprayer
  --email                 Email harvester
  --osint                 Shodan/WHOIS/ASN
  --chain                 Vulnerability chaining
  --wordlist              Wordlist generator
  --all                   ENABLE ALL

Settings:
  -m, --mode {1,2,3,4}    Scan mode
  -t, --threads N         Thread count
  --cookie COOKIE         Session cookie
  --proxy URL             Proxy (http/socks5)
  --html                  Generate HTML report
  --json                  Save JSON report
  --compare SCAN1 SCAN2   Compare two scans
```

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
