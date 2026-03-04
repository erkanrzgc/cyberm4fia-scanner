# cyberm4fia-scanner 🔴

<p align="center">
  <b>Red Team Vulnerability Scanner</b><br>
  <i>Advanced web application, network, and infrastructure security testing platform</i>
</p>

---

## 🚀 Features

### Web Application Attacks
| Module | Flag | Description |
|---|---|---|
| **XSS** | `--xss` | Reflected + Stored XSS with smart context-aware payload engine |
| **SQLi** | `--sqli` | Union-based + Blind (time-based) SQL injection with auto exploit |
| **LFI/RFI** | `--lfi` `--rfi` | Local & Remote File Inclusion with PHP wrapper detection |
| **CMDi** | `--cmdi` | OS Command Injection + Interactive Shell |
| **SSRF** | `--ssrf` | Server-Side Request Forgery (AWS/GCP/Azure metadata) |
| **SSTI** | `--ssti` | Server-Side Template Injection (Jinja2, Twig, Mako, Smarty) |
| **XXE** | `--xxe` | XML External Entity injection (/etc/passwd, SSRF, XInclude) |
| **Open Redirect** | `--redirect` | URL redirect abuse (20+ payloads) |
| **CORS** | `--cors` | Cross-Origin Resource Sharing misconfiguration |
| **Header Inject** | `--header-inject` | HTTP Header Injection / CRLF |
| **DOM XSS** | `--dom-xss` | Client-side JavaScript DOM-based XSS |
| **CSRF** | *(auto)* | Cross-Site Request Forgery token check |

### API Security (OWASP API Top 10)
| Module | Flag | Description |
|---|---|---|
| **API Scanner** | `--api-scan` | BOLA/IDOR, Rate Limiting, Mass Assignment, Verb Tampering, GraphQL Introspection, JWT Analysis |

### Network & Infrastructure
| Module | Flag | Description |
|---|---|---|
| **Recon** | `--recon` | Port scanning (asyncio + banner grabbing), DNS, SSL, headers |
| **Subdomain** | `--subdomain` | Subdomain enumeration |
| **Fuzzer** | `--fuzz` | Directory/file bruteforce with smart 404 calibration |
| **Crawler** | `--crawl` | Recursive site crawler with JS endpoint extraction |
| **Port Scan** | *(in recon)* | 60+ ports, banner grabbing, dangerous port warnings |
| **Credential Spray** | `--spray` | Default credentials for FTP, SSH, MySQL, Redis, MongoDB |
| **Cloud Buckets** | `--cloud` | Open S3/Azure/GCP bucket detection |
| **Subdomain Takeover** | `--takeover` | CNAME dangling detection |

### OSINT
| Module | Flag | Description |
|---|---|---|
| **Tech Fingerprint** | `--tech` | Wappalyzer-style technology detection |
| **Shodan/Whois/ASN** | `--osint` | IP enrichment via Shodan InternetDB (free), WHOIS, ASN |
| **Email Harvester** | `--email` | Google, GitHub, PGP key server email discovery |

### Smart Automation
| Module | Flag | Description |
|---|---|---|
| **Vuln Chaining** | `--chain` | Attack path analysis (SSRF→Metadata→IAM, SQLi→RCE, etc.) |
| **Wordlist Gen** | `--wordlist` | CeWL-style site-specific password wordlist generator |
| **Reverse Shell** | *(in CLI)* | Payload generator (Bash, Python, PowerShell, PHP, etc.) |
| **WAF Bypass** | *(auto)* | Automatic WAF fingerprinting + adaptive evasion |
| **Template Engine** | *(auto)* | Nuclei-style YAML scan templates |

---

## ⚡ Quick Start

```bash
# Clone
git clone https://github.com/yourusername/cyberm4fia-scanner.git
cd cyberm4fia-scanner

# Install dependencies
pip install -r requirements.txt

# Interactive mode
python3 scanner.py

# CLI mode — full scan
python3 scanner.py -u https://target.com --all

# Quick XSS + SQLi only
python3 scanner.py -u https://target.com --xss --sqli

# Multi-target from file
python3 scanner.py -l targets.txt --all

# Through Tor/SOCKS5 proxy
python3 scanner.py -u https://target.com --all --proxy socks5://127.0.0.1:9050
```

---

## 🎯 Scan Modes

| Mode | Flag | Delay | Threads | Use Case |
|---|---|---|---|---|
| Quick | `-m 1` | 0.05s | 10 | Fast general scan |
| Normal | `-m 2` | 0.3s | 10 | Default, balanced |
| Aggressive | `-m 3` | 0.05s | 30 | Full power (may trigger WAF) |
| Stealth | `-m 4` | 2.0s | 1 | Slow & stealthy, evade IDS |

---

## 📁 Project Structure

```
cyberm4fia-scanner/
├── scanner.py                  ← Main orchestrator
├── modules/
│   ├── recon.py                ← Port scan, DNS, SSL, headers
│   ├── xss.py                  ← XSS scanner (smart payload engine)
│   ├── sqli.py                 ← SQL Injection (Union + Blind)
│   ├── lfi.py / rfi.py         ← File Inclusion
│   ├── cmdi.py                 ← Command Injection
│   ├── ssrf.py                 ← Server-Side Request Forgery
│   ├── ssti.py                 ← Template Injection
│   ├── xxe.py                  ← XML External Entity
│   ├── open_redirect.py        ← Open Redirect
│   ├── spray.py                ← Credential Sprayer
│   ├── api_scanner.py          ← API Security (OWASP Top 10)
│   ├── cloud_enum.py           ← Cloud bucket enumeration
│   ├── subdomain_takeover.py   ← Subdomain takeover
│   ├── tech_detect.py          ← Technology fingerprinting
│   ├── email_harvest.py        ← Email harvester
│   ├── crawler.py              ← Site crawler
│   ├── fuzzer.py               ← Directory fuzzer
│   ├── dom_xss.py              ← DOM-based XSS
│   ├── cors.py / csrf.py       ← CORS / CSRF checks
│   ├── header_inject.py        ← Header injection
│   ├── report.py               ← HTML/JSON/TXT reports
│   └── template_engine.py      ← YAML template runner
├── utils/
│   ├── request.py              ← HTTP session manager (proxy, WAF, auth)
│   ├── revshell.py             ← Reverse shell payload generator
│   ├── vuln_chain.py           ← Vulnerability chaining engine
│   ├── wordlist_gen.py         ← CeWL-style wordlist generator
│   ├── shodan_lookup.py        ← Shodan/WHOIS/ASN OSINT
│   ├── waf.py                  ← WAF fingerprinting
│   ├── auth.py                 ← AuthChain (token/cookie auth)
│   ├── colors.py               ← Terminal colors & logging
│   └── oob.py                  ← Out-of-Band callback client
├── .github/workflows/
│   └── security-scan.yml       ← GitHub Actions CI/CD pipeline
├── wordlists/                  ← Fuzzer wordlists
├── plugins/                    ← Custom user plugins
├── scans/                      ← Scan output directory
├── usagewithai.md              ← AI assistant guide (🇹🇷)
└── README.md                   ← This file
```

---

## 🔧 CLI Reference

```
Usage: python3 scanner.py [options]

Target:
  -u, --url URL           Target URL
  -l, --list FILE         File with list of target URLs

Scan Modules:
  --recon                 Network reconnaissance
  --subdomain             Subdomain enumeration
  --fuzz                  Directory fuzzer
  --crawl                 Site crawler
  --xss                   XSS scanner
  --sqli                  SQL Injection
  --lfi                   Local File Inclusion
  --rfi                   Remote File Inclusion
  --cmdi                  Command Injection
  --ssrf                  SSRF scanner
  --ssti                  Template Injection
  --xxe                   XML External Entity
  --redirect              Open Redirect
  --cors                  CORS misconfiguration
  --header-inject         Header Injection
  --dom-xss               DOM-based XSS
  --api-scan              API security (OWASP)
  --cloud                 Cloud bucket scan
  --takeover              Subdomain takeover
  --tech                  Technology fingerprint
  --spray                 Credential sprayer
  --email                 Email harvester
  --osint                 Shodan/WHOIS/ASN
  --chain                 Vulnerability chaining
  --wordlist              Wordlist generator
  --all                   Enable ALL modules

Config:
  -m, --mode {1,2,3,4}    Scan mode (1=Quick, 2=Normal, 3=Aggressive, 4=Stealth)
  -t, --threads N         Number of threads (default: 10)
  --cookie COOKIE         Session cookie
  --proxy URL             Proxy (http/socks5)
  --html                  Generate HTML report
  --json                  Save JSON report
  --compare SCAN1 SCAN2   Compare two scans
  --api                   Start REST API server mode
```

---

## 🔐 CI/CD Integration

Add automated security scanning to your GitHub Actions:

```yaml
# .github/workflows/security-scan.yml is included in the repo!
# Set TARGET_URL as a GitHub secret, then:
# Every push/PR triggers automatic security scanning
```

---

## ⚠️ Legal Disclaimer

> **This tool is for authorized security testing and educational purposes only.**
> Unauthorized scanning of systems you do not own or have explicit permission to test is illegal.
> The developers are not responsible for misuse of this tool.

---

## 📝 License

Educational use only. Built by **Erkan** 🇹🇷

---

*cyberm4fia-scanner v5.0 — Full Arsenal Red Team Platform*
