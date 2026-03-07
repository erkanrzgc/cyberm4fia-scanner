# cyberm4fia-scanner

> Modular red team security scanner for web applications, APIs, networks, and cloud infrastructure.

---

## Features

### Web Application Scanning
| Module | Flag | Description |
|---|---|---|
| XSS | `--xss` | Reflected + Stored XSS with context-aware payload engine |
| SQLi | `--sqli` | Union-based + Blind (time-based) SQL injection with auto exploit |
| LFI / RFI | `--lfi` `--rfi` | Local & Remote File Inclusion |
| CMDi | `--cmdi` | OS Command Injection + Interactive Shell |
| SSRF | `--ssrf` | Server-Side Request Forgery (AWS/GCP/Azure metadata) |
| SSTI | `--ssti` | Template Injection (Jinja2, Twig, Mako, Smarty) |
| XXE | `--xxe` | XML External Entity Injection |
| Open Redirect | `--redirect` | URL redirect abuse (20+ payloads) |
| CORS | `--cors` | Cross-Origin Resource Sharing misconfiguration |
| Header Inject | `--header-inject` | HTTP Header Injection / CRLF |
| DOM XSS | `--dom-xss` | DOM-based XSS (Selenium) |
| CSRF | *(auto)* | Cross-Site Request Forgery token check |

### API Security
| Module | Flag | Description |
|---|---|---|
| API Scanner | `--api-scan` | BOLA/IDOR, Rate Limiting, Mass Assignment, Verb Tampering, GraphQL Introspection, JWT |

### Network & Infrastructure
| Module | Flag | Description |
|---|---|---|
| Recon | `--recon` | Async port scan + banner grabbing, DNS, SSL, headers |
| Subdomain | `--subdomain` | Subdomain enumeration |
| Fuzzer | `--fuzz` | Directory/file bruteforce with smart 404 calibration |
| Crawler | `--crawl` | Recursive crawler with JS endpoint extraction |
| Credential Spray | `--spray` | Default credentials for FTP, SSH, MySQL, Redis, MongoDB |
| Cloud Buckets | `--cloud` | Open S3 / Azure Blob / GCP bucket detection |
| Subdomain Takeover | `--takeover` | CNAME dangling detection |

### OSINT
| Module | Flag | Description |
|---|---|---|
| Tech Fingerprint | `--tech` | Wappalyzer-style technology detection (50+ technologies) |
| Shodan / WHOIS / ASN | `--osint` | IP enrichment via Shodan InternetDB, WHOIS, ASN |
| Email Harvester | `--email` | Google, GitHub, PGP key server email discovery |

### Automation
| Module | Flag | Description |
|---|---|---|
| Vuln Chaining | `--chain` | Attack path analysis (SSRF→Metadata, SQLi→RCE, etc.) |
| Wordlist Gen | `--wordlist` | CeWL-style site-specific password wordlist generator |
| Reverse Shell | *(in CLI)* | Payload generator (Bash, Python, PowerShell, PHP, etc.) |
| WAF Bypass | *(auto)* | WAF fingerprinting (22 vendors) + adaptive evasion |
| Race Condition | `--race` | TOCTOU / race condition scanner |
| Template Engine | *(auto)* | Nuclei-style YAML scan templates |
| PoC Generator | *(auto)* | Auto-generates HTML/JSON Proof-of-Concept exploits for vulnerabilities |
| Proxy Interceptor| *(auto)* | Built-in MITM proxy to capture and relay live browser traffic for scanning |

---

## Quick Start

```bash
git clone https://github.com/erkanrzgc/cyberm4fia-scanner.git
cd cyberm4fia-scanner
pip install -r requirements.txt

# Interactive mode
python3 scanner.py

# Full scan
python3 scanner.py -u https://target.com --all

# Specific modules
python3 scanner.py -u https://target.com --xss --sqli

# Multi-target
python3 scanner.py -l targets.txt --all

# Through proxy
python3 scanner.py -u https://target.com --all --proxy socks5://127.0.0.1:9050
```

---

## Scan Modes

| Mode | Flag | Delay | Threads | Use Case |
|---|---|---|---|---|
| Quick | `-m 1` | 0.05s | 10 | Fast general scan |
| Normal | `-m 2` | 0.3s | 10 | Balanced (default) |
| Aggressive | `-m 3` | 0.05s | 30 | Full power — may trigger WAF |
| Stealth | `-m 4` | 2.0s | 1 | Slow, IDS/WAF evasion |

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
├── utils/                  # HTTP client, WAF detection, auth, etc.
├── payloads/               # XSS, SQLi, LFI, SSRF, CMDi payload files
├── wordlists/              # fuzzer wordlists
├── tests/                  # pytest test suite (38 tests)
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

Available settings: `SHODAN_API_KEY`, `DEFAULT_THREADS`, `DEFAULT_DELAY`, `VERIFY_SSL`, `HTTP_PROXY`

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
