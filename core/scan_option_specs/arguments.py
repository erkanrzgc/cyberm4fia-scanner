"""Declarative argparse option specs."""

from __future__ import annotations

from utils.request import get_default_timeout, get_path_blacklist

from .defaults import DEFAULT_AI_MODEL, DEFAULT_NVIDIA_API_KEY
from .types import ArgumentSpec

PARSER_ARGUMENT_SPECS = (
    ArgumentSpec(("target",), {"nargs": "?", "default": "", "help": "Target URL (positional)"}),
    ArgumentSpec(("-u", "--url"), {"help": "Target URL"}),
    ArgumentSpec(
        ("-m", "--mode"),
        {
            "default": "normal",
            "metavar": "MODE",
            "help": "Scan mode (normal, stealth, lab). Legacy aliases: 1/2=normal, 3=lab, 4=stealth",
        },
    ),
    ArgumentSpec(
        ("-c", "--cookie"),
        {"help": "Session cookie (e.g. 'PHPSESSID=...')"},
    ),
    ArgumentSpec(("--all",), {"action": "store_true", "help": "Enable ALL scan modules"}),
    ArgumentSpec(
        ("--quiet", "-q"),
        {"action": "store_true", "help": "Quiet mode (only show vulns/errors)"},
    ),
    ArgumentSpec(("--xss",), {"action": "store_true", "help": "Enable XSS scan"}),
    ArgumentSpec(("--sqli",), {"action": "store_true", "help": "Enable SQLi scan"}),
    ArgumentSpec(("--lfi",), {"action": "store_true", "help": "Enable LFI scan"}),
    ArgumentSpec(("--rfi",), {"action": "store_true", "help": "Enable RFI scan"}),
    ArgumentSpec(
        ("--cmdi",),
        {"action": "store_true", "help": "Enable Command Injection scan"},
    ),
    ArgumentSpec(
        ("--dom-xss",),
        {"action": "store_true", "help": "Enable DOM XSS scan"},
    ),
    ArgumentSpec(
        ("--secrets",),
        {"action": "store_true", "help": "Scan for Secrets & API Keys in JS/HTML"},
    ),
    ArgumentSpec(
        ("--sca",),
        {"action": "store_true", "help": "Enable Software Composition Analysis (OSV-Scanner)"},
    ),
    ArgumentSpec(
        ("--recon",),
        {
            "action": "store_true",
            "help": "Enable deep server recon (extended port/DNS/TLS checks)",
        },
    ),
    ArgumentSpec(
        ("--subdomain",),
        {"action": "store_true", "help": "Enable Subdomain scan"},
    ),
    ArgumentSpec(
        ("--fuzz",),
        {"action": "store_true", "help": "Enable High-Speed API/Directory Fuzzer"},
    ),
    ArgumentSpec(
        ("--wordlist-file",),
        {
            "default": "wordlists/api_endpoints.txt",
            "metavar": "FILE",
            "help": "Custom wordlist for Fuzzer",
        },
    ),
    ArgumentSpec(("--ssrf",), {"action": "store_true", "help": "Enable SSRF scan"}),
    ArgumentSpec(
        ("--oob",),
        {"action": "store_true", "help": "Enable Out-Of-Band (OOB) testing"},
    ),
    ArgumentSpec(("--csrf",), {"action": "store_true", "help": "Enable CSRF scan"}),
    ArgumentSpec(("--cors",), {"action": "store_true", "help": "Enable CORS check"}),
    ArgumentSpec(
        ("--header-inject",),
        {"action": "store_true", "help": "Enable Header Injection scan"},
    ),
    ArgumentSpec(("--crawl",), {"action": "store_true", "help": "Enable Crawling"}),
    ArgumentSpec(("--html",), {"action": "store_true", "help": "Generate HTML report"}),
    ArgumentSpec(("--json",), {"action": "store_true", "help": "Save JSON report"}),
    ArgumentSpec(
        ("--sarif",),
        {
            "action": "store_true",
            "help": "Save SARIF report (for GitHub Security tab)",
        },
    ),
    ArgumentSpec(
        ("--passive",),
        {
            "action": "store_true",
            "help": "Enable passive scanning (header/secret/debug checks)",
        },
    ),
    ArgumentSpec(
        ("--tamper",),
        {
            "default": "",
            "help": "Tamper scripts for WAF bypass (comma-separated, e.g. space2comment,randomcase)",
        },
    ),
    ArgumentSpec(
        ("-t", "--threads"),
        {"type": int, "default": 10, "help": "Number of threads"},
    ),
    ArgumentSpec(
        ("--api",),
        {"action": "store_true", "help": "Start REST API server mode"},
    ),
    ArgumentSpec(
        ("--port",),
        {"type": int, "default": 8080, "help": "API server port (default: 8080)"},
    ),
    ArgumentSpec(
        ("--compare",),
        {
            "nargs": 2,
            "metavar": ("SCAN1", "SCAN2"),
            "help": "Compare two scan dirs",
        },
    ),
    ArgumentSpec(
        ("--proxy-listen",),
        {
            "type": int,
            "metavar": "PORT",
            "help": "Start local MITM proxy to automatically scan intercepted traffic (e.g., 8081)",
        },
    ),
    ArgumentSpec(
        ("--scope-proxy",),
        {
            "metavar": "DOMAIN",
            "help": "Target domain for the proxy interceptor (e.g., wisarc.com)",
        },
    ),
    ArgumentSpec(
        ("--cloud",),
        {"action": "store_true", "help": "Scan for open cloud buckets (S3/Azure/GCP)"},
    ),
    ArgumentSpec(
        ("--takeover",),
        {"action": "store_true", "help": "Scan for subdomain takeover"},
    ),
    ArgumentSpec(
        ("--tech",),
        {"action": "store_true", "help": "Technology fingerprinting"},
    ),
    ArgumentSpec(
        ("--api-scan",),
        {"action": "store_true", "help": "API security scan (OWASP API Top 10)"},
    ),
    ArgumentSpec(
        ("--api-spec",),
        {
            "default": "",
            "metavar": "FILE",
            "help": "Local OpenAPI/Swagger JSON or YAML file for API scanning",
        },
    ),
    ArgumentSpec(
        ("--ssti",),
        {"action": "store_true", "help": "SSTI (Template Injection) scan"},
    ),
    ArgumentSpec(
        ("--xxe",),
        {"action": "store_true", "help": "XXE (XML External Entity) scan"},
    ),
    ArgumentSpec(
        ("--redirect",),
        {"action": "store_true", "help": "Open Redirect scan"},
    ),
    ArgumentSpec(
        ("--spray",),
        {"action": "store_true", "help": "Default credential spraying"},
    ),
    ArgumentSpec(
        ("--email",),
        {"action": "store_true", "help": "Email harvesting"},
    ),
    ArgumentSpec(
        ("--osint",),
        {"action": "store_true", "help": "OSINT enrichment (Shodan/Whois)"},
    ),
    ArgumentSpec(
        ("--dorking",),
        {"action": "store_true", "help": "Automated Google Dorking for target"},
    ),
    ArgumentSpec(
        ("--wayback",),
        {"action": "store_true", "help": "Wayback Machine historical URL discovery"},
    ),
    ArgumentSpec(
        ("--urlscan",),
        {"action": "store_true", "help": "URLScan.io passive reconnaissance"},
    ),
    ArgumentSpec(
        ("--chain",),
        {"action": "store_true", "help": "Vulnerability chaining analysis"},
    ),
    ArgumentSpec(
        ("--wordlist",),
        {"action": "store_true", "help": "Generate site-specific wordlist"},
    ),
    ArgumentSpec(
        ("-l", "--list"),
        {"dest": "target_list", "help": "File with list of target URLs"},
    ),
    ArgumentSpec(
        ("--proxy",),
        {
            "dest": "proxy_url",
            "help": "Proxy URL (http/socks5, e.g. socks5://127.0.0.1:9050)",
        },
    ),
    ArgumentSpec(
        ("--rotate-proxy",),
        {
            "action": "store_true",
            "dest": "rotate_proxy",
            "help": "Rotate proxies from a live pool for each request (auto-enables with WAF evasion)",
        },
    ),
    ArgumentSpec(
        ("--headless",),
        {
            "action": "store_true",
            "help": "Use headless browser for SPA rendering (requires playwright)",
        },
    ),
    ArgumentSpec(
        ("--har-output",),
        {
            "action": "store_true",
            "help": "Record browser traffic as HAR file and analyze for API endpoints",
        },
    ),
    ArgumentSpec(
        ("--exploit",),
        {
            "action": "store_true",
            "help": "Enable exploit follow-up actions/prompts after scan results",
        },
    ),
    ArgumentSpec(
        ("--race",),
        {"action": "store_true", "help": "Race condition scanner"},
    ),
    ArgumentSpec(
        ("--jwt",),
        {"action": "store_true", "help": "JWT attack suite"},
    ),
    ArgumentSpec(
        ("--smuggle",),
        {
            "action": "store_true",
            "help": "HTTP request smuggling scanner (CL.TE/TE.CL)",
        },
    ),
    ArgumentSpec(
        ("--proto",),
        {"action": "store_true", "help": "Prototype pollution scanner (Node.js)"},
    ),
    ArgumentSpec(
        ("--deser",),
        {"action": "store_true", "help": "Insecure deserialization scanner"},
    ),
    ArgumentSpec(
        ("--bizlogic",),
        {"action": "store_true", "help": "Business logic flaw scanner"},
    ),
    ArgumentSpec(
        ("--forbidden-bypass",),
        {"action": "store_true", "dest": "forbidden_bypass", "help": "403/401 forbidden bypass scanner"},
    ),
    ArgumentSpec(
        ("--file-upload",),
        {"action": "store_true", "dest": "file_upload", "help": "File upload vulnerability scanner"},
    ),
    ArgumentSpec(
        ("--ato",),
        {"action": "store_true", "help": "Account takeover scanner"},
    ),
    ArgumentSpec(
        ("--auth-bypass",),
        {"action": "store_true", "dest": "auth_bypass", "help": "2FA & authentication bypass scanner"},
    ),
    ArgumentSpec(
        ("--scope",),
        {
            "default": "",
            "help": "Scope include patterns (comma-separated, e.g. '*.target.com')",
        },
    ),
    ArgumentSpec(
        ("--exclude",),
        {
            "default": "",
            "help": "Scope exclude patterns (comma-separated, e.g. '/logout,*.pdf')",
        },
    ),
    ArgumentSpec(
        ("--session",),
        {
            "default": "",
            "help": "Session file for save/resume (e.g. scan1.json)",
        },
    ),
    ArgumentSpec(
        ("--resume",),
        {"default": "", "help": "Resume scan from session file"},
    ),
    ArgumentSpec(
        ("--max-requests",),
        {
            "type": int,
            "default": 0,
            "metavar": "N",
            "help": "Stop a scan after N requests (0 disables the budget)",
        },
    ),
    ArgumentSpec(
        ("--request-timeout",),
        {
            "type": float,
            "default": get_default_timeout(),
            "metavar": "SECONDS",
            "help": "Default per-request timeout in seconds",
        },
    ),
    ArgumentSpec(
        ("--max-host-concurrency",),
        {
            "type": int,
            "default": 0,
            "metavar": "N",
            "help": "Limit simultaneous in-flight requests per host (0 disables the limit)",
        },
    ),
    ArgumentSpec(
        ("--path-blacklist",),
        {
            "default": ",".join(get_path_blacklist()),
            "metavar": "PATTERNS",
            "help": "Comma-separated risky path patterns to skip (e.g. '/logout,/checkout')",
        },
    ),
    ArgumentSpec(
        ("--ai",),
        {
            "action": "store_true",
            "help": "Enable AI analysis (NVIDIA API).",
        },
    ),
    ArgumentSpec(
        ("--agent",),
        {
            "action": "store_true",
            "help": "Run Multi-Agent autonomous pentesting mode (bypasses standard modules)",
        },
    ),
    ArgumentSpec(
        ("--auth-flow",),
        {
            "choices": ("form", "csrf"),
            "default": None,
            "help": (
                "Authenticate via the named flow before scanning. 'form' "
                "POSTs credentials to --auth-url; 'csrf' fetches --auth-form-url "
                "first to extract a hidden CSRF token. Captured cookies are "
                "applied to every subsequent request."
            ),
        },
    ),
    ArgumentSpec(
        ("--auth-url",),
        {
            "default": "",
            "help": "Login endpoint for --auth-flow form (POST target).",
        },
    ),
    ArgumentSpec(
        ("--auth-form-url",),
        {
            "default": "",
            "help": "Form page URL for --auth-flow csrf (GET to extract token).",
        },
    ),
    ArgumentSpec(
        ("--auth-fields",),
        {
            "default": "",
            "help": (
                "Comma-separated key=value pairs for the login payload "
                "(e.g. 'username=alice,password=hunter2'). The 'username' and "
                "'password' keys are required; additional fields are passed "
                "verbatim as extra_fields."
            ),
        },
    ),
    ArgumentSpec(
        ("--auth-success",),
        {
            "default": "",
            "help": (
                "Regex that must match the login response body for the flow "
                "to be considered successful (e.g. 'Welcome|Dashboard')."
            ),
        },
    ),
    ArgumentSpec(
        ("--accounts",),
        {
            "default": "",
            "help": (
                "Additional accounts for multi-identity tests (IDOR, "
                "privilege escalation). Format: 'name:user:pass,name2:user2:pass2'. "
                "All use the same --auth-flow + --auth-url."
            ),
        },
    ),
    ArgumentSpec(
        ("--agent-mode",),
        {
            "choices": ("legacy", "intent", "both"),
            "default": "legacy",
            "help": (
                "Agent execution mode. 'legacy' = utils.agent_framework multi-agent "
                "(bypasses standard modules); 'intent' = run standard scan then trigger "
                "the intent-driven LLM exploit pipeline (utils.agent_orchestrator) "
                "on collected findings; 'both' = legacy when --agent is set, otherwise "
                "intent post-scan. (default: legacy)"
            ),
        },
    ),
    ArgumentSpec(
        ("--ai-model",),
        {
            "default": DEFAULT_AI_MODEL,
            "help": "NVIDIA API model (default: meta/llama-3.3-70b-instruct)",
        },
    ),
    ArgumentSpec(
        ("--nvidia-api-key",),
        {
            "default": DEFAULT_NVIDIA_API_KEY,
            "help": "NVIDIA API Key (reads NVIDIA_API_KEY env var by default)",
        },
    ),
)
