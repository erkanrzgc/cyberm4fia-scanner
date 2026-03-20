"""
cyberm4fia-scanner - Scan option defaults and presets.
"""

from dataclasses import dataclass
import os

from core.module_registry import ASYNC_MODULES, PHASE_MODULES
from utils.request import (
    get_default_timeout,
    get_path_blacklist,
    get_request_delay,
    get_stealth_delay,
)


DEFAULT_AI_MODEL = "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B"
DEFAULT_OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")


@dataclass(frozen=True)
class ArgumentSpec:
    """Declarative argparse metadata."""

    flags: tuple[str, ...]
    kwargs: dict


@dataclass(frozen=True)
class InteractivePromptSpec:
    """Declarative interactive prompt metadata."""

    option_key: str
    prompt: str
    default: str = "N"
    value_type: str = "bool"
    skip_if_truthy: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScanModeSpec:
    """Runtime and documentation metadata for scan modes."""

    key: str
    label: str
    runtime_mode: str
    delay: float
    threads: int
    description: str
    cli_aliases: tuple[str, ...] = ()
    interactive_choice: str | None = None


@dataclass(frozen=True)
class AttackProfileSpec:
    """Interactive and documentation metadata for attack profiles."""

    choice: str
    label: str
    description: str
    option_keys: frozenset[str]
    interactive_label: str
    recommended_prompt_specs: tuple[InteractivePromptSpec, ...] = ()

SCAN_OPTION_DEFAULTS = {
    "recon": False,
    "subdomain": False,
    "fuzz": False,
    "crawl": False,
    "xss": False,
    "sqli": False,
    "lfi": False,
    "rfi": False,
    "cmdi": False,
    "dom_xss": False,
    "secrets": False,
    "oob": False,
    "ssrf": False,
    "csrf": False,
    "cors": False,
    "header_inject": False,
    "templates": False,
    "cloud": False,
    "takeover": False,
    "tech": False,
    "api_scan": False,
    "api_spec": "",
    "ssti": False,
    "xxe": False,
    "redirect": False,
    "spray": False,
    "email": False,
    "passive": False,
    "jwt": False,
    "race": False,
    "smuggle": False,
    "proto": False,
    "deser": False,
    "bizlogic": False,
    "osint": False,
    "chain": False,
    "wordlist": False,
    "headless": False,
    "exploit": False,
    "cookie": "",
    "tamper": "",
    "proxy_url": "",
    "scope": "",
    "exclude": "",
    "session": "",
    "resume": "",
    "max_requests": 0,
    "request_timeout": get_default_timeout(),
    "max_host_concurrency": 0,
    "path_blacklist": ",".join(get_path_blacklist()),
    "wordlist_file": "wordlists/api_endpoints.txt",
    "json_output": False,
    "html": False,
    "sarif": False,
    "threads": 10,
    "ai": False,
    "ai_model": DEFAULT_AI_MODEL,
    "ollama_url": DEFAULT_OLLAMA_URL,
    "proxy_listen": False,
}

BOOL_OPTION_KEYS = frozenset(
    key for key, value in SCAN_OPTION_DEFAULTS.items() if isinstance(value, bool)
)

REGISTRY_OPTION_KEYS = frozenset(
    [spec.option_key for spec in ASYNC_MODULES if spec.option_key]
    + [spec.option_key for spec in PHASE_MODULES if spec.option_key]
)

ALL_ENABLED_OPTION_KEYS = frozenset(
    REGISTRY_OPTION_KEYS
    | {
        "recon",
        "fuzz",
        "crawl",
        "secrets",
        "oob",
        "csrf",
        "tech",
        "osint",
        "headless",
        "html",
        "passive",
    }
) - {"wordlist", "sarif", "ai", "proxy_listen", "exploit"}

API_MODULE_OPTION_KEYS = (
    REGISTRY_OPTION_KEYS | {"recon"}
) - {"html", "sarif", "ai"}

PROFILE_PRESETS = {
    "1": frozenset({"recon", "subdomain", "fuzz", "tech", "passive"}),
    "2": frozenset(
        {"xss", "sqli", "lfi", "rfi", "cmdi", "csrf", "cors", "header_inject", "passive", "dom_xss"}
    ),
    "3": frozenset(
        {
            "jwt",
            "deser",
            "ssti",
            "race",
            "proto",
            "ssrf",
            "bizlogic",
            "redirect",
            "smuggle",
            "xxe",
            "api_scan",
            "oob",
        }
    ),
    "4": ALL_ENABLED_OPTION_KEYS,
}

SCAN_MODE_SPECS = (
    ScanModeSpec(
        key="normal",
        label="Normal",
        runtime_mode="normal",
        delay=get_request_delay(),
        threads=10,
        description="Balanced default mode for most targets.",
        cli_aliases=("1", "2"),
        interactive_choice="1",
    ),
    ScanModeSpec(
        key="stealth",
        label="Stealth",
        runtime_mode="stealth",
        delay=get_stealth_delay(),
        threads=1,
        description="Slow, low-noise mode for cautious testing.",
        cli_aliases=("4",),
        interactive_choice="2",
    ),
    ScanModeSpec(
        key="lab",
        label="Lab",
        runtime_mode="lab",
        delay=0.05,
        threads=30,
        description="High-noise mode for local labs, staging, and CTF environments only.",
        cli_aliases=("3",),
    ),
)

SCAN_MODE_MAP = {spec.key: spec for spec in SCAN_MODE_SPECS}
SCAN_MODE_ALIAS_MAP = {
    alias: spec.key for spec in SCAN_MODE_SPECS for alias in spec.cli_aliases
}
INTERACTIVE_SCAN_MODE_SPECS = tuple(
    spec for spec in SCAN_MODE_SPECS if spec.interactive_choice
)

ATTACK_PROFILE_SPECS = (
    AttackProfileSpec(
        choice="1",
        label="Fast Recon",
        description="Recon, subdomain discovery, endpoint fuzzing, technology intel, and passive checks.",
        option_keys=PROFILE_PRESETS["1"],
        interactive_label="[1] Fast Recon",
        recommended_prompt_specs=(
            InteractivePromptSpec("crawl", "[?] Recommended: crawl the site too? (Y/n)", "Y"),
            InteractivePromptSpec("osint", "[?] Recommended: enable OSINT enrichment? (y/N)", "N"),
            InteractivePromptSpec(
                "headless",
                "[?] Recommended: use headless SPA discovery? (y/N)",
                "N",
            ),
        ),
    ),
    AttackProfileSpec(
        choice="2",
        label="Core Web Vulns",
        description="Core web checks like XSS, SQLi, file inclusion, CMDi, CSRF, CORS, and DOM XSS.",
        option_keys=PROFILE_PRESETS["2"],
        interactive_label="[2] Core Web Vulns",
        recommended_prompt_specs=(
            InteractivePromptSpec(
                "secrets",
                "[?] Recommended: scan JS/HTML for secrets too? (Y/n)",
                "Y",
            ),
            InteractivePromptSpec(
                "oob",
                "[?] Recommended: enable OOB testing for blind checks? (y/N)",
                "N",
            ),
            InteractivePromptSpec(
                "headless",
                "[?] Recommended: use headless rendering for SPA targets? (y/N)",
                "N",
            ),
            InteractivePromptSpec(
                "exploit",
                "[?] Recommended: enable exploit follow-up actions/prompts? (y/N)",
                "N",
            ),
        ),
    ),
    AttackProfileSpec(
        choice="3",
        label="Advanced / Modern",
        description="JWT, deserialization, SSTI, race, prototype pollution, SSRF, business logic, API, OOB, and XXE coverage.",
        option_keys=PROFILE_PRESETS["3"],
        interactive_label="[3] Advanced / Modern",
        recommended_prompt_specs=(
            InteractivePromptSpec(
                "tech",
                "[?] Recommended: add technology fingerprinting? (Y/n)",
                "Y",
            ),
            InteractivePromptSpec(
                "passive",
                "[?] Recommended: include passive scanning too? (Y/n)",
                "Y",
            ),
            InteractivePromptSpec(
                "chain",
                "[?] Recommended: run vulnerability chaining analysis? (Y/n)",
                "Y",
            ),
            InteractivePromptSpec(
                "exploit",
                "[?] Recommended: enable exploit follow-up actions/prompts? (y/N)",
                "N",
            ),
        ),
    ),
    AttackProfileSpec(
        choice="4",
        label="All-In-One",
        description="Enables nearly every scan module except opt-in extras like AI and SARIF.",
        option_keys=PROFILE_PRESETS["4"],
        interactive_label="[4] ALL-IN-ONE",
        recommended_prompt_specs=(
            InteractivePromptSpec(
                "wordlist",
                "[?] Recommended: generate a site-specific wordlist too? (y/N)",
                "N",
            ),
            InteractivePromptSpec(
                "exploit",
                "[?] Recommended: enable exploit follow-up actions/prompts? (y/N)",
                "N",
            ),
        ),
    ),
    AttackProfileSpec(
        choice="5",
        label="Custom Choice",
        description="Ask every module prompt one by one.",
        option_keys=frozenset(),
        interactive_label="[5] Custom Choice",
    ),
)

ATTACK_PROFILE_MAP = {spec.choice: spec for spec in ATTACK_PROFILE_SPECS}

PARSER_ARGUMENT_SPECS = (
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
        ("--headless",),
        {
            "action": "store_true",
            "help": "Use headless browser for SPA rendering (requires playwright)",
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
            "help": "Enable AI analysis (Ollama, local & free). Requires Ollama running.",
        },
    ),
    ArgumentSpec(
        ("--ai-model",),
        {
            "default": DEFAULT_AI_MODEL,
            "help": "Ollama model (default: WhiteRabbitNeo-Llama-3.1-8B)",
        },
    ),
    ArgumentSpec(
        ("--ollama-url",),
        {
            "default": DEFAULT_OLLAMA_URL,
            "help": f"Ollama server URL (default: {DEFAULT_OLLAMA_URL})",
        },
    ),
)

INTERACTIVE_CUSTOM_PROMPT_GROUPS = (
    (
        "Custom Selection",
        (
            InteractivePromptSpec(
                "recon",
                "[?] Enable deep server recon? (Y/n)",
                "Y",
            ),
            InteractivePromptSpec("subdomain", "[?] Run Subdomain Scan? (y/N)", "N"),
            InteractivePromptSpec("fuzz", "[?] Run Directory Fuzzer? (y/N)", "N"),
            InteractivePromptSpec("crawl", "[?] Crawl site? (y/N)", "N"),
            InteractivePromptSpec(
                "headless",
                "[?] Use headless SPA discovery? (y/N)",
                "N",
            ),
            InteractivePromptSpec("xss", "[?] Test XSS? (y/N)", "N"),
            InteractivePromptSpec("sqli", "[?] Test SQLi? (y/N)", "N"),
            InteractivePromptSpec("lfi", "[?] Test LFI? (y/N)", "N"),
            InteractivePromptSpec("rfi", "[?] Test RFI? (y/N)", "N"),
            InteractivePromptSpec("cmdi", "[?] Test Command Injection? (y/N)", "N"),
            InteractivePromptSpec(
                "dom_xss",
                "[?] Test DOM XSS? (y/N) [Requires Playwright]",
                "N",
            ),
            InteractivePromptSpec(
                "secrets",
                "[?] Scan for Secrets in JS/HTML? (y/N)",
                "N",
            ),
            InteractivePromptSpec(
                "oob",
                "[?] Use Out-of-Band (OOB) Testing? (y/N)",
                "N",
            ),
            InteractivePromptSpec("ssrf", "[?] Test SSRF? (y/N)", "N"),
            InteractivePromptSpec("csrf", "[?] Test CSRF? (y/N)", "N"),
            InteractivePromptSpec("cors", "[?] Check CORS? (y/N)", "N"),
            InteractivePromptSpec(
                "header_inject",
                "[?] Test Header Injection? (y/N)",
                "N",
            ),
        ),
    ),
    (
        "Phase 4: Infrastructure & Cloud",
        (
            InteractivePromptSpec(
                "tech",
                "[?] Run Technology Fingerprinting? (Y/n)",
                "Y",
            ),
            InteractivePromptSpec(
                "cloud",
                "[?] Scan Cloud Buckets (S3/Azure/GCP)? (y/N)",
                "N",
            ),
            InteractivePromptSpec(
                "takeover",
                "[?] Scan Subdomain Takeover? (y/N)",
                "N",
            ),
            InteractivePromptSpec(
                "api_scan",
                "[?] Run API Security Scan? (y/N)",
                "N",
            ),
            InteractivePromptSpec(
                "osint",
                "[?] Run OSINT enrichment (Shodan/Whois)? (y/N)",
                "N",
            ),
        ),
    ),
    (
        "Phase 5: Advanced Injection & OSINT",
        (
            InteractivePromptSpec("ssti", "[?] Test SSTI? (y/N)", "N"),
            InteractivePromptSpec("xxe", "[?] Test XXE? (y/N)", "N"),
            InteractivePromptSpec("redirect", "[?] Test Open Redirect? (y/N)", "N"),
            InteractivePromptSpec(
                "spray",
                "[?] Default Credential Spraying? (y/N)",
                "N",
            ),
            InteractivePromptSpec("email", "[?] Email Harvesting? (y/N)", "N"),
            InteractivePromptSpec("passive", "[?] Passive Scanning? (Y/n)", "Y"),
            InteractivePromptSpec(
                "chain",
                "[?] Analyze vulnerability chains? (y/N)",
                "N",
            ),
            InteractivePromptSpec(
                "wordlist",
                "[?] Generate site-specific wordlist? (y/N)",
                "N",
            ),
        ),
    ),
    (
        "Phase 7: Advanced Attacks",
        (
            InteractivePromptSpec("jwt", "[?] JWT Attack Suite? (y/N)", "N"),
            InteractivePromptSpec(
                "race",
                "[?] Race Condition Scanner? (y/N)",
                "N",
            ),
            InteractivePromptSpec("smuggle", "[?] HTTP Smuggling? (y/N)", "N"),
            InteractivePromptSpec(
                "proto",
                "[?] Prototype Pollution? (y/N)",
                "N",
            ),
            InteractivePromptSpec(
                "deser",
                "[?] Insecure Deserialization? (y/N)",
                "N",
            ),
            InteractivePromptSpec(
                "bizlogic",
                "[?] Business Logic Flaws? (y/N)",
                "N",
            ),
            InteractivePromptSpec(
                "exploit",
                "[?] Enable exploit follow-up actions/prompts? (y/N)",
                "N",
            ),
        ),
    ),
)

INTERACTIVE_RUNTIME_PROMPTS = (
    InteractivePromptSpec(
        "cookie",
        "[?] Cookie (leave empty for none)",
        "",
        value_type="text",
    ),
    InteractivePromptSpec(
        "tamper",
        "[?] Tamper scripts (comma-separated, leave empty for none)",
        "",
        value_type="text",
    ),
    InteractivePromptSpec(
        "proxy_url",
        "[?] Proxy URL (leave empty for none)",
        "",
        value_type="text",
    ),
    InteractivePromptSpec(
        "scope",
        "[?] Scope include patterns (comma-separated, leave empty for none)",
        "",
        value_type="text",
    ),
    InteractivePromptSpec(
        "exclude",
        "[?] Scope exclude patterns (comma-separated, leave empty for none)",
        "",
        value_type="text",
    ),
    InteractivePromptSpec(
        "session",
        "[?] Session save file (leave empty to disable)",
        "",
        value_type="text",
        skip_if_truthy=("resume",),
    ),
)

INTERACTIVE_PROFILE_RUNTIME_PROMPTS = {
    "1": (
        INTERACTIVE_RUNTIME_PROMPTS[2],
        INTERACTIVE_RUNTIME_PROMPTS[3],
        INTERACTIVE_RUNTIME_PROMPTS[4],
        INTERACTIVE_RUNTIME_PROMPTS[5],
    ),
    "2": (
        INTERACTIVE_RUNTIME_PROMPTS[0],
        INTERACTIVE_RUNTIME_PROMPTS[1],
        INTERACTIVE_RUNTIME_PROMPTS[2],
        INTERACTIVE_RUNTIME_PROMPTS[5],
    ),
    "3": (
        INTERACTIVE_RUNTIME_PROMPTS[0],
        INTERACTIVE_RUNTIME_PROMPTS[2],
        INTERACTIVE_RUNTIME_PROMPTS[3],
        INTERACTIVE_RUNTIME_PROMPTS[4],
        INTERACTIVE_RUNTIME_PROMPTS[5],
    ),
    "4": INTERACTIVE_RUNTIME_PROMPTS,
    "5": INTERACTIVE_RUNTIME_PROMPTS,
}

INTERACTIVE_MODE_RUNTIME_PROMPTS = {
    "normal": (),
    "stealth": (
        INTERACTIVE_RUNTIME_PROMPTS[2],
        INTERACTIVE_RUNTIME_PROMPTS[3],
        INTERACTIVE_RUNTIME_PROMPTS[4],
        INTERACTIVE_RUNTIME_PROMPTS[5],
    ),
    "lab": (
        INTERACTIVE_RUNTIME_PROMPTS[1],
        INTERACTIVE_RUNTIME_PROMPTS[2],
    ),
}

INTERACTIVE_ALWAYS_RUNTIME_PROMPTS = (
    InteractivePromptSpec(
        "ai",
        "[?] Enable AI Vulnerability Analysis (Ollama)? (y/N)",
        "N",
    ),
    InteractivePromptSpec(
        "ollama_url",
        f"[?] Ollama URL (default: {DEFAULT_OLLAMA_URL})",
        DEFAULT_OLLAMA_URL,
        value_type="text",
    ),
    InteractivePromptSpec(
        "proxy_listen",
        "[?] Start MITM Proxy Interceptor in background (Port 8081)? (y/N)",
        "N",
    ),
    InteractivePromptSpec("html", "[?] Generate HTML report? (y/N)", "N"),
    InteractivePromptSpec("sarif", "[?] Generate SARIF report? (y/N)", "N"),
)

INTERACTIVE_RESUME_PROMPT = InteractivePromptSpec(
    "resume",
    "[?] Resume session file (leave empty to configure a new scan)",
    "",
    value_type="text",
)

API_SPEC_PROMPT = InteractivePromptSpec(
    "api_spec",
    "[?] OpenAPI spec file (leave empty to auto-discover)",
    "",
    value_type="text",
)

JSON_OUTPUT_PROMPT = InteractivePromptSpec(
    "json_output",
    "[?] Save JSON? (y/N)",
    "N",
)


