"""
cyberm4fia-scanner - Scan option defaults and presets.
"""

from dataclasses import dataclass

from core.module_registry import ASYNC_MODULES, PHASE_MODULES
from utils.request import (
    get_default_timeout,
    get_path_blacklist,
    get_request_delay,
    get_stealth_delay,
    normalize_proxy_url,
)


DEFAULT_AI_MODEL = "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B"


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
        "exploit",
        "[?] Enable exploit follow-up actions/prompts? (y/N)",
        "N",
    ),
    InteractivePromptSpec(
        "ai",
        "[?] Enable AI Vulnerability Analysis (Ollama)? (y/N)",
        "N",
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


def build_default_scan_options(threads=10, ai_model=DEFAULT_AI_MODEL):
    """Return a fresh options dict with consistent defaults."""
    options = dict(SCAN_OPTION_DEFAULTS)
    options["threads"] = threads
    options["ai_model"] = ai_model
    return options


def enable_option_keys(options: dict, keys):
    """Set a list of option keys to True in-place."""
    for key in keys:
        options[key] = True
    return options


def apply_profile_preset(options: dict, profile_choice: str):
    """Apply a predefined interactive profile to the options dict."""
    return enable_option_keys(options, PROFILE_PRESETS.get(profile_choice, ()))


def get_scan_mode_spec(choice: str):
    """Return scan mode metadata with the current default fallback."""
    normalized = str(choice or "").strip().lower()
    normalized = {"quick": "normal", "aggressive": "lab"}.get(normalized, normalized)
    if normalized in SCAN_MODE_MAP:
        return SCAN_MODE_MAP[normalized]
    if normalized in SCAN_MODE_ALIAS_MAP:
        return SCAN_MODE_MAP[SCAN_MODE_ALIAS_MAP[normalized]]
    return SCAN_MODE_MAP["normal"]


def get_scan_mode_runtime(choice: str):
    """Return runtime tuple for the selected scan mode."""
    spec = get_scan_mode_spec(choice)
    return spec.runtime_mode, spec.delay, spec.threads


def get_interactive_scan_mode_spec(choice: str):
    """Return the interactive primary mode (normal or stealth)."""
    normalized = str(choice or "").strip().lower()
    for spec in INTERACTIVE_SCAN_MODE_SPECS:
        if normalized in {spec.interactive_choice, spec.key}:
            return spec
    return INTERACTIVE_SCAN_MODE_SPECS[0]


def get_attack_profile_spec(choice: str):
    """Return interactive attack profile metadata with custom fallback."""
    return ATTACK_PROFILE_MAP.get(choice, ATTACK_PROFILE_MAP["5"])


def get_attack_profile_recommended_prompt_specs(choice: str, options: dict | None = None):
    """Return recommended extra prompts for an attack profile."""
    prompt_specs = get_attack_profile_spec(choice).recommended_prompt_specs
    if options is None:
        return prompt_specs
    return tuple(spec for spec in prompt_specs if not options.get(spec.option_key))


def merge_interactive_prompt_specs(*prompt_groups, options: dict | None = None):
    """Merge prompt groups, deduplicating by option key and honoring skip rules."""
    merged = []
    seen = set()

    for prompt_group in prompt_groups:
        for spec in prompt_group:
            if spec.option_key in seen:
                continue
            if options and options.get(spec.option_key):
                continue
            if options and any(options.get(key) for key in spec.skip_if_truthy):
                continue
            seen.add(spec.option_key)
            merged.append(spec)

    return tuple(merged)


def get_interactive_runtime_prompt_specs(
    mode_key: str,
    profile_choice: str,
    options: dict | None = None,
):
    """Return adaptive runtime prompts for the selected mode/profile."""
    profile_key = get_attack_profile_spec(profile_choice).choice
    profile_prompts = INTERACTIVE_PROFILE_RUNTIME_PROMPTS.get(profile_key, ())
    mode_prompts = INTERACTIVE_MODE_RUNTIME_PROMPTS.get(get_scan_mode_spec(mode_key).key, ())
    return merge_interactive_prompt_specs(
        profile_prompts,
        mode_prompts,
        INTERACTIVE_ALWAYS_RUNTIME_PROMPTS,
        options=options,
    )


def build_cli_scan_options(args, threads: int):
    """Build scanner options from argparse args while preserving current semantics."""
    use_all = bool(getattr(args, "all", False))
    options = build_default_scan_options(
        threads=threads,
        ai_model=getattr(args, "ai_model", DEFAULT_AI_MODEL),
    )

    for key in BOOL_OPTION_KEYS:
        enabled = bool(getattr(args, key, False))
        if enabled or (use_all and key in ALL_ENABLED_OPTION_KEYS):
            options[key] = True

    options["templates"] = use_all
    options["api_spec"] = getattr(args, "api_spec", "") or ""
    options["cookie"] = getattr(args, "cookie", "") or ""
    options["tamper"] = getattr(args, "tamper", "") or ""
    options["proxy_url"] = normalize_proxy_url(getattr(args, "proxy_url", "") or "")
    options["scope"] = getattr(args, "scope", "") or ""
    options["exclude"] = getattr(args, "exclude", "") or ""
    options["session"] = getattr(args, "session", "") or ""
    options["resume"] = getattr(args, "resume", "") or ""
    options["max_requests"] = int(getattr(args, "max_requests", 0) or 0)
    options["request_timeout"] = float(
        getattr(args, "request_timeout", get_default_timeout())
        or get_default_timeout()
    )
    options["max_host_concurrency"] = int(
        getattr(args, "max_host_concurrency", 0) or 0
    )
    options["path_blacklist"] = getattr(args, "path_blacklist", "") or ""
    options["wordlist_file"] = (
        getattr(args, "wordlist_file", "wordlists/api_endpoints.txt")
        or "wordlists/api_endpoints.txt"
    )
    options["json_output"] = bool(getattr(args, "json", False) or use_all)
    options["threads"] = threads
    options["ai_model"] = getattr(args, "ai_model", DEFAULT_AI_MODEL)
    return normalize_runtime_options(options)


def build_api_scan_options(
    modules: list[str] | None,
    *,
    threads: int,
    exploit: bool = False,
    api_spec: str = "",
    cookie: str = "",
    proxy_url: str = "",
    scope: str = "",
    exclude: str = "",
    max_requests: int = 0,
    request_timeout: float | None = None,
    max_host_concurrency: int = 0,
    path_blacklist: str = "",
):
    """Build API scan options using the same registry-driven flags as CLI scans."""
    requested_modules = [
        module.strip().lower().replace("-", "_")
        for module in (modules or ["all"])
        if module and module.strip()
    ]
    if not requested_modules:
        requested_modules = ["all"]

    unknown_modules = sorted(
        set(requested_modules) - (API_MODULE_OPTION_KEYS | {"all"})
    )
    if unknown_modules:
        raise ValueError(
            f"Unknown API modules: {', '.join(unknown_modules)}"
        )

    use_all = "all" in requested_modules
    options = build_default_scan_options(threads=threads, ai_model=DEFAULT_AI_MODEL)

    if use_all:
        for key in API_MODULE_OPTION_KEYS:
            options[key] = True
    else:
        for key in requested_modules:
            if key != "all":
                options[key] = True

    options["api_spec"] = api_spec or ""
    options["cookie"] = cookie or ""
    options["proxy_url"] = normalize_proxy_url(proxy_url or "")
    options["scope"] = scope or ""
    options["exclude"] = exclude or ""
    options["exploit"] = bool(exploit)
    options["max_requests"] = int(max_requests or 0)
    options["request_timeout"] = float(
        request_timeout or get_default_timeout()
    )
    options["max_host_concurrency"] = int(max_host_concurrency or 0)
    options["path_blacklist"] = path_blacklist or ""
    options["json_output"] = True
    options["html"] = True
    options["sarif"] = True
    options["threads"] = threads
    return normalize_runtime_options(options)


def add_parser_arguments(parser):
    """Populate an argparse parser from declarative metadata."""
    for spec in PARSER_ARGUMENT_SPECS:
        parser.add_argument(*spec.flags, **spec.kwargs)
    return parser


def resolve_interactive_prompt_value(spec: InteractivePromptSpec, raw_value: str):
    """Normalize an interactive response according to the prompt metadata."""
    if spec.value_type == "text":
        normalized = (raw_value or spec.default).strip()
        if spec.option_key == "proxy_url":
            return normalize_proxy_url(normalized)
        if spec.option_key in {"session", "resume"} and normalized.lower() in {
            "y",
            "yes",
            "n",
            "no",
        }:
            return ""
        return normalized

    normalized = (raw_value or "").strip().lower()
    default_enabled = spec.default.strip().lower() == "y"

    if not normalized:
        return default_enabled
    if default_enabled:
        return normalized not in {"n", "no"}
    return normalized in {"y", "yes"}


def apply_interactive_prompt_specs(target: dict, prompt_specs, input_func):
    """Populate target values by prompting through declarative prompt specs."""
    for spec in prompt_specs:
        if any(target.get(key) for key in spec.skip_if_truthy):
            continue
        response = input_func(spec.prompt, spec.default)
        target[spec.option_key] = resolve_interactive_prompt_value(spec, response)
    return target


def normalize_runtime_options(options: dict):
    """Normalize free-form runtime values shared by CLI, resume, and interactive flows."""
    options["proxy_url"] = normalize_proxy_url(options.get("proxy_url", ""))

    for key in ("session", "resume", "api_spec", "cookie", "tamper", "scope", "exclude"):
        value = options.get(key, "")
        if isinstance(value, str):
            options[key] = value.strip()

    for key in ("session", "resume"):
        if options.get(key, "").lower() in {"y", "yes", "n", "no"}:
            options[key] = ""

    return options
