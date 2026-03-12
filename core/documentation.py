"""
cyberm4fia-scanner - Documentation generation from scanner metadata.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

from core.module_registry import ASYNC_MODULES, PHASE_MODULES
from core.scan_options import (
    ATTACK_PROFILE_SPECS,
    SCAN_MODE_SPECS,
    add_parser_arguments,
)


@dataclass(frozen=True)
class FeatureDocSpec:
    """Declarative feature documentation metadata."""

    category: str
    name: str
    description: str
    option_key: str | None = None
    flag_label: str | None = None


ROOT_DIR = Path(__file__).resolve().parent.parent

FEATURE_DOC_CATEGORY_ORDER = (
    "Web Application Scanning",
    "API Security",
    "Network & Infrastructure",
    "Intelligence & OSINT",
    "Automation & Reporting",
)

FEATURE_DOC_SPECS = (
    FeatureDocSpec(
        "Web Application Scanning",
        "XSS",
        "Reflected and stored XSS checks with context-aware payload selection.",
        option_key="xss",
    ),
    FeatureDocSpec(
        "Web Application Scanning",
        "SQLi",
        "Union-based SQL injection with blind fallback and exploit post-processing.",
        option_key="sqli",
    ),
    FeatureDocSpec(
        "Web Application Scanning",
        "LFI",
        "Local File Inclusion checks against traversal and wrapper payloads.",
        option_key="lfi",
    ),
    FeatureDocSpec(
        "Web Application Scanning",
        "RFI",
        "Remote File Inclusion checks for remote fetch and execution sinks.",
        option_key="rfi",
    ),
    FeatureDocSpec(
        "Web Application Scanning",
        "CMDi",
        "OS command injection checks with optional interactive shell workflow.",
        option_key="cmdi",
    ),
    FeatureDocSpec(
        "Web Application Scanning",
        "SSRF",
        "Server-Side Request Forgery checks including cloud metadata probes.",
        option_key="ssrf",
    ),
    FeatureDocSpec(
        "Web Application Scanning",
        "CSRF",
        "CSRF token and form protection checks for discovered forms.",
        option_key="csrf",
    ),
    FeatureDocSpec(
        "Web Application Scanning",
        "CORS",
        "Cross-Origin Resource Sharing misconfiguration checks.",
        option_key="cors",
    ),
    FeatureDocSpec(
        "Web Application Scanning",
        "Header Injection",
        "CRLF and header injection checks.",
        option_key="header_inject",
    ),
    FeatureDocSpec(
        "Web Application Scanning",
        "DOM XSS",
        "DOM-based XSS checks with Playwright browser execution.",
        option_key="dom_xss",
    ),
    FeatureDocSpec(
        "Web Application Scanning",
        "SSTI",
        "Template injection checks for common server-side template engines.",
        option_key="ssti",
    ),
    FeatureDocSpec(
        "Web Application Scanning",
        "XXE",
        "XML External Entity injection checks.",
        option_key="xxe",
    ),
    FeatureDocSpec(
        "Web Application Scanning",
        "Open Redirect",
        "Redirect abuse checks across discovered URLs.",
        option_key="redirect",
    ),
    FeatureDocSpec(
        "Web Application Scanning",
        "Passive Scan",
        "Passive checks for headers, debug leakage, and lightweight disclosures.",
        option_key="passive",
    ),
    FeatureDocSpec(
        "Web Application Scanning",
        "Secrets Scan",
        "HTML and JavaScript secret exposure scanning for API keys and tokens.",
        option_key="secrets",
    ),
    FeatureDocSpec(
        "Web Application Scanning",
        "OOB Testing",
        "Out-of-band callback support for blind vulnerability verification.",
        option_key="oob",
    ),
    FeatureDocSpec(
        "API Security",
        "API Scanner",
        "OWASP API tests with OpenAPI import, schema-aware bodies, and auth intel.",
        option_key="api_scan",
    ),
    FeatureDocSpec(
        "Network & Infrastructure",
        "Recon",
        "Deep port, DNS, and TLS recon. Lightweight server and header intel runs on every scan.",
        option_key="recon",
    ),
    FeatureDocSpec(
        "Network & Infrastructure",
        "Subdomain Discovery",
        "Subdomain enumeration for the target host.",
        option_key="subdomain",
    ),
    FeatureDocSpec(
        "Network & Infrastructure",
        "Endpoint Fuzzer",
        "Directory and API endpoint brute forcing with smart 404 calibration.",
        option_key="fuzz",
    ),
    FeatureDocSpec(
        "Network & Infrastructure",
        "Crawler",
        "Recursive crawler with form and link discovery.",
        option_key="crawl",
    ),
    FeatureDocSpec(
        "Network & Infrastructure",
        "Headless Discovery",
        "Playwright-based SPA rendering and background endpoint discovery.",
        option_key="headless",
    ),
    FeatureDocSpec(
        "Network & Infrastructure",
        "Cloud Buckets",
        "Open S3, Azure Blob, and GCP bucket detection.",
        option_key="cloud",
    ),
    FeatureDocSpec(
        "Network & Infrastructure",
        "Subdomain Takeover",
        "Dangling DNS and takeover fingerprint checks.",
        option_key="takeover",
    ),
    FeatureDocSpec(
        "Network & Infrastructure",
        "Credential Spray",
        "Default credential checks for exposed services.",
        option_key="spray",
    ),
    FeatureDocSpec(
        "Intelligence & OSINT",
        "Technology Fingerprinting",
        "Wappalyzer-style technology detection with CVE enrichment.",
        option_key="tech",
    ),
    FeatureDocSpec(
        "Intelligence & OSINT",
        "OSINT Enrichment",
        "Shodan InternetDB, WHOIS, and ASN enrichment.",
        option_key="osint",
    ),
    FeatureDocSpec(
        "Intelligence & OSINT",
        "Email Harvesting",
        "Email discovery from public sources and on-page content.",
        option_key="email",
    ),
    FeatureDocSpec(
        "Automation & Reporting",
        "JWT Attack Suite",
        "Weak secret, algorithm confusion, and claim tampering checks.",
        option_key="jwt",
    ),
    FeatureDocSpec(
        "Automation & Reporting",
        "Race Condition",
        "TOCTOU and replay-style concurrency checks.",
        option_key="race",
    ),
    FeatureDocSpec(
        "Automation & Reporting",
        "HTTP Smuggling",
        "CL.TE and TE.CL request smuggling checks.",
        option_key="smuggle",
    ),
    FeatureDocSpec(
        "Automation & Reporting",
        "Prototype Pollution",
        "Node.js prototype pollution probes.",
        option_key="proto",
    ),
    FeatureDocSpec(
        "Automation & Reporting",
        "Deserialization",
        "Insecure deserialization checks.",
        option_key="deser",
    ),
    FeatureDocSpec(
        "Automation & Reporting",
        "Business Logic",
        "Multi-step business logic flaw checks.",
        option_key="bizlogic",
    ),
    FeatureDocSpec(
        "Automation & Reporting",
        "Vulnerability Chaining",
        "Attack path correlation across discovered findings.",
        option_key="chain",
    ),
    FeatureDocSpec(
        "Automation & Reporting",
        "Wordlist Generation",
        "Site-specific password wordlist generation.",
        option_key="wordlist",
    ),
    FeatureDocSpec(
        "Automation & Reporting",
        "AI Analysis",
        "Local AI-assisted false-positive filtering and remediation guidance.",
        option_key="ai",
    ),
    FeatureDocSpec(
        "Automation & Reporting",
        "Proxy Interceptor",
        "Built-in MITM proxy to capture traffic and feed scanner workflows.",
        option_key="proxy_listen",
    ),
    FeatureDocSpec(
        "Automation & Reporting",
        "PoC Generator",
        "Automatic HTML and JSON proof-of-concept generation for findings.",
        flag_label="`(auto)`",
    ),
    FeatureDocSpec(
        "Automation & Reporting",
        "Template Engine",
        "Built-in template-based checks that can be enabled through all-modules mode.",
        flag_label="`(auto via --all)`",
    ),
)

CLI_DOC_GROUPS = (
    (
        "Target & Scope",
        {
            "url",
            "target_list",
            "compare",
            "scope",
            "exclude",
            "session",
            "resume",
        },
    ),
    (
        "Scan Modules",
        {
            spec.option_key
            for spec in FEATURE_DOC_SPECS
            if spec.option_key and spec.option_key not in {"ai", "proxy_listen"}
        }
        | {"all", "api_spec"},
    ),
    (
        "Runtime & Output",
        {
            "mode",
            "cookie",
            "threads",
            "wordlist_file",
            "proxy_url",
            "tamper",
            "quiet",
            "html",
            "json",
            "sarif",
            "ai",
            "ai_model",
        },
    ),
    (
        "Service Modes",
        {"api", "port", "proxy_listen", "scope_proxy"},
    ),
)

DOC_TARGETS = {
    ROOT_DIR / "README.md": ("feature_tables", "scan_modes", "attack_profiles"),
    ROOT_DIR / "usagewithai.md": ("scan_modes", "attack_profiles", "cli_flags"),
}

GENERATED_SECTION_RENDERERS = {
    "feature_tables": lambda: render_feature_tables_markdown(),
    "scan_modes": lambda: render_scan_modes_markdown(),
    "attack_profiles": lambda: render_attack_profiles_markdown(),
    "cli_flags": lambda: render_cli_flags_markdown(),
}


def _build_registry_name_map():
    name_map = {}
    for spec in ASYNC_MODULES + PHASE_MODULES:
        if spec.option_key:
            name_map.setdefault(spec.option_key, spec.name)
    return name_map


REGISTRY_NAME_MAP = _build_registry_name_map()


def build_parser():
    """Create a parser populated from scanner metadata."""
    parser = argparse.ArgumentParser(description="cyberm4fia-scanner")
    add_parser_arguments(parser)
    return parser


def iter_documented_actions():
    """Yield parser actions that map to documented CLI flags."""
    parser = build_parser()
    for action in parser._actions:
        if not action.option_strings:
            continue
        yield action


def build_action_map():
    """Return documented parser actions keyed by argparse destination."""
    return {action.dest: action for action in iter_documented_actions()}


def format_action_invocation(action, long_only=False):
    """Render a CLI flag invocation similar to argparse help output."""
    if long_only:
        long_flags = [flag for flag in action.option_strings if flag.startswith("--")]
        if long_flags:
            option = long_flags[-1]
            metavar = _get_action_metavar(action)
            if metavar:
                return f"{option} {metavar}"
            return option

    formatter = argparse.HelpFormatter("scanner.py")
    return formatter._format_action_invocation(action)


def _get_action_metavar(action):
    if action.nargs == 0:
        return ""

    if action.metavar is None:
        return action.dest.upper()

    if isinstance(action.metavar, tuple):
        return " ".join(action.metavar)

    return str(action.metavar)


def render_feature_tables_markdown():
    """Render README feature tables from metadata."""
    action_map = build_action_map()
    lines = []

    for category in FEATURE_DOC_CATEGORY_ORDER:
        rows = [spec for spec in FEATURE_DOC_SPECS if spec.category == category]
        if not rows:
            continue

        lines.append(f"### {category}")
        lines.append("| Module | Flag | Description |")
        lines.append("|---|---|---|")

        for spec in rows:
            flag_label = spec.flag_label or _render_feature_flag_label(
                spec.option_key, action_map
            )
            lines.append(f"| {spec.name} | {flag_label} | {spec.description} |")

        lines.append("")

    return "\n".join(lines).strip()


def _render_feature_flag_label(option_key, action_map):
    if not option_key:
        return "`(auto)`"
    action = action_map.get(option_key)
    if action:
        return f"`{format_action_invocation(action, long_only=True)}`"
    return f"`{REGISTRY_NAME_MAP.get(option_key, option_key)}`"


def render_cli_flags_markdown():
    """Render CLI flag tables grouped for usage docs."""
    action_map = build_action_map()
    grouped_actions = {group_name: [] for group_name, _ in CLI_DOC_GROUPS}
    grouped_actions["Other"] = []

    for action in iter_documented_actions():
        assigned = False
        for group_name, dests in CLI_DOC_GROUPS:
            if action.dest in dests:
                grouped_actions[group_name].append(action)
                assigned = True
                break
        if not assigned:
            grouped_actions["Other"].append(action)

    lines = []
    for group_name, _ in CLI_DOC_GROUPS:
        actions = grouped_actions[group_name]
        if not actions:
            continue

        lines.append(f"### {group_name}")
        lines.append("| Flag | Description |")
        lines.append("|---|---|")
        for action in actions:
            lines.append(
                f"| `{format_action_invocation(action)}` | {action.help or ''} |"
            )
        lines.append("")

    if grouped_actions["Other"]:
        lines.append("### Other")
        lines.append("| Flag | Description |")
        lines.append("|---|---|")
        for action in grouped_actions["Other"]:
            lines.append(
                f"| `{format_action_invocation(action)}` | {action.help or ''} |"
            )
        lines.append("")

    return "\n".join(lines).strip()


def render_scan_modes_markdown():
    """Render scan mode documentation from runtime metadata."""
    lines = [
        "| Mode | Delay | Threads | Use Case |",
        "|---|---|---|---|",
    ]
    for spec in SCAN_MODE_SPECS:
        lines.append(
            f"| `{spec.key}` | {_format_delay(spec.delay)} | {spec.threads} | {spec.description} |"
        )
    return "\n".join(lines)


def render_attack_profiles_markdown():
    """Render attack profile documentation from preset metadata."""
    lines = [
        "| Profile | Coverage | Included Flags | Suggested Extras |",
        "|---|---|---|---|",
    ]
    action_map = build_action_map()
    for spec in ATTACK_PROFILE_SPECS:
        if spec.option_keys:
            sorted_flags = sorted(
                _render_profile_option_label(option_key, action_map)
                for option_key in spec.option_keys
            )
            flags = ", ".join(sorted_flags)
        else:
            flags = "`manual selection`"

        if spec.recommended_prompt_specs:
            extras = ", ".join(
                _render_prompt_spec_label(prompt_spec, action_map)
                for prompt_spec in spec.recommended_prompt_specs
            )
        else:
            extras = "-"
        lines.append(
            f"| `{spec.choice}-{spec.label}` | {spec.description} | {flags} | {extras} |"
        )
    return "\n".join(lines)


def replace_generated_section(text: str, section_name: str, rendered: str):
    """Replace a generated markdown section delimited by comment markers."""
    start_marker = f"<!-- BEGIN GENERATED: {section_name} -->"
    end_marker = f"<!-- END GENERATED: {section_name} -->"

    if start_marker not in text or end_marker not in text:
        raise ValueError(f"Missing generated section markers for {section_name}")

    start_index = text.index(start_marker) + len(start_marker)
    end_index = text.index(end_marker)

    replacement = f"\n{rendered.strip()}\n"
    return text[:start_index] + replacement + text[end_index:]


def _format_delay(delay: float):
    rendered = f"{delay:.2f}".rstrip("0").rstrip(".")
    if "." not in rendered:
        rendered += ".0"
    return f"{rendered}s"


def _render_profile_option_label(option_key, action_map):
    if option_key == "templates":
        return "`(auto via --all)`"
    return _render_feature_flag_label(option_key, action_map)


def _render_prompt_spec_label(prompt_spec, action_map):
    action = action_map.get(prompt_spec.option_key)
    if action:
        return f"`{format_action_invocation(action, long_only=True)}`"
    return f"`{prompt_spec.option_key}`"


def sync_generated_docs(paths=None):
    """Update generated documentation blocks in repository docs."""
    updated_paths = []
    selected_paths = paths or DOC_TARGETS.keys()

    for path in selected_paths:
        file_path = Path(path)
        text = file_path.read_text(encoding="utf-8")
        for section_name in DOC_TARGETS[file_path]:
            renderer = GENERATED_SECTION_RENDERERS[section_name]
            text = replace_generated_section(text, section_name, renderer())
        file_path.write_text(text, encoding="utf-8")
        updated_paths.append(file_path)

    return updated_paths
