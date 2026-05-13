"""Interactive runtime prompt specs."""

from __future__ import annotations

from .defaults import DEFAULT_NVIDIA_API_KEY
from .types import InteractivePromptSpec

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
            InteractivePromptSpec(
                "dorking",
                "[?] Run Google Dorking? (y/N)",
                "N",
            ),
            InteractivePromptSpec(
                "wayback",
                "[?] Harvest Wayback Machine URLs? (y/N)",
                "N",
            ),
            InteractivePromptSpec(
                "urlscan",
                "[?] Run URLScan.io passive recon? (y/N)",
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
                "forbidden_bypass",
                "[?] 403/401 Bypass? (y/N)",
                "N",
            ),
            InteractivePromptSpec(
                "file_upload",
                "[?] File Upload Vulns? (y/N)",
                "N",
            ),
            InteractivePromptSpec(
                "ato",
                "[?] Account Takeover? (y/N)",
                "N",
            ),
            InteractivePromptSpec(
                "auth_bypass",
                "[?] 2FA & Auth Bypass? (y/N)",
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
        "[?] Enable AI Vulnerability Analysis (NVIDIA API)? (y/N)",
        "N",
    ),
    InteractivePromptSpec(
        "nvidia_api_key",
        "[?] NVIDIA API Key (leave blank to use NVIDIA_API_KEY env var)",
        DEFAULT_NVIDIA_API_KEY,
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
