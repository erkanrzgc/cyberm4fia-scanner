"""Interactive attack profile specs."""

from __future__ import annotations

from .defaults import PROFILE_PRESETS
from .types import AttackProfileSpec, InteractivePromptSpec

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
    AttackProfileSpec(
        choice="6",
        label="Web Recon + Audit",
        description=(
            "OctoScan-style web chain: tech intel + nuclei community templates "
            "+ endpoint fuzz + crawl + 7-provider asset search + passive."
        ),
        option_keys=PROFILE_PRESETS["6"],
        interactive_label="[6] Web Recon + Audit",
        recommended_prompt_specs=(
            InteractivePromptSpec(
                "secrets", "[?] Recommended: scan JS/HTML for secrets too? (Y/n)", "Y",
            ),
            InteractivePromptSpec(
                "git_history",
                "[?] Recommended: probe for exposed .git/ directory? (y/N)",
                "N",
            ),
        ),
    ),
)

ATTACK_PROFILE_MAP = {spec.choice: spec for spec in ATTACK_PROFILE_SPECS}
