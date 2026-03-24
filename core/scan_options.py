"""
cyberm4fia-scanner – Scan option functions.
Uses scan_option_specs.py for spec/prompt/profile data.
"""

from core.scan_option_specs import (  # noqa: F401
    ArgumentSpec,
    InteractivePromptSpec,
    ScanModeSpec,
    AttackProfileSpec,
    DEFAULT_AI_MODEL,
    SCAN_OPTION_DEFAULTS,
    BOOL_OPTION_KEYS,
    ALL_ENABLED_OPTION_KEYS,
    API_MODULE_OPTION_KEYS,
    PROFILE_PRESETS,
    SCAN_MODE_SPECS,
    SCAN_MODE_MAP,
    SCAN_MODE_ALIAS_MAP,
    INTERACTIVE_SCAN_MODE_SPECS,
    ATTACK_PROFILE_SPECS,
    ATTACK_PROFILE_MAP,
    PARSER_ARGUMENT_SPECS,
    INTERACTIVE_RESUME_PROMPT,
    INTERACTIVE_CUSTOM_PROMPT_GROUPS,
    INTERACTIVE_ALWAYS_RUNTIME_PROMPTS,
    INTERACTIVE_MODE_RUNTIME_PROMPTS,
    INTERACTIVE_PROFILE_RUNTIME_PROMPTS,
    API_SPEC_PROMPT,
    JSON_OUTPUT_PROMPT,
)

from utils.request import (
    get_default_timeout,
    normalize_proxy_url,
)

# Backward-compat alias
ARGUMENT_SPECS = PARSER_ARGUMENT_SPECS


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


def _interactive_prompt_is_already_set(
    spec: InteractivePromptSpec,
    options: dict | None,
) -> bool:
    """Return True when an interactive prompt already has a meaningful value."""
    if not options:
        return False

    value = options.get(spec.option_key)
    if spec.value_type == "text":
        if not isinstance(value, str):
            return bool(value)
        normalized = value.strip()
        default = str(spec.default).strip()
        return bool(normalized) and normalized != default

    return bool(value)


def merge_interactive_prompt_specs(*prompt_groups, options: dict | None = None):
    """Merge prompt groups, deduplicating by option key and honoring skip rules."""
    merged = []
    seen = set()

    for prompt_group in prompt_groups:
        for spec in prompt_group:
            if spec.option_key in seen:
                continue
            if _interactive_prompt_is_already_set(spec, options):
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
    options["ollama_url"] = (
        getattr(args, "ollama_url", options["ollama_url"]) or options["ollama_url"]
    )
    options["agent"] = bool(getattr(args, "agent", False))
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
