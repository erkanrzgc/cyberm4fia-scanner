"""APTS / Anti-Shallow / WAF-Bypass constants used by the agent framework.

Pulled out of the main module so the orchestrator and depth tracker
can both import them without each carrying a copy.
"""

# Minimum probes per vulnerability class before declaring "no findings"
# Inspired by pentest-agents: 7-level WAF bypass + technique depth requirements
MIN_PROBES_PER_CLASS = {
    "xss": 8,
    "sqli": 10,
    "lfi": 8,
    "cmdi": 8,
    "ssrf": 10,
    "ssti": 6,
    "xxe": 6,
    "jwt": 5,
    "idor": 8,
    "open_redirect": 6,
    "cors": 6,
    "csrf": 5,
    "file_upload": 8,
    "deserialization": 5,
    "proto_pollution": 6,
    "race_condition": 10,
    "smuggling": 6,
    "header_inject": 6,
    "nosqli": 6,
    "cache_poisoning": 6,
    "log4shell": 8,
    "el_injection": 6,
    "ldap": 5,
    "xpath": 5,
    "crlf": 6,
    "csv_injection": 5,
    "graphql": 8,
    "business_logic": 8,
    "forbidden_bypass": 10,
    "subdomain_takeover": 5,
    "oauth": 8,
}

# Exhaustion requires all three conditions
EXHAUSTION_REQUIREMENTS = [
    "min_probes_met",
    "all_bypass_levels_attempted",
    "blocker_recorded",
]

# WAF bypass levels that must be attempted before declaring exhaustion
WAF_BYPASS_LEVELS = {
    1: "Encoding (URL, double-URL, Unicode, HTML entity)",
    2: "Tag alternatives (svg, details, math, dialog instead of script/img)",
    3: "Parser differentials (tag confusion, nesting, re-parenting)",
    4: "Protocol variations (javascript:, data:, vbscript:)",
    5: "Framework-specific sinks (React, Angular, Vue, jQuery, Bootstrap)",
    6: "CSP-bypass techniques (nonce, base-tag, srcdoc, dynamic import)",
    7: "Obfuscation (JSFuck, unicode identifiers, constructor chains)",
}

# Modules that must NEVER return "not vulnerable" without a browser probe
BROWSER_REQUIRED_MODULES = {
    "xss", "dom_xss", "csrf", "business_logic", "file_upload",
    "race_condition", "open_redirect", "account_takeover", "auth_bypass",
}

# Modules susceptible to WAF false negatives (curl 403 ≠ not vulnerable)
WAF_SENSITIVE_MODULES = {
    "xss", "sqli", "cmdi", "ssrf", "lfi", "ssti", "xxe", "forbidden_bypass",
    "header_inject", "smuggling", "cache_poisoning", "file_upload",
}

# Max failed candidates per depth (chain-table rule 5)
MAX_FAILED_CANDIDATES_PER_DEPTH = 3

# 20-minute time box per link (chain-table rule 4)
CHAIN_LINK_TIMEOUT = 1200
