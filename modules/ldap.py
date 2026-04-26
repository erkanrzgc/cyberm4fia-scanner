"""
cyberm4fia-scanner - LDAP Injection Scanner

Detects LDAP filter injection where user input is concatenated into an
LDAP query without proper escaping. Common impact: authentication bypass
on LDAP-backed login forms, blind enumeration of directory attributes.

Detection strategy
------------------
1. Send a probe payload that breaks the filter syntax (`(uid=*)(&(uid=*`).
   If the server returns 500 / LDAP error string → likely injection.
2. Send a tautology payload (`*)(uid=*))(|(uid=*`). If the response
   differs significantly from the baseline (e.g. login succeeds, more
   results returned) → confirmed injection.
3. Compare against the baseline: same path, harmless input.

Independent reimplementation; payloads are standard public LDAP-injection
patterns (OWASP Testing Guide, PayloadsAllTheThings).
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from utils.colors import log_info, log_success
from utils.request import BlockedTargetPath, ScanExceptions, smart_request


# Error fingerprints common across LDAP servers and bindings.
_LDAP_ERROR_PATTERNS = [
    re.compile(r"javax\.naming\.directory", re.IGNORECASE),
    re.compile(r"LDAPException", re.IGNORECASE),
    re.compile(r"com\.sun\.jndi\.ldap", re.IGNORECASE),
    re.compile(r"protocol error", re.IGNORECASE),
    re.compile(r"invalid DN syntax", re.IGNORECASE),
    re.compile(r"Bad search filter", re.IGNORECASE),
    re.compile(r"DSID-[0-9A-F]+", re.IGNORECASE),  # Microsoft AD error IDs
    re.compile(r"supplied argument is not a valid ldap", re.IGNORECASE),
    re.compile(r"ldap_search\(\):", re.IGNORECASE),
    re.compile(r"Search:\s*Bad search filter", re.IGNORECASE),
]


# Probe payloads — first to break, second to bypass, third to enumerate.
_LDAP_PROBES: tuple[str, ...] = (
    "*)(uid=*",                    # malformed → LDAP parser error
    "*)(&",                        # half-closed filter
    "admin)(&(password=*",         # auth-bypass classic
    "*)(|(uid=*))",                # tautology
    "*)(|(objectClass=*))",        # broad enumeration
    "(|(uid=*)(uid=*",             # nested disjunction
    ")(cn=*))(|(cn=*",             # combined
)


def _detect_ldap_error(body: str) -> str:
    """Return the first matched LDAP error pattern, or empty string."""
    if not body:
        return ""
    for pattern in _LDAP_ERROR_PATTERNS:
        m = pattern.search(body)
        if m:
            return m.group(0)
    return ""


def _inject(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    flat = {k: (v[0] if isinstance(v, list) else v) for k, v in qs.items()}
    return urlunparse(parsed._replace(query=urlencode(flat)))


def scan_ldap_injection(url: str, params: list[str] | None = None,
                        threads: int = 4, delay: float = 0.0) -> list[dict]:
    """Scan a URL's GET parameters for LDAP injection.

    Sends each probe to each parameter; flags the param if the response
    contains an LDAP error string the baseline did not.
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    target_params = list(params) if params else list(qs.keys())
    if not target_params:
        return []

    # Baseline — must NOT contain LDAP errors. If it already does, the
    # signal is meaningless.
    try:
        baseline = smart_request("get", url, delay=delay)
    except (ScanExceptions, BlockedTargetPath):
        baseline = None
    baseline_body = getattr(baseline, "text", "") or ""
    if _detect_ldap_error(baseline_body):
        log_info("⚠ LDAP: baseline already shows LDAP errors; skipping.")
        return []

    log_info(f"🪪  LDAP: {len(target_params)} param × {len(_LDAP_PROBES)} probe on {url[:60]}")

    findings: list[dict] = []
    seen: set[str] = set()

    def _probe(param: str, payload: str) -> dict | None:
        injected = _inject(url, param, payload)
        try:
            resp = smart_request("get", injected, delay=delay)
        except (ScanExceptions, BlockedTargetPath):
            return None
        body = getattr(resp, "text", "") or ""
        marker = _detect_ldap_error(body)
        if not marker:
            return None
        return {
            "type": "LDAP_Injection",
            "url": url,
            "param": param,
            "payload": payload,
            "evidence": f"LDAP error reflected in response: '{marker[:80]}'",
            "severity": "High",
            "module": "ldap",
        }

    jobs = [(p, payload) for p in target_params for payload in _LDAP_PROBES]
    with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futures = {pool.submit(_probe, p, pl): (p, pl) for p, pl in jobs}
        for fut in as_completed(futures):
            try:
                finding = fut.result()
            except Exception:
                continue
            if not finding:
                continue
            if finding["param"] in seen:
                continue
            seen.add(finding["param"])
            log_success(f"  ✅ LDAP injection on {finding['param']!r}")
            findings.append(finding)

    return findings
