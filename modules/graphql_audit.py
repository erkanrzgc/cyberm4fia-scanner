"""
cyberm4fia-scanner — GraphQL deep-audit module.

Existing introspection probe lives in `modules.api_scanner` and
`modules.api_inject`. This module covers the four vectors those
do not handle:

1. Query-depth DoS    — server has no max_depth limit
2. Batching attack    — alias-batched and array-batched queries
                        (auth brute-force / rate-limit bypass risk)
3. Field-suggestion   — "Did you mean ...?" leaks schema field
                        names even when introspection is disabled
4. CSRF over GET      — server accepts query via ?query=... GET

Reference: https://graphql.org/learn/security/
"""

from __future__ import annotations

from typing import Optional
from urllib.parse import urljoin

from utils.colors import log_info, log_warning
from utils.request import (
    ScanExceptions,
    increment_vulnerability_count,
    smart_request,
)


# ─── Constants ──────────────────────────────────────────────────────────────

GRAPHQL_PATHS = ("/graphql", "/graphiql", "/api/graphql")

# Probe used to confirm the endpoint is a live GraphQL server. `__typename`
# resolves on the root Query type for every spec-compliant server, so it
# works even when full introspection is disabled.
TYPENAME_PROBE = {"query": "{ __typename }"}

# Depth-limit error fingerprints — common across apollo, graphql-js,
# graphql-ruby, hot-chocolate, lighthouse-php.
DEPTH_LIMIT_HINTS = (
    "exceeds maximum depth",
    "query is too deep",
    "max query depth",
    "depth limit",
    "exceeds max depth",
)

# Alias / batching limit fingerprints.
ALIAS_LIMIT_HINTS = (
    "too many aliases",
    "max aliases",
    "alias limit",
    "batched queries are not allowed",
    "batching is disabled",
)

# Number of aliases / array entries we send when probing for batching.
# Big enough that a sane server would reject it, small enough to stay polite.
ALIAS_BATCH_SIZE = 50
ARRAY_BATCH_SIZE = 20

# Depth used in the DoS probe. 12 is well past the typical safe ceiling of 5–8.
DEPTH_PROBE_LEVELS = 12

# Did-you-mean leak — graphql-js emits this exact phrase by default. Other
# servers (graphql-ruby `did_you_mean`, hot-chocolate suggestions) reuse it.
SUGGESTION_HINT = "did you mean"


# ─── Helpers ────────────────────────────────────────────────────────────────


def _post_graphql(url: str, body, delay: float):
    """POST a GraphQL body. Returns the response or None on network error."""
    try:
        return smart_request(
            "post", url,
            json=body,
            delay=delay,
            headers={"Content-Type": "application/json"},
            timeout=8,
        )
    except ScanExceptions:
        return None


def _safe_json(resp):
    if resp is None:
        return None
    try:
        return resp.json()
    except (ValueError, AttributeError):
        return None


def _is_alive_graphql(resp) -> bool:
    """Endpoint is GraphQL if it returns either data or errors as JSON."""
    body = _safe_json(resp)
    if not isinstance(body, dict):
        return False
    return "data" in body or "errors" in body


def _has_hint(resp, hints: tuple[str, ...]) -> bool:
    body = _safe_json(resp)
    # Array-batched responses are lists of {data,errors} objects; flatten.
    bodies = body if isinstance(body, list) else [body]
    text_parts: list[str] = []
    for b in bodies:
        if not isinstance(b, dict):
            continue
        for e in b.get("errors") or []:
            text_parts.append(str(e.get("message", "")))
    text = " ".join(text_parts).lower()
    return any(h in text for h in hints)


def _build_nested_query(depth: int) -> str:
    """Build a query nested `depth` levels deep on a self-referencing field.

    `__typename` is universally available, so even without a recursive
    type the parser still has to walk the selection set, which is what
    a depth limit is supposed to bound.
    """
    inner = "__typename"
    for _ in range(depth):
        inner = "node { " + inner + " }"
    return "{ " + inner + " }"


# ─── Detection ──────────────────────────────────────────────────────────────


def _detect_graphql_endpoint(base_url: str, delay: float) -> Optional[str]:
    """Probe the conventional GraphQL paths under `base_url`.

    Returns the first URL that responds with a GraphQL-shaped JSON body,
    or None if no candidate path looks alive.
    """
    for path in GRAPHQL_PATHS:
        candidate = urljoin(base_url if base_url.endswith("/") else base_url + "/",
                            path.lstrip("/"))
        resp = _post_graphql(candidate, TYPENAME_PROBE, delay)
        if _is_alive_graphql(resp):
            return candidate
    return None


# ─── Sub-checks ─────────────────────────────────────────────────────────────


def _check_query_depth(endpoint: str, delay: float) -> list[dict]:
    findings: list[dict] = []
    query = _build_nested_query(DEPTH_PROBE_LEVELS)
    resp = _post_graphql(endpoint, {"query": query}, delay)
    if resp is None:
        return findings

    # If the server detected and rejected the depth, it is protected.
    if _has_hint(resp, DEPTH_LIMIT_HINTS):
        return findings

    body = _safe_json(resp) or {}
    accepted = (
        resp.status_code == 200
        and "data" in body
        and not body.get("errors")
    )
    if accepted:
        increment_vulnerability_count()
        findings.append({
            "type": "GraphQL_Query_Depth_DoS",
            "vuln": "GraphQL Query Depth Not Limited",
            "severity": "MEDIUM",
            "url": endpoint,
            "description": (
                f"Server accepted a query nested {DEPTH_PROBE_LEVELS} levels "
                "deep. Without a max_depth limit, attackers can craft "
                "exponential queries that exhaust CPU/memory."
            ),
            "evidence": query[:200],
        })
    return findings


def _check_alias_batching(endpoint: str, delay: float) -> list[dict]:
    findings: list[dict] = []
    aliases = " ".join(f"a{i}: __typename" for i in range(ALIAS_BATCH_SIZE))
    resp = _post_graphql(endpoint, {"query": "{ " + aliases + " }"}, delay)
    if resp is None or _has_hint(resp, ALIAS_LIMIT_HINTS):
        return findings

    body = _safe_json(resp) or {}
    data = body.get("data") or {}
    # The server processed at least most of the aliases — every alias key
    # should have come back. If it did, this endpoint is brute-forceable.
    if isinstance(data, dict) and len(data) >= ALIAS_BATCH_SIZE // 2:
        increment_vulnerability_count()
        findings.append({
            "type": "GraphQL_Alias_Batching",
            "vuln": "GraphQL Alias Batching Allowed",
            "severity": "HIGH",
            "url": endpoint,
            "description": (
                f"Server processed {len(data)} aliased operations in one "
                "request. This bypasses per-request rate limits and lets "
                "attackers brute-force `login`/`resetPassword`/`verifyOtp` "
                "mutations cheaply."
            ),
            "evidence": f"{len(data)} aliases echoed back",
        })
    return findings


def _check_array_batching(endpoint: str, delay: float) -> list[dict]:
    findings: list[dict] = []
    batch = [{"query": "{ __typename }"} for _ in range(ARRAY_BATCH_SIZE)]
    resp = _post_graphql(endpoint, batch, delay)
    if resp is None or _has_hint(resp, ALIAS_LIMIT_HINTS):
        return findings

    body = _safe_json(resp)
    # Array-batched servers return a list-of-results matching the input length.
    if isinstance(body, list) and len(body) >= ARRAY_BATCH_SIZE // 2:
        increment_vulnerability_count()
        findings.append({
            "type": "GraphQL_Array_Batching",
            "vuln": "GraphQL Array Batching Allowed",
            "severity": "HIGH",
            "url": endpoint,
            "description": (
                f"Server returned {len(body)} responses for a single "
                "array-batched request. Same brute-force / rate-limit "
                "bypass risk as alias batching."
            ),
            "evidence": f"{len(body)} responses",
        })
    return findings


def _check_field_suggestions(endpoint: str, delay: float) -> list[dict]:
    findings: list[dict] = []
    # Deliberately misspelled root field — graphql-js emits a "did you mean"
    # hint by default, leaking real field names even with introspection off.
    resp = _post_graphql(endpoint, {"query": "{ uesr { id } }"}, delay)
    body = _safe_json(resp) or {}
    errors = body.get("errors") or []
    msg = " ".join(str(e.get("message", "")) for e in errors)
    if SUGGESTION_HINT in msg.lower():
        increment_vulnerability_count()
        findings.append({
            "type": "GraphQL_Field_Suggestion",
            "vuln": "GraphQL Field Suggestions Enabled",
            "severity": "LOW",
            "url": endpoint,
            "description": (
                "Server replied with a 'Did you mean...?' hint. Even when "
                "introspection is disabled, suggestions leak the real "
                "schema field names one typo at a time."
            ),
            "evidence": msg[:300],
        })
    return findings


def _check_get_method(endpoint: str, delay: float) -> list[dict]:
    findings: list[dict] = []
    try:
        resp = smart_request(
            "get", endpoint,
            params={"query": "{ __typename }"},
            delay=delay,
            timeout=8,
        )
    except ScanExceptions:
        return findings

    if resp is None or resp.status_code in (405, 400, 403, 404):
        return findings

    if _is_alive_graphql(resp):
        increment_vulnerability_count()
        findings.append({
            "type": "GraphQL_GET_CSRF",
            "vuln": "GraphQL Accepts GET Requests",
            "severity": "MEDIUM",
            "url": endpoint,
            "description": (
                "Server processed a GraphQL query sent as a GET request. "
                "Combined with cookie-based auth, this is CSRF-able via "
                "<img>/<script> tags or simple links. Mutations should "
                "require POST + custom Content-Type or anti-CSRF token."
            ),
            "evidence": f"GET {endpoint}?query={{__typename}} → "
                        f"{resp.status_code}",
        })
    return findings


# ─── Public entry point ─────────────────────────────────────────────────────


def scan_graphql_audit(url: str, delay: float = 0,
                       options: dict | None = None) -> list[dict]:
    """Run the four advanced GraphQL checks against `url`.

    Returns a list of finding dicts with the same shape used elsewhere in
    the scanner. If no GraphQL endpoint is reachable, returns [].
    """
    del options  # reserved for future use; kept for runner-signature parity

    endpoint = _detect_graphql_endpoint(url, delay)
    if endpoint is None:
        return []

    log_info(f"📊 GraphQL audit: probing {endpoint}")

    findings: list[dict] = []
    findings.extend(_check_query_depth(endpoint, delay))
    findings.extend(_check_alias_batching(endpoint, delay))
    findings.extend(_check_array_batching(endpoint, delay))
    findings.extend(_check_field_suggestions(endpoint, delay))
    findings.extend(_check_get_method(endpoint, delay))

    if findings:
        log_warning(
            f"GraphQL audit found {len(findings)} issue(s) at {endpoint}"
        )
    return findings
