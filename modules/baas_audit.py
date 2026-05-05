"""cyberm4fia-scanner — Backend-as-a-Service misconfiguration audit.

Targets misconfigurations that ship routinely from AI-assisted apps:

1. **Supabase**  — anonymous JWT shipped to client + RLS-disabled tables that
   return rows for the bare anon key. Tables are guessed from a small list of
   common names (PostgREST has no listing endpoint by design).
2. **Firebase** — Realtime Database `/.json` left readable to anonymous, the
   single most common Firebase footgun.
3. **Clerk**    — *secret* (`sk_*`) keys that ended up in client-shipped JS.
                  The `pk_*` publishable key is supposed to be public, so we
                  do **not** alert on that — alerting on it would be noise.

Detection logic deliberately stays read-only: we never write, mutate, or call
admin endpoints. Discovery is bounded by `COMMON_TABLES` so we don't hammer
random hosts.

References:
  - https://supabase.com/docs/guides/auth/row-level-security
  - https://firebase.google.com/docs/database/security
  - https://clerk.com/docs/security/api-keys
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin

from utils.colors import log_info, log_warning
from utils.request import (
    ScanExceptions,
    increment_vulnerability_count,
    smart_request,
)


# ─── Detection patterns ─────────────────────────────────────────────────────

# Supabase project URL pattern: https://<sub>.supabase.co
_SUPABASE_URL_RE = re.compile(
    r"https://[a-z0-9-]+\.supabase\.co", re.IGNORECASE
)

# Supabase anon JWT — three base64url segments. The role claim is `anon`.
# We match a JWT-shaped string near a SUPABASE_*KEY assignment to avoid
# confusion with arbitrary unrelated tokens elsewhere on the page.
_SUPABASE_ANON_KEY_RE = re.compile(
    r"""SUPABASE[_A-Z]*KEY['"\s:=]+
        ['"]?(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)['"]?""",
    re.IGNORECASE | re.VERBOSE,
)

# Firebase Realtime Database URL.
_FIREBASE_DB_URL_RE = re.compile(
    r"https://[a-z0-9-]+(?:-default-rtdb)?\.firebaseio\.com", re.IGNORECASE
)

# Clerk secret key shipped to the client — CRITICAL when present.
_CLERK_SECRET_RE = re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{20,}")

# A small wordlist of table names commonly created by Supabase tutorials and
# AI-generated starter projects. Keep the list small — we are scanning a
# user's product, not running a brute force.
COMMON_TABLES = (
    "users",
    "profiles",
    "messages",
    "todos",
    "posts",
    "products",
    "orders",
    "subscriptions",
    "api_keys",
    "secrets",
)

# Cap how many tables we probe per scan to stay polite.
MAX_TABLES = 10


# ─── Detection ──────────────────────────────────────────────────────────────


def _detect_providers(html: str) -> dict[str, dict[str, str]]:
    """Inspect a string of HTML/JS and return a dict of detected providers."""
    providers: dict[str, dict[str, str]] = {}

    if not html:
        return providers

    # Supabase
    sb_url_match = _SUPABASE_URL_RE.search(html)
    sb_key_match = _SUPABASE_ANON_KEY_RE.search(html)
    if sb_url_match or sb_key_match:
        sb: dict[str, str] = {}
        if sb_url_match:
            sb["url"] = sb_url_match.group(0)
        if sb_key_match:
            sb["anon_key"] = sb_key_match.group(1)
        providers["supabase"] = sb

    # Firebase
    fb_url_match = _FIREBASE_DB_URL_RE.search(html)
    if fb_url_match:
        providers["firebase"] = {"database_url": fb_url_match.group(0)}

    # Clerk — only flag the secret key. The publishable pk_* key is
    # supposed to live in the client, so seeing it alone is not a finding.
    clerk_secret = _CLERK_SECRET_RE.search(html)
    if clerk_secret:
        providers["clerk"] = {"secret_key": clerk_secret.group(0)}

    return providers


# ─── Supabase RLS probe ─────────────────────────────────────────────────────


def _check_supabase(provider: dict[str, str], delay: float) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    base = provider.get("url")
    anon_key = provider.get("anon_key")
    if not base or not anon_key:
        return findings

    headers = {"apikey": anon_key, "Authorization": f"Bearer {anon_key}"}

    # Probe a bounded list of table names through PostgREST.
    for table in COMMON_TABLES[:MAX_TABLES]:
        rest_url = urljoin(base.rstrip("/") + "/", f"rest/v1/{table}?select=*&limit=1")
        try:
            resp = smart_request(
                "get", rest_url, headers=headers, delay=delay, timeout=8,
            )
        except ScanExceptions:
            continue

        if resp is None:
            continue

        # PostgREST returns 200 + JSON list when RLS allows the anon role.
        if resp.status_code != 200:
            continue
        try:
            body = resp.json()
        except (ValueError, AttributeError):
            continue

        if isinstance(body, list) and len(body) > 0:
            increment_vulnerability_count()
            findings.append({
                "type": "BaaS_Supabase_RLS_Disabled",
                "vuln": f"Supabase table `{table}` readable by anon role",
                "severity": "HIGH",
                "url": rest_url,
                "description": (
                    f"The Supabase REST endpoint returned {len(body)} row(s) "
                    f"using only the anonymous JWT shipped in the client. "
                    f"This means Row-Level Security is disabled or has a "
                    f"public-read policy on `{table}`. Anyone visiting the "
                    f"site can dump the table."
                ),
                "evidence": (
                    f"GET /rest/v1/{table} -> 200 with "
                    f"{len(body)} row(s)"
                ),
                "remediation": (
                    f"In Supabase Studio, enable RLS on `{table}` and add "
                    f"a policy that requires `auth.uid()` or another "
                    f"appropriate predicate. See "
                    f"https://supabase.com/docs/guides/auth/row-level-security"
                ),
            })
            # One leaky table is enough to make the case — keep scanning a
            # couple more for evidence breadth, but don't dump all of them.
            if len([f for f in findings
                    if f["type"] == "BaaS_Supabase_RLS_Disabled"]) >= 3:
                break

    return findings


# ─── Firebase Realtime DB probe ────────────────────────────────────────────


def _check_firebase(provider: dict[str, str], delay: float) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    db_url = provider.get("database_url")
    if not db_url:
        return findings

    probe_url = db_url.rstrip("/") + "/.json"
    try:
        resp = smart_request("get", probe_url, delay=delay, timeout=8)
    except ScanExceptions:
        return findings

    if resp is None or resp.status_code != 200:
        return findings

    # Firebase returns 200 + JSON for an open RTDB. `null` body means the DB
    # is empty but still publicly readable, which is also a finding.
    try:
        body = resp.json()
    except (ValueError, AttributeError):
        return findings

    is_open_with_data = body not in (None, {}, [])
    is_open_but_empty = body in (None, {}, [])

    if is_open_with_data:
        increment_vulnerability_count()
        findings.append({
            "type": "BaaS_Firebase_Open_RTDB",
            "vuln": "Firebase Realtime Database open to anonymous reads",
            "severity": "CRITICAL",
            "url": probe_url,
            "description": (
                "GET /.json on the Realtime Database returned a populated "
                "JSON tree without authentication. Public-read rules expose "
                "the entire database to anyone with the URL."
            ),
            "evidence": f"GET {probe_url} -> 200 (non-empty JSON)",
            "remediation": (
                'Set security rules to `{"rules": {".read": "auth != null"}}` '
                "or stricter. See "
                "https://firebase.google.com/docs/database/security"
            ),
        })
    elif is_open_but_empty:
        # Empty but readable — still misconfigured, downgrade severity.
        increment_vulnerability_count()
        findings.append({
            "type": "BaaS_Firebase_Open_RTDB",
            "vuln": "Firebase Realtime Database readable (empty)",
            "severity": "MEDIUM",
            "url": probe_url,
            "description": (
                "GET /.json returned 200 but the database is empty. The "
                "rules still allow anonymous reads, so any data created "
                "later will be exposed."
            ),
            "evidence": f"GET {probe_url} -> 200 (empty JSON)",
        })

    return findings


# ─── Clerk secret leak ─────────────────────────────────────────────────────


def _check_clerk(provider: dict[str, str],
                 source_url: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    secret = provider.get("secret_key")
    if not secret:
        return findings

    # Mask the middle of the key so we can show evidence without re-leaking it.
    masked = secret[:11] + "*" * max(0, len(secret) - 15) + secret[-4:]

    increment_vulnerability_count()
    findings.append({
        "type": "BaaS_Clerk_Secret_Key_Leak",
        "vuln": "Clerk secret key shipped to the browser",
        "severity": "CRITICAL",
        "url": source_url,
        "description": (
            "A Clerk secret key (sk_*) was found in client-shipped HTML/JS. "
            "Secret keys grant full backend privileges and must never be "
            "exposed to the browser. Rotate the key immediately and move "
            "any Clerk admin calls to a server-side route."
        ),
        "evidence": f"sk_* token: {masked}",
        "remediation": (
            "1) Rotate the key in the Clerk dashboard. "
            "2) Move all admin Clerk calls (createUser, updateUser, etc.) "
            "to a server-side function. "
            "3) On the client, only ship the publishable pk_* key."
        ),
    })
    return findings


# ─── Public entry point ────────────────────────────────────────────────────


def scan_baas_audit(url: str, delay: float = 0,
                    options: dict | None = None) -> list[dict[str, Any]]:
    """Fetch *url*, sniff for BaaS providers, and probe each one for
    well-known misconfigurations.

    Returns a list of finding dicts with the same shape used elsewhere in the
    scanner. Returns ``[]`` when no provider is detected or when network
    errors prevent any successful probe.
    """
    del options  # reserved; kept for runner-signature parity

    try:
        landing = smart_request("get", url, delay=delay, timeout=8)
    except ScanExceptions:
        return []

    html = getattr(landing, "text", "") or ""
    providers = _detect_providers(html)
    if not providers:
        return []

    log_info(f"☁️  BaaS audit: detected {', '.join(providers.keys())}")

    findings: list[dict[str, Any]] = []
    if "supabase" in providers:
        findings.extend(_check_supabase(providers["supabase"], delay))
    if "firebase" in providers:
        findings.extend(_check_firebase(providers["firebase"], delay))
    if "clerk" in providers:
        findings.extend(_check_clerk(providers["clerk"], source_url=url))

    if findings:
        log_warning(f"BaaS audit found {len(findings)} issue(s)")
    return findings
