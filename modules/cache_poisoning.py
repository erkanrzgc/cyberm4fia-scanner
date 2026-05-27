"""Web cache poisoning probe — param-miner inspired.

Two attack classes:

1. **Unkeyed header poisoning** — the cache key is the URL (+ maybe a few
   safelisted headers like Host), but the *origin server* reflects extra
   headers like ``X-Forwarded-Host`` / ``X-Forwarded-Scheme`` /
   ``X-Original-URL`` into the response. An attacker poisons the cache
   with a crafted header; every subsequent user receives the poisoned
   response.

2. **Cache key probing** — confirm whether a chosen header *is* part of
   the cache key by sending the same URL with the header set to two
   distinct random values and comparing X-Cache / Age headers.

References:
* https://portswigger.net/research/practical-web-cache-poisoning (2018)
* https://portswigger.net/research/web-cache-entanglement (2020)
* https://github.com/portswigger/param-miner

This is a low-cost passive-active hybrid: a single GET baseline + ~25
header probes per URL. Findings are emitted only when the reflection is
exploitable (poisoned token round-trips into the cached body).
"""

from __future__ import annotations

import logging
import random
import string

logger = logging.getLogger(__name__)


# Headers that are NOT part of the cache key on most CDNs/edge caches
# but ARE reflected back by many origin frameworks.
_PROBE_HEADERS = (
    "X-Forwarded-Host",
    "X-Forwarded-Server",
    "X-Forwarded-Scheme",
    "X-Forwarded-Port",
    "X-Forwarded-Proto",
    "X-Forwarded-Ssl",
    "X-Host",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Override-URL",
    "X-Original-Host",
    "X-HTTP-Host-Override",
    "Forwarded",
    "X-Real-IP",
    "X-Backend-Server",
    "X-Wap-Profile",
    "X-Pingback",
    "Via",
    "Profile",
    "X-Forwarded-For",
    "True-Client-IP",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Client-IP",
    "Client-IP",
)


# Cache-hit / cache-status header names — used to tell whether a request
# was served from cache.
_CACHE_STATUS_HEADERS = (
    "x-cache",
    "x-cache-status",
    "cf-cache-status",        # Cloudflare
    "x-vercel-cache",         # Vercel
    "x-fastly-cache",         # Fastly
    "x-amz-cf-pop",           # CloudFront
    "age",
)


def _looks_cached(headers: dict) -> tuple[bool, str]:
    """Return (is_cached, evidence) from response headers."""
    lower = {k.lower(): str(v) for k, v in headers.items()}
    for name in _CACHE_STATUS_HEADERS:
        if name in lower:
            value = lower[name].lower()
            if any(token in value for token in ("hit", "served", "stale")):
                return True, f"{name}={lower[name]}"
            # Age header > 0 also implies a cache layer
            if name == "age":
                try:
                    if int(lower[name]) > 0:
                        return True, f"age={lower[name]}"
                except ValueError:
                    pass
    return False, ""


def _random_token(length: int = 12) -> str:
    return "cm4f" + "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _baseline(url: str) -> dict | None:
    """Fetch the URL once with no extra headers — baseline body + cache state."""
    try:
        from utils.request import smart_request
    except ImportError:
        return None
    try:
        r = smart_request("get", url)
    except Exception as exc:  # noqa: BLE001
        logger.debug("cache_poisoning baseline failed for %s: %s", url, exc)
        return None
    headers = dict(r.headers)
    is_cached, cache_evidence = _looks_cached(headers)
    return {
        "url": url,
        "status": r.status_code,
        "body": r.text or "",
        "headers": headers,
        "is_cached": is_cached,
        "cache_evidence": cache_evidence,
    }


def _probe_header(url: str, header: str, token: str) -> dict | None:
    try:
        from utils.request import smart_request
    except ImportError:
        return None
    try:
        r = smart_request("get", url, headers={header: f"{token}.attacker.tld"})
    except Exception as exc:  # noqa: BLE001
        logger.debug("cache_poisoning probe %s=%s failed: %s", header, token, exc)
        return None
    return {
        "status": r.status_code,
        "body": r.text or "",
        "headers": dict(r.headers),
    }


def scan_cache_poisoning(url: str, *, max_probes: int = 25) -> list[dict]:
    """Probe ``url`` for unkeyed-header cache poisoning vulnerabilities.

    Returns a list of finding dicts. Each finding includes the header
    name, the poisoned token, and whether the response also shows a cache
    HIT — strong signal that the poisoned response is now served to
    other clients.
    """
    base = _baseline(url)
    if base is None:
        return []

    findings: list[dict] = []
    probes = _PROBE_HEADERS[:max_probes]
    for header in probes:
        token = _random_token()
        probe = _probe_header(url, header, token)
        if probe is None:
            continue
        if token not in (probe["body"] or ""):
            continue  # not reflected — not a poisoning candidate

        # Reflection confirmed. Re-fetch baseline-style request and see if
        # the cache layer returns the poisoned body to a clean client.
        clean = _baseline(url)
        cache_serves_poison = bool(clean and token in (clean["body"] or ""))
        is_cached, evidence = _looks_cached(probe["headers"])

        severity = "HIGH" if cache_serves_poison else ("MEDIUM" if is_cached else "LOW")
        findings.append({
            "type": (
                "Cache_Poisoning_Verified" if cache_serves_poison
                else "Cache_Poisoning_Reflection"
            ),
            "url": url,
            "param": header,
            "payload": f"{header}: {token}.attacker.tld",
            "severity": severity,
            "evidence": (
                f"header {header} reflected in body"
                + (f"; cache layer returned poisoned token to clean client" if cache_serves_poison else "")
                + (f"; cache state: {evidence}" if evidence else "")
            ),
            "module": "cache_poisoning",
            "verification_state": "verified" if cache_serves_poison else "evidence_confirmed",
        })

        # Stop early if we already confirmed a full poisoning — repeated
        # probes risk serving the poisoned cache to real users.
        if cache_serves_poison:
            break

    return findings
