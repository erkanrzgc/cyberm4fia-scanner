"""Scan URL normalization helpers."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

_NOISE_QUERY_KEYS = {
    "_rsc",
    "__nextdatareq",
    "fbclid",
    "gclid",
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
}


def canonicalize_scan_url(url: str) -> str:
    """Normalize scan URLs to reduce duplicate work on fragments/noise params."""
    if not url:
        return url

    parsed = urlparse(url)
    query_pairs = [
        (key, value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        if key.lower() not in _NOISE_QUERY_KEYS
    ]
    query_pairs.sort()
    normalized = parsed._replace(
        query=urlencode(query_pairs, doseq=True),
        fragment="",
    )
    return urlunparse(normalized)


def canonicalize_scan_urls(urls: list[str]) -> list[str]:
    """Deduplicate scan URLs after canonicalization while preserving order."""
    seen = set()
    normalized = []

    for url in urls:
        candidate = canonicalize_scan_url(url)
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        normalized.append(candidate)

    return normalized
