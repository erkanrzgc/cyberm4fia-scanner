"""Response fingerprinting for SPA/catch-all false-positive filtering.

Catches the case where a site returns HTTP 200 + its homepage template for any
unknown URL (SPA history routing, custom 404 with 200, Apache catch-all). The
endpoint fuzzer used to rely only on ``len(body) +/- 50`` which misses pages
that embed the request URL in ``<base href>`` / ``<link rel="canonical">``.

Dep-free: pure-Python 64-bit simhash on shingled tokens + tag-skeleton hash
+ ``<title>`` hash. No third-party packages required.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Iterable

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<\s*([a-zA-Z][a-zA-Z0-9]*)")
_WHITESPACE_RE = re.compile(r"\s+")
_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")

# Shingle size for simhash (number of tokens per shingle).
_SHINGLE = 4
_SIMHASH_BITS = 64


@dataclass(frozen=True)
class ResponseFingerprint:
    """Compact fingerprint of an HTTP response body.

    Designed for cheap similarity checks against calibration baselines so the
    fuzzer can discard catch-all/SPA fallback hits without re-fetching.
    """

    length: int
    sha256: str
    title_hash: str
    dom_skeleton_hash: str
    simhash_64: int
    content_type: str = ""

    def to_dict(self) -> dict:
        return {
            "length": self.length,
            "sha256": self.sha256,
            "title_hash": self.title_hash,
            "dom_skeleton_hash": self.dom_skeleton_hash,
            "simhash_64": self.simhash_64,
            "content_type": self.content_type,
        }


@dataclass(frozen=True)
class BaselineSet:
    """Merged fingerprint of several calibration responses.

    A new response is considered "matches the catch-all" if it is similar to
    *any* fingerprint in the set under :func:`is_similar`.
    """

    fingerprints: tuple[ResponseFingerprint, ...]

    def matches(
        self,
        candidate: ResponseFingerprint,
        *,
        length_band: float = 0.05,
        simhash_dist: int = 3,
    ) -> bool:
        return any(
            is_similar(fp, candidate, length_band=length_band, simhash_dist=simhash_dist)
            for fp in self.fingerprints
        )


def _extract_title(body: str) -> str:
    m = _TITLE_RE.search(body)
    if not m:
        return ""
    return _WHITESPACE_RE.sub(" ", m.group(1)).strip().lower()


def _extract_tag_skeleton(body: str) -> str:
    """Return a lowercase sequence of tag names — content stripped.

    Two pages built from the same template (e.g. the same SPA index.html) keep
    an identical tag sequence even when text content changes.
    """
    tags = _TAG_RE.findall(body)
    return ",".join(t.lower() for t in tags)


def _stable_hash_64(data: str) -> int:
    """Stable 64-bit hash. ``hash()`` is process-randomised, so we use sha1."""
    digest = hashlib.sha1(data.encode("utf-8", errors="replace")).digest()
    return int.from_bytes(digest[:8], "big", signed=False)


def _short_sha(data: str) -> str:
    return hashlib.sha1(data.encode("utf-8", errors="replace")).hexdigest()[:16]


def _shingles(tokens: list[str], size: int) -> Iterable[str]:
    if len(tokens) < size:
        if tokens:
            yield " ".join(tokens)
        return
    for i in range(len(tokens) - size + 1):
        yield " ".join(tokens[i : i + size])


def compute_simhash_64(body: str) -> int:
    """64-bit simhash over token shingles.

    Pages that share most of their template (boilerplate header/footer/script
    blocks) get hashes within Hamming distance 0-3 of each other even when URL
    fragments inside ``<base href>`` change.
    """
    tokens = _TOKEN_RE.findall(body.lower())
    counts = [0] * _SIMHASH_BITS
    saw_any = False
    for shingle in _shingles(tokens, _SHINGLE):
        saw_any = True
        h = _stable_hash_64(shingle)
        for bit in range(_SIMHASH_BITS):
            if h & (1 << bit):
                counts[bit] += 1
            else:
                counts[bit] -= 1
    if not saw_any:
        return 0
    out = 0
    for bit in range(_SIMHASH_BITS):
        if counts[bit] > 0:
            out |= 1 << bit
    return out


def hamming_distance(a: int, b: int) -> int:
    return (a ^ b).bit_count()


def compute_fingerprint(body: str, headers: dict | None = None) -> ResponseFingerprint:
    """Build a fingerprint from a response body and optional headers."""
    body = body or ""
    headers = headers or {}
    return ResponseFingerprint(
        length=len(body),
        sha256=_short_sha(body),
        title_hash=_short_sha(_extract_title(body)),
        dom_skeleton_hash=_short_sha(_extract_tag_skeleton(body)),
        simhash_64=compute_simhash_64(body),
        content_type=str(headers.get("Content-Type") or headers.get("content-type") or ""),
    )


def is_similar(
    a: ResponseFingerprint,
    b: ResponseFingerprint,
    *,
    length_band: float = 0.05,
    simhash_dist: int = 3,
) -> bool:
    """Return True when two responses look like the same template.

    Strong signal (any one is enough): identical sha256 OR identical DOM
    skeleton hash. Otherwise we require: same title + length within
    ``length_band`` (default 5%) + simhash Hamming distance ``<= simhash_dist``.
    """
    if a.sha256 == b.sha256 and a.sha256:
        return True
    if a.dom_skeleton_hash == b.dom_skeleton_hash and a.dom_skeleton_hash:
        return True
    if not (a.title_hash and a.title_hash == b.title_hash):
        return False
    max_len = max(a.length, b.length, 1)
    if abs(a.length - b.length) / max_len > length_band:
        return False
    return hamming_distance(a.simhash_64, b.simhash_64) <= simhash_dist


def compute_baseline_set(responses: list[tuple[str, dict | None]]) -> BaselineSet:
    """Build a baseline from ``[(body, headers), ...]`` calibration probes."""
    fps = tuple(compute_fingerprint(body, headers) for body, headers in responses)
    return BaselineSet(fingerprints=fps)
