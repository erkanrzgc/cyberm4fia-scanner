"""Two-account IDOR / privilege-escalation engine.

Real IDOR detection needs *two identities* — Alice owns resource X, can
Bob fetch resource X with his own session? Single-account scans miss
this entirely because the server happily returns Alice's data when
Alice asks.

This module pairs with :mod:`utils.session_manager` (Sprint 2) — the
caller registers two accounts, the engine swaps identities on every
endpoint, and a configurable diff detector decides whether the response
constitutes an access-control failure.

Public surface:

* ``IdResolver`` — pattern-driven scanner that pulls candidate IDs out
  of a URL / body / header / JWT claim. Works on numeric, UUID, base64,
  and JWT-sub forms.
* ``IdorEngine`` — sequences the (alice owns X) / (bob fetches X)
  comparison across a list of endpoints. Returns vuln-dict findings.

The HTTP layer is injectable so this is unit-testable without network.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional
from urllib.parse import parse_qs, urlparse

from utils.colors import log_info, log_success


# ── ID detection ───────────────────────────────────────────────────────────


_NUMERIC_PATH = re.compile(r"/(\d{1,12})(?=/|$|\?)")
_UUID_PATH = re.compile(
    r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    re.IGNORECASE,
)
_BASE64ISH_PATH = re.compile(r"/([A-Za-z0-9_-]{16,64}={0,2})(?=/|$|\?)")


@dataclass(frozen=True)
class CandidateId:
    """One injection point inside an outgoing request."""

    vector: str          # "path" | "query" | "body_json" | "jwt_sub"
    location: str        # path segment / query key / JSON pointer / "sub"
    value: str
    kind: str            # "numeric" | "uuid" | "base64" | "jwt_sub"


class IdResolver:
    """Walks URL/body/header/JWT to extract candidate IDs."""

    def from_url(self, url: str) -> list[CandidateId]:
        candidates: list[CandidateId] = []
        parsed = urlparse(url)

        for match in _UUID_PATH.finditer(parsed.path):
            candidates.append(
                CandidateId("path", parsed.path, match.group(1), "uuid")
            )
        for match in _NUMERIC_PATH.finditer(parsed.path):
            candidates.append(
                CandidateId("path", parsed.path, match.group(1), "numeric")
            )
        # base64 is checked last because UUIDs also look base64-ish.
        for match in _BASE64ISH_PATH.finditer(parsed.path):
            if not _UUID_PATH.search(match.group(0)) and not _NUMERIC_PATH.search(match.group(0)):
                candidates.append(
                    CandidateId("path", parsed.path, match.group(1), "base64")
                )

        if parsed.query:
            for key, values in parse_qs(parsed.query, keep_blank_values=True).items():
                for value in values:
                    kind = self._classify_value(value)
                    if kind:
                        candidates.append(CandidateId("query", key, value, kind))

        return candidates

    def from_json_body(self, body: dict) -> list[CandidateId]:
        candidates: list[CandidateId] = []

        def _walk(node: Any, path: str) -> None:
            if isinstance(node, dict):
                for key, val in node.items():
                    _walk(val, f"{path}/{key}")
            elif isinstance(node, list):
                for idx, val in enumerate(node):
                    _walk(val, f"{path}/{idx}")
            elif isinstance(node, (str, int)):
                kind = self._classify_value(str(node))
                if kind:
                    candidates.append(
                        CandidateId("body_json", path, str(node), kind)
                    )

        _walk(body, "")
        return candidates

    def from_jwt(self, jwt_token: str) -> Optional[CandidateId]:
        """Pull the `sub` (subject) claim from a JWT, no signature check."""
        parts = jwt_token.split(".")
        if len(parts) < 2:
            return None
        try:
            payload = parts[1] + "=" * (-len(parts[1]) % 4)
            decoded = base64.urlsafe_b64decode(payload.encode())
            data = json.loads(decoded)
        except (ValueError, TypeError):
            return None
        sub = data.get("sub")
        if not sub:
            return None
        return CandidateId("jwt_sub", "sub", str(sub), "jwt_sub")

    @staticmethod
    def _classify_value(value: str) -> Optional[str]:
        if not value:
            return None
        if _UUID_PATH.search(f"/{value}/"):
            return "uuid"
        if value.isdigit() and 1 <= len(value) <= 12:
            return "numeric"
        if 16 <= len(value) <= 64 and re.fullmatch(r"[A-Za-z0-9_\-=]+", value):
            return "base64"
        return None


# ── Diff detection ─────────────────────────────────────────────────────────


@dataclass
class ResponseSnapshot:
    status: int
    body_hash: str
    length: int

    @classmethod
    def from_response(cls, response: Any) -> "ResponseSnapshot":
        text = getattr(response, "text", "") or ""
        return cls(
            status=getattr(response, "status_code", 0),
            body_hash=hashlib.sha1(text.encode("utf-8", "ignore")).hexdigest(),
            length=len(text),
        )


def detect_idor(
    owner_snapshot: ResponseSnapshot,
    swapped_snapshot: ResponseSnapshot,
    *,
    length_tolerance: int = 32,
) -> tuple[bool, str]:
    """Return (is_vulnerable, reason).

    The cardinal sign of an IDOR is **same data returned to a different
    user**: same content hash + same status. A correct access-control
    server returns 403/404 to the swapped user, or substantially shorter
    "you don't have permission" output.
    """
    if owner_snapshot.status >= 400:
        return False, "owner request did not return a resource"
    if swapped_snapshot.status >= 400:
        return False, (
            f"access-control enforced — swapped session got "
            f"{swapped_snapshot.status}"
        )
    if owner_snapshot.body_hash == swapped_snapshot.body_hash:
        return True, "identical body served to non-owner session"
    if abs(owner_snapshot.length - swapped_snapshot.length) <= length_tolerance:
        return True, (
            "near-identical body length suggests same record served "
            "to non-owner session"
        )
    return False, "swapped session received a different body"


# ── Engine ─────────────────────────────────────────────────────────────────


@dataclass
class IdorFinding:
    url: str
    vector: str
    location: str
    owner: str
    swapped: str
    severity: str
    evidence: str

    def to_dict(self) -> dict:
        return {
            "type": "IDOR",
            "url": self.url,
            "param": self.location,
            "severity": self.severity,
            "evidence": self.evidence,
            "owner_account": self.owner,
            "swapped_account": self.swapped,
            "vector": self.vector,
            "module": "idor_engine",
        }


class IdorEngine:
    """Run two-account swap diffs across a list of endpoints."""

    def __init__(
        self,
        *,
        request_as: Callable[[str, str], Any],
        owner_account: str = "primary",
        swapped_account: str = "bob",
        resolver: Optional[IdResolver] = None,
    ) -> None:
        # ``request_as(account_name, url)`` performs the HTTP call using
        # that account's session. Caller wires this to SessionManager.
        self.request_as = request_as
        self.owner_account = owner_account
        self.swapped_account = swapped_account
        self.resolver = resolver or IdResolver()

    def scan_url(self, url: str) -> list[IdorFinding]:
        """Run owner-vs-swapped diff against a single resource URL."""
        candidates = self.resolver.from_url(url)
        if not candidates:
            return []

        try:
            owner_response = self.request_as(self.owner_account, url)
            swapped_response = self.request_as(self.swapped_account, url)
        except Exception:  # noqa: BLE001
            return []

        owner_snap = ResponseSnapshot.from_response(owner_response)
        swapped_snap = ResponseSnapshot.from_response(swapped_response)
        is_vuln, reason = detect_idor(owner_snap, swapped_snap)
        if not is_vuln:
            return []

        findings: list[IdorFinding] = []
        # Multiple candidates on one URL share the same evidence — emit
        # one finding per *vector* family rather than per ID match.
        seen_vectors: set[tuple[str, str]] = set()
        for cand in candidates:
            key = (cand.vector, cand.location)
            if key in seen_vectors:
                continue
            seen_vectors.add(key)
            findings.append(
                IdorFinding(
                    url=url,
                    vector=cand.vector,
                    location=cand.location,
                    owner=self.owner_account,
                    swapped=self.swapped_account,
                    severity="high",
                    evidence=(
                        f"Account '{self.swapped_account}' received the "
                        f"same {cand.kind} resource ({reason}); IDOR "
                        f"confirmed via response-diff oracle."
                    ),
                )
            )
        return findings

    def scan_endpoints(self, urls: Iterable[str]) -> list[dict]:
        all_findings: list[IdorFinding] = []
        scanned = 0
        for url in urls:
            scanned += 1
            all_findings.extend(self.scan_url(url))
        if all_findings:
            log_success(
                f"IDOR engine: {len(all_findings)} finding(s) across "
                f"{scanned} endpoint(s)"
            )
        else:
            log_info(f"IDOR engine: no diff hits across {scanned} endpoint(s)")
        return [f.to_dict() for f in all_findings]
