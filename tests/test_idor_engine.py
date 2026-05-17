"""Tests for modules/idor_engine — ID resolver + two-account diff."""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from modules.idor_engine import (
    CandidateId,
    IdorEngine,
    IdorFinding,
    IdResolver,
    ResponseSnapshot,
    detect_idor,
)


pytestmark = pytest.mark.unit


def _resp(status: int, text: str = "") -> SimpleNamespace:
    return SimpleNamespace(status_code=status, text=text)


# ── IdResolver ────────────────────────────────────────────────────────────────


def test_resolver_finds_numeric_path_id():
    candidates = IdResolver().from_url("https://t/api/users/42/profile")
    kinds = [c.kind for c in candidates]
    assert "numeric" in kinds


def test_resolver_finds_uuid_path_id():
    url = "https://t/api/orders/550e8400-e29b-41d4-a716-446655440000"
    candidates = IdResolver().from_url(url)
    assert any(c.kind == "uuid" for c in candidates)


def test_resolver_finds_query_id():
    candidates = IdResolver().from_url("https://t/api/doc?id=12345&unused=x")
    by_vector = {c.vector for c in candidates}
    assert "query" in by_vector
    numeric_query = [c for c in candidates if c.vector == "query" and c.kind == "numeric"]
    assert numeric_query and numeric_query[0].value == "12345"


def test_resolver_finds_base64_id_in_path():
    # "user_abc12345xyz67890token" is base64-ish length and matches the regex.
    url = "https://t/api/token/user_abc12345xyz67890token"
    candidates = IdResolver().from_url(url)
    assert any(c.kind == "base64" for c in candidates)


def test_resolver_no_candidates_on_idless_url():
    assert IdResolver().from_url("https://t/api/login") == []


def test_resolver_json_body_walks_nested_structure():
    body = {
        "user": {"id": 42, "name": "alice"},
        "orders": [{"order_id": 1001}, {"order_id": 1002}],
    }
    candidates = IdResolver().from_json_body(body)
    paths = {c.location for c in candidates}
    assert "/user/id" in paths
    assert "/orders/0/order_id" in paths


def test_resolver_jwt_extracts_sub():
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": "user-42", "iat": 1}).encode()
    ).decode().rstrip("=")
    token = f"header.{payload}.sig"
    cand = IdResolver().from_jwt(token)
    assert cand is not None
    assert cand.kind == "jwt_sub"
    assert cand.value == "user-42"


def test_resolver_jwt_malformed_returns_none():
    assert IdResolver().from_jwt("not-a-jwt") is None
    assert IdResolver().from_jwt("") is None


# ── detect_idor ─────────────────────────────────────────────────────────────


def test_detect_idor_flags_identical_bodies():
    snap = ResponseSnapshot(status=200, body_hash="abc", length=500)
    is_vuln, reason = detect_idor(snap, snap)
    assert is_vuln
    assert "identical" in reason.lower()


def test_detect_idor_flags_near_length_match():
    a = ResponseSnapshot(status=200, body_hash="aaa", length=500)
    b = ResponseSnapshot(status=200, body_hash="bbb", length=510)
    is_vuln, _ = detect_idor(a, b)
    assert is_vuln


def test_detect_idor_safe_when_swapped_is_forbidden():
    a = ResponseSnapshot(status=200, body_hash="aaa", length=500)
    b = ResponseSnapshot(status=403, body_hash="zzz", length=30)
    is_vuln, reason = detect_idor(a, b)
    assert not is_vuln
    assert "403" in reason


def test_detect_idor_safe_when_owner_fails():
    a = ResponseSnapshot(status=404, body_hash="zzz", length=0)
    b = ResponseSnapshot(status=200, body_hash="aaa", length=500)
    is_vuln, _ = detect_idor(a, b)
    assert not is_vuln


def test_detect_idor_safe_when_bodies_differ_substantially():
    a = ResponseSnapshot(status=200, body_hash="aaa", length=500)
    b = ResponseSnapshot(status=200, body_hash="bbb", length=50)
    is_vuln, _ = detect_idor(a, b)
    assert not is_vuln


# ── IdorEngine end-to-end ──────────────────────────────────────────────────


def test_engine_emits_finding_when_swap_returns_same_body():
    """The classic IDOR: Bob's session retrieves Alice's resource."""

    def request_as(account, url):
        return _resp(200, "<html>Alice private profile data ...</html>")

    engine = IdorEngine(request_as=request_as, owner_account="alice", swapped_account="bob")
    findings = engine.scan_endpoints(["https://t/api/users/42/profile"])
    assert len(findings) == 1
    assert findings[0]["type"] == "IDOR"
    assert findings[0]["owner_account"] == "alice"
    assert findings[0]["swapped_account"] == "bob"


def test_engine_no_finding_when_swap_blocked():
    """Properly access-controlled endpoint: Bob gets 403."""

    def request_as(account, url):
        if account == "bob":
            return _resp(403, "Forbidden")
        return _resp(200, "Alice's data")

    engine = IdorEngine(request_as=request_as, owner_account="alice", swapped_account="bob")
    findings = engine.scan_endpoints(["https://t/api/users/42/profile"])
    assert findings == []


def test_engine_skips_idless_urls():
    request_as = MagicMock()
    engine = IdorEngine(request_as=request_as)
    findings = engine.scan_endpoints(["https://t/api/login", "https://t/api/health"])
    assert findings == []
    request_as.assert_not_called()


def test_engine_dedupes_findings_per_vector():
    """A URL with both /42/ and ?id=42 still emits one finding per vector,
    not one per regex match."""

    def request_as(account, url):
        return _resp(200, "same body for everyone")

    engine = IdorEngine(request_as=request_as)
    findings = engine.scan_endpoints(["https://t/api/users/42/orders/100"])
    # Two numeric path matches → still one finding because both share
    # the same (vector=path, location=path-string) key.
    assert len(findings) == 1


def test_engine_handles_http_exception_gracefully():
    def request_as(account, url):
        raise RuntimeError("connection reset")

    engine = IdorEngine(request_as=request_as)
    findings = engine.scan_endpoints(["https://t/api/users/42"])
    assert findings == []


def test_engine_finding_dict_shape_matches_pipeline():
    def request_as(account, url):
        return _resp(200, "<html>private data</html>")

    engine = IdorEngine(request_as=request_as)
    findings = engine.scan_endpoints(["https://t/api/users/42"])
    assert findings[0]["module"] == "idor_engine"
    assert findings[0]["severity"] == "high"
    assert findings[0]["vector"] == "path"
