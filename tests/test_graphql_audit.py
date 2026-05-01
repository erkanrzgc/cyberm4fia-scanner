"""Tests for modules.graphql_audit — GraphQL deep-audit module.

All HTTP is mocked. Covers four vectors not handled by the existing
introspection probe in modules.api_scanner / modules.api_inject:

1. Query depth DoS  (no max_depth limit)
2. Batching attack  (alias-batched + array-batched)
3. Field suggestion leak  ("Did you mean...?" replies)
4. CSRF over GET  (GraphQL accepts query string GETs)
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest


pytestmark = pytest.mark.unit


def _resp(status_code: int = 200, body: dict | list | str | None = None,
          headers: dict | None = None):
    r = MagicMock()
    r.status_code = status_code
    if isinstance(body, (dict, list)):
        text = json.dumps(body)
        r.json = MagicMock(return_value=body)
    else:
        text = body or ""
        r.json = MagicMock(side_effect=ValueError("not json"))
    r.text = text
    r.headers = headers or {"Content-Type": "application/json"}
    return r


def _not_graphql():
    return _resp(404, body="Not Found")


def _graphql_alive(extra: dict | None = None):
    """Standard GraphQL response shape used to confirm the endpoint is live."""
    body: dict = {"data": {"__typename": "Query"}}
    if extra:
        body.update(extra)
    return _resp(200, body=body)


# ─── Endpoint detection ─────────────────────────────────────────────────────


class TestDetect:
    def test_detect_returns_endpoint_when_typename_responds(self):
        from modules.graphql_audit import _detect_graphql_endpoint

        with patch("modules.graphql_audit.smart_request",
                   return_value=_graphql_alive()) as m:
            ep = _detect_graphql_endpoint("https://example.com", delay=0)

        assert ep is not None
        assert ep.endswith("/graphql") or ep.endswith("/graphiql") \
            or ep.endswith("/api/graphql")
        assert m.called

    def test_detect_returns_none_when_no_endpoint_alive(self):
        from modules.graphql_audit import _detect_graphql_endpoint

        with patch("modules.graphql_audit.smart_request",
                   return_value=_not_graphql()):
            ep = _detect_graphql_endpoint("https://example.com", delay=0)

        assert ep is None


# ─── Query-depth DoS ────────────────────────────────────────────────────────


class TestQueryDepth:
    def test_unprotected_server_accepts_deep_nested_query(self):
        from modules.graphql_audit import _check_query_depth

        # Server returned 200 with data, no depth-limit error → vulnerable.
        responses = [_graphql_alive({"data": {"viewer": {}}})]
        with patch("modules.graphql_audit.smart_request",
                   side_effect=responses):
            findings = _check_query_depth("https://example.com/graphql", delay=0)

        assert any(f["type"] == "GraphQL_Query_Depth_DoS" for f in findings)
        f = next(f for f in findings if f["type"] == "GraphQL_Query_Depth_DoS")
        assert f["severity"] in ("MEDIUM", "HIGH")

    def test_protected_server_rejects_deep_query(self):
        from modules.graphql_audit import _check_query_depth

        # Server replied with depth-limit error → protected.
        rejected = _resp(200, body={
            "errors": [{"message": "query exceeds maximum depth of 5"}]
        })
        with patch("modules.graphql_audit.smart_request",
                   return_value=rejected):
            findings = _check_query_depth("https://example.com/graphql", delay=0)

        assert findings == []


# ─── Batching ───────────────────────────────────────────────────────────────


class TestBatching:
    def test_alias_batching_processed(self):
        from modules.graphql_audit import _check_alias_batching

        # All N aliases were processed by the server (data dict has each key).
        body = {"data": {f"a{i}": {"id": i} for i in range(50)}}
        with patch("modules.graphql_audit.smart_request",
                   return_value=_resp(200, body=body)):
            findings = _check_alias_batching(
                "https://example.com/graphql", delay=0,
            )

        assert any(f["type"] == "GraphQL_Alias_Batching" for f in findings)

    def test_alias_batching_blocked(self):
        from modules.graphql_audit import _check_alias_batching

        rejected = _resp(200, body={
            "errors": [{"message": "too many aliases (max 10)"}]
        })
        with patch("modules.graphql_audit.smart_request",
                   return_value=rejected):
            findings = _check_alias_batching(
                "https://example.com/graphql", delay=0,
            )

        assert findings == []

    def test_array_batching_processed(self):
        from modules.graphql_audit import _check_array_batching

        # Server returned a list of N results — array batching is on.
        body = [{"data": {"__typename": "Query"}} for _ in range(20)]
        with patch("modules.graphql_audit.smart_request",
                   return_value=_resp(200, body=body)):
            findings = _check_array_batching(
                "https://example.com/graphql", delay=0,
            )

        assert any(f["type"] == "GraphQL_Array_Batching" for f in findings)

    def test_array_batching_blocked(self):
        from modules.graphql_audit import _check_array_batching

        # Server only returned a single response, ignoring the batch.
        with patch("modules.graphql_audit.smart_request",
                   return_value=_graphql_alive()):
            findings = _check_array_batching(
                "https://example.com/graphql", delay=0,
            )

        assert findings == []


# ─── Field-suggestion leak ──────────────────────────────────────────────────


class TestFieldSuggestion:
    def test_did_you_mean_leak_detected(self):
        from modules.graphql_audit import _check_field_suggestions

        leaky = _resp(400, body={"errors": [{
            "message": 'Cannot query field "uesr" on type "Query". '
                       'Did you mean "user", "users" or "userById"?'
        }]})
        with patch("modules.graphql_audit.smart_request",
                   return_value=leaky):
            findings = _check_field_suggestions(
                "https://example.com/graphql", delay=0,
            )

        assert any(f["type"] == "GraphQL_Field_Suggestion" for f in findings)
        f = next(f for f in findings if f["type"] == "GraphQL_Field_Suggestion")
        assert "user" in f.get("evidence", "").lower()

    def test_no_suggestion_no_finding(self):
        from modules.graphql_audit import _check_field_suggestions

        clean = _resp(400, body={"errors": [{
            "message": "Syntax Error: Unexpected Name."
        }]})
        with patch("modules.graphql_audit.smart_request",
                   return_value=clean):
            findings = _check_field_suggestions(
                "https://example.com/graphql", delay=0,
            )

        assert findings == []


# ─── CSRF over GET ──────────────────────────────────────────────────────────


class TestCsrfGet:
    def test_get_method_accepted_with_query_param(self):
        from modules.graphql_audit import _check_get_method

        # Server returned valid GraphQL response over GET → CSRF-able.
        with patch("modules.graphql_audit.smart_request",
                   return_value=_graphql_alive()):
            findings = _check_get_method(
                "https://example.com/graphql", delay=0,
            )

        assert any(f["type"] == "GraphQL_GET_CSRF" for f in findings)

    def test_get_method_blocked(self):
        from modules.graphql_audit import _check_get_method

        # Server returned 405 for GET → not CSRF-able via this vector.
        with patch("modules.graphql_audit.smart_request",
                   return_value=_resp(405, body="Method Not Allowed")):
            findings = _check_get_method(
                "https://example.com/graphql", delay=0,
            )

        assert findings == []


# ─── Top-level audit ────────────────────────────────────────────────────────


class TestAudit:
    def test_audit_skips_when_no_endpoint(self):
        from modules.graphql_audit import scan_graphql_audit

        with patch("modules.graphql_audit.smart_request",
                   return_value=_not_graphql()):
            findings = scan_graphql_audit("https://example.com", delay=0)

        assert findings == []

    def test_audit_aggregates_subchecks(self):
        from modules.graphql_audit import scan_graphql_audit

        # Endpoint detected on first call, then each subcheck gets a
        # vulnerable response. We don't pin exact call count — only the
        # invariants: endpoint detected + at least one finding aggregated.
        responses = iter([
            _graphql_alive(),                                  # detect
            _graphql_alive({"data": {"viewer": {}}}),          # depth
            _resp(200, body={"data": {f"a{i}": {} for i in range(50)}}),  # alias
            _resp(200, body=[{"data": {}} for _ in range(20)]),  # array
            _resp(400, body={"errors": [{
                "message": 'field "x" — Did you mean "y"?'}]}),  # suggestion
            _graphql_alive(),                                   # GET csrf
        ])
        with patch("modules.graphql_audit.smart_request",
                   side_effect=lambda *a, **kw: next(responses)):
            findings = scan_graphql_audit("https://example.com", delay=0)

        assert len(findings) >= 1
        types = {f["type"] for f in findings}
        # At least one of the four advanced vectors must be flagged.
        assert types & {
            "GraphQL_Query_Depth_DoS",
            "GraphQL_Alias_Batching",
            "GraphQL_Array_Batching",
            "GraphQL_Field_Suggestion",
            "GraphQL_GET_CSRF",
        }

    def test_audit_handles_network_errors_gracefully(self):
        from modules.graphql_audit import scan_graphql_audit
        from utils.request import ScanExceptions

        # Pick the first concrete exception from the ScanExceptions tuple
        # so we don't depend on its exact composition.
        exc_cls = ScanExceptions[0] if isinstance(ScanExceptions, tuple) \
            else ScanExceptions

        with patch("modules.graphql_audit.smart_request",
                   side_effect=exc_cls("boom")):
            findings = scan_graphql_audit("https://example.com", delay=0)

        assert findings == []
