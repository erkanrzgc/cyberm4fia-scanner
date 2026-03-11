"""
Tests for modules/api_scanner.py — OpenAPI/Swagger import support.
"""

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import api_scanner
from utils.auth import auth_manager


SAMPLE_OPENAPI = """
openapi: 3.0.3
servers:
  - url: /api/v1
components:
  schemas:
    ReportCreate:
      type: object
      properties:
        title:
          type: string
          example: monthly
        public:
          type: boolean
        tags:
          type: array
          items:
            type: string
            example: internal
    UploadPayload:
      type: object
      properties:
        folder:
          type: string
          example: invoices
        metadata:
          type: object
          properties:
            owner:
              type: string
              example: alice
            flags:
              type: array
              items:
                type: string
                example: internal
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
    apiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key
    sessionCookie:
      type: apiKey
      in: cookie
      name: sessionid
    queryToken:
      type: apiKey
      in: query
      name: access_token
security:
  - bearerAuth: []
paths:
  /users/{userId}:
    parameters:
      - name: userId
        in: path
        schema:
          type: integer
          example: 42
    get:
      operationId: getUser
  /reports:
    post:
      operationId: createReport
      security:
        - apiKeyAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ReportCreate'
  /search:
    get:
      parameters:
        - name: q
          in: query
          schema:
            type: string
            example: admin
  /uploads:
    post:
      operationId: uploadFile
      security:
        - sessionCookie: []
        - queryToken: []
      requestBody:
        required: true
        content:
          multipart/form-data:
            schema:
              $ref: '#/components/schemas/UploadPayload'
"""


class _FakeResponse:
    def __init__(self, status_code=404, headers=None, text="", payload=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


class TestAPISpecImport:
    def test_load_api_spec_yaml(self, tmp_path):
        spec_path = tmp_path / "openapi.yaml"
        spec_path.write_text(SAMPLE_OPENAPI, encoding="utf-8")

        spec = api_scanner.load_api_spec(str(spec_path))

        assert spec["openapi"] == "3.0.3"
        assert "/users/{userId}" in spec["paths"]

    def test_extract_openapi_endpoints_builds_urls_and_methods(self):
        spec = api_scanner._parse_api_spec_text(SAMPLE_OPENAPI)

        endpoints = api_scanner.extract_openapi_endpoints(
            spec,
            "https://example.com/app",
            source="unit-test",
        )

        methods_and_urls = {(ep["method"], ep["url"]) for ep in endpoints}

        assert ("GET", "https://example.com/api/v1/users/42") in methods_and_urls
        assert ("POST", "https://example.com/api/v1/reports") in methods_and_urls
        assert ("GET", "https://example.com/api/v1/search?q=admin") in methods_and_urls

        report_endpoint = next(
            ep for ep in endpoints if ep["method"] == "POST" and ep["path"] == "/reports"
        )
        assert report_endpoint["request_body"] == {
            "title": "monthly",
            "public": True,
            "tags": ["internal"],
        }
        assert report_endpoint["request_body_content_type"] == "application/json"
        assert report_endpoint["auth_placeholders"] == {
            "headers": {"X-API-Key": "<X_API_KEY>"}
        }
        assert report_endpoint["auth_schemes"] == [
            {
                "id": "apiKeyAuth",
                "type": "apiKey",
                "scheme": "",
                "in": "header",
                "name": "X-API-Key",
                "bearer_format": "",
                "description": "",
                "scopes": [],
                "open_id_connect_url": "",
            }
        ]

        user_endpoint = next(ep for ep in endpoints if ep["path"] == "/users/{userId}")
        assert user_endpoint["auth_schemes"][0]["id"] == "bearerAuth"
        assert user_endpoint["auth_placeholders"] == {
            "headers": {"Authorization": "Bearer <JWT_TOKEN>"}
        }

        upload_endpoint = next(ep for ep in endpoints if ep["path"] == "/uploads")
        assert upload_endpoint["request_body"] == {
            "folder": "invoices",
            "metadata": {"owner": "alice", "flags": ["internal"]},
        }
        assert upload_endpoint["request_body_content_type"] == "multipart/form-data"
        assert upload_endpoint["auth_placeholders"] == {
            "cookies": {"sessionid": "<SESSIONID>"},
            "query": {"access_token": "<ACCESS_TOKEN>"},
        }

    def test_discover_api_endpoints_uses_local_spec(self, monkeypatch, tmp_path):
        spec_path = tmp_path / "openapi.yaml"
        spec_path.write_text(SAMPLE_OPENAPI, encoding="utf-8")

        monkeypatch.setattr(
            api_scanner,
            "smart_request",
            lambda *args, **kwargs: _FakeResponse(status_code=404),
        )

        endpoints = api_scanner.discover_api_endpoints(
            "https://example.com",
            delay=0,
            spec_path=str(spec_path),
        )

        methods_and_urls = {(ep["method"], ep["url"]) for ep in endpoints}
        assert ("GET", "https://example.com/api/v1/users/42") in methods_and_urls
        assert ("POST", "https://example.com/api/v1/reports") in methods_and_urls

    def test_mass_assignment_respects_spec_method(self, monkeypatch):
        calls = []

        def fake_request(method, url, **kwargs):
            calls.append((method, url, kwargs))
            return _FakeResponse(
                status_code=201,
                payload={"role": "admin", "status": "created"},
            )

        monkeypatch.setattr(api_scanner, "smart_request", fake_request)

        get_result = api_scanner.test_mass_assignment(
            {"url": "https://example.com/api/v1/users/42", "method": "GET"},
            delay=0,
        )
        post_result = api_scanner.test_mass_assignment(
            {
                "url": "https://example.com/api/v1/reports",
                "method": "POST",
                "request_body": {"title": "monthly", "public": True},
                "request_body_content_type": "application/json",
            },
            delay=0,
        )

        assert get_result == []
        assert len(post_result) == 1
        assert calls == [
            (
                "post",
                "https://example.com/api/v1/reports",
                {
                    "json": {
                        "title": "monthly",
                        "public": True,
                        "role": "admin",
                        "is_admin": True,
                        "admin": True,
                        "isAdmin": True,
                        "user_type": "administrator",
                        "permissions": ["admin", "write", "delete"],
                        "verified": True,
                        "is_staff": True,
                        "privilege": "root",
                    },
                    "delay": 0,
                    "timeout": 5,
                },
            )
        ]

    def test_build_request_body_kwargs_flattens_multipart_nested_payload(self):
        request_kwargs = api_scanner._build_request_body_kwargs(
            {
                "request_body": {
                    "folder": "invoices",
                    "metadata": {"owner": "alice", "flags": ["internal"]},
                },
                "request_body_content_type": "multipart/form-data",
            },
            {"role": "admin"},
        )

        assert request_kwargs == {
            "data": [
                ("folder", "invoices"),
                ("metadata[owner]", "alice"),
                ("metadata[flags][]", "internal"),
                ("role", "admin"),
            ],
            "headers": {"Content-Type": "multipart/form-data"},
        }

    def test_collect_auth_findings_returns_info_findings(self):
        findings = api_scanner.collect_auth_findings(
            [
                {
                    "url": "https://example.com/api/v1/users/42",
                    "source": "file:openapi.yaml",
                    "auth_placeholders": {
                        "headers": {"Authorization": "Bearer <JWT_TOKEN>"}
                    },
                    "auth_schemes": [
                        {
                            "id": "bearerAuth",
                            "type": "http",
                            "scheme": "bearer",
                            "in": "",
                            "name": "",
                            "bearer_format": "JWT",
                            "description": "",
                            "scopes": [],
                            "open_id_connect_url": "",
                        }
                    ],
                }
            ]
        )

        assert findings == [
            {
                "type": "API_Auth_Scheme",
                "severity": "INFO",
                "url": "https://example.com/api/v1/users/42",
                "param": "bearerAuth",
                "evidence": "bearerAuth: HTTP BEARER (JWT) Suggested placeholders: headers={'Authorization': 'Bearer <JWT_TOKEN>'}.",
                "description": "API spec declares authentication requirement: bearerAuth: HTTP BEARER (JWT). Suggested placeholders: headers={'Authorization': 'Bearer <JWT_TOKEN>'}.",
                "source": "file:openapi.yaml",
                "auth_scheme": {
                    "id": "bearerAuth",
                    "type": "http",
                    "scheme": "bearer",
                    "in": "",
                    "name": "",
                    "bearer_format": "JWT",
                    "description": "",
                    "scopes": [],
                    "open_id_connect_url": "",
                },
                "auth_placeholders": {
                    "headers": {"Authorization": "Bearer <JWT_TOKEN>"}
                },
            }
        ]

    def test_scan_api_forwards_spec_path(self, monkeypatch):
        captured = {}

        def fake_discover(url, delay=0, spec_path=None):
            captured["spec_path"] = spec_path
            return [
                {
                    "url": "https://example.com/api/v1/users/42",
                    "method": "GET",
                    "is_api": True,
                    "auth_schemes": [
                        {
                            "id": "bearerAuth",
                            "type": "http",
                            "scheme": "bearer",
                            "in": "",
                            "name": "",
                            "bearer_format": "JWT",
                            "description": "",
                            "scopes": [],
                            "open_id_connect_url": "",
                        }
                    ],
                    "auth_placeholders": {
                        "headers": {"Authorization": "Bearer <JWT_TOKEN>"}
                    },
                }
            ]

        monkeypatch.setattr(api_scanner, "discover_api_endpoints", fake_discover)
        monkeypatch.setattr(
            api_scanner,
            "test_bola",
            lambda target, delay=0: [
                {"type": "API_BOLA", "vuln": "BOLA", "url": target["url"]}
            ],
        )
        monkeypatch.setattr(api_scanner, "test_rate_limiting", lambda target, delay=0: [])
        monkeypatch.setattr(api_scanner, "test_mass_assignment", lambda target, delay=0: [])
        monkeypatch.setattr(api_scanner, "test_verb_tampering", lambda url, delay=0: [])
        monkeypatch.setattr(api_scanner, "test_graphql_introspection", lambda url, delay=0: [])
        monkeypatch.setattr(
            api_scanner,
            "smart_request",
            lambda *args, **kwargs: _FakeResponse(status_code=200, headers={}),
        )
        monkeypatch.setattr(api_scanner, "test_jwt_issues", lambda url, headers, delay=0: [])
        monkeypatch.setattr(api_scanner, "test_auth_response_diff", lambda target, delay=0: [])

        findings = api_scanner.scan_api(
            "https://example.com",
            delay=0,
            spec_path="local-openapi.yaml",
        )

        assert captured["spec_path"] == "local-openapi.yaml"
        assert findings == [
            {
                "type": "API_Auth_Scheme",
                "severity": "INFO",
                "url": "https://example.com/api/v1/users/42",
                "param": "bearerAuth",
                "evidence": "bearerAuth: HTTP BEARER (JWT) Suggested placeholders: headers={'Authorization': 'Bearer <JWT_TOKEN>'}.",
                "description": "API spec declares authentication requirement: bearerAuth: HTTP BEARER (JWT). Suggested placeholders: headers={'Authorization': 'Bearer <JWT_TOKEN>'}.",
                "source": None,
                "auth_scheme": {
                    "id": "bearerAuth",
                    "type": "http",
                    "scheme": "bearer",
                    "in": "",
                    "name": "",
                    "bearer_format": "JWT",
                    "description": "",
                    "scopes": [],
                    "open_id_connect_url": "",
                },
                "auth_placeholders": {
                    "headers": {"Authorization": "Bearer <JWT_TOKEN>"}
                },
            },
            {
                "type": "API_BOLA",
                "vuln": "BOLA",
                "url": "https://example.com/api/v1/users/42",
            }
        ]

    def test_scan_api_applies_endpoint_auth_placeholders(self, monkeypatch):
        observed = {}

        def fake_discover(url, delay=0, spec_path=None):
            return [
                {
                    "url": "https://example.com/api/v1/users/42",
                    "method": "GET",
                    "is_api": True,
                    "auth_schemes": [],
                    "auth_placeholders": {
                        "headers": {"Authorization": "Bearer <JWT_TOKEN>"},
                        "query": {"access_token": "<ACCESS_TOKEN>"},
                    },
                }
            ]

        def fake_bola(target, delay=0):
            observed["placeholders"] = dict(auth_manager.placeholder_auth)
            return []

        monkeypatch.setattr(api_scanner, "discover_api_endpoints", fake_discover)
        monkeypatch.setattr(api_scanner, "test_bola", fake_bola)
        monkeypatch.setattr(api_scanner, "test_rate_limiting", lambda target, delay=0: [])
        monkeypatch.setattr(api_scanner, "test_mass_assignment", lambda target, delay=0: [])
        monkeypatch.setattr(api_scanner, "test_verb_tampering", lambda url, delay=0: [])
        monkeypatch.setattr(api_scanner, "test_graphql_introspection", lambda url, delay=0: [])
        monkeypatch.setattr(api_scanner, "test_auth_response_diff", lambda target, delay=0: [])
        monkeypatch.setattr(
            api_scanner,
            "smart_request",
            lambda *args, **kwargs: _FakeResponse(status_code=200, headers={}),
        )
        monkeypatch.setattr(api_scanner, "test_jwt_issues", lambda url, headers, delay=0: [])

        try:
            api_scanner.scan_api("https://example.com", delay=0, spec_path="dummy.yaml")
            assert observed["placeholders"] == {
                "headers": {"Authorization": "Bearer <JWT_TOKEN>"},
                "query": {"access_token": "<ACCESS_TOKEN>"},
            }
            assert auth_manager.placeholder_auth == {}
        finally:
            auth_manager.clear_placeholder_auth()

    def test_auth_response_diff_flags_unauthenticated_get_access(self, monkeypatch):
        def fake_request(method, url, **kwargs):
            return _FakeResponse(
                status_code=200,
                headers={"content-type": "application/json"},
                text=json.dumps({"id": 42, "email": "admin@example.com"}),
                payload={"id": 42, "email": "admin@example.com"},
            )

        monkeypatch.setattr(api_scanner, "smart_request", fake_request)

        findings = api_scanner.test_auth_response_diff(
            {
                "url": "https://example.com/api/v1/users/42",
                "method": "GET",
                "auth_schemes": [{"id": "bearerAuth", "type": "http"}],
                "auth_placeholders": {
                    "headers": {"Authorization": "Bearer <JWT_TOKEN>"}
                },
            },
            delay=0,
        )

        assert findings == [
            {
                "type": "API_Unauth_Access",
                "url": "https://example.com/api/v1/users/42",
                "severity": "CRITICAL",
                "description": (
                    "OpenAPI declared authentication for GET "
                    "https://example.com/api/v1/users/42, but the unauthenticated "
                    "request still succeeded with HTTP 200."
                ),
                "evidence": "Unauthenticated request returned 200; auth status 200.",
                "confidence": "confirmed",
                "request": {
                    "method": "GET",
                    "url": "https://example.com/api/v1/users/42",
                },
                "repro_steps": ["GET https://example.com/api/v1/users/42"],
                "response_snippet": '{"id": 42, "email": "admin@example.com"}',
                "unauth_status": 200,
                "auth_status": 200,
            }
        ]

    def test_auth_response_diff_records_auth_only_response_schema(self, monkeypatch):
        def fake_request(method, url, **kwargs):
            if auth_manager.placeholder_auth:
                payload = {"id": 42, "email": "admin@example.com", "role": "admin"}
                return _FakeResponse(
                    status_code=200,
                    headers={"content-type": "application/json"},
                    text=json.dumps(payload),
                    payload=payload,
                )

            payload = {"detail": "forbidden"}
            return _FakeResponse(
                status_code=403,
                headers={"content-type": "application/json"},
                text=json.dumps(payload),
                payload=payload,
            )

        monkeypatch.setattr(api_scanner, "smart_request", fake_request)

        findings = api_scanner.test_auth_response_diff(
            {
                "url": "https://example.com/api/v1/admin/report",
                "method": "GET",
                "auth_schemes": [{"id": "bearerAuth", "type": "http"}],
                "auth_placeholders": {
                    "headers": {"Authorization": "Bearer <JWT_TOKEN>"}
                },
            },
            delay=0,
        )

        assert findings == [
            {
                "type": "API_Auth_Response_Diff",
                "url": "https://example.com/api/v1/admin/report",
                "severity": "INFO",
                "description": (
                    "Authenticated and unauthenticated responses differed for GET "
                    "https://example.com/api/v1/admin/report."
                ),
                "evidence": (
                    "Unauthenticated status 403; authenticated status 200; "
                    "auth-only fields: email, id, role."
                ),
                "confidence": "high",
                "request": {
                    "method": "GET",
                    "url": "https://example.com/api/v1/admin/report",
                },
                "repro_steps": ["GET https://example.com/api/v1/admin/report"],
                "response_snippet": '{"id": 42, "email": "admin@example.com", "role": "admin"}',
                "unauth_status": 403,
                "auth_status": 200,
                "auth_only_fields": ["email", "id", "role"],
            }
        ]
