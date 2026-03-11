"""
WSGI vulnerable API fixture used by integration tests.
"""

import json
from io import BytesIO


OPENAPI_SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Vulnerable API Fixture", "version": "1.0.0"},
    "paths": {
        "/api/private/users/{user_id}": {
            "get": {
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {
                        "name": "user_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer", "example": 1},
                    }
                ],
            }
        },
        "/api/admin/report": {
            "post": {
                "security": [{"apiKeyAuth": []}],
                "requestBody": {
                    "required": False,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string", "example": "quarterly"}
                                },
                            }
                        }
                    },
                },
            }
        },
        "/api/public/ping": {"get": {}},
    },
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
            "apiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
        }
    },
}


def _json_response(start_response, status, payload):
    body = json.dumps(payload).encode("utf-8")
    start_response(
        status,
        [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(body))),
        ],
    )
    return [body]


def create_app():
    def app(environ, start_response):
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "/")
        body = environ.get("wsgi.input") or BytesIO()
        raw_body = body.read()

        if method == "GET" and path == "/openapi.json":
            return _json_response(start_response, "200 OK", OPENAPI_SPEC)

        if method == "GET" and path.startswith("/api/private/users/"):
            try:
                user_id = int(path.rsplit("/", 1)[-1])
            except ValueError:
                return _json_response(start_response, "404 Not Found", {"detail": "not found"})

            return _json_response(
                start_response,
                "200 OK",
                {
                    "id": user_id,
                    "email": f"user{user_id}@example.com",
                    "role": "admin" if user_id == 1 else "user",
                    "authenticated": False,
                },
            )

        if method == "POST" and path == "/api/admin/report":
            try:
                payload = json.loads(raw_body.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                payload = {}

            payload.setdefault("status", "created")
            payload["used_api_key"] = False
            return _json_response(start_response, "201 Created", payload)

        if method == "GET" and path == "/api/public/ping":
            return _json_response(start_response, "200 OK", {"ok": True})

        return _json_response(start_response, "404 Not Found", {"detail": "not found"})

    return app
