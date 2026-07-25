"""HTTP login fixture using stdlib http.server only.

Three endpoints, picked because they cover the auth flows the project
needs to test today:

* ``GET  /login-form``   — returns HTML with a CSRF-token hidden input.
* ``POST /login``        — accepts ``username`` + ``password`` (+ optional
                          ``csrf_token``). On success: ``Set-Cookie:
                          session=...; HttpOnly`` + 200 with ``Welcome``.
                          On failure: 401 ``Bad credentials``.
* ``GET  /protected``    — 200 ``ok`` when a valid session cookie is
                          present, 401 ``Session expired`` otherwise.

The fixture runs on an ephemeral port (``port=0``); call ``app.url`` to
get the live URL. Test code is expected to use it as a context manager::

    with MockLoginApp(require_csrf=True) as app:
        ... requests against app.url ...

We avoid Flask / Werkzeug / pytest-httpserver to keep the test suite
dependency-light and CI-deterministic. The cost is verbose handlers; the
benefit is zero pip dependencies for the auth tests.
"""

from __future__ import annotations

import secrets
import threading
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs

import pytest


class MockLoginApp:
    """Threaded HTTP server with login + protected endpoints.

    Public attributes after ``start()``:
      * ``port``  — bound port (chosen by OS when constructed with port=0)
      * ``url``   — ``http://127.0.0.1:<port>``

    Configurable:
      * ``require_csrf``     — when True, /login rejects POSTs without a
                              matching csrf_token from /login-form.
      * ``valid_credentials``— dict mapping username → password.
      * ``expire_after_hits``— if set, /protected returns 401 after N hits
                              (simulates session expiry).
    """

    def __init__(
        self,
        *,
        require_csrf: bool = False,
        valid_credentials: Optional[dict[str, str]] = None,
        expire_after_hits: Optional[int] = None,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        self.require_csrf = require_csrf
        self.valid_credentials = dict(valid_credentials or {"alice": "hunter2"})
        self.expire_after_hits = expire_after_hits
        self.host = host
        self.port = port

        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._valid_sessions: set[str] = set()
        self._csrf_tokens: set[str] = set()
        self._protected_hits: dict[str, int] = {}

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def start(self) -> None:
        handler = self._make_handler()
        try:
            self._server = ThreadingHTTPServer((self.host, self.port), handler)
        except PermissionError:
            pytest.skip("local TCP listener unavailable in this test sandbox")
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

    def __enter__(self) -> "MockLoginApp":
        self.start()
        return self

    def __exit__(self, *_exc) -> None:
        self.stop()

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    # ── Test hooks ─────────────────────────────────────────────────────────

    def force_expire_all(self) -> None:
        with self._lock:
            self._valid_sessions.clear()

    def session_count(self) -> int:
        with self._lock:
            return len(self._valid_sessions)

    # ── Handler factory ────────────────────────────────────────────────────

    def _make_handler(self):
        app = self

        class Handler(BaseHTTPRequestHandler):
            # Quiet test output — BaseHTTPRequestHandler logs to stderr by default.
            def log_message(self, *_args, **_kwargs):
                return

            def _send(self, status: int, body: str, headers=None):
                payload = body.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(payload)

            def _session_from_cookies(self) -> Optional[str]:
                raw = self.headers.get("Cookie", "")
                if not raw:
                    return None
                jar = SimpleCookie()
                jar.load(raw)
                morsel = jar.get("session")
                return morsel.value if morsel else None

            def do_GET(self):  # noqa: N802 — stdlib signature
                if self.path.startswith("/login-form"):
                    token = secrets.token_hex(8)
                    with app._lock:
                        app._csrf_tokens.add(token)
                    body = (
                        f"<html><body><form method=POST action='/login'>"
                        f"<input type=hidden name='csrf_token' value='{token}'>"
                        f"<input name='username'><input name='password' type=password>"
                        f"<button>Sign in</button></form></body></html>"
                    )
                    return self._send(HTTPStatus.OK, body)

                if self.path.startswith("/protected"):
                    sess = self._session_from_cookies()
                    valid = False
                    with app._lock:
                        if sess and sess in app._valid_sessions:
                            valid = True
                            if app.expire_after_hits is not None:
                                hits = app._protected_hits.get(sess, 0) + 1
                                app._protected_hits[sess] = hits
                                if hits > app.expire_after_hits:
                                    app._valid_sessions.discard(sess)
                                    valid = False
                    if valid:
                        return self._send(HTTPStatus.OK, "ok")
                    return self._send(HTTPStatus.UNAUTHORIZED, "Session expired")

                return self._send(HTTPStatus.NOT_FOUND, "not found")

            def do_POST(self):  # noqa: N802
                if not self.path.startswith("/login"):
                    return self._send(HTTPStatus.NOT_FOUND, "not found")

                length = int(self.headers.get("Content-Length", 0) or 0)
                raw = self.rfile.read(length).decode("utf-8", errors="replace")
                fields = {k: v[0] for k, v in parse_qs(raw).items()}

                if app.require_csrf:
                    token = fields.get("csrf_token", "")
                    with app._lock:
                        consumed = token in app._csrf_tokens
                        app._csrf_tokens.discard(token)
                    if not consumed:
                        return self._send(
                            HTTPStatus.FORBIDDEN, "CSRF token missing/invalid"
                        )

                user = fields.get("username", "")
                pw = fields.get("password", "")
                if app.valid_credentials.get(user) != pw:
                    return self._send(HTTPStatus.UNAUTHORIZED, "Bad credentials")

                token = secrets.token_hex(16)
                with app._lock:
                    app._valid_sessions.add(token)
                cookie = f"session={token}; HttpOnly; Path=/"
                return self._send(
                    HTTPStatus.OK,
                    f"<html><body>Welcome {user}</body></html>",
                    headers={"Set-Cookie": cookie},
                )

        return Handler
