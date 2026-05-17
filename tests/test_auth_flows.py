"""Integration tests for utils.auth_flows against the stdlib login fixture."""

from __future__ import annotations

import pytest

from tests.fixtures_login_app import MockLoginApp
from utils.auth_flows import (
    csrf_token_login,
    form_login,
    register_default_flows,
)
from utils.auth_flows.csrf_token_login import CSRFTokenLoginError
from utils.auth_flows.form_login import FormLoginError
from utils.session_manager import SessionManager


pytestmark = pytest.mark.integration


# ── form_login ────────────────────────────────────────────────────────────────


def test_form_login_success_captures_session_cookie():
    with MockLoginApp(require_csrf=False) as app:
        cookies, headers, bearer = form_login.login(
            credentials={"username": "alice", "password": "hunter2"},
            flow_config={
                "login_url": f"{app.url}/login",
                "success_indicator": r"Welcome alice",
            },
        )
        assert "session" in cookies
        assert headers == {}
        assert bearer is None


def test_form_login_bad_credentials_raises():
    with MockLoginApp(require_csrf=False) as app, pytest.raises(FormLoginError):
        form_login.login(
            credentials={"username": "alice", "password": "wrong"},
            flow_config={"login_url": f"{app.url}/login"},
        )


def test_form_login_success_indicator_mismatch_raises():
    with MockLoginApp(require_csrf=False) as app, pytest.raises(FormLoginError):
        form_login.login(
            credentials={"username": "alice", "password": "hunter2"},
            flow_config={
                "login_url": f"{app.url}/login",
                "success_indicator": r"Greetings comrade",
            },
        )


def test_form_login_missing_login_url_raises():
    with pytest.raises(FormLoginError):
        form_login.login(
            credentials={"username": "a", "password": "b"},
            flow_config={},
        )


# ── csrf_token_login ──────────────────────────────────────────────────────────


def test_csrf_login_fetches_token_then_posts():
    with MockLoginApp(require_csrf=True) as app:
        cookies, headers, bearer = csrf_token_login.login(
            credentials={"username": "alice", "password": "hunter2"},
            flow_config={
                "form_url": f"{app.url}/login-form",
                "login_url": f"{app.url}/login",
                "success_indicator": r"Welcome alice",
            },
        )
        assert "session" in cookies


def test_csrf_login_token_absent_in_form_raises():
    with MockLoginApp(require_csrf=True) as app, pytest.raises(CSRFTokenLoginError):
        csrf_token_login.login(
            credentials={"username": "alice", "password": "hunter2"},
            flow_config={
                "form_url": f"{app.url}/login",  # /login has no form HTML
                "login_url": f"{app.url}/login",
            },
        )


# ── End-to-end SessionManager wiring ─────────────────────────────────────────


def test_session_manager_with_default_flows_replays_protected_resource():
    import httpx

    with MockLoginApp(require_csrf=False) as app:
        mgr = SessionManager()
        register_default_flows(mgr)
        mgr.add_account(
            "alice",
            flow="form",
            credentials={"username": "alice", "password": "hunter2"},
            flow_config={
                "login_url": f"{app.url}/login",
                "success_indicator": r"Welcome alice",
            },
            success_indicator=r"Welcome alice",
        )

        rs = httpx.Client(timeout=5, trust_env=False)
        try:
            mgr.apply_to_http_client(rs)
            resp = rs.get(f"{app.url}/protected")
            assert resp.status_code == 200
            assert resp.text == "ok"
        finally:
            rs.close()


def test_session_manager_refresh_on_server_side_expiry():
    """Server expires session after 1 hit; manager refreshes and the next hit succeeds."""
    import httpx

    with MockLoginApp(require_csrf=False, expire_after_hits=1) as app:
        mgr = SessionManager()
        register_default_flows(mgr)
        mgr.add_account(
            "alice",
            flow="form",
            credentials={"username": "alice", "password": "hunter2"},
            flow_config={"login_url": f"{app.url}/login"},
        )

        rs = httpx.Client(timeout=5, trust_env=False)
        try:
            mgr.apply_to_http_client(rs)
            # First hit — OK.
            assert rs.get(f"{app.url}/protected").status_code == 200
            # Second hit — server says expired.
            expired = rs.get(f"{app.url}/protected")
            assert expired.status_code == 401
        finally:
            rs.close()

        refreshed = mgr.refresh_if_expired(
            "alice", last_status=expired.status_code, last_body=expired.text
        )
        assert refreshed is True

        rs2 = httpx.Client(timeout=5, trust_env=False)
        try:
            mgr.apply_to_http_client(rs2)
            assert rs2.get(f"{app.url}/protected").status_code == 200
        finally:
            rs2.close()
