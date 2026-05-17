"""Tests for utils/session_manager — login capture, replay, refresh, multi-account."""

from __future__ import annotations

import time

import pytest

from utils.session_manager import SessionManager, SessionState


pytestmark = pytest.mark.unit


def _fake_flow_factory(captured: dict[str, dict] | None = None):
    """Return a flow callable that records calls and emits a fresh cookie."""
    captured = captured if captured is not None else {}
    counter = {"n": 0}

    def flow(credentials, config):
        counter["n"] += 1
        captured["last"] = {"credentials": dict(credentials), "config": dict(config)}
        cookies = {"session": f"token-{counter['n']}-{credentials.get('username', '')}"}
        headers = {"X-Captured": "1"}
        return cookies, headers, None

    flow.counter = counter
    return flow


# ── Flow registration ─────────────────────────────────────────────────────────


def test_register_and_query_flows():
    mgr = SessionManager()
    assert not mgr.has_flow("form")
    mgr.register_flow("form", _fake_flow_factory())
    assert mgr.has_flow("form")


def test_add_account_without_registered_flow_raises():
    mgr = SessionManager()
    with pytest.raises(KeyError):
        mgr.add_account("alice", flow="form", credentials={"username": "a", "password": "b"})


# ── Account capture + switch ─────────────────────────────────────────────────


def test_add_account_captures_initial_state():
    mgr = SessionManager()
    flow = _fake_flow_factory()
    mgr.register_flow("form", flow)
    state = mgr.add_account(
        "alice",
        flow="form",
        credentials={"username": "alice", "password": "hunter2"},
        flow_config={"login_url": "http://t/login"},
    )

    assert isinstance(state, SessionState)
    assert state.name == "alice"
    assert state.flow == "form"
    assert state.cookies["session"].startswith("token-1-alice")
    assert state.headers == {"X-Captured": "1"}
    assert mgr.active() is state
    assert mgr.names() == ["alice"]


def test_multiple_accounts_and_switch():
    mgr = SessionManager()
    mgr.register_flow("form", _fake_flow_factory())
    mgr.add_account("alice", flow="form", credentials={"username": "alice", "password": "x"})
    mgr.add_account("bob", flow="form", credentials={"username": "bob", "password": "y"})

    assert mgr.active().name == "alice"  # first add becomes active
    mgr.switch("bob")
    assert mgr.active().name == "bob"
    assert "bob" in mgr.active().cookies["session"]
    with pytest.raises(KeyError):
        mgr.switch("eve")


# ── Refresh behaviour ────────────────────────────────────────────────────────


def test_refresh_reruns_flow_with_saved_credentials():
    mgr = SessionManager()
    flow = _fake_flow_factory()
    mgr.register_flow("form", flow)
    mgr.add_account("alice", flow="form", credentials={"username": "alice", "password": "x"})

    initial_token = mgr.active().cookies["session"]
    mgr.refresh("alice")
    new_token = mgr.active().cookies["session"]
    assert initial_token != new_token
    assert flow.counter["n"] == 2


def test_refresh_if_expired_triggers_on_401():
    mgr = SessionManager()
    mgr.register_flow("form", _fake_flow_factory())
    mgr.add_account("alice", flow="form", credentials={"username": "alice", "password": "x"})

    initial_token = mgr.active().cookies["session"]
    refreshed = mgr.refresh_if_expired("alice", last_status=401, last_body="")
    assert refreshed is True
    assert mgr.active().cookies["session"] != initial_token


def test_refresh_if_expired_triggers_on_age():
    mgr = SessionManager()
    mgr.register_flow("form", _fake_flow_factory())
    mgr.add_account(
        "alice",
        flow="form",
        credentials={"username": "alice", "password": "x"},
        ttl_seconds=0.001,
    )
    # Age past TTL.
    time.sleep(0.01)
    assert mgr.refresh_if_expired("alice", last_status=200, last_body="") is True


def test_refresh_if_expired_skips_on_healthy_state():
    mgr = SessionManager()
    mgr.register_flow("form", _fake_flow_factory())
    mgr.add_account("alice", flow="form", credentials={"username": "alice", "password": "x"})
    assert (
        mgr.refresh_if_expired("alice", last_status=200, last_body="welcome")
        is False
    )


def test_expired_indicator_regex_drives_refresh():
    mgr = SessionManager()
    mgr.register_flow("form", _fake_flow_factory())
    mgr.add_account(
        "alice",
        flow="form",
        credentials={"username": "alice", "password": "x"},
        expired_indicator=r"please log in again",
    )
    refreshed = mgr.refresh_if_expired(
        "alice", last_status=200, last_body="Sorry, please log in again."
    )
    assert refreshed is True


def test_refresh_failure_is_isolated():
    mgr = SessionManager()
    calls = {"n": 0}

    def flaky(creds, cfg):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"session": "ok"}, {}, None
        raise RuntimeError("login service down")

    mgr.register_flow("form", flaky)
    mgr.add_account("alice", flow="form", credentials={"username": "alice", "password": "x"})

    refreshed = mgr.refresh_if_expired("alice", last_status=401, last_body="")
    assert refreshed is False  # refresh threw → reported but didn't propagate
    # Manager survives — original session still queryable.
    assert mgr.get("alice").cookies["session"] == "ok"


# ── Injection into requests.Session ─────────────────────────────────────────


def test_apply_to_requests_session_injects_cookies_headers_bearer():
    import httpx

    mgr = SessionManager()

    def bearer_flow(creds, cfg):
        return {"session": "abc"}, {"X-Tenant": "acme"}, "the-bearer-token"

    mgr.register_flow("bearer", bearer_flow)
    mgr.add_account("alice", flow="bearer", credentials={"username": "alice"})

    rs = httpx.Client(trust_env=False)
    try:
        mgr.apply_to_http_client(rs)
        assert rs.cookies.get("session") == "abc"
        assert rs.headers.get("X-Tenant") == "acme"
        assert rs.headers.get("Authorization") == "Bearer the-bearer-token"
    finally:
        rs.close()


def test_apply_with_no_active_session_is_noop():
    import httpx

    rs = httpx.Client(trust_env=False)
    try:
        rs.headers["X-Existing"] = "keep"
        SessionManager().apply_to_http_client(rs)
        assert rs.headers["X-Existing"] == "keep"
    finally:
        rs.close()


# ── SessionState helpers ─────────────────────────────────────────────────────


def test_session_state_matches_expired_response_status_codes():
    state = SessionState(name="x", flow="form")
    assert state.matches_expired_response(401, "anything")
    assert state.matches_expired_response(419, "")
    assert not state.matches_expired_response(200, "")


def test_session_state_invalid_regex_is_safe():
    state = SessionState(name="x", flow="form", expired_indicator="[unclosed")
    # No exception — just returns False.
    assert state.matches_expired_response(200, "anything") is False
