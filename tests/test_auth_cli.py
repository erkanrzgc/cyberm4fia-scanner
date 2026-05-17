"""Tests for utils/auth_cli — option-string → SessionManager wiring."""

from __future__ import annotations

import pytest

from tests.fixtures_login_app import MockLoginApp
from utils.auth_cli import (
    configure_session_manager_from_options,
    parse_accounts_list,
    parse_kv_list,
)
from utils.session_manager import SessionManager


pytestmark = pytest.mark.unit


# ── parse_kv_list ────────────────────────────────────────────────────────────


def test_parse_kv_list_basic():
    assert parse_kv_list("username=alice,password=hunter2") == {
        "username": "alice",
        "password": "hunter2",
    }


def test_parse_kv_list_whitespace_tolerant():
    assert parse_kv_list("  user=a , pass = b ") == {"user": "a", "pass": "b"}


def test_parse_kv_list_empty():
    assert parse_kv_list("") == {}
    assert parse_kv_list("   ") == {}


def test_parse_kv_list_ignores_malformed_chunks():
    assert parse_kv_list("good=1,malformed,also_bad=") == {
        "good": "1",
        "also_bad": "",
    }


# ── parse_accounts_list ──────────────────────────────────────────────────────


def test_parse_accounts_list_basic():
    out = parse_accounts_list("alice:alice:hunter2,bob:bob:s3cret")
    assert out == [
        ("alice", "alice", "hunter2"),
        ("bob", "bob", "s3cret"),
    ]


def test_parse_accounts_list_password_with_colon():
    # The password may legitimately contain ':' (URI-style, base64-padded).
    out = parse_accounts_list("alice:alice:hun:ter:2")
    assert out == [("alice", "alice", "hun:ter:2")]


def test_parse_accounts_list_skips_short_entries():
    out = parse_accounts_list("ok:user:pass,missing,short:only")
    assert out == [("ok", "user", "pass")]


# ── configure_session_manager_from_options ───────────────────────────────────


def test_no_auth_flow_returns_none():
    assert configure_session_manager_from_options({}) is None
    assert configure_session_manager_from_options({"auth_flow": ""}) is None


def test_missing_credentials_logs_and_skips():
    mgr = SessionManager()
    out = configure_session_manager_from_options(
        {"auth_flow": "form", "auth_url": "http://t/login", "auth_fields": ""},
        manager=mgr,
    )
    assert out is None
    assert mgr.names() == []


def test_form_flow_end_to_end_with_extra_fields():
    with MockLoginApp(require_csrf=False) as app:
        mgr = SessionManager()
        out = configure_session_manager_from_options(
            {
                "auth_flow": "form",
                "auth_url": f"{app.url}/login",
                "auth_fields": (
                    "username=alice,password=hunter2,client_id=ui"
                ),
                "auth_success": r"Welcome alice",
                "accounts": "",
            },
            manager=mgr,
        )
        assert out is mgr
        assert "primary" in mgr.names()
        assert mgr.active().name == "primary"
        # extra_fields propagated into flow_config.
        assert mgr.get("primary")._flow_config.get("extra_fields") == {
            "client_id": "ui"
        }


def test_csrf_flow_uses_form_url():
    with MockLoginApp(require_csrf=True) as app:
        mgr = SessionManager()
        out = configure_session_manager_from_options(
            {
                "auth_flow": "csrf",
                "auth_form_url": f"{app.url}/login-form",
                "auth_url": f"{app.url}/login",
                "auth_fields": "username=alice,password=hunter2",
                "auth_success": r"Welcome alice",
            },
            manager=mgr,
        )
        assert out is mgr
        assert "primary" in mgr.names()


def test_multi_account_populates_manager():
    with MockLoginApp(
        require_csrf=False,
        valid_credentials={"alice": "hunter2", "bob": "s3cret"},
    ) as app:
        mgr = SessionManager()
        configure_session_manager_from_options(
            {
                "auth_flow": "form",
                "auth_url": f"{app.url}/login",
                "auth_fields": "username=alice,password=hunter2",
                "auth_success": r"Welcome",
                "accounts": "bob:bob:s3cret",
            },
            manager=mgr,
        )
        names = mgr.names()
        assert "primary" in names and "bob" in names
        assert mgr.active().name == "primary"
        mgr.switch("bob")
        assert "session" in mgr.active().cookies


def test_bad_primary_login_returns_none():
    with MockLoginApp(require_csrf=False) as app:
        mgr = SessionManager()
        out = configure_session_manager_from_options(
            {
                "auth_flow": "form",
                "auth_url": f"{app.url}/login",
                "auth_fields": "username=alice,password=WRONG",
                "auth_success": r"Welcome",
            },
            manager=mgr,
        )
        assert out is None
        assert mgr.names() == []
