"""
Tests for utils/auth.py — explicit auth and placeholder auth injection.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from utils.auth import auth_manager


@pytest.fixture(autouse=True)
def reset_auth_manager():
    auth_manager.clear_auth()
    auth_manager.clear_placeholder_auth()
    yield
    auth_manager.clear_auth()
    auth_manager.clear_placeholder_auth()


class TestAuthChain:
    def test_placeholder_auth_injects_headers_cookies_and_query(self):
        headers = {"X-Trace": "1"}
        kwargs = {}

        with auth_manager.using_placeholders(
            {
                "headers": {"Authorization": "Bearer <JWT_TOKEN>"},
                "cookies": {"sessionid": "<SESSIONID>"},
                "query": {"access_token": "<ACCESS_TOKEN>"},
            }
        ):
            auth_manager.inject_auth(headers, kwargs)

        assert headers["Authorization"] == "Bearer <JWT_TOKEN>"
        assert headers["Cookie"] == "sessionid=<SESSIONID>"
        assert kwargs["params"] == {"access_token": "<ACCESS_TOKEN>"}

    def test_placeholder_auth_does_not_override_existing_values(self):
        headers = {
            "Authorization": "Bearer real-token",
            "Cookie": "sessionid=real-session",
        }
        kwargs = {"params": {"access_token": "real-query", "page": "1"}}

        with auth_manager.using_placeholders(
            {
                "headers": {"Authorization": "Bearer <JWT_TOKEN>"},
                "cookies": {"sessionid": "<SESSIONID>", "tenant": "<TENANT>"},
                "query": {"access_token": "<ACCESS_TOKEN>", "lang": "en"},
            }
        ):
            auth_manager.inject_auth(headers, kwargs)

        assert headers["Authorization"] == "Bearer real-token"
        assert headers["Cookie"] == "sessionid=real-session; tenant=<TENANT>"
        assert kwargs["params"] == {
            "access_token": "real-query",
            "page": "1",
            "lang": "en",
        }

    def test_explicit_bearer_auth_takes_precedence_over_placeholder(self):
        headers = {}
        kwargs = {}

        auth_manager.set_bearer_token("real-token")
        with auth_manager.using_placeholders(
            {"headers": {"Authorization": "Bearer <JWT_TOKEN>"}}
        ):
            auth_manager.inject_auth(headers, kwargs)

        assert headers["Authorization"] == "Bearer real-token"

    def test_context_manager_restores_previous_placeholder_state(self):
        auth_manager.set_placeholder_auth({"headers": {"X-API-Key": "<KEY>"}})

        with auth_manager.using_placeholders(
            {"headers": {"Authorization": "Bearer <JWT_TOKEN>"}}
        ):
            headers = {}
            kwargs = {}
            auth_manager.inject_auth(headers, kwargs)
            assert headers["Authorization"] == "Bearer <JWT_TOKEN>"
            assert "X-API-Key" not in headers

        headers = {}
        kwargs = {}
        auth_manager.inject_auth(headers, kwargs)
        assert headers["X-API-Key"] == "<KEY>"

    def test_snapshot_restore_round_trip(self):
        auth_manager.set_custom_header("X-Token", "outer")
        auth_manager.set_placeholder_auth({"headers": {"X-API-Key": "<KEY>"}})

        snapshot = auth_manager.snapshot_state()
        auth_manager.set_bearer_token("inner")
        auth_manager.clear_placeholder_auth()
        auth_manager.restore_state(snapshot)

        headers = {}
        kwargs = {}
        auth_manager.inject_auth(headers, kwargs)
        assert headers["X-Token"] == "outer"
        assert headers["X-API-Key"] == "<KEY>"

    def test_without_auth_temporarily_disables_all_auth_injection(self):
        auth_manager.set_bearer_token("real-token")
        auth_manager.set_placeholder_auth({"headers": {"X-API-Key": "<KEY>"}})

        with auth_manager.without_auth():
            headers = {}
            kwargs = {}
            auth_manager.inject_auth(headers, kwargs)
            assert headers == {}
            assert kwargs == {}

        headers = {}
        kwargs = {}
        auth_manager.inject_auth(headers, kwargs)
        assert headers["Authorization"] == "Bearer real-token"
        assert headers["X-API-Key"] == "<KEY>"
