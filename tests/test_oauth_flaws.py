"""Tests for modules/oauth_flaws — OAuth 2.0 / OIDC misconfig checks."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from modules.oauth_flaws import (
    OAuthEndpoint,
    OAuthFinding,
    check_code_reuse,
    check_implicit_flow_leak,
    check_pkce_downgrade,
    check_redirect_uri,
    check_state_parameter,
    scan_oauth_endpoint,
)


pytestmark = pytest.mark.unit


def _resp(status: int, text: str = "", headers: dict | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        status_code=status, text=text, headers=dict(headers or {})
    )


def _endpoint(**overrides) -> OAuthEndpoint:
    defaults = dict(
        authorize_url="https://idp.t/oauth/authorize",
        token_url="https://idp.t/oauth/token",
        client_id="abc",
        expected_redirect_uri="https://client.example/cb",
    )
    defaults.update(overrides)
    return OAuthEndpoint(**defaults)


# ── redirect_uri ────────────────────────────────────────────────────────────


def test_redirect_uri_accepted_redirect_is_critical():
    """Server 302s straight to attacker.invalid → critical takeover risk."""

    def fake_get(url, timeout, allow_redirects):
        if "attacker.invalid" in url:
            return _resp(
                302, "", headers={"Location": "https://attacker.invalid/cb?code=X"}
            )
        return _resp(200, "")

    findings = check_redirect_uri(_endpoint(), http_get=fake_get)
    assert any(f.flaw == "redirect_uri_accepted" for f in findings)


def test_redirect_uri_reflected_in_body_is_high():
    """No redirect, but the evil URL is echoed back as if registered."""

    def fake_get(url, timeout, allow_redirects):
        return _resp(
            200,
            "<form action='https://attacker.invalid/cb'>...</form>",
        )

    findings = check_redirect_uri(_endpoint(), http_get=fake_get)
    assert any(f.flaw == "redirect_uri_reflected" for f in findings)


def test_redirect_uri_properly_rejected():
    def fake_get(url, timeout, allow_redirects):
        return _resp(400, '{"error": "invalid_redirect_uri"}')

    findings = check_redirect_uri(_endpoint(), http_get=fake_get)
    assert findings == []


def test_redirect_uri_get_raises_safely():
    def boom(url, timeout, allow_redirects):
        raise RuntimeError("dns failure")

    findings = check_redirect_uri(_endpoint(), http_get=boom)
    assert findings == []


# ── state parameter ────────────────────────────────────────────────────────


def test_state_missing_in_redirect_location_is_medium():
    def fake_get(url, timeout, allow_redirects):
        return _resp(
            302, "", headers={"Location": "https://client.example/cb?code=X"}
        )

    findings = check_state_parameter(_endpoint(), http_get=fake_get)
    assert any(f.flaw == "state_missing" for f in findings)


def test_state_present_in_redirect_is_clean():
    def fake_get(url, timeout, allow_redirects):
        return _resp(
            302,
            "",
            headers={"Location": "https://client.example/cb?code=X&state=ZZZ"},
        )

    findings = check_state_parameter(_endpoint(), http_get=fake_get)
    assert all(f.flaw != "state_missing" for f in findings)


# ── PKCE downgrade ─────────────────────────────────────────────────────────


def test_pkce_downgrade_when_token_issued_without_verifier():
    def fake_post(url, data, timeout):
        # Vulnerable server: accepts the code with no code_verifier.
        return _resp(200, '{"access_token": "abc", "token_type": "Bearer"}')

    findings = check_pkce_downgrade(
        _endpoint(), http_post=fake_post, authorization_code="x"
    )
    assert findings and findings[0].flaw == "pkce_downgrade"
    assert findings[0].severity == "critical"


def test_pkce_safe_when_token_endpoint_rejects():
    def fake_post(url, data, timeout):
        return _resp(400, '{"error":"invalid_grant"}')

    findings = check_pkce_downgrade(
        _endpoint(), http_post=fake_post, authorization_code="x"
    )
    assert findings == []


def test_pkce_skipped_when_no_token_url():
    findings = check_pkce_downgrade(
        _endpoint(token_url=""),
        http_post=lambda *a, **kw: pytest.fail("should not call"),
        authorization_code="x",
    )
    assert findings == []


# ── Code reuse ─────────────────────────────────────────────────────────────


def test_code_reuse_detected_when_both_redemptions_succeed():
    state = {"calls": 0}

    def fake_post(url, data, timeout):
        state["calls"] += 1
        return _resp(200, '{"access_token": "t"}')

    findings = check_code_reuse(
        _endpoint(), http_post=fake_post, authorization_code="C0DE"
    )
    assert findings and findings[0].flaw == "code_reuse"
    assert state["calls"] == 2


def test_code_reuse_safe_when_second_fails():
    state = {"calls": 0}

    def fake_post(url, data, timeout):
        state["calls"] += 1
        if state["calls"] == 1:
            return _resp(200, '{"access_token": "t"}')
        return _resp(400, '{"error":"invalid_grant"}')

    findings = check_code_reuse(
        _endpoint(), http_post=fake_post, authorization_code="C0DE"
    )
    assert findings == []


# ── Implicit flow leak ─────────────────────────────────────────────────────


def test_implicit_flow_leak_detected():
    def fake_get(url, timeout, allow_redirects):
        return _resp(
            302,
            "",
            headers={
                "Location": (
                    "https://attacker.invalid/cb#access_token=abc&token_type=Bearer"
                )
            },
        )

    findings = check_implicit_flow_leak(_endpoint(), http_get=fake_get)
    assert findings and findings[0].flaw == "implicit_flow_leak"


def test_implicit_flow_leak_safe_when_evil_rejected():
    def fake_get(url, timeout, allow_redirects):
        return _resp(400, '{"error":"invalid_redirect_uri"}')

    findings = check_implicit_flow_leak(_endpoint(), http_get=fake_get)
    assert findings == []


# ── Orchestrator ───────────────────────────────────────────────────────────


def test_orchestrator_runs_only_get_checks_without_post():
    """When http_post is not supplied, PKCE+reuse checks are skipped."""

    def fake_get(url, timeout, allow_redirects):
        if "attacker.invalid" in url:
            return _resp(302, "", headers={"Location": "https://attacker.invalid/cb"})
        return _resp(400, "")

    findings = scan_oauth_endpoint(_endpoint(), http_get=fake_get)
    flaws = {f["flaw"] for f in findings}
    assert "redirect_uri_accepted" in flaws
    assert "pkce_downgrade" not in flaws
    assert "code_reuse" not in flaws


def test_orchestrator_combines_get_and_post_checks():
    def fake_get(url, timeout, allow_redirects):
        return _resp(400, '{"error":"invalid_redirect_uri"}')

    def fake_post(url, data, timeout):
        return _resp(200, '{"access_token": "t"}')

    findings = scan_oauth_endpoint(
        _endpoint(),
        http_get=fake_get,
        http_post=fake_post,
        authorization_code="C0DE",
    )
    flaws = {f["flaw"] for f in findings}
    # PKCE downgrade should fire even when redirect_uri is properly enforced.
    assert "pkce_downgrade" in flaws
    assert "code_reuse" in flaws


def test_finding_dict_carries_module_and_type():
    def fake_get(url, timeout, allow_redirects):
        if "attacker.invalid" in url:
            return _resp(302, "", headers={"Location": "https://attacker.invalid/cb"})
        return _resp(400, "")

    findings = scan_oauth_endpoint(_endpoint(), http_get=fake_get)
    for f in findings:
        assert f["module"] == "oauth_flaws"
        assert f["type"] == "OAuth_Misconfiguration"
