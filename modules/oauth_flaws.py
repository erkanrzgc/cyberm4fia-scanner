"""OAuth 2.0 / OIDC misconfiguration catalogue.

We focus on the misconfigurations that consistently turn into account
takeover, not the spec esoterica:

* **redirect_uri** — open redirect / unregistered URI / subdomain
  takeover via dangling redirect targets. Triggers because the
  authorization server doesn't apply strict exact-match validation.
* **state** parameter — absent or echo-only ``state`` enables CSRF
  binding-bypass on the OAuth login flow. ``RFC 6749 §10.12``.
* **PKCE** — endpoint accepts ``code_verifier`` mismatch (``S256 →
  none`` downgrade). Critical on native/mobile clients where the
  authorization code is observable in the redirect.
* **Authorization code reuse** — the same code redeems for a token
  more than once.
* **Implicit-flow / fragment leak** — access token returned in
  fragment to an unregistered redirect domain.

Each check returns vuln-dict findings shaped for the standard pipeline.
Network is injected (``http_get`` / ``http_post``) so unit tests don't
need a real OAuth server.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from utils.colors import log_info, log_success


# ── Data shapes ────────────────────────────────────────────────────────────


@dataclass
class OAuthFinding:
    flaw: str
    severity: str
    evidence: str
    url: str

    def to_dict(self) -> dict:
        return {
            "type": "OAuth_Misconfiguration",
            "url": self.url,
            "severity": self.severity,
            "evidence": self.evidence,
            "flaw": self.flaw,
            "module": "oauth_flaws",
        }


@dataclass
class OAuthEndpoint:
    """The bits of an OAuth flow worth describing as data."""

    authorize_url: str
    token_url: str = ""
    client_id: str = ""
    expected_redirect_uri: str = ""


# ── redirect_uri checks ────────────────────────────────────────────────────


_EVIL_REDIRECTS = (
    "https://attacker.invalid/cb",
    "https://attacker.invalid/.evil-suffix",
    "//attacker.invalid/cb",          # protocol-relative
    "javascript:alert(1)",            # scheme bypass
    "https://attacker.invalid#@trusted.example.com/cb",  # fragment trick
)


def _build_authorize_url(
    endpoint: OAuthEndpoint,
    *,
    redirect_uri: str,
    state: str = "",
    response_type: str = "code",
    extra_params: Optional[dict] = None,
) -> str:
    params = {
        "client_id": endpoint.client_id,
        "redirect_uri": redirect_uri,
        "response_type": response_type,
    }
    if state:
        params["state"] = state
    if extra_params:
        params.update(extra_params)
    sep = "&" if "?" in endpoint.authorize_url else "?"
    return f"{endpoint.authorize_url}{sep}{urlencode(params)}"


def check_redirect_uri(
    endpoint: OAuthEndpoint,
    *,
    http_get: Callable,
    evil_redirects: tuple[str, ...] = _EVIL_REDIRECTS,
    timeout: float = 10.0,
) -> list[OAuthFinding]:
    """Send authorize requests with hostile redirect_uri values.

    A safe server rejects with 400 / ``invalid_redirect_uri``. A broken
    server either issues a Location redirect to the evil URL or returns
    an authorize page that embeds it without rejection.
    """
    findings: list[OAuthFinding] = []

    for evil in evil_redirects:
        url = _build_authorize_url(endpoint, redirect_uri=evil, state="probe")
        try:
            response = http_get(url, timeout=timeout, allow_redirects=False)
        except Exception:  # noqa: BLE001
            continue

        status = getattr(response, "status_code", 0)
        location = getattr(response, "headers", {}).get("Location", "")
        text = getattr(response, "text", "") or ""

        # Accepted-and-redirected → critical.
        if status in (301, 302, 303, 307, 308) and "attacker.invalid" in location:
            findings.append(
                OAuthFinding(
                    flaw="redirect_uri_accepted",
                    severity="critical",
                    url=endpoint.authorize_url,
                    evidence=(
                        f"Authorization server redirected to attacker-controlled "
                        f"URL ({evil!r}) without rejecting the redirect_uri."
                    ),
                )
            )
            continue
        # Returned authorize page with evil URL echoed back. Tighten the
        # "no error indication" check so we don't accidentally swallow
        # "attacker.invalid" itself (which contains the substring "invalid").
        text_lc = text.lower()
        looks_like_error = any(
            marker in text_lc
            for marker in (
                "invalid_redirect_uri",
                "invalid_request",
                "error_description",
                '"error"',
                "redirect_uri mismatch",
            )
        )
        if status == 200 and "attacker.invalid" in text and not looks_like_error:
            findings.append(
                OAuthFinding(
                    flaw="redirect_uri_reflected",
                    severity="high",
                    url=endpoint.authorize_url,
                    evidence=(
                        f"redirect_uri {evil!r} reflected in the authorize "
                        f"response without an error indication."
                    ),
                )
            )

    return findings


# ── state parameter check ──────────────────────────────────────────────────


def check_state_parameter(
    endpoint: OAuthEndpoint,
    *,
    http_get: Callable,
    timeout: float = 10.0,
) -> list[OAuthFinding]:
    """Detect missing or echo-only state binding.

    Vulnerable server: accepts an authorize request with no ``state``
    and returns a Location whose query string also has no state.
    Spec says ``state`` is recommended; for production OAuth its
    absence enables login-CSRF.
    """
    findings: list[OAuthFinding] = []

    # No-state probe.
    url = _build_authorize_url(
        endpoint,
        redirect_uri=endpoint.expected_redirect_uri or "https://client.example/cb",
        state="",
    )
    try:
        response = http_get(url, timeout=timeout, allow_redirects=False)
    except Exception:  # noqa: BLE001
        return findings

    status = getattr(response, "status_code", 0)
    body = getattr(response, "text", "") or ""

    if status in (301, 302, 303, 307, 308):
        location = getattr(response, "headers", {}).get("Location", "")
        if "state=" not in location:
            findings.append(
                OAuthFinding(
                    flaw="state_missing",
                    severity="medium",
                    url=endpoint.authorize_url,
                    evidence=(
                        "Authorize endpoint accepted a request without a "
                        "state parameter and the resulting Location lacks "
                        "state — login CSRF binding bypass."
                    ),
                )
            )
    elif status == 200 and "state" not in body.lower() and "error" not in body.lower():
        # Authorize page has no state input either — at-best advisory.
        findings.append(
            OAuthFinding(
                flaw="state_advisory",
                severity="low",
                url=endpoint.authorize_url,
                evidence=(
                    "Authorize endpoint does not appear to enforce the "
                    "state parameter in its response."
                ),
            )
        )

    return findings


# ── PKCE downgrade check ───────────────────────────────────────────────────


def check_pkce_downgrade(
    endpoint: OAuthEndpoint,
    *,
    http_post: Callable,
    authorization_code: str,
    timeout: float = 10.0,
) -> list[OAuthFinding]:
    """Try to redeem a code with no/mismatched code_verifier.

    A correctly-configured PKCE server rejects with
    ``invalid_grant`` when ``code_verifier`` is missing for a code
    that was issued with ``code_challenge``. A vulnerable server
    accepts the missing verifier and issues a token — full downgrade.
    """
    findings: list[OAuthFinding] = []
    if not endpoint.token_url:
        return findings

    body = {
        "grant_type": "authorization_code",
        "code": authorization_code,
        "redirect_uri": endpoint.expected_redirect_uri or "https://client.example/cb",
        "client_id": endpoint.client_id,
        # Note: deliberately NO code_verifier.
    }
    try:
        response = http_post(endpoint.token_url, data=body, timeout=timeout)
    except Exception:  # noqa: BLE001
        return findings

    status = getattr(response, "status_code", 0)
    text = getattr(response, "text", "") or ""
    if status == 200 and "access_token" in text:
        findings.append(
            OAuthFinding(
                flaw="pkce_downgrade",
                severity="critical",
                url=endpoint.token_url,
                evidence=(
                    "Token endpoint issued an access_token for an "
                    "authorization code without a matching code_verifier — "
                    "PKCE downgrade confirmed."
                ),
            )
        )
    return findings


# ── Authorization code reuse ───────────────────────────────────────────────


def check_code_reuse(
    endpoint: OAuthEndpoint,
    *,
    http_post: Callable,
    authorization_code: str,
    code_verifier: Optional[str] = None,
    timeout: float = 10.0,
) -> list[OAuthFinding]:
    """Issue two token exchanges with the same code — the second must fail."""
    findings: list[OAuthFinding] = []
    if not endpoint.token_url:
        return findings

    body = {
        "grant_type": "authorization_code",
        "code": authorization_code,
        "redirect_uri": endpoint.expected_redirect_uri or "https://client.example/cb",
        "client_id": endpoint.client_id,
    }
    if code_verifier:
        body["code_verifier"] = code_verifier

    try:
        first = http_post(endpoint.token_url, data=body, timeout=timeout)
        second = http_post(endpoint.token_url, data=body, timeout=timeout)
    except Exception:  # noqa: BLE001
        return findings

    first_text = getattr(first, "text", "") or ""
    second_text = getattr(second, "text", "") or ""
    first_status = getattr(first, "status_code", 0)
    second_status = getattr(second, "status_code", 0)

    first_ok = first_status == 200 and "access_token" in first_text
    second_ok = second_status == 200 and "access_token" in second_text
    if first_ok and second_ok:
        findings.append(
            OAuthFinding(
                flaw="code_reuse",
                severity="high",
                url=endpoint.token_url,
                evidence=(
                    "Authorization code was redeemed twice for an "
                    "access_token; codes must be single-use (RFC 6749 §4.1.2)."
                ),
            )
        )
    return findings


# ── Implicit-flow / fragment leak ──────────────────────────────────────────


def check_implicit_flow_leak(
    endpoint: OAuthEndpoint,
    *,
    http_get: Callable,
    timeout: float = 10.0,
) -> list[OAuthFinding]:
    """Try ``response_type=token`` with an evil redirect_uri."""
    findings: list[OAuthFinding] = []
    evil = "https://attacker.invalid/cb"
    url = _build_authorize_url(
        endpoint,
        redirect_uri=evil,
        state="probe",
        response_type="token",
    )
    try:
        response = http_get(url, timeout=timeout, allow_redirects=False)
    except Exception:  # noqa: BLE001
        return findings

    status = getattr(response, "status_code", 0)
    location = getattr(response, "headers", {}).get("Location", "")
    if status in (301, 302, 303, 307, 308) and (
        "attacker.invalid" in location and "#access_token=" in location
    ):
        findings.append(
            OAuthFinding(
                flaw="implicit_flow_leak",
                severity="critical",
                url=endpoint.authorize_url,
                evidence=(
                    "Authorization server issued an access_token in the URL "
                    "fragment to an attacker-controlled redirect_uri "
                    "(implicit flow + open redirect = full account takeover)."
                ),
            )
        )
    return findings


# ── Orchestrator ─────────────────────────────────────────────────────────


def scan_oauth_endpoint(
    endpoint: OAuthEndpoint,
    *,
    http_get: Callable,
    http_post: Optional[Callable] = None,
    authorization_code: Optional[str] = None,
    code_verifier: Optional[str] = None,
) -> list[dict]:
    """Run every flaw check that's applicable to the available endpoint data."""
    findings: list[OAuthFinding] = []
    findings.extend(check_redirect_uri(endpoint, http_get=http_get))
    findings.extend(check_state_parameter(endpoint, http_get=http_get))
    findings.extend(check_implicit_flow_leak(endpoint, http_get=http_get))
    if http_post and authorization_code:
        findings.extend(
            check_pkce_downgrade(
                endpoint,
                http_post=http_post,
                authorization_code=authorization_code,
            )
        )
        findings.extend(
            check_code_reuse(
                endpoint,
                http_post=http_post,
                authorization_code=authorization_code,
                code_verifier=code_verifier,
            )
        )
    if findings:
        log_success(
            f"OAuth flaws: {len(findings)} misconfiguration(s) on "
            f"{endpoint.authorize_url}"
        )
    else:
        log_info(f"OAuth flaws: clean on {endpoint.authorize_url}")
    return [f.to_dict() for f in findings]
