"""CSRF-token-aware login: fetch the form, extract the token, then POST.

Many real-world login forms embed a one-shot CSRF token in a hidden input
and reject any POST that doesn't carry it back. This flow handles that
pattern explicitly.

Flow config keys (additive over form_login):
    form_url         : str  — GET this URL to retrieve the form (required)
    login_url        : str  — POST credentials here (default: same as form_url)
    token_field      : str  — name of the hidden CSRF input (default "csrf_token")
    token_input_name : str  — explicit name attribute to look for in the form
                              HTML; overrides token_field for the regex.
    field_user / field_pass / extra_fields / success_indicator /
    success_status / timeout / verify_ssl — same semantics as form_login.

We use a regex over the HTML instead of pulling in BeautifulSoup so this
flow stays lightweight and synchronous; the project already uses bs4 for
crawling but not for auth.
"""

from __future__ import annotations

import re
from typing import Any, Optional

import httpx


_DEFAULT_SUCCESS_STATUSES = (200, 302, 303)


class CSRFTokenLoginError(RuntimeError):
    """Raised when the CSRF login flow cannot complete successfully."""


def _coerce_statuses(value: Any) -> tuple[int, ...]:
    if value is None:
        return _DEFAULT_SUCCESS_STATUSES
    if isinstance(value, int):
        return (value,)
    return tuple(int(v) for v in value)


def _extract_csrf_token(html: str, field_name: str) -> Optional[str]:
    """Find ``<input name="field_name" value="...">`` in the form HTML."""
    pattern = (
        r"<input[^>]+name=[\"']"
        + re.escape(field_name)
        + r"[\"'][^>]*value=[\"']([^\"']+)[\"']"
    )
    match = re.search(pattern, html, flags=re.IGNORECASE)
    if match:
        return match.group(1)
    # Try the reverse attribute order: value="..." before name="..."
    pattern_rev = (
        r"<input[^>]+value=[\"']([^\"']+)[\"'][^>]*name=[\"']"
        + re.escape(field_name)
        + r"[\"']"
    )
    match = re.search(pattern_rev, html, flags=re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def login(
    credentials: dict[str, str],
    flow_config: dict[str, Any],
) -> tuple[dict[str, str], dict[str, str], Optional[str]]:
    form_url = flow_config.get("form_url")
    if not form_url:
        raise CSRFTokenLoginError(
            "csrf_token_login: 'form_url' is required in flow_config"
        )
    login_url = flow_config.get("login_url", form_url)
    token_field = flow_config.get(
        "token_input_name", flow_config.get("token_field", "csrf_token")
    )
    field_user = flow_config.get("field_user", "username")
    field_pass = flow_config.get("field_pass", "password")
    extra_fields = dict(flow_config.get("extra_fields") or {})
    success_pat = flow_config.get("success_indicator")
    success_statuses = _coerce_statuses(flow_config.get("success_status"))
    timeout = float(flow_config.get("timeout", 10))
    verify_ssl = bool(flow_config.get("verify_ssl", True))

    trust_env = bool(flow_config.get("trust_env", False))
    client = httpx.Client(
        timeout=timeout,
        verify=verify_ssl,
        follow_redirects=True,
        trust_env=trust_env,
    )

    try:
        get_resp = client.get(form_url)
    except httpx.HTTPError as exc:
        client.close()
        raise CSRFTokenLoginError(
            f"csrf_token_login: GET {form_url} failed: "
            f"{type(exc).__name__}: {exc}"
        ) from exc

    token = _extract_csrf_token(get_resp.text or "", token_field)
    if not token:
        raise CSRFTokenLoginError(
            f"csrf_token_login: could not find CSRF token "
            f"(field={token_field!r}) in form HTML"
        )

    payload = dict(extra_fields)
    payload[token_field] = token
    payload[field_user] = credentials.get(field_user) or credentials.get("username", "")
    payload[field_pass] = credentials.get(field_pass) or credentials.get("password", "")

    try:
        post_resp = client.post(login_url, data=payload)
    except httpx.HTTPError as exc:
        client.close()
        raise CSRFTokenLoginError(
            f"csrf_token_login: POST {login_url} failed: "
            f"{type(exc).__name__}: {exc}"
        ) from exc

    if post_resp.status_code not in success_statuses:
        raise CSRFTokenLoginError(
            f"csrf_token_login: unexpected status {post_resp.status_code} "
            f"(accepted: {success_statuses})"
        )
    if success_pat:
        try:
            if not re.search(success_pat, post_resp.text or ""):
                raise CSRFTokenLoginError(
                    f"csrf_token_login: success indicator did not match "
                    f"(pattern={success_pat!r})"
                )
        except re.error as exc:
            raise CSRFTokenLoginError(
                f"csrf_token_login: invalid success_indicator regex: {exc}"
            ) from exc

    cookies = dict(client.cookies)
    client.close()
    return cookies, {}, None
