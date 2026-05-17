"""Form-based login flow — POST credentials, capture Set-Cookie.

Flow config keys:
    login_url        : str  — where to POST credentials (required)
    field_user       : str  — credentials key holding the username (default "username")
    field_pass       : str  — credentials key holding the password (default "password")
    extra_fields     : dict — additional form fields to send verbatim
    success_indicator: str  — regex to confirm login success in response body
    success_status   : int|tuple — accepted status codes (default 200, 302, 303)
    method           : str  — "POST" (default) or "GET"
    timeout          : float — request timeout in seconds (default 10)
    verify_ssl       : bool — TLS verification (default True)

Credentials dict carries the actual values, e.g.::

    {"username": "alice", "password": "hunter2"}

The two-key split keeps secrets out of the flow_config — flow_config is
echoed back from SessionState while credentials stay in the private
``_credentials`` slot only.

Returns ``(cookies, headers, None)`` — bearer is never produced here;
use a dedicated flow for token endpoints.
"""

from __future__ import annotations

import re
from typing import Any, Optional

import httpx


_DEFAULT_SUCCESS_STATUSES = (200, 302, 303)


class FormLoginError(RuntimeError):
    """Raised when the form login attempt cannot be confirmed as successful."""


def _coerce_statuses(value: Any) -> tuple[int, ...]:
    if value is None:
        return _DEFAULT_SUCCESS_STATUSES
    if isinstance(value, int):
        return (value,)
    return tuple(int(v) for v in value)


def login(
    credentials: dict[str, str],
    flow_config: dict[str, Any],
) -> tuple[dict[str, str], dict[str, str], Optional[str]]:
    login_url = flow_config.get("login_url")
    if not login_url:
        raise FormLoginError("form_login: 'login_url' is required in flow_config")

    field_user = flow_config.get("field_user", "username")
    field_pass = flow_config.get("field_pass", "password")
    extra_fields = dict(flow_config.get("extra_fields") or {})
    success_pat = flow_config.get("success_indicator")
    success_statuses = _coerce_statuses(flow_config.get("success_status"))
    method = str(flow_config.get("method", "POST")).upper()
    timeout = float(flow_config.get("timeout", 10))
    verify_ssl = bool(flow_config.get("verify_ssl", True))

    payload = dict(extra_fields)
    if field_user in credentials:
        payload[field_user] = credentials[field_user]
    elif "username" in credentials:
        payload[field_user] = credentials["username"]
    if field_pass in credentials:
        payload[field_pass] = credentials[field_pass]
    elif "password" in credentials:
        payload[field_pass] = credentials["password"]

    trust_env = bool(flow_config.get("trust_env", False))
    client = httpx.Client(
        timeout=timeout,
        verify=verify_ssl,
        follow_redirects=True,
        trust_env=trust_env,
    )
    try:
        if method == "GET":
            response = client.get(login_url, params=payload)
        else:
            response = client.request(method, login_url, data=payload)
    except httpx.HTTPError as exc:
        client.close()
        raise FormLoginError(
            f"form_login: request to {login_url} failed: "
            f"{type(exc).__name__}: {exc}"
        ) from exc

    body = response.text or ""

    if response.status_code not in success_statuses:
        raise FormLoginError(
            f"form_login: unexpected status {response.status_code} "
            f"(accepted: {success_statuses})"
        )
    if success_pat:
        try:
            if not re.search(success_pat, body):
                raise FormLoginError(
                    f"form_login: success indicator did not match "
                    f"(pattern={success_pat!r})"
                )
        except re.error as exc:
            raise FormLoginError(
                f"form_login: invalid success_indicator regex: {exc}"
            ) from exc

    cookies = dict(client.cookies)
    client.close()
    headers: dict[str, str] = {}
    return cookies, headers, None
