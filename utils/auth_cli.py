"""CLI argument parsing for authenticated scanning.

Translates the flat ``--auth-*`` / ``--accounts`` options surface into a
populated ``SessionManager`` instance. Kept separate from scanner.py to
avoid bloating the entry-point module and to make the parsing logic
unit-testable in isolation.

Argument shapes:
    --auth-fields  : "k1=v1,k2=v2"  (username + password required)
    --accounts     : "name:user:pass,name2:user2:pass2"
"""

from __future__ import annotations

from typing import Any, Optional

from utils.auth_flows import register_default_flows
from utils.colors import log_info, log_warning
from utils.session_manager import SessionManager, session_manager


def parse_kv_list(raw: str) -> dict[str, str]:
    """Parse ``k=v,k2=v2`` into a dict. Empty input → empty dict."""
    if not raw:
        return {}
    out: dict[str, str] = {}
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        key, value = chunk.split("=", 1)
        out[key.strip()] = value.strip()
    return out


def parse_accounts_list(raw: str) -> list[tuple[str, str, str]]:
    """Parse ``name:user:pass,name2:user2:pass2`` → list of triples."""
    if not raw:
        return []
    out: list[tuple[str, str, str]] = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = chunk.split(":")
        if len(parts) < 3:
            log_warning(
                f"--accounts entry skipped (need name:user:pass): {chunk!r}"
            )
            continue
        name = parts[0].strip()
        user = parts[1].strip()
        # Allow ":" inside the password by re-joining the tail.
        password = ":".join(parts[2:]).strip()
        out.append((name, user, password))
    return out


def _build_flow_config(options: dict[str, Any]) -> dict[str, Any]:
    """Translate scanner options into a flow_config dict.

    Only fields the flow knows about are forwarded — extra options stay
    in ``options`` and are ignored by the flow.
    """
    flow = options.get("auth_flow")
    config: dict[str, Any] = {}
    if flow == "form":
        config["login_url"] = options.get("auth_url", "")
    elif flow == "csrf":
        form_url = options.get("auth_form_url") or options.get("auth_url", "")
        login_url = options.get("auth_url", "") or form_url
        config["form_url"] = form_url
        config["login_url"] = login_url
    if options.get("auth_success"):
        config["success_indicator"] = options["auth_success"]
    return config


def configure_session_manager_from_options(
    options: dict[str, Any],
    *,
    manager: Optional[SessionManager] = None,
) -> Optional[SessionManager]:
    """Initialise the global SessionManager from parsed CLI options.

    Returns the populated manager, or ``None`` when authentication was
    not requested (``--auth-flow`` omitted). Any login failure is logged
    and the function returns ``None`` so the scan can proceed unauth'd.
    """
    flow = options.get("auth_flow")
    if not flow:
        return None

    mgr = manager or session_manager
    register_default_flows(mgr)

    fields = parse_kv_list(options.get("auth_fields", ""))
    primary_user = fields.get("username") or fields.get("user")
    primary_pass = fields.get("password") or fields.get("pass")
    if not primary_user or not primary_pass:
        log_warning(
            "--auth-flow set but --auth-fields missing username/password — "
            "scan will continue unauthenticated."
        )
        return None

    extra_fields = {
        k: v for k, v in fields.items()
        if k not in ("username", "user", "password", "pass")
    }

    config = _build_flow_config(options)
    if extra_fields:
        config["extra_fields"] = extra_fields

    primary_creds = {"username": primary_user, "password": primary_pass}
    success_pat = options.get("auth_success") or None
    try:
        mgr.add_account(
            "primary",
            flow=flow,
            credentials=primary_creds,
            flow_config=config,
            success_indicator=success_pat,
        )
    except Exception as exc:  # noqa: BLE001
        log_warning(
            f"primary login failed via --auth-flow {flow!r}: "
            f"{type(exc).__name__}: {exc} — scan continuing unauthenticated."
        )
        return None

    log_info(f"Primary session captured via {flow!r}.")

    # Additional accounts for multi-identity tests.
    accounts = parse_accounts_list(options.get("accounts", ""))
    for name, user, password in accounts:
        try:
            mgr.add_account(
                name,
                flow=flow,
                credentials={"username": user, "password": password},
                flow_config=config,
                success_indicator=success_pat,
            )
        except Exception as exc:  # noqa: BLE001
            log_warning(
                f"--accounts entry {name!r} failed to log in: "
                f"{type(exc).__name__}: {exc}"
            )
    if accounts:
        log_info(
            f"Multi-account ready: {[a[0] for a in accounts]} (active=primary)"
        )

    # The primary session is the active one by default — switch back to it
    # explicitly in case the last add_account flipped active to something
    # else in some future implementation.
    try:
        mgr.switch("primary")
    except KeyError:
        pass
    return mgr
