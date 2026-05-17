"""Authentication flow implementations for SessionManager.

Each submodule exposes a ``login(credentials, flow_config)`` function with
the signature documented in ``utils.session_manager.FlowFunc``:

    login(credentials: dict[str, str], flow_config: dict[str, Any])
        -> tuple[cookies: dict[str, str],
                 headers: dict[str, str],
                 bearer_token: Optional[str]]

``register_default_flows(manager)`` wires every shipped flow into a
``SessionManager`` in one call. New flows just need a submodule with a
``login`` function and an entry in ``_DEFAULT_FLOWS``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from . import csrf_token_login, form_login

if TYPE_CHECKING:  # pragma: no cover
    from utils.session_manager import SessionManager


_DEFAULT_FLOWS = {
    "form": form_login.login,
    "csrf": csrf_token_login.login,
}


def register_default_flows(manager: "SessionManager") -> None:
    """Register every flow shipped in this package with ``manager``."""
    for name, func in _DEFAULT_FLOWS.items():
        manager.register_flow(name, func)


__all__ = ["register_default_flows", "form_login", "csrf_token_login"]
