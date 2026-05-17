"""Authenticated session manager — login capture, replay, refresh, multi-account.

Companion to ``utils.auth.AuthChain``. ``AuthChain`` handles **static**
credentials (basic / bearer / custom header / placeholder cookies) used
by every outbound request. ``SessionManager`` is for **dynamic** sessions:

* Replay a login flow against the target, capture cookies/tokens, store
  them in a ``SessionState``.
* Inject the captured cookies into outbound ``requests.Session`` objects.
* Re-run the login when an "expired" indicator is detected in a response.
* Keep multiple named accounts on hand so IDOR / privilege-escalation
  modules can swap identities deterministically.

Auth flows themselves live in ``utils.auth_flows`` — this module is the
storage + selection + refresh policy only. That separation keeps the
manager small and lets new flow types (OAuth, SAML, JWT-refresh) plug in
without touching the manager surface.

Threat model: captured credentials stay in memory only; never written to
disk by this module. The scope filter still applies to every replayed
request through the standard ``utils.request`` path.
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from utils.colors import log_info, log_success, log_warning


_DEFAULT_SESSION_TTL_SECONDS = 30 * 60  # 30 min — conservative default


@dataclass
class SessionState:
    """One captured session. Mutated by ``SessionManager.refresh_if_expired``."""

    name: str
    flow: str                                  # "form", "csrf", "oauth", "bearer", ...
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    bearer_token: Optional[str] = None
    captured_at: float = field(default_factory=time.time)
    ttl_seconds: float = _DEFAULT_SESSION_TTL_SECONDS
    # Echoed-back credentials only used for re-login. NEVER persisted.
    _credentials: dict[str, str] = field(default_factory=dict, repr=False)
    # Original flow config so refresh can replay it. NEVER persisted.
    _flow_config: dict[str, Any] = field(default_factory=dict, repr=False)
    # Expiry indicator regex — when response body/status matches, refresh.
    expired_indicator: Optional[str] = None
    success_indicator: Optional[str] = None

    @property
    def age_seconds(self) -> float:
        return time.time() - self.captured_at

    @property
    def likely_expired(self) -> bool:
        return self.age_seconds > self.ttl_seconds

    def matches_expired_response(self, status_code: int, body: str) -> bool:
        """True when the response looks like a session-expired sentinel."""
        if status_code in (401, 419, 440):
            return True
        if not self.expired_indicator:
            return False
        try:
            return bool(re.search(self.expired_indicator, body or ""))
        except re.error:
            return False


# Flow-callable signature: takes credentials + flow_config, returns a
# (cookies, headers, bearer_token) tuple. Raising means login failed.
FlowFunc = Callable[
    [dict[str, str], dict[str, Any]],
    tuple[dict[str, str], dict[str, str], Optional[str]],
]


class SessionManager:
    """Stores named sessions + flow registrations.

    The manager is intentionally agnostic to *how* login happens — flows
    are pluggable callables registered by ``utils.auth_flows`` or by
    callers directly. This keeps the manager unit-testable without any
    real network stack.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, SessionState] = {}
        self._flows: dict[str, FlowFunc] = {}
        self._active: Optional[str] = None

    # ── Flow registration ──────────────────────────────────────────────────

    def register_flow(self, name: str, func: FlowFunc) -> None:
        """Register a login flow callable (idempotent)."""
        with self._lock:
            self._flows[name] = func

    def has_flow(self, name: str) -> bool:
        with self._lock:
            return name in self._flows

    # ── Account / session storage ──────────────────────────────────────────

    def add_account(
        self,
        name: str,
        flow: str,
        credentials: dict[str, str],
        *,
        flow_config: Optional[dict[str, Any]] = None,
        ttl_seconds: float = _DEFAULT_SESSION_TTL_SECONDS,
        expired_indicator: Optional[str] = None,
        success_indicator: Optional[str] = None,
    ) -> SessionState:
        """Record an account and run its flow now to capture initial state.

        Raises ``KeyError`` if the flow is not registered, or whatever the
        flow itself raises on auth failure.
        """
        with self._lock:
            if flow not in self._flows:
                raise KeyError(f"unknown auth flow: {flow!r}")
            flow_func = self._flows[flow]

        config = dict(flow_config or {})
        cookies, headers, bearer = flow_func(credentials, config)

        state = SessionState(
            name=name,
            flow=flow,
            cookies=dict(cookies or {}),
            headers=dict(headers or {}),
            bearer_token=bearer,
            ttl_seconds=ttl_seconds,
            _credentials=dict(credentials),
            _flow_config=config,
            expired_indicator=expired_indicator,
            success_indicator=success_indicator,
        )
        with self._lock:
            self._sessions[name] = state
            if self._active is None:
                self._active = name
        log_success(f"session captured: {name} (flow={flow})")
        return state

    def switch(self, name: str) -> SessionState:
        """Activate the named session (for IDOR / privilege-escalation tests)."""
        with self._lock:
            if name not in self._sessions:
                raise KeyError(f"unknown session: {name!r}")
            self._active = name
            return self._sessions[name]

    def active(self) -> Optional[SessionState]:
        with self._lock:
            if self._active is None:
                return None
            return self._sessions.get(self._active)

    def get(self, name: str) -> Optional[SessionState]:
        with self._lock:
            return self._sessions.get(name)

    def names(self) -> list[str]:
        with self._lock:
            return list(self._sessions.keys())

    # ── Refresh policy ─────────────────────────────────────────────────────

    def refresh(self, name: str) -> SessionState:
        """Re-run the captured flow with the same credentials/config."""
        with self._lock:
            state = self._sessions.get(name)
            if state is None:
                raise KeyError(f"unknown session: {name!r}")
            flow_func = self._flows.get(state.flow)
            credentials = dict(state._credentials)
            config = dict(state._flow_config)
        if flow_func is None:
            raise KeyError(f"flow not registered: {state.flow!r}")

        cookies, headers, bearer = flow_func(credentials, config)
        with self._lock:
            state.cookies = dict(cookies or {})
            state.headers = dict(headers or {})
            state.bearer_token = bearer
            state.captured_at = time.time()
        log_info(f"session refreshed: {name}")
        return state

    def refresh_if_expired(
        self,
        name: str,
        *,
        last_status: int = 200,
        last_body: str = "",
    ) -> bool:
        """Refresh when the session is age-expired or response matches expiry.

        Returns True when a refresh actually happened.
        """
        state = self.get(name)
        if state is None:
            return False
        if state.likely_expired or state.matches_expired_response(
            last_status, last_body
        ):
            try:
                self.refresh(name)
                return True
            except Exception as exc:  # noqa: BLE001
                log_warning(
                    f"session refresh failed for {name}: "
                    f"{type(exc).__name__}: {exc}"
                )
                return False
        return False

    # ── Injection helpers ─────────────────────────────────────────────────

    def apply_to_http_client(self, http_client: Any) -> None:
        """Push the active session's cookies + headers into an httpx Client
        (or any object with ``cookies`` and ``headers`` mappings)."""
        state = self.active()
        if state is None:
            return
        for k, v in state.cookies.items():
            try:
                http_client.cookies.set(k, v)
            except AttributeError:
                http_client.cookies[k] = v
        for k, v in state.headers.items():
            http_client.headers[k] = v
        if state.bearer_token:
            http_client.headers["Authorization"] = f"Bearer {state.bearer_token}"

    # Backwards-compat alias for callers still passing a requests.Session-shaped
    # object. The duck-typed implementation works with both.
    apply_to_requests_session = apply_to_http_client


# Global singleton — symmetric with ``utils.auth.auth_manager``.
session_manager = SessionManager()
