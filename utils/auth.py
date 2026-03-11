"""
cyberm4fia-scanner - Authentication Management
Handles Basic Auth, Bearer Tokens, and Session Cookies
"""

from copy import deepcopy
from contextlib import contextmanager
import threading


class AuthChain:
    """Manages credentials and injects them into requests."""

    def __init__(self):
        self.lock = threading.Lock()
        self.auth_type = None
        self.credentials = {}
        self.placeholder_auth = {}

    def set_basic_auth(self, username, password):
        with self.lock:
            self.auth_type = "basic"
            self.credentials = {"username": username, "password": password}

    def set_bearer_token(self, token):
        with self.lock:
            self.auth_type = "bearer"
            self.credentials = {"token": token}

    def set_custom_header(self, header_name, header_value):
        with self.lock:
            self.auth_type = "custom_header"
            self.credentials = {"name": header_name, "value": header_value}

    def clear_auth(self):
        with self.lock:
            self.auth_type = None
            self.credentials = {}

    def set_placeholder_auth(self, placeholders=None):
        with self.lock:
            self.placeholder_auth = placeholders or {}

    def clear_placeholder_auth(self):
        with self.lock:
            self.placeholder_auth = {}

    def snapshot_state(self):
        """Capture current auth configuration for later restoration."""
        with self.lock:
            return {
                "auth_type": self.auth_type,
                "credentials": dict(self.credentials),
                "placeholder_auth": deepcopy(self.placeholder_auth),
            }

    def restore_state(self, state=None):
        """Restore auth configuration from a snapshot."""
        state = state or {}
        with self.lock:
            self.auth_type = state.get("auth_type")
            self.credentials = dict(state.get("credentials", {}))
            self.placeholder_auth = deepcopy(state.get("placeholder_auth", {}))

    @contextmanager
    def using_placeholders(self, placeholders=None):
        with self.lock:
            previous = deepcopy(self.placeholder_auth)
            self.placeholder_auth = placeholders or {}
        try:
            yield
        finally:
            with self.lock:
                self.placeholder_auth = previous

    @contextmanager
    def without_auth(self):
        """Temporarily disable explicit and placeholder auth injection."""
        snapshot = self.snapshot_state()
        self.clear_auth()
        self.clear_placeholder_auth()
        try:
            yield
        finally:
            self.restore_state(snapshot)

    def _merge_cookie_placeholders(self, headers, cookies):
        cookie_header = headers.get("Cookie", "")
        existing = {}

        for chunk in cookie_header.split(";"):
            if "=" not in chunk:
                continue
            key, value = chunk.split("=", 1)
            existing[key.strip()] = value.strip()

        for key, value in (cookies or {}).items():
            existing.setdefault(key, value)

        if existing:
            headers["Cookie"] = "; ".join(
                f"{key}={value}" for key, value in existing.items()
            )

    def _inject_placeholder_auth(self, headers, kwargs):
        placeholders = self.placeholder_auth or {}
        if not placeholders:
            return

        for name, value in placeholders.get("headers", {}).items():
            headers.setdefault(name, value)

        self._merge_cookie_placeholders(headers, placeholders.get("cookies"))

        query_placeholders = placeholders.get("query", {})
        if query_placeholders:
            params = kwargs.get("params")
            if not isinstance(params, dict):
                params = dict(params or {})
            for key, value in query_placeholders.items():
                params.setdefault(key, value)
            kwargs["params"] = params

    def inject_auth(self, headers, kwargs):
        """Inject auth into a request's headers or kwargs."""
        with self.lock:
            if self.auth_type == "bearer":
                headers["Authorization"] = f"Bearer {self.credentials['token']}"
            elif self.auth_type == "custom_header":
                headers[self.credentials["name"]] = self.credentials["value"]
            elif self.auth_type == "basic":
                kwargs["auth"] = (
                    self.credentials["username"],
                    self.credentials["password"],
                )

            self._inject_placeholder_auth(headers, kwargs)


# Global AuthManager instance
auth_manager = AuthChain()
