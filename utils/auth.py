"""
cyberm4fia-scanner - Authentication Management
Handles Basic Auth, Bearer Tokens, and Session Cookies
"""

import threading


class AuthChain:
    """Manages credentials and injects them into requests."""

    def __init__(self):
        self.lock = threading.Lock()
        self.auth_type = None
        self.credentials = {}

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

    def inject_auth(self, headers, kwargs):
        """Inject auth into a request's headers or kwargs."""
        with self.lock:
            if not self.auth_type:
                return

            if self.auth_type == "bearer":
                headers["Authorization"] = f"Bearer {self.credentials['token']}"
            elif self.auth_type == "custom_header":
                headers[self.credentials["name"]] = self.credentials["value"]
            elif self.auth_type == "basic":
                kwargs["auth"] = (
                    self.credentials["username"],
                    self.credentials["password"],
                )


# Global AuthManager instance
auth_manager = AuthChain()
