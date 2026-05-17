"""
cyberm4fia-scanner - OOB (Out-of-Band) Interaction Manager

Handles external interaction tokens and polling for blind vulnerabilities.
Supports:
  - Local HTTP Listener (Internal/Bridged)
"""

import random
import string
import threading
from datetime import datetime
from typing import Dict, List, Optional
from http.server import HTTPServer, BaseHTTPRequestHandler

from utils.colors import log_info


class OOBInteraction:
    """Represents a single external interaction."""
    def __init__(self, token: str, interaction_type: str, raw: dict):
        self.token = token
        self.type = interaction_type  # http, dns, etc.
        self.timestamp = datetime.now()
        self.remote_addr = raw.get("remote-address") or raw.get("client-ip", "unknown")
        self.raw = raw

    def __repr__(self):
        return f"<OOBInteraction {self.type} from {self.remote_addr}>"


class OOBProvider:
    """Abstract base for OOB interaction providers.

    Concrete providers (see ``LocalOOBProvider``) override every method.
    The default implementations are deliberate no-ops only so that an
    abstract instance is still callable in a typed sense; callers should
    instantiate a concrete subclass via ``OOBClient(mode=...)`` rather
    than this class directly.
    """

    def get_host(self) -> str:
        raise NotImplementedError

    def start(self) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError

    def poll(self) -> List[OOBInteraction]:
        raise NotImplementedError


class LocalOOBProvider(OOBProvider):
    """Local HTTP listener for internal/bridged network OOB."""
    
    def __init__(self, port: int = 8081, host_ip: str = "0.0.0.0"):
        self.port = port
        self.host_ip = host_ip
        self.interactions: List[OOBInteraction] = []
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def get_host(self) -> str:
        ip = self.host_ip
        if ip == "0.0.0.0":
            import socket
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                s.close()
            except Exception:
                ip = "127.0.0.1"
        return f"{ip}:{self.port}"

    def start(self):
        provider_ref = self

        class OOBHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")
                provider_ref.interactions.append(OOBInteraction(
                    token=self.path.strip("/"),
                    interaction_type="http",
                    raw={"remote-address": self.client_address[0], "method": "GET", "path": self.path}
                ))

            def do_POST(self):
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")
                provider_ref.interactions.append(OOBInteraction(
                    token=self.path.strip("/"),
                    interaction_type="http",
                    raw={"remote-address": self.client_address[0], "method": "POST", "body": body.decode(errors='ignore')}
                ))

            def log_message(self, format, *args):
                return # quiet

        server = None
        for p in range(self.port, self.port + 10):
            try:
                server = HTTPServer((self.host_ip, p), OOBHandler)
                self.port = p
                break
            except OSError as e:
                if e.errno == 98:  # Address already in use
                    continue
                raise
                
        if not server:
            raise OSError(f"OOB: Could not bind to any port between {self.port} and {self.port + 9}")

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._server = server
        self._thread = thread
        thread.start()
        log_info(f"OOB: Local listener started on {self.get_host()}")

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread:
            self._thread = None

    def poll(self) -> List[OOBInteraction]:
        new = list(self.interactions)
        self.interactions.clear()
        return new


class InteractshProvider(OOBProvider):
    """Public Interactsh server polling (default: oast.fun).

    The Interactsh protocol uses an RSA-encrypted per-client correlation
    ID. To keep this dependency-free we run in *poll-only* mode against
    a public REST endpoint exposing the per-correlation log; full
    encryption is left to the upstream ``interactsh-client`` binary. The
    intent here is to give scans an off-host callback without standing
    up a listener, not to replace the official client.
    """

    def __init__(
        self,
        *,
        server: str = "oast.fun",
        correlation_id: Optional[str] = None,
        http_get: Optional[object] = None,
    ) -> None:
        # 33-char correlation ID is the Interactsh standard.
        self.server = server
        self.correlation_id = correlation_id or "".join(
            random.choices(string.ascii_lowercase + string.digits, k=33)
        )
        self.interactions: List[OOBInteraction] = []
        self._http_get = http_get  # injectable for tests

    def get_host(self) -> str:
        return f"{self.correlation_id}.{self.server}"

    def start(self) -> None:
        log_info(f"OOB: Interactsh provider registered for {self.get_host()}")

    def stop(self) -> None:
        return None  # nothing to tear down

    def poll(self) -> List[OOBInteraction]:
        """GET the public log for our correlation ID and parse interactions."""
        client = self._http_get
        if client is None:
            try:
                import httpx
                client = httpx.get
            except ImportError:
                return []

        url = f"https://{self.server}/poll?id={self.correlation_id}"
        try:
            response = client(url, timeout=8)
        except Exception:  # noqa: BLE001
            return []

        try:
            payload = response.json()
        except Exception:  # noqa: BLE001
            return []

        new_interactions: List[OOBInteraction] = []
        for entry in (payload or {}).get("data", []) or []:
            interaction_type = entry.get("protocol") or "http"
            full_id = entry.get("full-id") or entry.get("unique-id") or ""
            token = full_id.split(".")[0] if full_id else ""
            new_interactions.append(
                OOBInteraction(
                    token=token,
                    interaction_type=interaction_type,
                    raw=entry,
                )
            )
        self.interactions.extend(new_interactions)
        return new_interactions


class CollaboratorProvider(OOBProvider):
    """Burp Collaborator wrapper — env-driven for credential isolation.

    Reads ``BURP_COLLAB_SERVER`` (e.g. ``yourserver.example``) and
    ``BURP_COLLAB_KEY`` (the secret key) from the environment. Polls
    the standard ``/results?biid=...`` endpoint. Same caveats as the
    Interactsh provider — encryption / key management is shallow.
    """

    def __init__(
        self,
        *,
        server: Optional[str] = None,
        biid: Optional[str] = None,
        http_get: Optional[object] = None,
    ) -> None:
        import os
        self.server = server or os.environ.get("BURP_COLLAB_SERVER", "")
        self.biid = biid or os.environ.get("BURP_COLLAB_KEY", "")
        self._http_get = http_get
        self.interactions: List[OOBInteraction] = []

    def get_host(self) -> str:
        if not self.server:
            return ""
        token = "".join(
            random.choices(string.ascii_lowercase + string.digits, k=12)
        )
        return f"{token}.{self.server}"

    def start(self) -> None:
        if not self.server or not self.biid:
            log_info(
                "OOB: Collaborator provider missing BURP_COLLAB_SERVER / "
                "BURP_COLLAB_KEY — provider stays inert."
            )
            return
        log_info(f"OOB: Collaborator provider polling {self.server}")

    def stop(self) -> None:
        return None

    def poll(self) -> List[OOBInteraction]:
        if not self.server or not self.biid:
            return []
        client = self._http_get
        if client is None:
            try:
                import httpx
                client = httpx.get
            except ImportError:
                return []
        url = f"https://{self.server}/burpresults?biid={self.biid}"
        try:
            response = client(url, timeout=8)
        except Exception:  # noqa: BLE001
            return []
        try:
            payload = response.json()
        except Exception:  # noqa: BLE001
            return []

        new_interactions: List[OOBInteraction] = []
        for entry in (payload or {}).get("responses", []) or []:
            token = entry.get("interactionString") or ""
            new_interactions.append(
                OOBInteraction(
                    token=token,
                    interaction_type=entry.get("protocol", "http"),
                    raw=entry,
                )
            )
        self.interactions.extend(new_interactions)
        return new_interactions


class OOBClient:
    """Main orchestrator for OOB interactions."""

    def __init__(self, mode: str = "local", listener_port: int = 8081, **kwargs):
        self.mode = mode
        self.provider: OOBProvider
        self.token_map: Dict[str, dict] = {} # token -> finding info
        self._active = False

        if mode == "local":
            self.provider = LocalOOBProvider(port=listener_port)
        elif mode == "interactsh":
            self.provider = InteractshProvider(
                server=kwargs.get("server") or "oast.fun",
                correlation_id=kwargs.get("correlation_id"),
                http_get=kwargs.get("http_get"),
            )
        elif mode == "collab" or mode == "collaborator":
            self.provider = CollaboratorProvider(
                server=kwargs.get("server"),
                biid=kwargs.get("biid"),
                http_get=kwargs.get("http_get"),
            )
        else:
            raise ValueError(
                f"OOBClient: unsupported mode {mode!r}; expected one of "
                f"'local', 'interactsh', 'collab'"
            )

    @property
    def ready(self) -> bool:
        return self._active

    def start(self):
        if self._active:
            return
        self.provider.start()
        self._active = True

    def stop(self):
        if not self._active:
            return
        self.provider.stop()
        self._active = False

    def generate_token(self, metadata: Optional[dict] = None) -> str:
        """Generate a new unique token and map it to finding metadata."""
        token = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        self.token_map[token] = metadata or {}
        return token

    def generate_payload(self, vuln_type: str, param: str) -> str:
        """Compatibility method for scanning modules to get a callback URL."""
        token = self.generate_token({"vuln_type": vuln_type, "param": param})
        return self.get_callback_url(token)

    def get_callback_url(self, token: str) -> str:
        """Get the full callback URL for a token."""
        host = self.provider.get_host()
        return f"http://{host}/{token}"

    def poll(self) -> List[dict]:
        """Poll the provider and return confirmed findings based on token map."""
        interactions = self.provider.poll()
        findings = []
        
        for inter in interactions:
            token = inter.token
            if token in self.token_map:
                meta = self.token_map[token]
                finding = {
                    "type": f"Blind_{meta.get('vuln_type', 'Vulnerability')}",
                    "url": meta.get("url", "N/A"),
                    "payload": meta.get("payload", "N/A"),
                    "oob_type": inter.type,
                    "remote_addr": inter.remote_addr,
                    "severity": "High",
                    "description": f"OOB interaction detected via {inter.type} from {inter.remote_addr}."
                }
                findings.append(finding)
                
        return findings

# Singleton instance
oob_manager = OOBClient()
