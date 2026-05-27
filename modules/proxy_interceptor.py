"""
cyberm4fia-scanner - OWASP ZAP Alternative (Proxy Interceptor Module)
Acts as a local MITM proxy to capture browser traffic and forward it to scanning modules.

Requirement: pip install mitmproxy
"""

import os
import sys

# Add project root to path so mitmdump can find the utils and core packages
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import threading
from urllib.parse import urlparse
import json

from utils.colors import log_info, log_success, log_warning, log_error
from utils.request import get_request_delay, set_cookie
from utils.request import ScanExceptions

try:
    from mitmproxy import ctx
    from mitmproxy import http
except ImportError:
    log_warning("mitmproxy is not installed. To use the proxy module, run: pip install mitmproxy")
    ctx = None

class Cyberm4fiaInterceptor:
    def __init__(self, target_scope):
        # target_scope is a string (e.g., 'wisarc.com') used to filter traffic
        self.target_scope = target_scope
        self.captured_requests = 0
        log_info(f"🛡️ Proxy Interceptor started. Listening for traffic to: {self.target_scope}")

    def request(self, flow: "http.HTTPFlow"):
        """Intercepts HTTP requests before they are sent to the server."""
        if not flow.request.host.endswith(self.target_scope):
            return  # Skip out-of-scope traffic

        url = flow.request.url
        method = flow.request.method
        
        # We generally care about requests with parameters (GET with query string, POST/PUT with body)
        if method == "GET" and not flow.request.query:
            # Skip static assets or simple GETs without params
            if url.endswith((".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg")):
                return
                
        self.captured_requests += 1
        log_success(f"[{self.captured_requests}] Captured {method} {url}")

        # Extract headers (especially cookies for authenticated scanning)
        headers = dict(flow.request.headers)
        if "Cookie" in headers:
            set_cookie(headers["Cookie"])

        # Parse form data or query parameters
        params = {}
        if flow.request.query:
            params.update(dict(flow.request.query))
            
        if method in ["POST", "PUT"] and flow.request.urlencoded_form:
            params.update(dict(flow.request.urlencoded_form))
        elif method in ["POST", "PUT"] and flow.request.content:
            try:
                # Try JSON body
                json_data = json.loads(flow.request.get_text())
                if isinstance(json_data, dict):
                    params.update(json_data)
            except ScanExceptions:
                pass
                
        # If we found actionable parameters, process them asynchronously
        if params:
            log_info(f"Target parameters found: {list(params.keys())}")
            # Dispatch to core engine for scanning
            threading.Thread(target=self._scan_captured_request, args=(url, method, params, headers)).start()

    def _scan_captured_request(self, url, method, params, headers):
        """Asynchronously forwards captured data to vulnerability modules"""
        # Import dynamically to avoid circular dependencies
        from core.engine import run_modules_async
        from bs4 import BeautifulSoup
        
        try:
            log_info(f"🔍 Automatically scanning captured endpoint: {urlparse(url).path}")
            
            # Since we captured a direct request, we simulate a dummy form for the engine payload injectors
            dummy_form = BeautifulSoup(f'<form action="{url}" method="{method}"></form>', 'html.parser').form
            for k in params.keys():
                dummy_input = BeautifulSoup(f'<input name="{k}" type="text">', 'html.parser').input
                dummy_form.append(dummy_input)
                
            # Default options equivalent to full scan
            options = {
                "xss": True,
                "sqli": True,
                "cmdi": True,
                "lfi": True,
                "ssti": True
            }
            
            # Use the global Config delay (removed unsupported `method` keyword)
            run_modules_async(url, [dummy_form], get_request_delay(), options)
            
        except ScanExceptions as e:
            log_error(f"Failed to scan intercepted request {url}: {e}")

# Addon registration for mitmdump
addons = []
if ctx:
    # Read scope from environment variable (mitmproxy limitation on direct args)
    target = os.environ.get("CYBERM4FIA_SCOPE", "")
    if target:
        addons.append(Cyberm4fiaInterceptor(target))

def _mitmdump_works() -> tuple[bool, str]:
    """Return (ok, message) — runs ``mitmdump --version`` and reports.

    Catches the passlib/bcrypt incompatibilities that crash mitmdump at
    import time on modern Python environments (bcrypt>=4.1 + passlib<1.8
    raises ``ValueError: password cannot be longer than 72 bytes``).
    """
    import subprocess
    try:
        result = subprocess.run(
            ["mitmdump", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except FileNotFoundError:
        return False, "mitmdump executable not found — pip install mitmproxy"
    except subprocess.TimeoutExpired:
        return False, "mitmdump --version timed out"
    except OSError as exc:  # noqa: BLE001
        return False, f"mitmdump launch error: {exc}"

    if result.returncode == 0:
        return True, ""

    # Most common: passlib/bcrypt incompatibility. Surface a one-line fix.
    err = (result.stderr or "") + (result.stdout or "")
    if "bcrypt" in err and ("72 bytes" in err or "has no attribute" in err):
        return False, (
            "mitmdump crashes on startup due to a passlib/bcrypt version "
            "mismatch. Fix: `pip install 'bcrypt<4.1'` (or upgrade passlib "
            "to a release that ships the bcrypt-72-byte truncation patch)."
        )
    snippet = err.strip().splitlines()[-1] if err.strip() else f"exit code {result.returncode}"
    return False, f"mitmdump unavailable: {snippet}"


def start_proxy(listen_port=8081, scope=""):
    """Launch the proxy via mitmdump in a subprocess"""
    import subprocess
    import socket

    if not scope:
        log_error("A target scope (e.g. wisarc.com) must be provided for the proxy to avoid scanning everything.")
        return

    # Pre-flight: refuse to launch the proxy if mitmdump itself is broken.
    # Without this guard, the user sees a full passlib traceback dumped into
    # the middle of the scan output even though the proxy never starts.
    ok, reason = _mitmdump_works()
    if not ok:
        log_warning(f"Proxy interceptor disabled — {reason}")
        log_info("Scan will continue without the MITM proxy.")
        return

    def is_port_in_use(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('127.0.0.1', port)) == 0

    original_port = listen_port
    while is_port_in_use(listen_port):
        listen_port += 1

    if listen_port != original_port:
        log_warning(f"Port {original_port} is in use. Falling back to port {listen_port}.")

    log_info(f"Starting mitmproxy on port {listen_port} (Scope: {scope})")
    log_warning("Configure your browser to use HTTP Proxy: 127.0.0.1:" + str(listen_port))

    env = os.environ.copy()
    env["CYBERM4FIA_SCOPE"] = scope
    env["PYTHONWARNINGS"] = "ignore"  # Suppress CryptographyDeprecationWarning + passlib chatter

    try:
        script_path = os.path.abspath(__file__)
        process = subprocess.Popen(
            ["mitmdump", "-s", script_path, "-p", str(listen_port), "--quiet"],
            env=env,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Filter the noisy passlib/bcrypt tracebacks but surface real errors.
        # Covers both the old AttributeError and the newer ValueError(72 bytes).
        def filter_stderr(pipe):
            in_passlib_tb = False
            for line in iter(pipe.readline, ''):
                if line == '':
                    break
                if "(trapped) error reading bcrypt version" in line:
                    continue
                if "Traceback (most recent call last):" in line:
                    in_passlib_tb = True
                    continue
                if in_passlib_tb:
                    if line.startswith(("AttributeError: module 'bcrypt'",
                                        "ValueError: password cannot be longer than 72 bytes")):
                        in_passlib_tb = False
                        continue
                    # Still inside the traceback frames — swallow.
                    if line.lstrip().startswith(("File \"", "return ", "import ", "from ",
                                                  "raise ", "self.", "cls.")):
                        continue
                    # Any other line ends the suppression window.
                    in_passlib_tb = False
                print(line, end='', file=sys.stderr)

        threading.Thread(target=filter_stderr, args=(process.stderr,), daemon=True).start()
        process.wait()
    except FileNotFoundError:
        log_error("mitmdump executable not found. Did you run pip install mitmproxy?")
    except KeyboardInterrupt:
        log_info("Proxy shutdown.")
