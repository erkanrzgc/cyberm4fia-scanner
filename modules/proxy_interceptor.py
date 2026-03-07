"""
cyberm4fia-scanner - OWASP ZAP Alternative (Proxy Interceptor Module)
Acts as a local MITM proxy to capture browser traffic and forward it to scanning modules.

Requirement: pip install mitmproxy
"""

import os
import sys
import threading
from urllib.parse import urlparse
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.colors import log_info, log_success, log_warning, log_error
from utils.request import Config, _global_headers

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
            _global_headers["Cookie"] = headers["Cookie"]

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
            except Exception:
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
            run_modules_async(url, [dummy_form], Config.REQUEST_DELAY, options)
            
        except Exception as e:
            log_error(f"Failed to scan intercepted request {url}: {e}")

# Addon registration for mitmdump
addons = []
if ctx:
    # Read scope from environment variable (mitmproxy limitation on direct args)
    target = os.environ.get("CYBERM4FIA_SCOPE", "")
    if target:
        addons.append(Cyberm4fiaInterceptor(target))

def start_proxy(listen_port=8081, scope=""):
    """Launch the proxy via mitmdump in a subprocess"""
    import subprocess
    import socket
    
    if not scope:
        log_error("A target scope (e.g. wisarc.com) must be provided for the proxy to avoid scanning everything.")
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
    env["PYTHONWARNINGS"] = "ignore" # Suppresses CryptographyDeprecationWarning and passlib/bcrypt AttributeErrors
    
    try:
        # Run mitmdump and filter stderr to swallow passlib/bcrypt tracebacks
        script_path = os.path.abspath(__file__)
        process = subprocess.Popen(
            ["mitmdump", "-s", script_path, "-p", str(listen_port), "--quiet"],
            env=env,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Thread to process stderr and filter out the annoying traceback
        def filter_stderr(pipe):
            skip_traceback = False
            for line in iter(pipe.readline, ''):
                if line == '':
                    break
                if "(trapped) error reading bcrypt version" in line or "Traceback (most recent call last):" in line and "passlib" in line:
                    skip_traceback = True
                
                if skip_traceback:
                    if line.startswith("AttributeError: module 'bcrypt' has no attribute"):
                        skip_traceback = False # End of traceback
                    continue
                
                # Print any other legitimate errors
                print(line, end='', file=sys.stderr)
                
        threading.Thread(target=filter_stderr, args=(process.stderr,), daemon=True).start()
        process.wait()
    except FileNotFoundError:
        log_error("mitmdump executable not found. Did you run pip install mitmproxy?")
    except KeyboardInterrupt:
        log_info("Proxy shutdown.")
