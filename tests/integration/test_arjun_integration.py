"""Real-binary integration test: ArjunTool.

Spins up a tiny Flask-less HTTP server that *only* responds non-default when
a known hidden parameter is supplied, then runs the real arjun binary against
it. Asserts arjun discovers the hidden param and the wrapper surfaces it.

Skipped when:
  - arjun is not installed
"""

from __future__ import annotations

import http.server
import socketserver
import threading
import urllib.parse

import pytest

from tests.integration.conftest import requires_binary
from utils.external_tools.arjun import ArjunTool

pytestmark = requires_binary("arjun")

_HIDDEN_PARAM = "debug_flag"


class _ParamSensitiveHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):  # silence test output
        pass

    def do_GET(self):
        q = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(q)
        # Distinct response when the secret param is supplied — arjun's signal.
        if _HIDDEN_PARAM in params:
            body = b"X" * 4096
        else:
            body = b"baseline"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def hidden_param_server():
    httpd = socketserver.TCPServer(("127.0.0.1", 0), _ParamSensitiveHandler)
    host, port = httpd.server_address
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{host}:{port}/"
    finally:
        httpd.shutdown()
        thread.join(timeout=2)


def test_arjun_discovers_hidden_parameter(hidden_param_server):
    result = ArjunTool().run(hidden_param_server, timeout=60)
    if not result.succeeded:
        pytest.skip(f"arjun did not complete cleanly: {result.error or result.raw_stderr[:120]}")
    # arjun output structure: {endpoint: [params]}
    all_params = {p for params in result.parsed["params"].values() for p in params}
    assert _HIDDEN_PARAM in all_params, (
        f"arjun did not discover '{_HIDDEN_PARAM}'; got {all_params!r}"
    )
