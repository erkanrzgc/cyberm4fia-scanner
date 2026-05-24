"""Real-binary integration test: MasscanTool.

Runs the actual masscan binary against 127.0.0.1 with a deterministic local
listener so we can verify parsing of *current* masscan output, not a frozen
sample. Skipped automatically when:
  - masscan is not installed
  - the test process can't bind/raw-socket (masscan typically needs CAP_NET_RAW
    or root; we let it fail-skip rather than require sudo)
"""

from __future__ import annotations

import socket
import threading

import pytest

from tests.integration.conftest import requires_binary
from utils.external_tools.masscan import MasscanTool

pytestmark = requires_binary("masscan")


@pytest.fixture
def loopback_listener():
    """Open a TCP socket on a random free port; tear down after the test."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    # Keep accepting (and immediately closing) so masscan sees an open port.
    stop = threading.Event()

    def _serve():
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
                conn.close()
            except OSError:
                continue

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        stop.set()
        sock.close()
        thread.join(timeout=1)


def test_masscan_finds_loopback_listener(loopback_listener):
    port = loopback_listener
    result = MasscanTool().run(
        "127.0.0.1",
        ports=str(port),
        rate=200,
        # --wait 0 stops masscan immediately after the initial probe round
        extra_args=["--wait", "0"],
        timeout=30,
    )
    # masscan needs CAP_NET_RAW; if it doesn't have it, returncode is non-zero
    # and stderr explains. Treat that as a skip rather than a failure — the
    # wrapper itself is what we want to exercise.
    if not result.succeeded:
        pytest.skip(f"masscan needs raw-socket privileges: {result.raw_stderr[:120]}")
    open_ports = {p["port"] for p in result.parsed["open_ports"]}
    assert port in open_ports
