"""
cyberm4fia-scanner - Reverse Shell Listener
TCP listener that catches incoming reverse shell connections and provides
an interactive PTY-like session.
"""

import os
import sys
import select
import socket
import threading
import termios
import tty

from utils.colors import Colors, log_info, log_success, log_warning, log_error
from utils.request import ScanExceptions


class ReverseShellListener:
    """
    TCP listener that accepts a single reverse shell connection and
    provides raw bidirectional I/O (interactive TTY).
    """

    def __init__(self, host="0.0.0.0", port=4444, timeout=120):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._server_sock = None
        self._client_sock = None
        self._client_addr = None
        self._running = False
        self._connected = threading.Event()

    # ── Lifecycle ────────────────────────────────────────────────────────

    def start(self):
        """Bind and listen in a background thread, wait for one connection."""
        try:
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.settimeout(self.timeout)
            self._server_sock.bind((self.host, self.port))
            self._server_sock.listen(1)
            self._running = True
            log_success(f"Reverse-shell listener started on {self.host}:{self.port}")
            log_info(f"Waiting up to {self.timeout}s for incoming connection …")
        except OSError as exc:
            log_error(f"Cannot bind listener on port {self.port}: {exc}")
            return False

        accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        accept_thread.start()
        return True

    def _accept_loop(self):
        """Accept a single connection, then signal _connected event."""
        try:
            self._client_sock, self._client_addr = self._server_sock.accept()
            self._client_sock.setblocking(False)
            log_success(
                f"Connection received from {self._client_addr[0]}:{self._client_addr[1]}"
            )
            self._connected.set()
        except socket.timeout:
            log_warning("Listener timed out — no connection received.")
            self._running = False
        except OSError:
            # Socket was closed externally (stop() called)
            pass

    def wait_for_connection(self, timeout=None):
        """Block until a shell connects or timeout expires."""
        wait = timeout or self.timeout
        return self._connected.wait(timeout=wait)

    # ── Interactive session ──────────────────────────────────────────────

    def interact(self):
        """
        Drop into a raw-terminal interactive session with the remote shell.
        Ctrl-C sends to the remote; Ctrl-] exits the session locally.
        """
        if not self._client_sock:
            log_error("No active connection to interact with.")
            return

        print(
            f"\n{Colors.GREEN}{Colors.BOLD}"
            f"╔══════════════════════════════════════════╗\n"
            f"║     REVERSE SHELL SESSION ESTABLISHED    ║\n"
            f"╚══════════════════════════════════════════╝{Colors.END}"
        )
        print(
            f"  Remote: {self._client_addr[0]}:{self._client_addr[1]}\n"
            f"  Press {Colors.YELLOW}Ctrl+]{Colors.END} to detach.\n"
        )

        # Save and modify terminal settings
        old_settings = termios.tcgetattr(sys.stdin)
        try:
            tty.setraw(sys.stdin)
            self._io_loop()
        except ScanExceptions:
            pass
        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
            print(f"\n{Colors.YELLOW}[*] Session detached.{Colors.END}")

    def _io_loop(self):
        """Bidirectional I/O: stdin → socket, socket → stdout."""
        DETACH = b"\x1d"  # Ctrl-]

        while self._running:
            readable, _, _ = select.select(
                [sys.stdin, self._client_sock], [], [], 0.5
            )

            for src in readable:
                if src is sys.stdin:
                    data = os.read(sys.stdin.fileno(), 4096)
                    if not data or data == DETACH:
                        return
                    try:
                        self._client_sock.sendall(data)
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        log_error("Remote connection lost.")
                        return

                elif src is self._client_sock:
                    try:
                        data = self._client_sock.recv(4096)
                        if not data:
                            log_warning("Remote shell closed the connection.")
                            return
                        sys.stdout.buffer.write(data)
                        sys.stdout.buffer.flush()
                    except BlockingIOError:
                        continue
                    except (ConnectionResetError, OSError):
                        log_error("Remote connection lost.")
                        return

    # ── Cleanup ──────────────────────────────────────────────────────────

    def stop(self):
        """Close all sockets."""
        self._running = False
        if self._client_sock:
            try:
                self._client_sock.close()
            except OSError:
                pass
            self._client_sock = None

        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None

    @property
    def connected(self):
        return self._connected.is_set()


def start_reverse_listener(port=4444, timeout=120):
    """Convenience function — start listener and return the instance."""
    listener = ReverseShellListener(port=port, timeout=timeout)
    if listener.start():
        return listener
    return None
