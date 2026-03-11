"""
cyberm4fia-scanner - Scan runtime context helpers.
"""

from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
import os
import time
from typing import Any
from urllib.parse import urlparse

import utils.colors as color_utils
from utils.auth import auth_manager
from utils.colors import Colors, log_info, log_success
from utils.oob import OOBClient
from utils.request import (
    get_oob_client,
    get_runtime_stats,
    get_thread_count,
    is_json_output_enabled,
    reset_runtime_stats,
    restore_runtime_state,
    set_json_output_enabled,
    set_oob_client,
    set_request_controls,
    set_cookie,
    set_proxy,
    set_request_delay,
    set_thread_count,
    snapshot_runtime_state,
)


@dataclass
class ScanContext:
    """Isolates per-scan runtime state and filesystem metadata."""

    target_url: str
    mode: str
    delay: float
    options: dict = field(default_factory=dict)
    session_options: dict | None = None
    session: Any = None
    base_scan_dir: str = "scans"
    scan_suffix: str = ""
    target_host: str = field(init=False)
    safe_target: str = field(init=False)
    scan_dir: str = field(init=False)
    log_file: str = field(init=False)
    _owned_oob_client: Any = field(init=False, default=None, repr=False)

    def __post_init__(self):
        parsed = urlparse(self.target_url)
        self.target_host = parsed.hostname or parsed.netloc.split(":")[0]
        self.safe_target = self.target_host.replace(".", "_").replace(":", "_")
        scan_name = self.safe_target
        if self.scan_suffix:
            scan_name = f"{scan_name}_{self.scan_suffix}"
        self.scan_dir = os.path.join(self.base_scan_dir, scan_name)
        self.log_file = os.path.join(self.scan_dir, "scan.txt")

    def prepare_filesystem(self):
        """Ensure scan output directories and log file exist."""
        os.makedirs(self.scan_dir, exist_ok=True)
        color_utils.set_log_file(self.log_file)
        with open(self.log_file, "w", encoding="utf-8") as handle:
            handle.write(
                f"--- cyberm4fia-scanner Scan: {self.target_url} at {datetime.now()} ---\n"
            )

    def _apply_runtime_options(self):
        set_request_delay(self.delay)
        set_json_output_enabled(
            self.options.get("json_output", is_json_output_enabled())
        )
        set_thread_count(self.options.get("threads", get_thread_count()))

        proxy_url = self.options.get("proxy_url")
        if proxy_url:
            set_proxy(proxy_url)

        cookie = self.options.get("cookie")
        if cookie:
            set_cookie(cookie)

        set_request_controls(
            request_budget=self.options.get("max_requests"),
            max_host_concurrency=self.options.get("max_host_concurrency"),
            path_blacklist=self.options.get("path_blacklist"),
            default_timeout=self.options.get("request_timeout"),
            cancel_event=self.options.get("cancel_event"),
        )

        auth_state = self.options.get("auth_state")
        if auth_state:
            auth_manager.restore_state(auth_state)

        placeholder_auth = self.options.get("placeholder_auth")
        if placeholder_auth is not None:
            auth_manager.set_placeholder_auth(placeholder_auth)

        if self.options.get("oob"):
            listener_port = int(self.options.get("oob_listener_port", 9999))
            self._owned_oob_client = OOBClient(listener_port=listener_port)
            set_oob_client(self._owned_oob_client)
        else:
            set_oob_client(None)

    def prepare_urls_for_scan(self, urls_to_scan):
        """Attach session metadata and filter already scanned URLs."""
        if not self.session or not self.session.active:
            return urls_to_scan

        self.session.set_target(
            self.target_url,
            self.mode,
            self.session_options if self.session_options is not None else self.options,
        )
        self.session.add_pending_urls(urls_to_scan)

        if not self.session.is_resume:
            return urls_to_scan

        remaining = [url for url in urls_to_scan if not self.session.is_url_done(url)]
        log_info(f"Session resume: {len(remaining)} URLs remaining")
        return remaining

    def mark_url_done(self, url):
        """Persist completed URL progress when session storage is enabled."""
        if not self.session or not self.session.active:
            return

        self.session.mark_url_done(url)
        self.session.save()

    def finalize_session(self, vulnerabilities, finding_count):
        """Write final scan result back into the session file."""
        if not self.session or not self.session.active:
            return

        self.session.add_vulnerabilities(vulnerabilities)
        self.session.update_stats(self.report_stats(finding_count))
        self.session.mark_completed()

    def wait_for_oob_hits(self, wait_seconds=15):
        """Wait briefly for late OOB callbacks and return the newly observed hits."""
        oob_client = get_oob_client()
        if not oob_client or not getattr(oob_client, "ready", False):
            return []

        print(
            f"\n{Colors.BOLD}[*] Waiting {wait_seconds}s for late Out-of-Band (OOB) callbacks...{Colors.END}"
        )
        time.sleep(wait_seconds)
        hits = oob_client.poll()
        if hits:
            log_success(f"Processed {len(hits)} OOB hit(s)!")
        else:
            log_info("No OOB callbacks received.")
        return hits

    def _cleanup_owned_oob(self):
        """Tear down scan-local OOB resources before restoring outer state."""
        if self._owned_oob_client and get_oob_client() is self._owned_oob_client:
            try:
                self._owned_oob_client.stop()
            except Exception:
                pass
        self._owned_oob_client = None

    @contextmanager
    def activate(self, reset_stats=True):
        """Apply scan-local runtime config and restore globals afterwards."""
        runtime_state = snapshot_runtime_state()
        auth_state = auth_manager.snapshot_state()
        previous_oob_client = get_oob_client()
        previous_log_file = color_utils.LOG_FILE

        try:
            self.prepare_filesystem()
            self._apply_runtime_options()
            if reset_stats:
                reset_runtime_stats()
            yield self
        finally:
            self._cleanup_owned_oob()
            set_oob_client(previous_oob_client)
            auth_manager.restore_state(auth_state)
            restore_runtime_state(runtime_state)
            color_utils.set_log_file(previous_log_file)

    def collect_stats(self, vulnerability_count=None):
        """Return verbose scan stats for reports/API."""
        runtime_stats = get_runtime_stats()
        stats = {
            "total_requests": runtime_stats["total_requests"],
            "vulnerabilities": (
                vulnerability_count
                if vulnerability_count is not None
                else runtime_stats["vulnerabilities_found"]
            ),
            "waf_blocks": runtime_stats["waf_blocks"],
            "errors": runtime_stats["errors"],
            "retries": runtime_stats["retries"],
        }

        if runtime_stats["start_time"]:
            stats["duration_seconds"] = round(
                time.time() - runtime_stats["start_time"], 2
            )

        return stats

    def report_stats(self, vulnerability_count):
        """Return compact stats for JSON/session exporters."""
        runtime_stats = get_runtime_stats()
        return {
            "requests": runtime_stats["total_requests"],
            "vulns": vulnerability_count,
            "waf": runtime_stats["waf_blocks"],
            "errors": runtime_stats["errors"],
            "retries": runtime_stats["retries"],
        }
