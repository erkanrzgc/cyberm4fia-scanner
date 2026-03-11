"""
cyberm4fia-scanner — Session Manager

Save and resume scan state for long-running scans.

Usage:
    python3 scanner.py -u https://target.com --all --session scan1.json
    # (interrupted)
    python3 scanner.py --resume scan1.json
"""

import json
import os
from datetime import datetime
from utils.colors import log_info, log_success, log_warning


class ScanSession:
    """
    Manages scan state persistence.

    Saves:
        - Target URL and scan options
        - Scanned URLs (completed)
        - Discovered vulnerabilities
        - Scan progress metadata
    """

    def __init__(self, session_file: str = None):
        self.session_file = session_file
        self.data = {
            "version": "1.0",
            "created": datetime.now().isoformat(),
            "updated": datetime.now().isoformat(),
            "target": "",
            "mode": "",
            "options": {},
            "scanned_urls": [],
            "pending_urls": [],
            "vulnerabilities": [],
            "stats": {},
            "completed": False,
        }

    def save(self):
        """Save current session state to file."""
        if not self.session_file:
            return

        self.data["updated"] = datetime.now().isoformat()

        # Ensure directory exists
        os.makedirs(os.path.dirname(self.session_file) or ".", exist_ok=True)

        with open(self.session_file, "w") as f:
            json.dump(self.data, f, indent=2, default=str)

        log_info(f"Session saved: {self.session_file}")

    @classmethod
    def load(cls, session_file: str) -> "ScanSession":
        """Load a session from file."""
        if not os.path.isfile(session_file):
            log_warning(f"Session file not found: {session_file}")
            return cls(session_file)

        session = cls(session_file)
        with open(session_file, "r") as f:
            session.data = json.load(f)

        log_success(
            f"Session loaded: {session_file} "
            f"({len(session.data.get('scanned_urls', []))} URLs done, "
            f"{len(session.data.get('pending_urls', []))} pending)"
        )
        return session

    def set_target(self, url: str, mode: str, options: dict):
        """Set target info for this session."""
        self.data["target"] = url
        self.data["mode"] = mode
        # Filter out non-serializable values
        self.data["options"] = {
            k: v
            for k, v in options.items()
            if isinstance(v, (str, int, float, bool, list, type(None)))
        }

    def restore_config(self, default_options=None, override_options=None, override_keys=()):
        """Return target/mode/options restored from the session with optional overrides."""
        restored_options = dict(default_options or {})
        restored_options.update(self.data.get("options", {}))

        if override_options:
            for key in override_keys:
                if key in override_options:
                    restored_options[key] = override_options[key]

        return {
            "target": self.data.get("target", ""),
            "mode": self.data.get("mode", ""),
            "options": restored_options,
        }

    def mark_url_done(self, url: str):
        """Mark a URL as scanned."""
        if url not in self.data["scanned_urls"]:
            self.data["scanned_urls"].append(url)

    def is_url_done(self, url: str) -> bool:
        """Check if a URL has been scanned already."""
        return url in self.data["scanned_urls"]

    def add_pending_urls(self, urls: list):
        """Add URLs to the pending queue."""
        for url in urls:
            if (
                url not in self.data["pending_urls"]
                and url not in self.data["scanned_urls"]
            ):
                self.data["pending_urls"].append(url)

    def get_pending_urls(self) -> list:
        """Get URLs that haven't been scanned yet."""
        return [
            u for u in self.data["pending_urls"] if u not in self.data["scanned_urls"]
        ]

    def add_vulnerabilities(self, vulns: list):
        """Add discovered vulnerabilities."""
        self.data["vulnerabilities"].extend(vulns)

    def update_stats(self, stats: dict):
        """Update scan statistics."""
        self.data["stats"] = stats

    def mark_completed(self):
        """Mark scan as completed."""
        self.data["completed"] = True
        self.save()

    @property
    def active(self) -> bool:
        """Whether session persistence is active."""
        return self.session_file is not None

    @property
    def is_resume(self) -> bool:
        """Whether this is a resumed session with existing data."""
        return len(self.data.get("scanned_urls", [])) > 0
