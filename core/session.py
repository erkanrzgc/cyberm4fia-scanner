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
import tempfile
from datetime import datetime
from utils.colors import log_info, log_success, log_warning


class ScanSession:
    """
    Manages scan state persistence with hardened I/O.

    Features:
        - Atomic writes (temp file + rename) to prevent corruption on crash
        - Automatic backup before each save (.bak file)
        - Corruption recovery: falls back to .bak if main file is corrupt
        - Auto-checkpoint after every N scanned URLs
        - O(1) URL lookups via internal set
        - Vulnerability deduplication on add
    """

    CHECKPOINT_INTERVAL = 5  # auto-save every N URLs scanned

    def __init__(self, session_file: str = None):
        self.session_file = session_file
        self._scanned_set: set[str] = set()
        self._pending_set: set[str] = set()
        self._urls_since_save = 0
        self.data = {
            "version": "2.0",
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

    # ── Persistence ───────────────────────────────────────────────────────

    def save(self):
        """Save current session state atomically (temp + rename)."""
        if not self.session_file:
            return

        self.data["updated"] = datetime.now().isoformat()
        # Sync internal sets back to lists for serialization
        self.data["scanned_urls"] = sorted(self._scanned_set)
        self.data["pending_urls"] = sorted(self._pending_set - self._scanned_set)

        os.makedirs(os.path.dirname(self.session_file) or ".", exist_ok=True)

        # Backup existing file before overwrite
        if os.path.isfile(self.session_file):
            bak = self.session_file + ".bak"
            try:
                os.replace(self.session_file, bak)
            except OSError:
                pass

        # Atomic write: write to temp file in same dir, then rename
        dir_name = os.path.dirname(self.session_file) or "."
        try:
            fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp", prefix=".session_")
            with os.fdopen(fd, "w") as f:
                json.dump(self.data, f, indent=2, default=str)
            os.replace(tmp_path, self.session_file)
        except OSError as e:
            log_warning(f"Session save failed: {e}")
            # Clean up temp file if rename failed
            if os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            return

        self._urls_since_save = 0
        log_info(f"Session saved: {self.session_file}")

    @classmethod
    def load(cls, session_file: str) -> "ScanSession":
        """Load a session from file with corruption recovery."""
        session = cls(session_file)

        loaded = False
        # Try main file first, then .bak on failure
        for path in (session_file, session_file + ".bak"):
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "r") as f:
                    raw = f.read().strip()
                if not raw:
                    continue
                data = json.loads(raw)
                if not isinstance(data, dict):
                    continue
                session.data = data
                loaded = True
                if path != session_file:
                    log_warning(f"Main session corrupt — recovered from backup: {path}")
                break
            except (json.JSONDecodeError, OSError) as e:
                log_warning(f"Cannot read {path}: {e}")
                continue

        if loaded:
            # Rebuild internal sets from loaded lists
            session._scanned_set = set(session.data.get("scanned_urls", []))
            session._pending_set = set(session.data.get("pending_urls", []))

            log_success(
                f"Session loaded: {session_file} "
                f"({len(session._scanned_set)} URLs done, "
                f"{len(session._pending_set - session._scanned_set)} pending)"
            )
        else:
            if os.path.isfile(session_file) or os.path.isfile(session_file + ".bak"):
                log_warning(f"Session file(s) corrupt — starting fresh: {session_file}")
            else:
                log_warning(f"Session file not found: {session_file}")

        return session

    # ── Target / config ───────────────────────────────────────────────────

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

    # ── URL tracking ──────────────────────────────────────────────────────

    def mark_url_done(self, url: str):
        """Mark a URL as scanned and auto-checkpoint if interval reached."""
        self._scanned_set.add(url)
        self._urls_since_save += 1
        if self._urls_since_save >= self.CHECKPOINT_INTERVAL and self.session_file:
            self.save()

    def is_url_done(self, url: str) -> bool:
        """Check if a URL has been scanned already. O(1)."""
        return url in self._scanned_set

    def add_pending_urls(self, urls: list):
        """Add URLs to the pending queue."""
        for url in urls:
            if url not in self._scanned_set:
                self._pending_set.add(url)

    def get_pending_urls(self) -> list:
        """Get URLs that haven't been scanned yet."""
        return sorted(self._pending_set - self._scanned_set)

    # ── Vulnerabilities ───────────────────────────────────────────────────

    def add_vulnerabilities(self, vulns: list):
        """Add discovered vulnerabilities with deduplication."""
        existing = {
            (v.get("type"), v.get("url"), v.get("payload"), v.get("param"), v.get("field"))
            for v in self.data["vulnerabilities"]
        }
        for v in vulns:
            key = (v.get("type"), v.get("url"), v.get("payload"), v.get("param"), v.get("field"))
            if key not in existing:
                self.data["vulnerabilities"].append(v)
                existing.add(key)

    # ── Stats / completion ────────────────────────────────────────────────

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
        return len(self._scanned_set) > 0
