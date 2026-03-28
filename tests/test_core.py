"""
Tests for core/scope.py and core/session.py
"""

import os
import json
import tempfile

from core.scope import ScopeFilter
from core.session import ScanSession

class TestScopeFilter:
    """Tests for URL scope filtering."""

    def test_empty_scope_allows_all(self):
        scope = ScopeFilter()
        assert scope.is_allowed("https://anything.com/page")
        assert not scope.active

    def test_include_domain(self):
        scope = ScopeFilter(include=["*.example.com"])
        assert scope.is_allowed("https://app.example.com/login")
        assert scope.is_allowed("https://api.example.com/v1")
        assert not scope.is_allowed("https://evil.com/xss")

    def test_include_exact_domain(self):
        scope = ScopeFilter(include=["example.com"])
        assert scope.is_allowed("https://example.com/page")
        assert not scope.is_allowed("https://sub.example.com/page")

    def test_exclude_path(self):
        scope = ScopeFilter(exclude=["/logout", "/static/*"])
        assert scope.is_allowed("https://example.com/login")
        assert not scope.is_allowed("https://example.com/logout")
        assert not scope.is_allowed("https://example.com/static/js/app.js")

    def test_exclude_extension(self):
        scope = ScopeFilter(exclude=["*.pdf", "*.jpg"])
        assert scope.is_allowed("https://example.com/page.html")
        assert not scope.is_allowed("https://example.com/doc.pdf")
        assert not scope.is_allowed("https://example.com/img.jpg")

    def test_combined_scope(self):
        scope = ScopeFilter(include=["*.target.com"], exclude=["/logout", "*.pdf"])
        assert scope.is_allowed("https://app.target.com/dashboard")
        assert not scope.is_allowed("https://evil.com/page")  # Not in scope
        assert not scope.is_allowed("https://app.target.com/logout")  # Excluded
        assert not scope.is_allowed("https://app.target.com/doc.pdf")  # Excluded

    def test_filter_urls(self):
        scope = ScopeFilter(include=["*.example.com"])
        urls = [
            "https://app.example.com/a",
            "https://evil.com/b",
            "https://api.example.com/c",
        ]
        filtered = scope.filter_urls(urls)
        assert len(filtered) == 2
        assert "https://evil.com/b" not in filtered

    def test_stats(self):
        scope = ScopeFilter(include=["*.example.com"])
        scope.is_allowed("https://app.example.com/a")
        scope.is_allowed("https://evil.com/b")
        assert scope.stats["allowed"] == 1
        assert scope.stats["blocked_scope"] == 1

    def test_active_property(self):
        assert not ScopeFilter().active
        assert ScopeFilter(include=["*.example.com"]).active
        assert ScopeFilter(exclude=["/logout"]).active

class TestScanSession:
    """Tests for scan session save/resume."""

    def test_new_session(self):
        session = ScanSession()
        assert not session.active
        assert not session.is_resume

    def test_session_with_file(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            session = ScanSession(f.name)
            assert session.active
            os.unlink(f.name)

    def test_set_target(self):
        session = ScanSession()
        session.set_target("https://example.com", "aggressive", {"xss": True})
        assert session.data["target"] == "https://example.com"
        assert session.data["mode"] == "aggressive"

    def test_url_tracking(self):
        session = ScanSession()
        session.mark_url_done("https://example.com/a")
        session.mark_url_done("https://example.com/b")
        assert session.is_url_done("https://example.com/a")
        assert not session.is_url_done("https://example.com/c")

    def test_pending_urls(self):
        session = ScanSession()
        session.add_pending_urls(
            [
                "https://example.com/a",
                "https://example.com/b",
                "https://example.com/c",
            ]
        )
        session.mark_url_done("https://example.com/a")
        pending = session.get_pending_urls()
        assert len(pending) == 2
        assert "https://example.com/a" not in pending

    def test_save_and_load(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            # Save
            session = ScanSession(path)
            session.set_target("https://example.com", "normal", {"xss": True})
            session.mark_url_done("https://example.com/page1")
            session.add_vulnerabilities(
                [{"type": "XSS_Param", "url": "https://example.com"}]
            )
            session.save()

            # Load
            loaded = ScanSession.load(path)
            assert loaded.data["target"] == "https://example.com"
            assert loaded.is_url_done("https://example.com/page1")
            assert len(loaded.data["vulnerabilities"]) == 1
            assert loaded.is_resume
        finally:
            os.unlink(path)

    def test_mark_completed(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            session = ScanSession(path)
            session.mark_completed()
            assert session.data["completed"]

            # Verify saved to file
            with open(path) as f:
                data = json.load(f)
            assert data["completed"]
        finally:
            os.unlink(path)

    def test_no_duplicate_pending(self):
        session = ScanSession()
        session.add_pending_urls(["a", "b", "c"])
        session.add_pending_urls(["b", "c", "d"])
        assert len(session.get_pending_urls()) == 4

    def test_atomic_save_creates_file(self):
        """Atomic write should produce a valid JSON file."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        os.unlink(path)  # start clean

        try:
            session = ScanSession(path)
            session.set_target("https://t.com", "normal", {})
            session.save()

            assert os.path.isfile(path)
            with open(path) as f:
                data = json.load(f)
            assert data["target"] == "https://t.com"
        finally:
            if os.path.isfile(path):
                os.unlink(path)
            bak = path + ".bak"
            if os.path.isfile(bak):
                os.unlink(bak)

    def test_backup_created_on_second_save(self):
        """Second save should create a .bak file."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        os.unlink(path)

        try:
            session = ScanSession(path)
            session.set_target("https://t.com", "normal", {})
            session.save()
            assert not os.path.isfile(path + ".bak")

            session.mark_url_done("https://t.com/a")
            session.save()
            assert os.path.isfile(path + ".bak")
        finally:
            for p in (path, path + ".bak"):
                if os.path.isfile(p):
                    os.unlink(p)

    def test_corruption_recovery_from_backup(self):
        """If main file is corrupt, load should recover from .bak."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            # Create a valid session and save twice to get a .bak
            session = ScanSession(path)
            session.set_target("https://t.com", "normal", {})
            session.mark_url_done("https://t.com/page1")
            session.save()  # first save
            session.mark_url_done("https://t.com/page2")
            session.save()  # second save creates .bak

            # Corrupt the main file
            with open(path, "w") as f:
                f.write("{corrupt json!!")

            loaded = ScanSession.load(path)
            assert loaded.data["target"] == "https://t.com"
            assert loaded.is_url_done("https://t.com/page1")
        finally:
            for p in (path, path + ".bak"):
                if os.path.isfile(p):
                    os.unlink(p)

    def test_auto_checkpoint(self):
        """After CHECKPOINT_INTERVAL URLs, session should auto-save."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        os.unlink(path)

        try:
            session = ScanSession(path)
            session.set_target("https://t.com", "normal", {})

            # Mark exactly CHECKPOINT_INTERVAL URLs
            for i in range(ScanSession.CHECKPOINT_INTERVAL):
                session.mark_url_done(f"https://t.com/page{i}")

            # File should exist now (auto-saved)
            assert os.path.isfile(path)
            with open(path) as f:
                data = json.load(f)
            assert len(data["scanned_urls"]) == ScanSession.CHECKPOINT_INTERVAL
        finally:
            for p in (path, path + ".bak"):
                if os.path.isfile(p):
                    os.unlink(p)

    def test_vuln_deduplication(self):
        """add_vulnerabilities should skip duplicates."""
        session = ScanSession()
        vuln = {"type": "XSS", "url": "https://t.com", "payload": "<script>", "param": "q", "field": "q"}
        session.add_vulnerabilities([vuln])
        session.add_vulnerabilities([vuln])  # duplicate
        session.add_vulnerabilities([dict(vuln, payload="<img>")])  # different payload

        assert len(session.data["vulnerabilities"]) == 2

    def test_load_nonexistent_file(self):
        """Loading a missing file should return a fresh session."""
        session = ScanSession.load("/tmp/nonexistent_session_xyz123.json")
        assert not session.is_resume
        assert session.data["target"] == ""

    def test_o1_url_lookup_performance(self):
        """is_url_done should be O(1) — set-based."""
        session = ScanSession()
        for i in range(1000):
            session.mark_url_done(f"https://t.com/{i}")
        assert session.is_url_done("https://t.com/500")
        assert not session.is_url_done("https://t.com/9999")

    def test_restore_config_merges_saved_options_with_explicit_overrides(self):
        session = ScanSession()
        session.set_target(
            "https://example.com",
            "stealth",
            {
                "xss": True,
                "threads": 1,
                "proxy_url": "http://saved:8080",
                "json_output": True,
            },
        )

        restored = session.restore_config(
            default_options={"xss": False, "threads": 10, "proxy_url": "", "json_output": False},
            override_options={"threads": 30, "proxy_url": "http://override:8080"},
            override_keys={"threads"},
        )

        assert restored["target"] == "https://example.com"
        assert restored["mode"] == "stealth"
        assert restored["options"]["xss"] is True
        assert restored["options"]["threads"] == 30
        assert restored["options"]["proxy_url"] == "http://saved:8080"
        assert restored["options"]["json_output"] is True
