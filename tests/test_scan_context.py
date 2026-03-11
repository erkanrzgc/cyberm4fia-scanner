"""
Tests for core/scan_context.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import utils.colors as color_utils
from core.scan_context import ScanContext
from core.session import ScanSession
from utils.auth import auth_manager
from utils.request import (
    Config,
    Stats,
    _get_session,
    _global_headers,
    restore_runtime_state,
    set_cookie,
    snapshot_runtime_state,
)


class TestScanContext:
    def setup_method(self):
        self.runtime_state = snapshot_runtime_state()
        self.previous_log_file = color_utils.LOG_FILE
        self.auth_state = auth_manager.snapshot_state()
        self.previous_oob_client = Config.OOB_CLIENT

    def teardown_method(self):
        restore_runtime_state(self.runtime_state)
        auth_manager.restore_state(self.auth_state)
        Config.OOB_CLIENT = self.previous_oob_client
        color_utils.set_log_file(self.previous_log_file)

    def test_activate_prepares_scan_dir_and_log_file(self, tmp_path):
        ctx = ScanContext(
            "https://app.example.com:8443/login",
            "quick",
            0.2,
            base_scan_dir=str(tmp_path),
        )

        assert ctx.target_host == "app.example.com"
        assert ctx.safe_target == "app_example_com"

        with ctx.activate():
            assert os.path.isdir(ctx.scan_dir)
            assert color_utils.LOG_FILE == ctx.log_file
            assert Config.REQUEST_DELAY == 0.2
            assert Stats.start_time is not None

        with open(ctx.log_file, "r", encoding="utf-8") as handle:
            assert "cyberm4fia-scanner Scan:" in handle.read()

    def test_activate_restores_runtime_state(self, tmp_path):
        color_utils.set_log_file(str(tmp_path / "previous.log"))
        Config.PROXY = "http://old-proxy:8080"
        Config.REQUEST_DELAY = 1.5
        Config.JSON_OUTPUT = False
        Config.THREADS = 12
        Config.DEFAULT_TIMEOUT = 11
        Config.REQUEST_BUDGET = 0
        Config.MAX_HOST_CONCURRENCY = 0
        set_cookie("original=1")

        ctx = ScanContext(
            "http://example.com",
            "quick",
            0.25,
            options={
                "cookie": "scan=1",
                "proxy_url": "http://scan-proxy:9090",
                "json_output": True,
                "threads": 99,
                "request_timeout": 4.5,
                "max_requests": 150,
                "max_host_concurrency": 2,
                "path_blacklist": "/logout,/checkout",
            },
            base_scan_dir=str(tmp_path),
        )

        with ctx.activate():
            assert Config.PROXY == "http://scan-proxy:9090"
            assert Config.REQUEST_DELAY == 0.25
            assert Config.JSON_OUTPUT is True
            assert Config.THREADS == 99
            assert Config.DEFAULT_TIMEOUT == 4.5
            assert Config.REQUEST_BUDGET == 150
            assert Config.MAX_HOST_CONCURRENCY == 2
            assert Config.PATH_BLACKLIST == ("/logout", "/checkout")
            assert _global_headers["Cookie"] == "scan=1"
            assert _get_session().headers["Cookie"] == "scan=1"

        assert Config.PROXY == "http://old-proxy:8080"
        assert Config.REQUEST_DELAY == 1.5
        assert Config.JSON_OUTPUT is False
        assert Config.THREADS == 12
        assert Config.DEFAULT_TIMEOUT == 11
        assert Config.REQUEST_BUDGET == 0
        assert Config.MAX_HOST_CONCURRENCY == 0
        assert _global_headers["Cookie"] == "original=1"
        assert _get_session().headers["Cookie"] == "original=1"
        assert color_utils.LOG_FILE == str(tmp_path / "previous.log")

    def test_stats_helpers_return_expected_shapes(self, tmp_path):
        ctx = ScanContext(
            "http://example.com",
            "normal",
            0.5,
            base_scan_dir=str(tmp_path),
        )

        Stats.reset()
        Stats.total_requests = 7
        Stats.waf_blocks = 2
        Stats.errors = 1
        Stats.retries = 3

        verbose = ctx.collect_stats(vulnerability_count=4)
        compact = ctx.report_stats(4)

        assert verbose["total_requests"] == 7
        assert verbose["vulnerabilities"] == 4
        assert verbose["waf_blocks"] == 2
        assert verbose["errors"] == 1
        assert verbose["retries"] == 3
        assert "duration_seconds" in verbose

        assert compact == {
            "requests": 7,
            "vulns": 4,
            "waf": 2,
            "errors": 1,
            "retries": 3,
        }

    def test_activate_restores_auth_and_oob_state(self, tmp_path, monkeypatch):
        class DummyOOB:
            instances = []

            def __init__(self, listener_port=9999):
                self.listener_port = listener_port
                self.ready = True
                self.stopped = False
                self.poll_calls = 0
                DummyOOB.instances.append(self)

            def poll(self):
                self.poll_calls += 1
                return [{"path": "/xss"}]

            def stop(self):
                self.stopped = True

        monkeypatch.setattr("core.scan_context.OOBClient", DummyOOB)

        previous_oob = object()
        Config.OOB_CLIENT = previous_oob
        auth_manager.set_bearer_token("outer-token")
        auth_manager.set_placeholder_auth({"headers": {"X-Outer": "1"}})

        ctx = ScanContext(
            "http://example.com",
            "quick",
            0.25,
            options={
                "oob": True,
                "oob_listener_port": 7777,
                "auth_state": {
                    "auth_type": "custom_header",
                    "credentials": {"name": "X-Scan-Token", "value": "scan-token"},
                    "placeholder_auth": {"headers": {"X-Scan": "1"}},
                },
            },
            base_scan_dir=str(tmp_path),
        )

        with ctx.activate():
            current_oob = Config.OOB_CLIENT
            headers = {}
            kwargs = {}
            auth_manager.inject_auth(headers, kwargs)

            assert isinstance(current_oob, DummyOOB)
            assert current_oob.listener_port == 7777
            assert headers["X-Scan-Token"] == "scan-token"
            assert headers["X-Scan"] == "1"
            assert ctx.wait_for_oob_hits(wait_seconds=0) == [{"path": "/xss"}]
            assert current_oob.poll_calls == 1

        headers = {}
        kwargs = {}
        auth_manager.inject_auth(headers, kwargs)
        assert Config.OOB_CLIENT is previous_oob
        assert DummyOOB.instances[0].stopped is True
        assert headers["Authorization"] == "Bearer outer-token"
        assert headers["X-Outer"] == "1"

    def test_session_helpers_resume_and_finalize(self, tmp_path):
        session_path = tmp_path / "scan.json"
        session = ScanSession(str(session_path))
        session.mark_url_done("http://example.com/done")
        session.save()

        ctx = ScanContext(
            "http://example.com",
            "normal",
            0.5,
            options={"threads": 10},
            session_options={"xss": True, "threads": 10},
            session=session,
            base_scan_dir=str(tmp_path),
        )

        pending = ctx.prepare_urls_for_scan(
            [
                "http://example.com/done",
                "http://example.com/new",
            ]
        )

        assert pending == ["http://example.com/new"]

        Stats.reset()
        Stats.total_requests = 3
        ctx.mark_url_done("http://example.com/new")
        ctx.finalize_session(
            [{"type": "XSS_Param", "url": "http://example.com/new"}],
            1,
        )

        loaded = ScanSession.load(str(session_path))
        assert loaded.data["target"] == "http://example.com"
        assert loaded.data["mode"] == "normal"
        assert loaded.is_url_done("http://example.com/new")
        assert loaded.data["stats"]["requests"] == 3
        assert loaded.data["stats"]["vulns"] == 1
        assert loaded.data["completed"] is True
