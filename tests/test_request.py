"""
Tests for utils/request.py — Config, Stats, session management, User-Agent pool
"""

import sys
import os
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from utils.request import (
    BlockedTargetPath,
    Config,
    RequestBudgetExceeded,
    ScanCancelled,
    Stats,
    USER_AGENTS,
    _get_session,
    is_url_blocked,
    lock,
    normalize_proxy_url,
    restore_runtime_state,
    set_request_controls,
    set_proxy,
    snapshot_runtime_state,
    smart_request,
)


@pytest.fixture(autouse=True)
def reset_request_runtime():
    state = snapshot_runtime_state()
    yield
    restore_runtime_state(state)


class TestConfig:
    """Tests for Config class defaults and .env integration."""

    def test_default_delay(self):
        assert isinstance(Config.REQUEST_DELAY, float)
        assert Config.REQUEST_DELAY > 0

    def test_default_threads(self):
        assert isinstance(Config.THREADS, int)
        assert Config.THREADS > 0

    def test_default_max_retries(self):
        assert Config.MAX_RETRIES >= 1

    def test_verify_ssl_is_bool(self):
        assert isinstance(Config.VERIFY_SSL, bool)

    def test_shodan_api_key_is_string(self):
        assert isinstance(Config.SHODAN_API_KEY, str)

    def test_delay_modes(self):
        assert Config.QUICK_DELAY < Config.REQUEST_DELAY
        assert Config.REQUEST_DELAY < Config.STEALTH_DELAY

    def test_default_timeout_and_blacklist_shape(self):
        assert Config.DEFAULT_TIMEOUT > 0
        assert isinstance(Config.PATH_BLACKLIST, tuple)


class TestStats:
    """Tests for Stats class thread-safety."""

    def test_reset(self):
        Stats.total_requests = 100
        Stats.errors = 5
        Stats.reset()
        assert Stats.total_requests == 0
        assert Stats.errors == 0
        assert Stats.start_time is not None

    def test_thread_safe_increment(self):
        Stats.reset()
        errors = []

        def increment():
            try:
                for _ in range(100):
                    with lock:
                        Stats.total_requests += 1
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=increment) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert Stats.total_requests == 1000


class TestUserAgents:
    """Tests for User-Agent pool."""

    def test_minimum_count(self):
        assert len(USER_AGENTS) >= 20, f"Only {len(USER_AGENTS)} User-Agents, need 20+"

    def test_all_are_strings(self):
        for ua in USER_AGENTS:
            assert isinstance(ua, str)
            assert len(ua) > 30, f"User-Agent too short: {ua}"

    def test_has_mobile(self):
        mobile_uas = [ua for ua in USER_AGENTS if "Mobile" in ua]
        assert len(mobile_uas) >= 3, "Need at least 3 mobile User-Agents"

    def test_has_chrome(self):
        chrome_uas = [ua for ua in USER_AGENTS if "Chrome" in ua]
        assert len(chrome_uas) >= 4

    def test_has_firefox(self):
        firefox_uas = [ua for ua in USER_AGENTS if "Firefox" in ua]
        assert len(firefox_uas) >= 3

    def test_no_duplicates(self):
        assert len(USER_AGENTS) == len(set(USER_AGENTS)), "Duplicate User-Agents found"


class TestSession:
    """Tests for _get_session cache invalidation."""

    def test_session_created(self):
        session = _get_session(verify=False)
        assert session is not None

    def test_session_reused(self):
        s1 = _get_session(verify=False)
        s2 = _get_session(verify=False)
        assert s1 is s2

    def test_session_invalidated_on_verify_change(self):
        s1 = _get_session(verify=False)
        s2 = _get_session(verify=True)
        assert s1 is not s2
        # Cleanup
        _get_session(verify=False)


class TestRequestControls:
    def test_normalize_proxy_url_adds_http_scheme(self):
        assert normalize_proxy_url("127.0.0.1:8080") == "http://127.0.0.1:8080"
        assert (
            normalize_proxy_url("socks5://127.0.0.1:9050")
            == "socks5://127.0.0.1:9050"
        )

    def test_set_proxy_normalizes_runtime_proxy(self):
        set_proxy("127.0.0.1:8080")
        assert Config.PROXY == "http://127.0.0.1:8080"

    def test_path_blacklist_helper_matches_risky_paths(self):
        set_request_controls(path_blacklist="/logout,/checkout")

        assert is_url_blocked("https://example.com/logout") is True
        assert is_url_blocked("https://example.com/account") is False

    def test_smart_request_blocks_blacklisted_paths_before_network(self, monkeypatch):
        calls = []

        monkeypatch.setattr("utils.request._get_session", lambda **kwargs: calls.append(kwargs))
        set_request_controls(path_blacklist="/logout")

        with pytest.raises(BlockedTargetPath):
            smart_request("get", "https://example.com/logout", delay=0)

        assert calls == []

    def test_request_budget_raises_before_network(self, monkeypatch):
        Stats.reset()
        Stats.total_requests = 2
        set_request_controls(request_budget=2, path_blacklist="", cancel_event=None)

        with pytest.raises(RequestBudgetExceeded):
            smart_request("get", "https://example.com", delay=0)

    def test_cancelled_scan_raises_before_network(self, monkeypatch):
        event = threading.Event()
        event.set()
        set_request_controls(cancel_event=event, path_blacklist="")

        with pytest.raises(ScanCancelled):
            smart_request("get", "https://example.com", delay=0)
