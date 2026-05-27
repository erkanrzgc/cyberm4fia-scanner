"""Tests for the NvidiaApiClient.generate() retry/backoff behaviour.

We stub ``httpx.post`` so the tests run offline. Verify:

* 200 → returns content with no retry, no sleep.
* 429 once then 200 → retries, honours Retry-After header, returns content.
* 5xx repeated → returns "" after exhausting attempts, no exception.
* 4xx other than 429 → returns "" without retrying.
* Timeout retries up to the cap then returns "".
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from utils.ai import NvidiaApiClient

pytestmark = pytest.mark.unit


def _make_response(status_code: int, body=None, headers=None):
    m = MagicMock(spec=httpx.Response)
    m.status_code = status_code
    m.headers = headers or {}
    m.text = "stub"
    if body is None:
        body = {"choices": [{"message": {"content": "hello"}}]}
    m.json.return_value = body
    return m


def _client():
    c = NvidiaApiClient.__new__(NvidiaApiClient)
    c.available = True
    c.api_key = "stub"
    c.model = "stub-model"
    c.base_url = "https://nim.local/v1"
    return c


class TestHappyPath:
    def test_200_returns_content_first_try(self):
        c = _client()
        with patch("utils.ai.httpx.post", return_value=_make_response(200)) as p:
            out = c.generate("hi")
        assert out == "hello"
        assert p.call_count == 1


class TestRateLimitRetry:
    def test_429_then_200_succeeds(self):
        c = _client()
        responses = [
            _make_response(429, headers={"Retry-After": "0"}),
            _make_response(200),
        ]
        with patch("utils.ai.httpx.post", side_effect=responses) as p, \
             patch("utils.ai.time.sleep") if False else patch("time.sleep"):
            out = c.generate("hi")
        assert out == "hello"
        assert p.call_count == 2

    def test_429_repeated_returns_empty(self):
        c = _client()
        responses = [_make_response(429, headers={"Retry-After": "0"})] * 5
        with patch("utils.ai.httpx.post", side_effect=responses) as p, \
             patch("time.sleep"):
            out = c.generate("hi")
        assert out == ""
        # Capped at _RETRY_MAX_ATTEMPTS
        assert p.call_count == NvidiaApiClient._RETRY_MAX_ATTEMPTS

    def test_retry_after_header_honoured(self):
        c = _client()
        responses = [
            _make_response(429, headers={"Retry-After": "1"}),
            _make_response(200),
        ]
        sleep_calls: list[float] = []
        with patch("utils.ai.httpx.post", side_effect=responses), \
             patch("time.sleep", side_effect=lambda s: sleep_calls.append(s)):
            c.generate("hi")
        # The first (and only) sleep should be ~1.0 from Retry-After
        assert sleep_calls
        assert sleep_calls[0] == pytest.approx(1.0)

    def test_retry_after_capped_at_30s(self):
        c = _client()
        responses = [
            _make_response(429, headers={"Retry-After": "99999"}),
            _make_response(200),
        ]
        sleep_calls: list[float] = []
        with patch("utils.ai.httpx.post", side_effect=responses), \
             patch("time.sleep", side_effect=lambda s: sleep_calls.append(s)):
            c.generate("hi")
        assert sleep_calls[0] <= 30.0

    def test_invalid_retry_after_falls_back_to_exponential(self):
        c = _client()
        responses = [
            _make_response(429, headers={"Retry-After": "garbage"}),
            _make_response(200),
        ]
        sleep_calls: list[float] = []
        with patch("utils.ai.httpx.post", side_effect=responses), \
             patch("time.sleep", side_effect=lambda s: sleep_calls.append(s)):
            c.generate("hi")
        # Exponential first delay = base_delay * 2**0 = 2.0
        assert sleep_calls[0] == pytest.approx(NvidiaApiClient._RETRY_BASE_DELAY)


class Test5xxRetry:
    def test_500_repeated_returns_empty_after_cap(self):
        c = _client()
        responses = [_make_response(503)] * 5
        with patch("utils.ai.httpx.post", side_effect=responses) as p, \
             patch("time.sleep"):
            out = c.generate("hi")
        assert out == ""
        assert p.call_count == NvidiaApiClient._RETRY_MAX_ATTEMPTS

    def test_503_then_200_succeeds(self):
        c = _client()
        responses = [_make_response(503), _make_response(200)]
        with patch("utils.ai.httpx.post", side_effect=responses) as p, \
             patch("time.sleep"):
            out = c.generate("hi")
        assert out == "hello"
        assert p.call_count == 2


class TestNonRetriable:
    def test_400_returns_empty_without_retry(self):
        c = _client()
        responses = [_make_response(400)]
        with patch("utils.ai.httpx.post", side_effect=responses) as p, \
             patch("time.sleep") as s:
            out = c.generate("hi")
        assert out == ""
        assert p.call_count == 1
        assert s.call_count == 0

    def test_401_returns_empty_without_retry(self):
        c = _client()
        responses = [_make_response(401)]
        with patch("utils.ai.httpx.post", side_effect=responses) as p, \
             patch("time.sleep") as s:
            out = c.generate("hi")
        assert out == ""
        assert p.call_count == 1
        assert s.call_count == 0


class TestTimeoutRetry:
    def test_timeout_repeated_returns_empty(self):
        c = _client()
        with patch(
            "utils.ai.httpx.post",
            side_effect=httpx.TimeoutException("slow"),
        ) as p, patch("time.sleep"):
            out = c.generate("hi")
        assert out == ""
        assert p.call_count == NvidiaApiClient._RETRY_MAX_ATTEMPTS

    def test_timeout_then_200_succeeds(self):
        c = _client()
        side = [httpx.TimeoutException("slow"), _make_response(200)]
        with patch("utils.ai.httpx.post", side_effect=side), patch("time.sleep"):
            out = c.generate("hi")
        assert out == "hello"


class TestUnavailable:
    def test_client_without_api_key_returns_empty(self):
        c = NvidiaApiClient.__new__(NvidiaApiClient)
        c.available = True
        c.api_key = None
        c.model = "stub"
        c.base_url = "stub"
        assert c.generate("hi") == ""

    def test_client_marked_unavailable_returns_empty(self):
        c = _client()
        c.available = False
        with patch("utils.ai.httpx.post") as p:
            assert c.generate("hi") == ""
        assert p.call_count == 0
