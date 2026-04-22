"""
cyberm4fia-scanner - HTTP Request Utilities
"""

import os
import json
import fnmatch
import httpx
import time
import random
import threading
from urllib.parse import urlparse

class RequestControlError(RuntimeError):
    """Base class for scan/runtime request guardrails."""

class RequestBudgetExceeded(RequestControlError):
    """Raised when the configured per-scan request budget is exhausted."""

class ScanCancelled(RequestControlError):
    """Raised when a running scan has been cancelled."""

class BlockedTargetPath(RequestControlError):
    """Raised when a request targets a risky blacklisted path."""

# Network/HTTP exceptions — use when wrapping smart_request or httpx calls.
NetworkExceptions = (
    httpx.RequestError,
    httpx.HTTPStatusError,
    httpx.TimeoutException,
)

# Scan-module exceptions — for top-level module wrappers that must never crash
# the pipeline. Intentionally broader than NetworkExceptions, but excludes
# programming errors (AttributeError, NameError, RecursionError) so real bugs
# still surface.
ScanExceptions = (
    httpx.RequestError,
    httpx.HTTPStatusError,
    httpx.TimeoutException,
    json.JSONDecodeError,
    UnicodeError,
    OSError,
    BlockedTargetPath,
)

# Legacy alias kept for backward compatibility with any external importers.
# New code should prefer NetworkExceptions or ScanExceptions explicitly.
ScanNetworkExceptions = NetworkExceptions

# Load .env file if python-dotenv is available
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

from utils.auth import auth_manager  # noqa: E402
from utils.waf import waf_detector  # noqa: E402

# Thread-local storage for sessions
_thread_local = threading.local()
_global_headers = {}
_host_semaphores = {}
lock = threading.Lock()


class HostRateLimiter:
    """Per-host rate limiting with adaptive backoff.

    Tracks separate delay values per host so a 429 from host-A
    doesn't slow down requests to host-B.
    """

    def __init__(self):
        self._host_delays: dict[str, float] = {}
        self._lock = threading.Lock()

    def get_delay(self, url: str) -> float:
        """Return the delay for the host in *url*, falling back to the global default."""
        host = urlparse(url).netloc or ""
        with self._lock:
            return self._host_delays.get(host, Config.REQUEST_DELAY)

    def bump_delay(self, url: str, factor: float = 1.5, ceiling: float = 5.0):
        """Increase the delay for a specific host (e.g. after a 429)."""
        host = urlparse(url).netloc or ""
        with self._lock:
            current = self._host_delays.get(host, Config.REQUEST_DELAY)
            self._host_delays[host] = min(current * factor, ceiling)
            return self._host_delays[host]

    def set_delay(self, url: str, value: float):
        """Set an explicit delay for a host."""
        host = urlparse(url).netloc or ""
        with self._lock:
            self._host_delays[host] = float(value)

    def set_minimum(self, url: str, minimum: float):
        """Ensure a host's delay is at least *minimum*."""
        host = urlparse(url).netloc or ""
        with self._lock:
            current = self._host_delays.get(host, Config.REQUEST_DELAY)
            if current < minimum:
                self._host_delays[host] = minimum

    def reset(self):
        """Clear all per-host delays."""
        with self._lock:
            self._host_delays.clear()

    def snapshot(self) -> dict[str, float]:
        """Return a copy of all per-host delays."""
        with self._lock:
            return dict(self._host_delays)

    def restore(self, data: dict[str, float]):
        """Restore per-host delays from a snapshot."""
        with self._lock:
            self._host_delays.clear()
            self._host_delays.update(data)


# Module-level singleton
host_rate_limiter = HostRateLimiter()


# Request control exceptions have been moved up


def _reset_session():
    """Drop the cached thread-local session so new config is applied cleanly."""
    if hasattr(_thread_local, "session"):
        try:
            _thread_local.session.close()
        except Exception:
            pass

    for attr in ("session", "_verify", "_proxy"):
        if hasattr(_thread_local, attr):
            delattr(_thread_local, attr)


def _get_session(verify=False, proxies=None):
    """Get or create a thread-local httpx Client with HTTP/2 support"""
    # Invalidate cached session if verify or proxy config changed
    needs_new = not hasattr(_thread_local, "session")
    if not needs_new:
        if (
            getattr(_thread_local, "_verify", None) != verify
            or getattr(_thread_local, "_proxy", None) != proxies
        ):
            _thread_local.session.close()
            needs_new = True

    if needs_new:
        _thread_local.session = httpx.Client(
            http2=True,
            verify=verify,
            proxy=proxies,
            follow_redirects=False,  # We control this per-request
            limits=httpx.Limits(max_keepalive_connections=50, max_connections=100),
        )
        _thread_local._verify = verify
        _thread_local._proxy = proxies
        if _global_headers:
            _thread_local.session.headers.update(_global_headers)
    return _thread_local.session


# Configuration (reads from .env if available)
class Config:
    REQUEST_DELAY = float(os.environ.get("DEFAULT_DELAY", "0.5"))
    STEALTH_DELAY = 3
    QUICK_DELAY = 0.2
    RANDOM_DELAY = False
    PROXY = os.environ.get("HTTP_PROXY") or os.environ.get("SOCKS5_PROXY")
    VERBOSE = True
    JSON_OUTPUT = False
    THREADS = int(os.environ.get("DEFAULT_THREADS", "10"))
    MAX_RETRIES = 2
    DEFAULT_TIMEOUT = float(os.environ.get("DEFAULT_TIMEOUT", "10"))
    VERIFY_SSL = os.environ.get("VERIFY_SSL", "false").lower() == "true"
    OOB_CLIENT = None
    SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
    REQUEST_BUDGET = int(os.environ.get("REQUEST_BUDGET", "0"))
    MAX_HOST_CONCURRENCY = int(os.environ.get("MAX_HOST_CONCURRENCY", "0"))
    PATH_BLACKLIST = tuple(
        part.strip()
        for part in os.environ.get(
            "PATH_BLACKLIST",
            "/logout,/signout,/delete,/remove,/destroy,/reset,/terminate,/deactivate,/checkout,/payment",
        ).split(",")
        if part.strip()
    )
    CANCEL_EVENT = None


USER_AGENTS = [
    # Chrome Desktop
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Firefox Desktop
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    # Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    # Mobile Chrome
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.134 Mobile Safari/537.36",
    # Mobile Safari (iPhone)
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
    # Opera
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    # Brave
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Brave/120",
    # Vivaldi
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.5",
    # Older browsers (for diversity)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
]


class Stats:
    total_requests = 0
    vulnerabilities_found = 0
    waf_blocks = 0
    errors = 0
    retries = 0
    start_time = None

    @classmethod
    def reset(cls):
        with lock:
            cls.total_requests = 0
            cls.vulnerabilities_found = 0
            cls.waf_blocks = 0
            cls.errors = 0
            cls.retries = 0
            cls.start_time = time.time()


def get_request_delay():
    """Return the active per-request delay."""
    return Config.REQUEST_DELAY


def set_request_delay(delay):
    """Update the active per-request delay."""
    Config.REQUEST_DELAY = float(delay)


def get_stealth_delay():
    """Return the configured stealth-mode delay."""
    return Config.STEALTH_DELAY


def use_random_delay():
    """Return whether randomized backoff is enabled."""
    return Config.RANDOM_DELAY


def get_proxy():
    """Return the active outbound proxy, if any."""
    return normalize_proxy_url(Config.PROXY)


def get_thread_count():
    """Return the active worker/thread count."""
    return Config.THREADS


def set_thread_count(threads):
    """Update the active worker/thread count."""
    Config.THREADS = int(threads)


def get_default_timeout():
    """Return the active request timeout."""
    return Config.DEFAULT_TIMEOUT


def get_max_retries():
    """Return the active retry count for requests."""
    return Config.MAX_RETRIES


def is_ssl_verification_enabled():
    """Return whether SSL verification is enabled."""
    return Config.VERIFY_SSL


def is_json_output_enabled():
    """Return whether JSON output is enabled."""
    return Config.JSON_OUTPUT


def set_json_output_enabled(enabled):
    """Update JSON output mode."""
    Config.JSON_OUTPUT = bool(enabled)


def get_path_blacklist():
    """Return the configured risky-path blacklist."""
    return tuple(Config.PATH_BLACKLIST)


def get_oob_client():
    """Return the active out-of-band interaction client, if any."""
    return Config.OOB_CLIENT


def set_oob_client(client):
    """Update the active out-of-band interaction client."""
    Config.OOB_CLIENT = client


def get_global_headers():
    """Return a copy of globally applied request headers."""
    return dict(_global_headers)


def get_runtime_stats():
    """Return a snapshot of mutable request counters."""
    with lock:
        return {
            "total_requests": Stats.total_requests,
            "vulnerabilities_found": Stats.vulnerabilities_found,
            "waf_blocks": Stats.waf_blocks,
            "errors": Stats.errors,
            "retries": Stats.retries,
            "start_time": Stats.start_time,
        }


def increment_request_count(amount=1):
    """Increment the total request counter."""
    with lock:
        Stats.total_requests += int(amount)
        return Stats.total_requests


def increment_vulnerability_count(amount=1):
    """Increment the vulnerability counter."""
    with lock:
        Stats.vulnerabilities_found += int(amount)
        return Stats.vulnerabilities_found


def increment_waf_block_count(amount=1):
    """Increment the WAF block counter."""
    with lock:
        Stats.waf_blocks += int(amount)
        return Stats.waf_blocks


def increment_retry_count(amount=1):
    """Increment the retry counter."""
    with lock:
        Stats.retries += int(amount)
        return Stats.retries


def increment_error_count(amount=1):
    """Increment the error counter."""
    with lock:
        Stats.errors += int(amount)
        return Stats.errors


def reset_runtime_stats():
    """Reset request counters and start time for a new scan."""
    Stats.reset()


def normalize_proxy_url(proxy_addr):
    """Normalize proxy inputs like 127.0.0.1:8080 into http://127.0.0.1:8080."""
    proxy = str(proxy_addr or "").strip()
    if not proxy:
        return ""

    parsed = urlparse(proxy)
    if parsed.scheme:
        return proxy

    if proxy.startswith("//"):
        return f"http:{proxy}"

    return f"http://{proxy}"


def smart_request(
    method,
    url,
    data=None,
    params=None,
    headers=None,
    delay=None,
    evasion_level=0,
    **kwargs,
):
    """Make HTTP request with retry, HTTP/2, WAF detection, and Protocol Evasion."""
    _raise_if_scan_cancelled()
    _raise_if_path_blocked(url)
    _reserve_request_budget()

    if delay is None:
        delay = host_rate_limiter.get_delay(url)

    if use_random_delay():
        time.sleep(delay * random.uniform(0.5, 1.5))
    else:
        time.sleep(delay)

    req_headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    }

    if headers:
        req_headers.update(headers)

    # --- PROTOCOL-LEVEL WAF EVASION ---
    if evasion_level > 0:
        from utils.waf_evasion import apply_advanced_evasion

        url, params, data, req_headers = apply_advanced_evasion(
            url, params, data, req_headers, evasion_level
        )

    proxies = get_proxy() if get_proxy() else None

    # Defaults - HTTPX uses `follow_redirects` instead of `allow_redirects`
    allow_redirects = kwargs.pop("allow_redirects", True)
    timeout_val = kwargs.pop("timeout", get_default_timeout())
    verify = kwargs.pop("verify", is_ssl_verification_enabled())

    timeout = httpx.Timeout(timeout_val)

    # Inject Authentication
    auth_manager.inject_auth(req_headers, kwargs)
    params = kwargs.pop("params", params)

    last_error = None
    max_retries = get_max_retries()
    host_semaphore = _get_host_semaphore(url)
    acquired_host_slot = False

    for attempt in range(max_retries + 1):
        try:
            _raise_if_scan_cancelled()
            if host_semaphore and not acquired_host_slot:
                acquired_host_slot = host_semaphore.acquire(
                    timeout=max(float(timeout_val), 1.0)
                )
                if not acquired_host_slot:
                    raise RequestControlError(
                        f"Timed out waiting for host concurrency slot: {url}"
                    )

            sess = _get_session(verify=verify, proxies=proxies)

            # Remove unsupported kwargs for httpx
            kwargs.pop("stream", None)

            resp = sess.request(
                method=method,
                url=url,
                params=params,
                data=data,
                headers=req_headers,
                timeout=timeout,
                follow_redirects=allow_redirects,
                **kwargs,
            )

            # WAF Fingerprinting (first response only)
            if not waf_detector.detected_waf:
                detected = waf_detector.analyze_response(resp.headers, resp.text)
                if detected:
                    from utils.colors import log_warning

                    log_warning(
                        f"WAF Detected: {detected} - Auto-calibrating request delays to avoid bans."
                    )
                    # Throttle this host's delay to evade automated dropping
                    host_rate_limiter.set_minimum(url, 1.0)

            # Active WAF blocking detection
            if resp.status_code in (403, 406, 429, 503):
                waf_indicators = [
                    "blocked",
                    "forbidden",
                    "firewall",
                    "waf",
                    "captcha",
                    "access denied",
                ]
                if any(ind in resp.text.lower() for ind in waf_indicators):
                    increment_waf_block_count()

                # Adaptive rate limiting: auto-backoff on 429
                if resp.status_code == 429 and attempt < max_retries:
                    retry_after = resp.headers.get("retry-after", "")
                    try:
                        wait_time = int(retry_after)
                    except (ValueError, TypeError):
                        wait_time = (2**attempt) * 2  # Exponential: 2s, 4s, 8s
                    from utils.colors import log_warning

                    log_warning(
                        f"Rate limited (429). Waiting {wait_time}s "
                        f"(attempt {attempt + 1}/{max_retries + 1})"
                    )
                    time.sleep(wait_time)
                    # Increase this host's delay to prevent future 429s
                    host_rate_limiter.bump_delay(url, factor=1.5, ceiling=5.0)
                    increment_retry_count()
                    continue  # Retry the request

            return resp

        except httpx.RequestError as e:
            last_error = e
            if attempt < max_retries:
                increment_retry_count()
                # Exponential backoff: 0.5s, 1s, 2s...
                backoff = (2**attempt) * 0.5
                time.sleep(backoff)
            else:
                increment_error_count()
                raise last_error
        finally:
            if acquired_host_slot:
                host_semaphore.release()
                acquired_host_slot = False


def set_cookie(cookie_str):
    """Set cookie for all sessions"""
    cookie_val = cookie_str.strip("\"'")
    _global_headers["Cookie"] = cookie_val
    _get_session().headers["Cookie"] = cookie_val


def set_proxy(proxy_addr):
    """Set proxy for requests"""
    Config.PROXY = normalize_proxy_url(proxy_addr) or None


def set_request_controls(
    request_budget=None,
    max_host_concurrency=None,
    path_blacklist=None,
    default_timeout=None,
    cancel_event=None,
):
    """Apply mutable per-scan request guardrails."""
    if request_budget is not None:
        Config.REQUEST_BUDGET = int(request_budget or 0)
    if max_host_concurrency is not None:
        Config.MAX_HOST_CONCURRENCY = int(max_host_concurrency or 0)
    if path_blacklist is not None:
        if isinstance(path_blacklist, str):
            path_blacklist = [
                item.strip() for item in path_blacklist.split(",") if item.strip()
            ]
        Config.PATH_BLACKLIST = tuple(path_blacklist or ())
    if default_timeout is not None:
        Config.DEFAULT_TIMEOUT = float(default_timeout)
    Config.CANCEL_EVENT = cancel_event
    _host_semaphores.clear()


def is_url_blocked(url):
    """Return True when a URL path matches a configured risky-path blacklist."""
    path = urlparse(url).path or "/"
    for pattern in Config.PATH_BLACKLIST:
        normalized = pattern.strip()
        if not normalized:
            continue
        if fnmatch.fnmatch(path, normalized) or normalized in path:
            return True
    return False


def _raise_if_path_blocked(url):
    if is_url_blocked(url):
        raise BlockedTargetPath(f"Blocked risky target path: {url}")


def _raise_if_scan_cancelled():
    if Config.CANCEL_EVENT is not None and Config.CANCEL_EVENT.is_set():
        raise ScanCancelled("Scan cancelled by user request.")


def _reserve_request_budget():
    with lock:
        if Config.REQUEST_BUDGET and Stats.total_requests >= Config.REQUEST_BUDGET:
            raise RequestBudgetExceeded(
                f"Request budget exceeded ({Stats.total_requests}/{Config.REQUEST_BUDGET})"
            )
        Stats.total_requests += 1


def _get_host_semaphore(url):
    limit = int(getattr(Config, "MAX_HOST_CONCURRENCY", 0) or 0)
    if limit <= 0:
        return None

    host = urlparse(url).netloc or urlparse(url).path
    if not host:
        return None

    with lock:
        semaphore = _host_semaphores.get(host)
        if semaphore is None:
            semaphore = threading.BoundedSemaphore(limit)
            _host_semaphores[host] = semaphore
        return semaphore


def snapshot_runtime_state():
    """Capture mutable request/runtime globals for later restoration."""
    with lock:
        return {
            "proxy": Config.PROXY,
            "request_delay": Config.REQUEST_DELAY,
            "random_delay": Config.RANDOM_DELAY,
            "json_output": Config.JSON_OUTPUT,
            "threads": Config.THREADS,
            "max_retries": Config.MAX_RETRIES,
            "default_timeout": Config.DEFAULT_TIMEOUT,
            "verify_ssl": Config.VERIFY_SSL,
            "request_budget": Config.REQUEST_BUDGET,
            "max_host_concurrency": Config.MAX_HOST_CONCURRENCY,
            "path_blacklist": tuple(Config.PATH_BLACKLIST),
            "cancel_event": Config.CANCEL_EVENT,
            "global_headers": dict(_global_headers),
            "host_delays": host_rate_limiter.snapshot(),
            "stats": {
                "total_requests": Stats.total_requests,
                "vulnerabilities_found": Stats.vulnerabilities_found,
                "waf_blocks": Stats.waf_blocks,
                "errors": Stats.errors,
                "retries": Stats.retries,
                "start_time": Stats.start_time,
            },
        }


def restore_runtime_state(state):
    """Restore mutable request/runtime globals from a snapshot."""
    with lock:
        Config.PROXY = state.get("proxy")
        Config.REQUEST_DELAY = state.get("request_delay", Config.REQUEST_DELAY)
        Config.RANDOM_DELAY = state.get("random_delay", Config.RANDOM_DELAY)
        Config.JSON_OUTPUT = state.get("json_output", Config.JSON_OUTPUT)
        Config.THREADS = state.get("threads", Config.THREADS)
        Config.MAX_RETRIES = state.get("max_retries", Config.MAX_RETRIES)
        Config.DEFAULT_TIMEOUT = state.get("default_timeout", Config.DEFAULT_TIMEOUT)
        Config.VERIFY_SSL = state.get("verify_ssl", Config.VERIFY_SSL)
        Config.REQUEST_BUDGET = state.get("request_budget", Config.REQUEST_BUDGET)
        Config.MAX_HOST_CONCURRENCY = state.get(
            "max_host_concurrency",
            Config.MAX_HOST_CONCURRENCY,
        )
        Config.PATH_BLACKLIST = tuple(state.get("path_blacklist", Config.PATH_BLACKLIST))
        Config.CANCEL_EVENT = state.get("cancel_event")

        # Restore stats if captured
        saved_stats = state.get("stats")
        if saved_stats:
            Stats.total_requests = saved_stats["total_requests"]
            Stats.vulnerabilities_found = saved_stats["vulnerabilities_found"]
            Stats.waf_blocks = saved_stats["waf_blocks"]
            Stats.errors = saved_stats["errors"]
            Stats.retries = saved_stats["retries"]
            Stats.start_time = saved_stats["start_time"]

    _global_headers.clear()
    _global_headers.update(state.get("global_headers", {}))
    _host_semaphores.clear()
    host_rate_limiter.restore(state.get("host_delays", {}))
    _reset_session()


# Disable SSL warnings when verification is off
if not Config.VERIFY_SSL:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
