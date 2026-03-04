"""
cyberm4fia-scanner - HTTP Request Utilities
"""

import os
import httpx
import time
import random
import threading

# Load .env file if python-dotenv is available
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

from utils.auth import auth_manager
from utils.waf import waf_detector

# Thread-local storage for sessions
_thread_local = threading.local()
_global_headers = {}
lock = threading.Lock()


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
    VERIFY_SSL = os.environ.get("VERIFY_SSL", "false").lower() == "true"
    OOB_CLIENT = None
    SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")


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


def smart_request(
    method, url, data=None, params=None, headers=None, delay=None, **kwargs
):
    """Make HTTP request with retry, HTTP/2, and WAF detection"""
    if delay is None:
        delay = Config.REQUEST_DELAY

    if Config.RANDOM_DELAY:
        time.sleep(delay * random.uniform(0.5, 1.5))
    else:
        time.sleep(delay)

    with lock:
        Stats.total_requests += 1

    req_headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    }

    if headers:
        req_headers.update(headers)

    proxies = Config.PROXY if Config.PROXY else None

    # Defaults - HTTPX uses `follow_redirects` instead of `allow_redirects`
    allow_redirects = kwargs.pop("allow_redirects", True)
    timeout_val = kwargs.pop("timeout", 10)
    verify = kwargs.pop("verify", Config.VERIFY_SSL)

    timeout = httpx.Timeout(timeout_val)

    # Inject Authentication
    auth_manager.inject_auth(req_headers, kwargs)

    last_error = None
    max_retries = Config.MAX_RETRIES

    for attempt in range(max_retries + 1):
        try:
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
                    # Throttle default delay to evade automated dropping
                    if Config.REQUEST_DELAY < 1.0:
                        Config.REQUEST_DELAY = 1.0

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
                    with lock:
                        Stats.waf_blocks += 1

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
                    # Increase global delay to prevent future 429s
                    with lock:
                        if Config.REQUEST_DELAY < 2.0:
                            Config.REQUEST_DELAY = min(Config.REQUEST_DELAY * 1.5, 3.0)
                        Stats.retries += 1
                    continue  # Retry the request

            return resp

        except httpx.RequestError as e:
            last_error = e
            if attempt < max_retries:
                with lock:
                    Stats.retries += 1
                # Exponential backoff: 0.5s, 1s, 2s...
                backoff = (2**attempt) * 0.5
                time.sleep(backoff)
            else:
                with lock:
                    Stats.errors += 1
                raise last_error


def set_cookie(cookie_str):
    """Set cookie for all sessions"""
    cookie_val = cookie_str.strip("\"'")
    _global_headers["Cookie"] = cookie_val
    _get_session().headers["Cookie"] = cookie_val


def set_proxy(proxy_addr):
    """Set proxy for requests"""
    Config.PROXY = proxy_addr


# Disable SSL warnings when verification is off
if not Config.VERIFY_SSL:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
