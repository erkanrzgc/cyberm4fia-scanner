"""
cyberm4fia-scanner - Proxy Rotator
Thread-safe proxy pool from proxifly free proxy list with connectivity testing.
"""
import random
import threading
import time
from urllib.parse import urlparse

import httpx

from utils.colors import log_info, log_warning, log_success

_PROXY_LIST_URL = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt"
_FALLBACK_LIST_URLS = [
    "https://raw.githubusercontent.com/Argh94/Proxy-List/main/HTTP.txt",
    "https://raw.githubusercontent.com/Argh94/Proxy-List/main/HTTPS.txt",
    "https://raw.githubusercontent.com/Argh94/Proxy-List/main/SOCKS4.txt",
    "https://raw.githubusercontent.com/Argh94/Proxy-List/main/SOCKS5.txt",
]
_DEFAULT_REFRESH_INTERVAL = 600
_TEST_TIMEOUT = 5.0
_TEST_URL = "http://httpbin.org/get"


class ProxyRotator:
    """Thread-safe rotating proxy pool with health checking."""

    def __init__(self, protocols=None, refresh_interval=_DEFAULT_REFRESH_INTERVAL):
        self._protocols = [p.upper() for p in (protocols or ["HTTP", "SOCKS4", "SOCKS5"])]
        self._refresh_interval = refresh_interval
        self._pool = []
        self._index = 0
        self._lock = threading.Lock()
        self._last_fetch = 0.0
        self._fetching = False
        self._fetch_lock = threading.Lock()

    def _fetch_proxy_list(self):
        with self._fetch_lock:
            if self._fetching:
                return
            self._fetching = True
        try:
            raw_proxies: list[str] = []
            for url in (_PROXY_LIST_URL, *_FALLBACK_LIST_URLS):
                try:
                    resp = httpx.get(url, timeout=10.0, follow_redirects=True)
                    resp.raise_for_status()
                except httpx.RequestError:
                    continue
                for line in resp.text.strip().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    raw_proxies.append(line)
                if raw_proxies:
                    break  # first source that yields anything wins
            if not raw_proxies:
                return

            healthy = []
            for proxy_addr in raw_proxies:
                proxy_url = normalize_proxy_address(proxy_addr)
                protocol = (
                    proxy_url.split("://")[0].upper()
                    if "://" in proxy_url
                    else "HTTP"
                )
                if protocol not in self._protocols:
                    continue
                latency = self._test_proxy(proxy_url)
                if latency is not None:
                    healthy.append({
                        "url": proxy_url,
                        "protocol": protocol,
                        "latency": latency,
                        "last_check": time.time(),
                    })

            with self._lock:
                self._pool = healthy
                self._index = 0
                self._last_fetch = time.time()

            if healthy:
                log_success(
                    f"ProxyRotator: {len(healthy)} healthy proxies collected"
                )
            else:
                log_warning(
                    "ProxyRotator: no healthy proxies found (falling back to direct connection)"
                )
        finally:
            with self._fetch_lock:
                self._fetching = False

    @staticmethod
    def _test_proxy(proxy_url):
        try:
            start = time.time()
            proxies = {"http://": proxy_url, "https://": proxy_url}
            resp = httpx.get(
                _TEST_URL,
                proxies=proxies,
                timeout=_TEST_TIMEOUT,
                follow_redirects=True,
            )
            if resp.status_code == 200:
                return time.time() - start
        except Exception:
            pass
        return None

    def _maybe_refresh(self):
        now = time.time()
        with self._lock:
            if self._pool and (now - self._last_fetch) < self._refresh_interval:
                return
        self._fetch_proxy_list()

    def get_proxy(self):
        """Return the next healthy proxy URL via round-robin, or None if none available."""
        self._maybe_refresh()
        with self._lock:
            if not self._pool:
                return None
            proxy = self._pool[self._index % len(self._pool)]
            self._index += 1
            return proxy["url"]

    def get_random_proxy(self):
        """Return a random healthy proxy URL, or None if none available."""
        self._maybe_refresh()
        with self._lock:
            if not self._pool:
                return None
            return random.choice(self._pool)["url"]

    def mark_dead(self, proxy_url):
        with self._lock:
            self._pool = [p for p in self._pool if p["url"] != proxy_url]

    @property
    def pool_size(self):
        with self._lock:
            return len(self._pool)

    @property
    def healthy(self):
        return self.pool_size > 0


def normalize_proxy_address(address):
    addr = str(address or "").strip()
    if not addr:
        return ""
    parsed = urlparse(addr)
    if parsed.scheme:
        return addr
    if addr.startswith("//"):
        return f"http:{addr}"
    return f"http://{addr}"


_rotator_instance = None
_rotator_lock = threading.Lock()
_rotator_enabled = False


def get_proxy_rotator(protocols=None, refresh_interval=_DEFAULT_REFRESH_INTERVAL):
    global _rotator_instance
    with _rotator_lock:
        if _rotator_instance is None:
            _rotator_instance = ProxyRotator(
                protocols=protocols, refresh_interval=refresh_interval
            )
            log_info("ProxyRotator: initializing from proxifly CDN...")
            _rotator_instance._fetch_proxy_list()
        return _rotator_instance


def enable_proxy_rotation(enabled=True):
    global _rotator_enabled
    _rotator_enabled = bool(enabled)
    if _rotator_enabled:
        get_proxy_rotator()


def is_proxy_rotation_enabled():
    return _rotator_enabled


def get_rotation_proxy():
    if not _rotator_enabled:
        return None
    rotator = get_proxy_rotator()
    return rotator.get_proxy()
