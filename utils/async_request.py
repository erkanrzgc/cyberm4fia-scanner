"""
cyberm4fia-scanner - Async HTTP Utilities
High-performance async requests with httpx.AsyncClient

Usage:
    from utils.async_request import async_scan_urls

    results = async_scan_urls(urls, callback, delay=0.3)
"""
from utils.request import ScanExceptions

import asyncio
import random
import httpx

from utils.request import (
    USER_AGENTS,
    _raise_if_scan_cancelled,
    _reserve_request_budget,
    get_default_timeout,
    get_global_headers,
    get_max_retries,
    host_rate_limiter,
    increment_error_count,
    increment_retry_count,
    increment_waf_block_count,
    is_ssl_verification_enabled,
    use_random_delay,
)


async def async_smart_request(
    session, method, url, data=None, params=None, headers=None, delay=None, **kwargs
):
    """Async version of smart_request with retry and HTTP/2."""
    if delay is None:
        delay = host_rate_limiter.get_delay(url)

    _raise_if_scan_cancelled()
    _reserve_request_budget()

    if use_random_delay():
        await asyncio.sleep(delay * random.uniform(0.5, 1.5))
    else:
        await asyncio.sleep(delay)

    req_headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    }
    if headers:
        req_headers.update(headers)

    timeout = httpx.Timeout(kwargs.pop("timeout", get_default_timeout()))
    allow_redirects = kwargs.pop("allow_redirects", True)
    max_retries = get_max_retries()
    last_error = None

    for attempt in range(max_retries + 1):
        try:
            kwargs.pop("stream", None)
            kwargs.pop("follow_redirects", None)
            resp = await session.request(
                method,
                url,
                data=data,
                params=params,
                headers=req_headers,
                timeout=timeout,
                follow_redirects=allow_redirects,
                **kwargs,
            )

            # WAF / rate limiting detection
            if resp.status_code in (403, 429):
                if resp.status_code == 403:
                    increment_waf_block_count()
                # Adaptive per-host rate limiting on 429
                if resp.status_code == 429 and attempt < max_retries:
                    retry_after = resp.headers.get("retry-after", "")
                    try:
                        wait_time = int(retry_after)
                    except (ValueError, TypeError):
                        wait_time = (2**attempt) * 2
                    await asyncio.sleep(wait_time)
                    host_rate_limiter.bump_delay(url, factor=1.5, ceiling=5.0)
                    increment_retry_count()
                    continue

            return resp

        except httpx.RequestError as e:
            last_error = e
            if attempt < max_retries:
                increment_retry_count()
                backoff = (2**attempt) * 0.5
                await asyncio.sleep(backoff)
            else:
                increment_error_count()
                raise last_error


async def async_get(session, url, delay=None, **kwargs):
    """Async GET shortcut."""
    return await async_smart_request(session, "GET", url, delay=delay, **kwargs)


async def async_post(session, url, data=None, delay=None, **kwargs):
    """Async POST shortcut."""
    return await async_smart_request(
        session, "POST", url, data=data, delay=delay, **kwargs
    )


async def async_scan_urls(urls, scan_callback, concurrency=20, delay=None):
    """Scan multiple URLs concurrently with httpx.AsyncClient.

    Args:
        urls: list of URLs to scan
        scan_callback: async function(session, url)
                      that returns list of vulns
        concurrency: max concurrent connections
        delay: delay between requests

    Returns: list of all vulns found
    """
    all_vulns = []
    semaphore = asyncio.Semaphore(concurrency)

    headers = get_global_headers()
    cookie_str = headers.get("Cookie")

    async_headers = {}
    if cookie_str:
        async_headers["Cookie"] = cookie_str

    limits = httpx.Limits(
        max_keepalive_connections=concurrency,
        max_connections=concurrency,
    )

    async with httpx.AsyncClient(
        http2=True,
        verify=is_ssl_verification_enabled(),
        limits=limits,
        headers=async_headers,
        follow_redirects=True,
    ) as session:

        async def _bounded_scan(url):
            async with semaphore:
                try:
                    result = await scan_callback(session, url)
                    if result:
                        all_vulns.extend(result)
                except ScanExceptions:
                    pass

        tasks = [asyncio.create_task(_bounded_scan(u)) for u in urls]
        await asyncio.gather(*tasks)

    return all_vulns


def run_async_scan(urls, scan_callback, concurrency=20, delay=None):
    """Synchronous wrapper for async_scan_urls.

    Use this from non-async code:
        vulns = run_async_scan(urls, my_callback)
    """
    return asyncio.run(
        async_scan_urls(urls, scan_callback, concurrency=concurrency, delay=delay)
    )


# ── Managed async client for module-level async scanning ──────────────────

class AsyncClientManager:
    """Context manager that provides a shared httpx.AsyncClient for async modules.

    Usage:
        async with AsyncClientManager() as client:
            resp = await client.get("http://example.com")

    Or use the module-level helper:
        async with get_async_client() as client:
            ...
    """

    def __init__(self, concurrency=50):
        self._concurrency = concurrency
        self._client = None

    async def __aenter__(self):
        headers = get_global_headers()
        async_headers = {}
        cookie_str = headers.get("Cookie")
        if cookie_str:
            async_headers["Cookie"] = cookie_str

        limits = httpx.Limits(
            max_keepalive_connections=self._concurrency,
            max_connections=self._concurrency,
        )
        self._client = httpx.AsyncClient(
            http2=True,
            verify=is_ssl_verification_enabled(),
            limits=limits,
            headers=async_headers,
            follow_redirects=False,
        )
        return self._client

    async def __aexit__(self, *exc):
        if self._client:
            await self._client.aclose()
        self._client = None


def get_async_client(concurrency=50):
    """Return an AsyncClientManager for use in async with blocks."""
    return AsyncClientManager(concurrency=concurrency)
