"""
cyberm4fia-scanner - Dynamic Crawler Module
Playwright-based smart crawler for modern web apps (Next.js, React, Vue, etc.)
"""

import sys
import os
import asyncio
from urllib.parse import urlparse, urljoin

from utils.colors import log_info, log_success, log_warning, log_error
from utils.request import (
    USER_AGENTS,
    get_global_headers,
    get_proxy,
)
from bs4 import BeautifulSoup
from utils.request import ScanExceptions

try:
    from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout
except ImportError:
    async_playwright = None

class DynamicCrawler:
    def __init__(self, target_url, delay=0, har_output=None):
        self.target_url = target_url
        self.delay = delay
        self.har_output = har_output
        self.found_endpoints = set()
        self.found_forms = []
        self.found_links = set()
        self.base_domain = urlparse(target_url).netloc

    async def _intercept_request(self, request):
        """Intercept outgoing network requests to find APIs"""
        if request.resource_type in ["xhr", "fetch"]:
            url = request.url
            if self.base_domain in urlparse(url).netloc or "/api/" in url or "/wp-json/" in url:
                self.found_endpoints.add((request.method, url))

    async def run(self):
        """Run the Playwright crawler with optional HAR recording"""
        if async_playwright is None:
            log_error("Playwright is not installed. Run: pip install playwright && playwright install")
            return {"endpoints": [], "forms": [], "links": [], "html": "", "har_path": None}

        log_info(f"\U0001f577\ufe0f Starting Dynamic Crawler (Playwright) on {self.target_url}...")

        har_path = None
        if self.har_output:
            os.makedirs(self.har_output, exist_ok=True)
            har_path = os.path.join(self.har_output, "recording.har")
            log_info(f"HAR recording enabled: {har_path}")

        async with async_playwright() as p:
            proxy_settings = None
            proxy = get_proxy()
            if proxy:
                proxy_settings = {"server": proxy}

            browser = await p.chromium.launch(
                headless=True,
                proxy=proxy_settings,
                args=['--disable-web-security', '--disable-features=IsolateOrigins,site-per-process']
            )

            import random
            headers = get_global_headers()
            user_agent = headers.pop("User-Agent", random.choice(USER_AGENTS))

            context_kwargs = {
                "user_agent": user_agent,
                "extra_http_headers": headers,
                "ignore_https_errors": True,
                "viewport": {"width": 1920, "height": 1080},
            }
            if har_path:
                context_kwargs["record_har_path"] = har_path
                context_kwargs["record_har_content"] = "embed"

            context = await browser.new_context(**context_kwargs)

            page = await context.new_page()

            page.on("request", self._intercept_request)

            try:
                await page.goto(self.target_url, wait_until="networkidle", timeout=30000)

                await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                await asyncio.sleep(2)

                final_html = await page.content()

                soup = BeautifulSoup(final_html, "lxml")

                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    method = form.get("method", "get").lower()
                    inputs = []
                    for inp in form.find_all(["input", "textarea"]):
                        name = inp.get("name")
                        if name:
                            inputs.append({"name": name, "type": inp.get("type", "text")})

                    self.found_forms.append({
                        "action": urljoin(self.target_url, action),
                        "method": method,
                        "inputs": inputs
                    })

                for a in soup.find_all("a", href=True):
                    href = a.get("href")
                    if not href.startswith("javascript:") and not href.startswith("#"):
                        full_url = urljoin(self.target_url, href)
                        if self.base_domain in urlparse(full_url).netloc:
                            self.found_links.add(full_url)

                log_success(f"Dynamic crawling finished. Found {len(self.found_endpoints)} API endpoints and {len(self.found_forms)} forms.")

            except PlaywrightTimeout:
                log_warning(f"Timeout while dynamically crawling {self.target_url}")
                final_html = ""
            except ScanExceptions as e:
                log_error(f"Error during dynamic crawling: {e}")
                final_html = ""

            finally:
                await browser.close()

        return {
            "endpoints": list(self.found_endpoints),
            "forms": self.found_forms,
            "links": list(self.found_links),
            "html": final_html,
            "har_path": har_path,
        }

def run_dynamic_spider(url, delay=0, har_output=None):
    """Synchronous wrapper for the crawler"""
    crawler = DynamicCrawler(url, delay, har_output=har_output)
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    return loop.run_until_complete(crawler.run())

if __name__ == "__main__":
    if len(sys.argv) > 1:
        res = run_dynamic_spider(sys.argv[1])
        print(f"\\nEndpoints: {res['endpoints']}")
        print(f"\\nForms: {res['forms']}")
