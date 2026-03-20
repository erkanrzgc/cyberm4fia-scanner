"""
cyberm4fia-scanner - Dynamic Crawler Module
Playwright-based smart crawler for modern web apps (Next.js, React, Vue, etc.)
"""

import sys
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
    def __init__(self, target_url, delay=0):
        self.target_url = target_url
        self.delay = delay
        self.found_endpoints = set()
        self.found_forms = []
        self.found_links = set()
        self.base_domain = urlparse(target_url).netloc
        
    async def _intercept_request(self, request):
        """Intercept outgoing network requests to find APIs"""
        # We only care about XHR or Fetch requests that the page makes
        if request.resource_type in ["xhr", "fetch"]:
            url = request.url
            # Stay within the same domain or track useful third-party API routes
            if self.base_domain in urlparse(url).netloc or "/api/" in url or "/wp-json/" in url:
                self.found_endpoints.add((request.method, url))
                
    async def run(self):
        """Run the Playwright crawler"""
        if async_playwright is None:
            log_error("Playwright is not installed. Run: pip install playwright && playwright install")
            return {"endpoints": [], "forms": [], "links": [], "html": ""}

        log_info(f"🕷️ Starting Dynamic Crawler (Playwright) on {self.target_url}...")
        
        async with async_playwright() as p:
            # Set up proxy if configured
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
            # Use realistic user agent
            headers = get_global_headers()
            user_agent = headers.pop("User-Agent", random.choice(USER_AGENTS))
            
            context = await browser.new_context(
                user_agent=user_agent,
                extra_http_headers=headers,
                ignore_https_errors=True,
                viewport={"width": 1920, "height": 1080}
            )
            
            page = await context.new_page()
            
            # Intercept events
            page.on("request", self._intercept_request)
            
            try:
                # Go to the target and wait for it to fully load (JS executed)
                await page.goto(self.target_url, wait_until="networkidle", timeout=30000)
                
                # Scroll to bottom to trigger lazy loading
                await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                await asyncio.sleep(2) # Give it a moment to load lazy content
                
                # Get the fully rendered final HTML
                final_html = await page.content()
                
                # Parse with BeautifulSoup to find forms and links
                soup = BeautifulSoup(final_html, "lxml")
                
                # Find Forms
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
                    
                # Find Links
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
            "html": final_html
        }

def run_dynamic_spider(url, delay=0):
    """Synchronous wrapper for the crawler"""
    crawler = DynamicCrawler(url, delay)
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
