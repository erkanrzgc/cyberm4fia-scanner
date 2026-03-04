"""
cyberm4fia-scanner - Headless Browser Engine
Playwright-based SPA renderer for modern JavaScript-heavy websites.
Extracts rendered DOM, forms, API calls, and JS-generated endpoints.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from urllib.parse import urlparse
from utils.colors import log_info, log_success, log_warning, log_error


def _check_playwright():
    """Check if Playwright is installed."""
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401

        return True
    except ImportError:
        return False


def render_page(url, timeout=15000, wait_for_idle=True):
    """
    Render a page with headless Chromium and return the full DOM.
    Returns dict with: html, forms, links, api_calls, cookies, console_logs
    """
    if not _check_playwright():
        log_error(
            "Playwright not installed. Run: pip install playwright && playwright install chromium"
        )
        return None

    from playwright.sync_api import sync_playwright

    result = {
        "url": url,
        "html": "",
        "forms": [],
        "links": set(),
        "api_calls": [],
        "cookies": [],
        "console_logs": [],
        "local_storage": {},
        "session_storage": {},
        "js_variables": {},
    }

    api_calls = []

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                viewport={"width": 1920, "height": 1080},
                ignore_https_errors=True,
            )
            page = context.new_page()

            # Intercept network requests to capture API calls
            def handle_request(request):
                if request.resource_type in ("xhr", "fetch"):
                    api_calls.append(
                        {
                            "url": request.url,
                            "method": request.method,
                            "headers": dict(request.headers),
                            "post_data": request.post_data,
                        }
                    )

            page.on("request", handle_request)

            # Capture console logs (often reveal debug info)
            def handle_console(msg):
                result["console_logs"].append(
                    {
                        "type": msg.type,
                        "text": msg.text[:500],
                    }
                )

            page.on("console", handle_console)

            # Navigate
            log_info(f"Rendering {url} with headless Chromium...")
            page.goto(
                url,
                wait_until="networkidle" if wait_for_idle else "domcontentloaded",
                timeout=timeout,
            )

            # Wait for dynamic content
            page.wait_for_timeout(2000)

            # Get rendered HTML
            result["html"] = page.content()

            # Extract forms from rendered DOM
            forms_data = page.evaluate("""() => {
                const forms = [];
                document.querySelectorAll('form').forEach(form => {
                    const inputs = [];
                    form.querySelectorAll('input, textarea, select').forEach(inp => {
                        inputs.push({
                            name: inp.name || '',
                            type: inp.type || 'text',
                            value: inp.value || '',
                            id: inp.id || '',
                            placeholder: inp.placeholder || '',
                        });
                    });
                    forms.push({
                        action: form.action || '',
                        method: (form.method || 'GET').toUpperCase(),
                        inputs: inputs.filter(i => i.name),
                        id: form.id || '',
                    });
                });
                return forms;
            }""")
            result["forms"] = forms_data

            # Extract all links from rendered DOM
            links_data = page.evaluate("""() => {
                const links = [];
                document.querySelectorAll('a[href]').forEach(a => {
                    links.push(a.href);
                });
                return links;
            }""")
            result["links"] = set(links_data)

            # Extract localStorage and sessionStorage
            try:
                result["local_storage"] = page.evaluate("() => ({...localStorage})")
                result["session_storage"] = page.evaluate("() => ({...sessionStorage})")
            except Exception:
                pass

            # Look for interesting JS variables
            interesting_vars = page.evaluate("""() => {
                const found = {};
                const keywords = ['api', 'token', 'key', 'secret', 'config', 'endpoint',
                                  'base_url', 'baseUrl', 'apiUrl', 'apiKey', 'auth'];
                for (const key of keywords) {
                    if (window[key] !== undefined) {
                        try { found[key] = JSON.stringify(window[key]).substring(0, 200); }
                        catch(e) { found[key] = String(window[key]).substring(0, 200); }
                    }
                }
                // Check common framework config objects
                if (window.__NEXT_DATA__) found['__NEXT_DATA__'] = JSON.stringify(window.__NEXT_DATA__).substring(0, 500);
                if (window.__NUXT__) found['__NUXT__'] = 'present';
                if (window.__APP_CONFIG__) found['__APP_CONFIG__'] = JSON.stringify(window.__APP_CONFIG__).substring(0, 500);
                return found;
            }""")
            result["js_variables"] = interesting_vars

            # Get cookies
            cookies = context.cookies()
            result["cookies"] = cookies

            # Store captured API calls
            result["api_calls"] = api_calls

            browser.close()

    except Exception as e:
        log_error(f"Headless rendering failed: {e}")
        return None

    # Report findings
    log_success(f"Rendered page: {len(result['html'])} bytes DOM")
    if result["forms"]:
        log_success(f"Found {len(result['forms'])} form(s) in rendered DOM")
    if result["api_calls"]:
        log_success(f"Intercepted {len(result['api_calls'])} API call(s)")
    if result["js_variables"]:
        log_warning(f"Exposed JS variables: {', '.join(result['js_variables'].keys())}")
    if result["console_logs"]:
        errors = [log for log in result["console_logs"] if log["type"] == "error"]
        if errors:
            log_warning(f"Console errors: {len(errors)}")

    return result


def crawl_spa(start_url, max_pages=20, timeout=10000):
    """
    Crawl a SPA by rendering each page and following client-side routes.
    Returns same format as crawler.py for compatibility.
    """
    if not _check_playwright():
        log_error("Playwright required for SPA crawling")
        return {"urls": [start_url], "forms": [], "api_endpoints": [], "comments": []}

    from playwright.sync_api import sync_playwright

    base_domain = urlparse(start_url).netloc
    visited = set()
    to_visit = [start_url]
    all_urls = set()
    all_forms = []
    all_api_endpoints = set()
    all_api_calls = []

    log_info(
        f"SPA Crawling {base_domain} with headless browser (max {max_pages} pages)..."
    )

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                ignore_https_errors=True,
            )

            while to_visit and len(visited) < max_pages:
                url = to_visit.pop(0)
                if url in visited:
                    continue
                visited.add(url)

                try:
                    page = context.new_page()

                    # Capture API calls
                    def handle_req(request, current_url=url):
                        if request.resource_type in ("xhr", "fetch"):
                            all_api_calls.append(
                                {
                                    "url": request.url,
                                    "method": request.method,
                                    "source_page": current_url,
                                }
                            )
                            all_api_endpoints.add(request.url)

                    page.on("request", handle_req)

                    page.goto(url, wait_until="networkidle", timeout=timeout)
                    page.wait_for_timeout(1500)

                    # Extract forms
                    forms = page.evaluate("""() => {
                        const forms = [];
                        document.querySelectorAll('form').forEach(form => {
                            const inputs = [];
                            form.querySelectorAll('input, textarea, select').forEach(inp => {
                                if (inp.name) inputs.push({name: inp.name, type: inp.type || 'text', value: inp.value || ''});
                            });
                            if (inputs.length) forms.push({action: form.action, method: (form.method || 'GET').toUpperCase(), inputs: inputs});
                        });
                        return forms;
                    }""")
                    all_forms.extend(forms)

                    # Extract links
                    links = page.evaluate("""() => {
                        return Array.from(document.querySelectorAll('a[href]')).map(a => a.href);
                    }""")

                    for link in links:
                        parsed = urlparse(link)
                        if parsed.netloc == base_domain and link not in visited:
                            to_visit.append(link)
                            all_urls.add(link)

                    all_urls.add(url)
                    page.close()

                    log_info(
                        f"SPA rendered: {url} ({len(forms)} forms, {len(links)} links)"
                    )

                except Exception:
                    pass

            browser.close()

    except Exception as e:
        log_error(f"SPA crawling failed: {e}")

    log_success(
        f"SPA crawl complete: {len(all_urls)} pages, {len(all_forms)} forms, {len(all_api_endpoints)} API endpoints"
    )

    return {
        "urls": list(all_urls),
        "forms": all_forms,
        "api_endpoints": list(all_api_endpoints),
        "api_calls": all_api_calls,
        "comments": [],
    }
