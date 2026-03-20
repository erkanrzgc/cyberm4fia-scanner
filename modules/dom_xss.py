"""
cyberm4fia-scanner - DOM XSS Module
DOM-based Cross-Site Scripting detection using Selenium
"""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from utils.colors import log_info, log_success, log_warning, log_error, log_vuln
from utils.request import increment_vulnerability_count
from utils.request import ScanExceptions

DOM_XSS_PAYLOADS = [
    '<img src=x onerror=alert("DOMXSS")>',
    '<svg/onload=alert("DOMXSS")>',
    '"><script>alert("DOMXSS")</script>',
    "'-alert('DOMXSS')-'",
    "javascript:alert('DOMXSS')",
]

def scan_dom_xss(url):
    """Scan for DOM-based XSS using Playwright headless browser"""
    try:
        from playwright.sync_api import (
            sync_playwright,
            TimeoutError as PlaywrightTimeoutError,
        )
    except ImportError:
        log_error(
            "Playwright not installed. Run: pip install playwright && playwright install chromium"
        )
        return []

    log_info("Testing DOM XSS with Playwright (headless Chromium)...")
    vulns = []
    parsed = urlparse(url)

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(
                headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"]
            )
            context = browser.new_context(viewport={"width": 1920, "height": 1080})
        except ScanExceptions as e:
            log_error(f"Playwright browser error: {e}")
            log_warning("Ensure browsers are installed: playwright install chromium")
            return []

        try:
            for payload in DOM_XSS_PAYLOADS:
                # Test 1: URL Hash (#fragment)
                test_url = f"{url}#{payload}"
                page = context.new_page()

                alert_triggered = [False]

                def handle_dialog(dialog):
                    if "DOMXSS" in dialog.message:
                        alert_triggered[0] = True
                    dialog.accept()

                page.on("dialog", handle_dialog)

                try:
                    page.goto(test_url, timeout=5000, wait_until="load")
                    page.wait_for_timeout(1000)
                except PlaywrightTimeoutError:
                    pass
                except ScanExceptions:
                    pass

                if alert_triggered[0]:
                    increment_vulnerability_count()
                    log_vuln("DOM XSS VULNERABILITY FOUND!")
                    log_success(f"Type: URL Hash | Payload: {payload[:40]}...")
                    vulns.append(
                        {
                            "type": "DOM_XSS_Hash",
                            "payload": payload,
                            "context": "URL Fragment",
                        }
                    )
                page.close()

                # Test 2: URL Params
                params = parse_qs(parsed.query)
                for param in params:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url_param = urlunparse(
                        parsed._replace(query=urlencode(test_params, doseq=True))
                    )

                    page = context.new_page()
                    alert_triggered_param = [False]

                    def handle_dialog_param(dialog):
                        if "DOMXSS" in dialog.message:
                            alert_triggered_param[0] = True
                        dialog.accept()

                    page.on("dialog", handle_dialog_param)

                    try:
                        page.goto(test_url_param, timeout=5000, wait_until="load")
                        page.wait_for_timeout(1000)
                    except PlaywrightTimeoutError:
                        pass
                    except ScanExceptions:
                        pass

                    if alert_triggered_param[0]:
                        increment_vulnerability_count()
                        log_vuln("DOM XSS VULNERABILITY FOUND!")
                        log_success(
                            f"Type: URL Param '{param}' | Payload: {payload[:40]}..."
                        )
                        vulns.append(
                            {
                                "type": "DOM_XSS_Param",
                                "param": param,
                                "payload": payload,
                                "context": "URL Parameter",
                            }
                        )
                    page.close()
        finally:
            browser.close()

    if not vulns:
        log_info("No DOM XSS vulnerabilities found")

    return vulns
