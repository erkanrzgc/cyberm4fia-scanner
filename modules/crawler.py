"""
cyberm4fia-scanner - Advanced Crawler Module v2
Web spider that extracts HTML links, forms, and hidden API endpoints from JS files.
Returns both URLs and forms for downstream scanning modules.
"""

import os
import re

from urllib.parse import urlparse, urlunparse, urljoin
from bs4 import BeautifulSoup
from utils.colors import log_info, log_success, log_warning
from utils.request import smart_request
from utils.request import ScanExceptions

# Regex to find endpoints in JS files (Katana/LinkFinder style)
JS_PATH_REGEX = re.compile(
    r"""(?:"|')(((?:[a-zA-Z]{1,10}://|/|\./|\.\./|)[a-zA-Z0-9_\-\./]+(?:\?[a-zA-Z0-9_\-\.=]+)?))(?:"|')"""
)

# Interesting file extensions to flag for deeper analysis
INTERESTING_EXTENSIONS = {
    ".php",
    ".asp",
    ".aspx",
    ".jsp",
    ".do",
    ".action",
    ".cgi",
    ".pl",
    ".py",
    ".rb",
    ".cfm",
}

def _extract_js_endpoints(js_content, base_url):
    """Extract paths from raw JS content."""
    links = set()
    for match in JS_PATH_REGEX.findall(js_content):
        path = match[0]
        if any(
            path.endswith(ext)
            for ext in [
                ".png",
                ".jpg",
                ".css",
                ".gif",
                ".svg",
                ".woff",
                ".woff2",
                ".ttf",
                ".ico",
            ]
        ):
            continue
        if len(path) < 2 or " " in path:
            continue
        full_url = urljoin(base_url, path)
        links.add(full_url)
    return links

def _extract_forms(soup, page_url):
    """Extract all forms with their inputs from a page."""
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = (form.get("method", "GET")).upper()
        form_url = urljoin(page_url, action) if action else page_url

        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            input_data = {
                "name": inp.get("name", ""),
                "type": inp.get("type", "text"),
                "value": inp.get("value", ""),
            }
            if input_data["name"]:
                inputs.append(input_data)

        if inputs:
            forms.append(
                {
                    "action": form_url,
                    "method": method,
                    "inputs": inputs,
                    "source_page": page_url,
                }
            )

    return forms

def _extract_comments(html):
    """Extract HTML comments that might reveal hidden info."""
    comments = re.findall(r"<!--(.*?)-->", html, re.DOTALL)
    interesting = []
    keywords = [
        "password",
        "admin",
        "todo",
        "debug",
        "hack",
        "key",
        "secret",
        "api",
        "token",
    ]
    for comment in comments:
        comment_lower = comment.lower().strip()
        if any(kw in comment_lower for kw in keywords):
            interesting.append(comment.strip()[:200])
    return interesting

def crawl_site(start_url, max_pages=50):
    """
    Advanced contextual crawling.
    Returns: dict with 'urls', 'forms', 'api_endpoints', 'comments'
    """
    visited = set()
    to_visit = [start_url]
    base_domain = urlparse(start_url).netloc
    found_urls = set([start_url])
    api_endpoints = set()
    all_forms = []
    all_comments = []
    interesting_files = []

    log_info(f"Crawling {base_domain} (max {max_pages} pages, parsing JS) ...")

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue

        try:
            resp = smart_request("get", url, timeout=10)
            visited.add(url)

            # If it's a JS file, parse with regex
            if url.endswith(".js") or "application/javascript" in resp.headers.get(
                "Content-Type", ""
            ):
                js_links = _extract_js_endpoints(resp.text, url)
                for link in js_links:
                    parsed_link = urlparse(link)
                    if parsed_link.netloc == base_domain:
                        api_endpoints.add(link)
                        clean_link = urlunparse(parsed_link._replace(fragment=""))
                        if clean_link not in visited and clean_link not in to_visit:
                            to_visit.append(clean_link)
                            found_urls.add(clean_link)
                continue

            # Standard HTML parsing
            soup = BeautifulSoup(resp.content, "lxml")

            # Extract forms
            page_forms = _extract_forms(soup, url)
            all_forms.extend(page_forms)

            # Extract comments
            comments = _extract_comments(resp.text)
            if comments:
                all_comments.extend(comments)
                log_warning(f"Interesting HTML comments on {url}")

            # Extract links from all tag types
            for tag in soup.find_all(
                [
                    "a",
                    "link",
                    "script",
                    "img",
                    "form",
                    "iframe",
                    "embed",
                    "source",
                    "video",
                    "audio",
                ]
            ):
                href = (
                    tag.get("href")
                    or tag.get("src")
                    or tag.get("action")
                    or tag.get("data")
                )
                if not href:
                    continue

                full_url = urljoin(url, href)
                parsed = urlparse(full_url)

                if parsed.netloc == base_domain and full_url not in visited:
                    clean_url = urlunparse(parsed._replace(fragment=""))
                    if clean_url not in to_visit and clean_url not in visited:
                        to_visit.append(clean_url)
                        found_urls.add(clean_url)

                    # Flag interesting files
                    ext = os.path.splitext(parsed.path)[1].lower()
                    if ext in INTERESTING_EXTENSIONS:
                        interesting_files.append(clean_url)

            # Also extract inline JS endpoints from <script> blocks
            for script_tag in soup.find_all("script"):
                if script_tag.string:
                    inline_links = _extract_js_endpoints(script_tag.string, url)
                    for link in inline_links:
                        parsed_link = urlparse(link)
                        if parsed_link.netloc == base_domain:
                            api_endpoints.add(link)

        except ScanExceptions:
            pass

    # Deduplicate forms by action URL
    seen_forms = set()
    unique_forms = []
    for form in all_forms:
        key = f"{form['method']}:{form['action']}"
        if key not in seen_forms:
            seen_forms.add(key)
            unique_forms.append(form)

    # Filter static assets from the final URLs list to be scanned
    def is_static(u):
        p = urlparse(u).path.lower()
        static_exts = [
            ".css",
            ".js",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".svg",
            ".woff",
            ".woff2",
            ".ttf",
            ".eot",
            ".ico",
            ".mp4",
            ".mp3",
            ".webp",
        ]
        if any(p.endswith(ext) for ext in static_exts):
            return True

        static_paths = [
            "/_next/static/",
            "/node_modules/",
            "/static/css/",
            "/static/js/",
        ]
        if any(path in p for path in static_paths):
            return True
        return False

    scannable_urls = [u for u in found_urls if not is_static(u)]

    # Always ensure the starting URL is scanned
    if start_url not in scannable_urls:
        scannable_urls.insert(0, start_url)

    log_success(
        f"Crawling finished. Found {len(found_urls)} URLs (Filtered to {len(scannable_urls)} scannable), {len(unique_forms)} forms, {len(api_endpoints)} API endpoints"
    )
    if all_comments:
        log_warning(f"Found {len(all_comments)} interesting HTML comments")

    return {
        "urls": scannable_urls,
        "forms": unique_forms,
        "api_endpoints": list(api_endpoints),
        "comments": all_comments,
        "interesting_files": interesting_files,
    }
