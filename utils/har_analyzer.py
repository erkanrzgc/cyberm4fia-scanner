"""
cyberm4fia-scanner – HAR (HTTP Archive) file analyzer.
Extracts API endpoints, auth patterns, and undocumented endpoints from HAR files.
"""

import json
import re
from collections import defaultdict
from urllib.parse import urlparse, parse_qs, urljoin

from utils.colors import log_info, log_success, log_warning

AUTH_HEADER_KEYS = {
    "authorization", "x-api-key", "x-auth-token", "x-access-token",
    "api-key", "x-csrf-token", "x-xsrf-token", "cookie",
    "x-api-key", "token", "x-forwarded-for",
}

API_PATH_PATTERNS = re.compile(
    r"/(api|graphql|rest|v[0-9]+|query|mutation|rpc|json|ajax|wp-json)"
    r"(?:/|$|[a-zA-Z0-9])",
    re.IGNORECASE,
)

PARAM_PATTERN = re.compile(r"/:[a-zA-Z_][a-zA-Z0-9_]*|\{[a-zA-Z_][a-zA-Z0-9_]*\}|/([0-9a-f]{8}-?[0-9a-f]{4}-?|\d+)")

STATIC_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".mp4",
    ".webm", ".mp3", ".pdf", ".zip", ".tar", ".gz",
}


def _is_static_resource(url):
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in STATIC_EXTENSIONS)


def _is_api_path(url):
    path = urlparse(url).path
    return bool(API_PATH_PATTERNS.search(path))


def _normalize_path(path):
    """Replace dynamic path segments with parameter placeholders."""
    path = re.sub(r"/\d+", "/{id}", path)
    path = re.sub(
        r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "/{uuid}",
        path,
        flags=re.IGNORECASE,
    )
    path = re.sub(r"/[0-9a-f]{24,}", "/{hash}", path, flags=re.IGNORECASE)
    return path


def parse_har_file(har_path):
    """Load HAR JSON from a file path, returning the parsed dict."""
    if not har_path:
        return None
    try:
        with open(har_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        log_warning(f"Failed to parse HAR file {har_path}: {exc}")
        return None


def extract_endpoints_from_har(har_data, base_url=None):
    """Extract unique API endpoints from a HAR log dict.

    Returns a list of endpoint dicts compatible with the API scanner:
        {url, method, request_body, request_body_content_type, auth_headers, ...}
    """
    if not har_data:
        return []

    entries = har_data.get("log", {}).get("entries", [])
    if not entries:
        return []

    seen_urls = set()
    endpoints = []

    for entry in entries:
        request = entry.get("request", {})
        response = entry.get("response", {})

        url = request.get("url", "")
        method = request.get("method", "GET").upper()
        parsed = urlparse(url)

        if _is_static_resource(url):
            continue

        if not _is_api_path(url) and method not in ("POST", "PUT", "PATCH", "DELETE"):
            continue

        normalized_path = _normalize_path(parsed.path)
        key = (method, normalized_path)
        if key in seen_urls:
            continue
        seen_urls.add(key)

        auth_headers = {}
        for header in request.get("headers", []):
            name = header.get("name", "").lower()
            if name in AUTH_HEADER_KEYS:
                auth_headers[name] = header.get("value", "")

        content_type = ""
        request_body = None
        post_data = request.get("postData", {})
        if post_data:
            content_type = post_data.get("mimeType", "")
            text = post_data.get("text", "")
            if text:
                if "json" in content_type:
                    try:
                        request_body = json.loads(text)
                    except json.JSONDecodeError:
                        request_body = text
                else:
                    request_body = text

        resp_content_type = ""
        response_mime = response.get("content", {}).get("mimeType", "")
        for header in response.get("headers", []):
            if header.get("name", "").lower() == "content-type":
                resp_content_type = header.get("value", "").lower()
                break
        if not resp_content_type and response_mime:
            resp_content_type = response_mime

        status = response.get("status", 0)
        is_api = (
            "json" in resp_content_type
            or "xml" in resp_content_type
            or _is_api_path(url)
        )

        auth_schemes = []
        auth_placeholders = {"headers": {}}
        if "authorization" in auth_headers:
            auth_val = auth_headers["authorization"]
            if auth_val.lower().startswith("bearer "):
                auth_schemes.append({
                    "id": "bearer",
                    "type": "http",
                    "scheme": "bearer",
                    "in": "header",
                    "name": "Authorization",
                    "bearer_format": "JWT",
                })
                auth_placeholders["headers"]["Authorization"] = "Bearer <TOKEN>"
            elif auth_val.lower().startswith("basic "):
                auth_schemes.append({
                    "id": "basic",
                    "type": "http",
                    "scheme": "basic",
                    "in": "header",
                    "name": "Authorization",
                })
                auth_placeholders["headers"]["Authorization"] = "Basic <CREDENTIALS>"

        for key in ("x-api-key", "api-key", "x-auth-token"):
            if key in auth_headers:
                auth_schemes.append({
                    "id": key,
                    "type": "apiKey",
                    "scheme": "",
                    "in": "header",
                    "name": key,
                })
                auth_placeholders["headers"][key] = f"<{key.upper().replace('-', '_')}>"
                break

        endpoints.append({
            "url": url,
            "method": method,
            "status": status,
            "content_type": resp_content_type or "application/json",
            "is_api": is_api,
            "body_preview": "",
            "request_body": request_body,
            "request_body_content_type": content_type,
            "auth_schemes": auth_schemes,
            "auth_placeholders": auth_placeholders,
            "source": "har",
            "path": parsed.path,
        })

    return endpoints


def extract_auth_tokens(har_data):
    """Extract authentication headers and tokens discovered in HAR traffic.

    Returns dict of token_type -> list of token values found.
    """
    if not har_data:
        return {}

    tokens = defaultdict(set)
    entries = har_data.get("log", {}).get("entries", [])

    for entry in entries:
        request = entry.get("request", {})
        for header in request.get("headers", []):
            name = header.get("name", "").lower()
            value = header.get("value", "")
            if not value:
                continue
            if name == "authorization":
                parts = value.split(" ", 1)
                scheme = parts[0].lower() if parts else ""
                if scheme == "bearer":
                    tokens["bearer"].add(parts[1][:40] + "..." if len(parts) > 1 else value)
                elif scheme == "basic":
                    tokens["basic"].add(parts[1][:30] + "..." if len(parts) > 1 else value)
                else:
                    tokens[name].add(value[:40])
            elif name in AUTH_HEADER_KEYS:
                tokens[name].add(value[:40])

    return {k: sorted(v) for k, v in tokens.items()}


def summarize_har(har_data):
    """Generate a summary of the API surface discovered in HAR data."""
    if not har_data:
        return {}

    entries = har_data.get("log", {}).get("entries", [])
    endpoints = extract_endpoints_from_har(har_data)
    auth_tokens = extract_auth_tokens(har_data)

    methods = defaultdict(int)
    domains = set()
    total_requests = len(entries)
    api_requests = 0

    for entry in entries:
        request = entry.get("request", {})
        method = request.get("method", "GET")
        methods[method] += 1
        parsed = urlparse(request.get("url", ""))
        domains.add(parsed.netloc)

        if not _is_static_resource(request.get("url", "")) and (
            _is_api_path(request.get("url", "")) or method in ("POST", "PUT", "PATCH")
        ):
            api_requests += 1

    return {
        "total_requests": total_requests,
        "api_requests": api_requests,
        "unique_endpoints": len(endpoints),
        "domains": sorted(domains),
        "methods": dict(methods),
        "auth_tokens_found": list(auth_tokens.keys()),
        "endpoints": endpoints,
        "auth_tokens": auth_tokens,
    }


def find_hidden_endpoints(har_endpoints, openapi_endpoint_urls):
    """Find endpoints discovered in HAR that are NOT in the OpenAPI spec.

    Args:
        har_endpoints: list of endpoint dicts from HAR analysis
        openapi_endpoint_urls: set of URL strings from OpenAPI spec parsing

    Returns:
        List of endpoints unique to HAR traffic (hidden/undocumented).
    """
    hidden = []
    for ep in har_endpoints:
        url = ep.get("url", "")
        normalized = _normalize_path(urlparse(url).path)
        if normalized not in openapi_endpoint_urls and url not in openapi_endpoint_urls:
            hidden.append(ep)
    return hidden


def analyze_har_file(har_path, base_url=None):
    """Full HAR analysis: parse, extract endpoints, summarize, return findings.

    Returns a dict with keys: summary, endpoints, hidden_endpoints, findings.
    """
    har_data = parse_har_file(har_path)
    if not har_data:
        return None

    summary = summarize_har(har_data)
    endpoints = summary.get("endpoints", [])

    log_success(f"HAR analysis: {summary['total_requests']} requests, "
                f"{len(endpoints)} unique API endpoints, "
                f"{len(summary['domains'])} domains")

    if summary.get("auth_tokens_found"):
        log_info(f"Auth tokens/headers found: {', '.join(summary['auth_tokens_found'])}")

    findings = []
    for ep in endpoints:
        if ep.get("auth_schemes"):
            scheme_names = [s.get("id", "") for s in ep["auth_schemes"]]
            findings.append({
                "type": "HAR_Auth_Discovered",
                "severity": "INFO",
                "url": ep["url"],
                "description": f"HAR traffic revealed auth: {', '.join(scheme_names)} at {ep['method']} {ep['path']}",
                "evidence": f"Auth headers observed in recorded traffic for {ep['method']} {ep['url']}",
            })

    auth_tokens = summary.get("auth_tokens", {})
    if auth_tokens.get("bearer"):
        findings.append({
            "type": "HAR_Bearer_Token",
            "severity": "WARNING",
            "url": base_url or "",
            "description": f"Bearer token(s) observed in recorded traffic ({len(auth_tokens['bearer'])} unique)",
            "evidence": "JWT/opaque bearer tokens captured; validate expiry and scope.",
        })

    return {
        "summary": summary,
        "endpoints": endpoints,
        "findings": findings,
    }
