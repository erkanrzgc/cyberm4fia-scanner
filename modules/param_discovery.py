"""
cyberm4fia-scanner - Hidden Parameter Discovery Engine
Discovers hidden GET/POST parameters on endpoints using differential analysis.

Strategy:
  1. Get baseline response for each endpoint
  2. Send requests with common param names + canary values
  3. Detect valid params via response diff (size, status, new headers, body change)
  4. Return enriched URLs with discovered params for exploit modules
"""

from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

from utils.colors import log_info, log_success
from utils.request import smart_request, ScanExceptions

# ── Common parameter names (high-signal, ordered by likelihood) ──────────
COMMON_PARAMS = [
    # Data/ID params (most likely to be accepted)
    "id", "page", "p", "q", "s", "search", "query", "keyword",
    "user", "username", "name", "email", "pass", "password",
    "file", "filename", "path", "dir", "folder", "doc", "document",
    "url", "uri", "link", "src", "source", "dest", "redirect",
    "return", "next", "goto", "continue", "returnUrl", "redirect_uri",
    "callback", "cb", "ref", "referrer",
    # Action params
    "action", "act", "cmd", "command", "exec", "run", "do",
    "type", "cat", "category", "sort", "order", "filter",
    "limit", "offset", "start", "count", "num", "size",
    "lang", "language", "locale", "l", "lg",
    # View/Template params
    "view", "template", "tpl", "theme", "layout", "style",
    "format", "output", "mode", "debug", "test", "dev",
    "include", "require", "load", "import", "module", "plugin",
    # API params
    "api_key", "apikey", "key", "token", "auth", "access_token",
    "secret", "hash", "sig", "signature",
    "version", "v", "api", "method",
    "data", "body", "payload", "input", "value", "val",
    "json", "xml", "raw",
    # Database params
    "table", "db", "database", "column", "col", "field",
    "select", "where", "from", "join",
    # File operation params
    "upload", "download", "read", "write", "delete", "edit",
    "create", "update", "remove", "save",
    "image", "img", "photo", "pic", "avatar", "icon",
    "attachment", "media", "content",
    # Config params
    "config", "conf", "setting", "settings", "option", "options",
    "param", "parameter", "var", "variable",
    # Misc high-value params
    "admin", "root", "system", "internal", "private",
    "proxy", "host", "port", "ip", "address",
    "domain", "subdomain", "site", "server",
    "log", "error", "trace", "verbose",
    "redir", "location", "target", "to", "from",
    "channel", "topic", "message", "msg",
    "item", "product", "price", "qty", "quantity",
    "year", "month", "day", "date", "time", "timestamp",
]

# Canary value for detection
CANARY = "cybm4f1a_d1sc0v3ry"
CANARY_INT = "13371337"


def _calculate_similarity(text1, text2):
    """Quick similarity ratio based on length and shared lines."""
    if not text1 and not text2:
        return 1.0
    if not text1 or not text2:
        return 0.0

    len_ratio = min(len(text1), len(text2)) / max(len(text1), len(text2))

    # Quick line-based check
    lines1 = set(text1.split("\n")[:50])
    lines2 = set(text2.split("\n")[:50])
    if lines1 and lines2:
        intersection = lines1 & lines2
        union = lines1 | lines2
        jaccard = len(intersection) / len(union) if union else 1.0
    else:
        jaccard = len_ratio

    return (len_ratio + jaccard) / 2


async def _get_baseline(url, delay):
    """Get baseline response for differential comparison."""
    try:
        resp = smart_request("get", url, delay=delay)
        return {
            "status": resp.status_code,
            "size": len(resp.text),
            "headers": dict(resp.headers),
            "body": resp.text[:5000],  # Only keep first 5KB for comparison
        }
    except ScanExceptions:
        return None


async def _test_param_batch(url, params_batch, method, delay, baseline):
    """Test a batch of params against baseline."""
    found = []
    parsed = urlparse(url)

    for param_name in params_batch:
        try:
            if method == "get":
                # Add canary param to URL
                existing = parse_qs(parsed.query)
                existing[param_name] = CANARY
                test_url = urlunparse(
                    parsed._replace(query=urlencode(existing, doseq=True))
                )
                resp = smart_request("get", test_url, delay=delay)
            else:
                # POST with param
                data = {param_name: CANARY}
                resp = smart_request("post", url, data=data, delay=delay)

            # ── Differential Analysis ──
            is_different = False
            reason = ""

            # 1. Status code change (significant)
            if resp.status_code != baseline["status"]:
                # 404 → 200 or 200 → 302 etc = param accepted
                if resp.status_code not in [403, 429, 503]:
                    is_different = True
                    reason = f"status:{baseline['status']}→{resp.status_code}"

            # 2. Response size difference (> 10% change)
            size_diff = abs(len(resp.text) - baseline["size"])
            size_ratio = size_diff / max(baseline["size"], 1)
            if size_ratio > 0.10 and size_diff > 50:
                is_different = True
                reason = f"size_delta:{size_diff}B ({size_ratio:.0%})"

            # 3. New headers appeared
            new_headers = set(resp.headers.keys()) - set(baseline["headers"].keys())
            interesting_headers = {
                h for h in new_headers
                if h.lower() not in ["date", "age", "x-request-id", "x-trace-id",
                                      "cf-ray", "x-cache", "x-cache-hits"]
            }
            if interesting_headers:
                is_different = True
                reason = f"new_headers:{','.join(interesting_headers)}"

            # 4. Body content similarity check
            if not is_different and baseline["body"]:
                similarity = _calculate_similarity(
                    resp.text[:5000], baseline["body"]
                )
                if similarity < 0.85:
                    is_different = True
                    reason = f"body_diff:{similarity:.2f}"

            # 5. Canary reflection (param value appears in response)
            if CANARY in resp.text:
                is_different = True
                reason = "reflected"

            # 6. Error indicators (param triggered an error)
            error_indicators = [
                "missing", "required", "invalid", "error",
                "undefined", "null", "exception", "traceback",
                "warning:", "notice:", "fatal",
            ]
            resp_lower = resp.text.lower()[:3000]
            if not is_different:
                for indicator in error_indicators:
                    if indicator in resp_lower and indicator not in baseline["body"].lower()[:3000]:
                        is_different = True
                        reason = f"error_leak:{indicator}"
                        break

            if is_different:
                found.append({
                    "param": param_name,
                    "method": method,
                    "reason": reason,
                    "status": resp.status_code,
                })

        except ScanExceptions:
            continue

    return found


async def async_discover_params(urls, delay, options=None):
    """
    Discover hidden parameters on a list of URLs.

    Returns list of enriched URLs with discovered params:
        [{"url": "https://...", "params": [{"name": "id", ...}], ...}]
    """
    options = options or {}
    max_params_per_url = options.get("param_discovery_limit", 120)
    all_discovered = []

    # Only test URLs that don't already have params
    paramless_urls = []
    for url in urls:
        parsed = urlparse(url)
        if not parsed.query:
            paramless_urls.append(url)

    if not paramless_urls:
        return []

    # Limit to avoid excessive scanning
    test_urls = paramless_urls[:15]  # Max 15 endpoints

    log_info(
        f"🔍 Starting Hidden Parameter Discovery on "
        f"{len(test_urls)} endpoint(s)..."
    )

    params_to_test = COMMON_PARAMS[:max_params_per_url]

    for url in test_urls:
        # Get baseline
        baseline = await _get_baseline(url, delay)
        if not baseline:
            continue

        # Test GET params in batches
        found_params = []

        batch_size = 20
        for i in range(0, len(params_to_test), batch_size):
            batch = params_to_test[i : i + batch_size]
            batch_results = await _test_param_batch(
                url, batch, "get", delay, baseline
            )
            found_params.extend(batch_results)

            # Early stop if we found enough
            if len(found_params) >= 5:
                break

        # Also test POST if no GET params found
        if not found_params:
            post_params = [
                p for p in params_to_test[:40]
                if p in [
                    "id", "q", "search", "query", "file", "path",
                    "url", "cmd", "action", "data", "input", "name",
                    "username", "password", "email", "user", "debug",
                    "template", "view", "include", "page", "lang",
                ]
            ]
            for i in range(0, len(post_params), batch_size):
                batch = post_params[i : i + batch_size]
                batch_results = await _test_param_batch(
                    url, batch, "post", delay, baseline
                )
                found_params.extend(batch_results)
                if found_params:
                    break

        if found_params:
            log_success(
                f"  💎 Found {len(found_params)} hidden param(s) on "
                f"{urlparse(url).path}: "
                f"{', '.join(p['param'] for p in found_params[:5])}"
            )
            all_discovered.append({
                "url": url,
                "params": found_params,
            })

    if all_discovered:
        total = sum(len(d["params"]) for d in all_discovered)
        log_success(
            f"🔍 Parameter discovery complete: {total} param(s) "
            f"across {len(all_discovered)} endpoint(s)"
        )
    else:
        log_info("🔍 No hidden parameters discovered.")

    return all_discovered


def build_enriched_urls(discovered):
    """Convert discovered params to enriched URLs for exploit modules."""
    enriched = []
    for entry in discovered:
        url = entry["url"]
        for param_info in entry["params"]:
            if param_info["method"] == "get":
                parsed = urlparse(url)
                enriched_url = urlunparse(
                    parsed._replace(
                        query=urlencode({param_info["param"]: "1"})
                    )
                )
                enriched.append(enriched_url)
    return enriched
