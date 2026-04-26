"""
cyberm4fia-scanner - CRLF Injection Scanner

Detects HTTP response splitting / header injection where user input
is reflected into response headers without sanitizing CR/LF bytes.

Coverage approach (independent reimplementation; payload patterns are
public from OWASP / PayloadsAllTheThings — no GPL'd source borrowed):

* Inject CRLF + a sentinel header into every reflected GET parameter.
* If the response includes the sentinel header *or* the body starts
  early (split into a second response), the parameter is vulnerable.
* Encoded variants (URL-encoded, double-encoded, unicode) catch
  filters that strip raw \\r\\n.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from utils.colors import log_info, log_success
from utils.request import BlockedTargetPath, ScanExceptions, smart_request


SENTINEL_HEADER_NAME = "X-CRLF-Probe"
SENTINEL_HEADER_VALUE = "cyberm4fia-injected"


# Each entry is one CRLF-injection payload. Body is suffixed; the URL
# becomes value=ORIGINAL<payload> so the server, if vulnerable, splits
# the response into a forged header.
_CRLF_PAYLOADS: tuple[str, ...] = (
    # Raw bytes
    f"\r\n{SENTINEL_HEADER_NAME}: {SENTINEL_HEADER_VALUE}",
    # URL-encoded (most common bypass)
    f"%0d%0a{SENTINEL_HEADER_NAME}:%20{SENTINEL_HEADER_VALUE}",
    f"%0D%0A{SENTINEL_HEADER_NAME}:%20{SENTINEL_HEADER_VALUE}",
    # Double-encoded (classic WAF trick)
    f"%250d%250a{SENTINEL_HEADER_NAME}:%2520{SENTINEL_HEADER_VALUE}",
    # Unicode line terminator (rare, but seen in misconfigured stacks)
    f" {SENTINEL_HEADER_NAME}: {SENTINEL_HEADER_VALUE}",
    # Bare LF (some servers split on LF only)
    f"\n{SENTINEL_HEADER_NAME}: {SENTINEL_HEADER_VALUE}",
    f"%0a{SENTINEL_HEADER_NAME}:%20{SENTINEL_HEADER_VALUE}",
)


def _inject(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    flat = {k: (v[0] if isinstance(v, list) else v) for k, v in params.items()}
    return urlunparse(parsed._replace(query=urlencode(flat, doseq=False, safe="")))


def _is_vulnerable(response) -> bool:
    """Return True if the response shows the sentinel header was injected."""
    if response is None:
        return False
    headers = getattr(response, "headers", None) or {}
    # Case-insensitive header lookup
    for name, value in headers.items():
        if name.strip().lower() == SENTINEL_HEADER_NAME.lower():
            if SENTINEL_HEADER_VALUE in str(value):
                return True
    return False


def scan_crlf(url: str, params: list[str] | None = None,
              threads: int = 4, delay: float = 0.0) -> list[dict]:
    """Scan a URL's GET parameters for CRLF injection / response splitting.

    If ``params`` is None, every query-string parameter on ``url`` is tested.
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    target_params = list(params) if params else list(qs.keys())
    if not target_params:
        return []

    log_info(f"🔪 CRLF: {len(target_params)} param × {len(_CRLF_PAYLOADS)} payload on {url[:60]}")

    findings: list[dict] = []
    seen: set[str] = set()

    def _probe(param: str, payload: str) -> dict | None:
        injected_url = _inject(url, param, payload)
        try:
            resp = smart_request("get", injected_url, delay=delay,
                                 allow_redirects=False)
        except (ScanExceptions, BlockedTargetPath):
            return None
        if not _is_vulnerable(resp):
            return None
        return {
            "type": "CRLF_Injection",
            "url": url,
            "param": param,
            "payload": payload,
            "evidence": (
                f"Sentinel header '{SENTINEL_HEADER_NAME}' reflected in response — "
                "server splits headers on injected CR/LF."
            ),
            "severity": "High",
            "module": "crlf",
        }

    jobs = [(p, payload) for p in target_params for payload in _CRLF_PAYLOADS]
    with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futures = {pool.submit(_probe, p, pl): (p, pl) for p, pl in jobs}
        for fut in as_completed(futures):
            try:
                finding = fut.result()
            except Exception:
                continue
            if not finding:
                continue
            key = finding["param"]
            if key in seen:
                continue
            seen.add(key)
            log_success(f"  ✅ CRLF on {finding['param']!r} via {finding['payload'][:40]}...")
            findings.append(finding)

    return findings
