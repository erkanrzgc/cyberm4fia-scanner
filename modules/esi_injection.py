"""Edge Side Includes (ESI) injection probe — active-scan++ inspired.

ESI is a markup language processed by edge caches and reverse proxies
(Varnish, Akamai, Fastly, Squid, F5, CloudFront with Lambda@Edge). If
user input reaches an ESI-aware cache without sanitisation, an attacker
can inject ``<esi:include src="…">`` to:

* exfiltrate cookies from the request (``<esi:include src="…?$(HTTP_COOKIE)">``)
* SSRF via includes pointing at internal services
* XSS via includes that fetch attacker-controlled markup

Detection strategy: send each value-injection point a benign ESI tag
that wraps a unique random token and an out-of-band callback URL pattern.
Then check the response body — if the ESI block was *stripped or
processed* (token disappears while the surrounding content remains), the
cache layer parses ESI and the input is exploitable.

Lightweight: no actual OOB capture needed for detection. The tag
processing alone proves ESI is live.

Reference:
* https://www.gosecure.net/blog/2018/04/03/beyond-xss-edge-side-include-injection/
* https://github.com/PortSwigger/active-scan-plus-plus
"""

from __future__ import annotations

import logging
import random
import string
from typing import Iterable
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl

logger = logging.getLogger(__name__)


def _random_token(length: int = 10) -> str:
    return "esi" + "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _esi_payload(token: str) -> str:
    """Benign ESI tag that wraps a token — processing strips the tag."""
    # ``<esi:vars>...</esi:vars>`` is rendered by ESI engines as the inner
    # value. We embed a sentinel inside so we can detect:
    #   * raw token in body  → input reflected, ESI NOT processed
    #   * sentinel in body   → ESI processed, vulnerable
    #   * neither             → input dropped, not reachable
    return f"<esi:vars>{token}-INSIDE</esi:vars>"


def _send(method: str, url: str, *, params=None, data=None, headers=None):
    try:
        from utils.request import smart_request
    except ImportError:
        return None
    try:
        return smart_request(method, url, params=params, data=data, headers=headers)
    except Exception as exc:  # noqa: BLE001
        logger.debug("esi_injection request failed for %s: %s", url, exc)
        return None


def _scan_param(url: str, param_name: str, method: str = "get") -> dict | None:
    """Inject ESI tag into one URL/form param and look for processing."""
    token = _random_token()
    payload = _esi_payload(token)

    if method.lower() == "get":
        parsed = urlparse(url)
        qs = dict(parse_qsl(parsed.query))
        qs[param_name] = payload
        injected_url = urlunparse(parsed._replace(query=urlencode(qs)))
        r = _send("get", injected_url)
    else:
        r = _send(method.lower(), url, data={param_name: payload})

    if r is None:
        return None
    body = r.text or ""

    # Two clear outcomes:
    #   ESI processed → tag stripped, sentinel (-INSIDE) remains (or token)
    #   ESI not processed → raw tag chars (<esi:vars>) reflected
    if "<esi:vars>" in body and token in body:
        return None  # raw reflection only — XSS, not ESI
    if f"{token}-INSIDE" in body and "<esi:vars>" not in body:
        return {
            "url": url,
            "param": param_name,
            "method": method.upper(),
            "payload": payload,
            "evidence": (
                f"ESI tag was processed: sentinel {token}-INSIDE "
                "appears in response without the surrounding <esi:vars> markup"
            ),
        }
    return None


def scan_esi(url: str, *, params: Iterable[str] = (), form_fields: Iterable[str] = ()) -> list[dict]:
    """Probe ``url`` for ESI injection across the given parameter list.

    ``params`` are GET query parameters; ``form_fields`` are POST body
    fields. When both are empty, the function probes a few common
    parameter names (q, search, page, name, id, msg) against GET.
    """
    if not params and not form_fields:
        params = ("q", "search", "page", "name", "id", "msg")

    findings: list[dict] = []
    for p in params:
        hit = _scan_param(url, p, method="get")
        if hit:
            findings.append({
                "type": "ESI_Injection",
                "url": hit["url"],
                "param": hit["param"],
                "method": hit["method"],
                "severity": "HIGH",
                "payload": hit["payload"],
                "evidence": hit["evidence"],
                "module": "esi_injection",
                "verification_state": "verified",
            })
    for f in form_fields:
        hit = _scan_param(url, f, method="post")
        if hit:
            findings.append({
                "type": "ESI_Injection",
                "url": hit["url"],
                "param": hit["param"],
                "method": hit["method"],
                "severity": "HIGH",
                "payload": hit["payload"],
                "evidence": hit["evidence"],
                "module": "esi_injection",
                "verification_state": "verified",
            })
    return findings
