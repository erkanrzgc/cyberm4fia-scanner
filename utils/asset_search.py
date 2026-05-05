"""
cyberm4fia-scanner - Multi-Provider Asset Search

Unified interface over 7 internet-asset search engines (Shodan parallels):
  Censys, ZoomEye, FOFA, Onyphe, Netlas, FullHunt, LeakIX.

API keys read from environment. Providers without a key are skipped silently
(except LeakIX which has a public unauthenticated tier).

Each provider returns a normalized dict:
    {
        "provider": str,
        "ip": str | None,
        "host": str,
        "ports": list[int],
        "services": list[dict],
        "vulns": list[str],
        "hostnames": list[str],
        "tags": list[str],
        "asn": str | None,
        "country": str | None,
        "raw": dict,            # provider-native payload
    }
"""

from __future__ import annotations

import base64
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable
from urllib.parse import urlparse

from utils.colors import log_info, log_success, log_warning
from utils.request import smart_request, ScanExceptions


_TIMEOUT = 12


def _empty_result(provider: str, host: str) -> dict:
    return {
        "provider": provider,
        "ip": None,
        "host": host,
        "ports": [],
        "services": [],
        "vulns": [],
        "hostnames": [],
        "tags": [],
        "asn": None,
        "country": None,
        "raw": {},
    }


def _safe_get(url: str, *, headers: dict | None = None, params: dict | None = None) -> dict | None:
    try:
        resp = smart_request(
            "get", url, headers=headers, params=params, timeout=_TIMEOUT
        )
        if resp.status_code == 200:
            return resp.json()
    except (ScanExceptions, ValueError):
        return None
    return None


def _safe_post(url: str, *, headers: dict | None = None, json: dict | None = None) -> dict | None:
    try:
        resp = smart_request(
            "post", url, headers=headers, json=json, timeout=_TIMEOUT
        )
        if resp.status_code == 200:
            return resp.json()
    except (ScanExceptions, ValueError):
        return None
    return None


# ─── Censys (search.censys.io) ────────────────────────────────────────────
def censys_lookup(host: str) -> dict:
    """Censys Search v2 — requires CENSYS_API_ID + CENSYS_API_SECRET."""
    result = _empty_result("censys", host)
    api_id = os.environ.get("CENSYS_API_ID")
    api_secret = os.environ.get("CENSYS_API_SECRET")
    if not (api_id and api_secret):
        return result

    token = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
    headers = {"Authorization": f"Basic {token}"}
    data = _safe_get(
        f"https://search.censys.io/api/v2/hosts/{host}", headers=headers
    )
    if not data or "result" not in data:
        return result

    payload = data["result"]
    services = payload.get("services") or []
    result["raw"] = payload
    result["ip"] = payload.get("ip")
    result["ports"] = sorted({s.get("port") for s in services if s.get("port")})
    result["services"] = [
        {"port": s.get("port"), "service": s.get("service_name"),
         "transport": s.get("transport_protocol")}
        for s in services
    ]
    result["asn"] = (payload.get("autonomous_system") or {}).get("name")
    result["country"] = (payload.get("location") or {}).get("country")
    result["hostnames"] = payload.get("dns", {}).get("names", []) or []
    return result


# ─── ZoomEye (api.zoomeye.org) ─────────────────────────────────────────────
def zoomeye_lookup(host: str) -> dict:
    """ZoomEye — requires ZOOMEYE_API_KEY."""
    result = _empty_result("zoomeye", host)
    api_key = os.environ.get("ZOOMEYE_API_KEY")
    if not api_key:
        return result

    headers = {"API-KEY": api_key}
    data = _safe_get(
        "https://api.zoomeye.org/host/search",
        headers=headers,
        params={"query": f"ip:{host}"},
    )
    if not data or "matches" not in data:
        return result

    matches = data.get("matches", [])
    result["raw"] = data
    ports, services, hostnames = set(), [], set()
    for match in matches:
        port = match.get("portinfo", {}).get("port")
        if port:
            ports.add(port)
            services.append({
                "port": port,
                "service": match.get("portinfo", {}).get("service"),
                "banner": match.get("portinfo", {}).get("banner", "")[:200],
            })
        for name in match.get("rdns", []) if isinstance(match.get("rdns"), list) else []:
            hostnames.add(name)
    result["ports"] = sorted(ports)
    result["services"] = services
    result["hostnames"] = sorted(hostnames)
    return result


# ─── FOFA (fofa.info) ──────────────────────────────────────────────────────
def fofa_lookup(host: str) -> dict:
    """FOFA — requires FOFA_EMAIL + FOFA_API_KEY."""
    result = _empty_result("fofa", host)
    email = os.environ.get("FOFA_EMAIL")
    api_key = os.environ.get("FOFA_API_KEY")
    if not (email and api_key):
        return result

    qbase64 = base64.b64encode(f'ip="{host}"'.encode()).decode()
    data = _safe_get(
        "https://fofa.info/api/v1/search/all",
        params={
            "email": email,
            "key": api_key,
            "qbase64": qbase64,
            "size": 100,
            "fields": "host,ip,port,protocol,server,title,country",
        },
    )
    if not data or data.get("error"):
        return result

    rows = data.get("results", [])
    result["raw"] = data
    ports, services, hostnames = set(), [], set()
    for row in rows:
        # row order matches fields= above
        host_field, ip, port, protocol, server, title, country = (row + [None] * 7)[:7]
        if port:
            try:
                ports.add(int(port))
            except (TypeError, ValueError):
                pass
        services.append({
            "port": port, "protocol": protocol, "server": server, "title": title,
        })
        if host_field:
            hostnames.add(host_field)
        if ip and not result["ip"]:
            result["ip"] = ip
        if country and not result["country"]:
            result["country"] = country
    result["ports"] = sorted(ports)
    result["services"] = services
    result["hostnames"] = sorted(hostnames)
    return result


# ─── Onyphe (onyphe.io) ────────────────────────────────────────────────────
def onyphe_lookup(host: str) -> dict:
    """Onyphe — requires ONYPHE_API_KEY."""
    result = _empty_result("onyphe", host)
    api_key = os.environ.get("ONYPHE_API_KEY")
    if not api_key:
        return result

    headers = {"Authorization": f"bearer {api_key}"}
    data = _safe_get(
        f"https://www.onyphe.io/api/v2/summary/host/{host}", headers=headers
    )
    if not data or data.get("status") != "ok":
        return result

    results = data.get("results", [])
    result["raw"] = data
    ports, vulns, hostnames, tags = set(), set(), set(), set()
    for row in results:
        if row.get("port"):
            ports.add(row["port"])
        for cve in row.get("cve", []) or []:
            vulns.add(cve)
        for h in row.get("hostname", []) or []:
            hostnames.add(h)
        for tag in row.get("tag", []) or []:
            tags.add(tag)
        if row.get("asn") and not result["asn"]:
            result["asn"] = row["asn"]
        if row.get("country") and not result["country"]:
            result["country"] = row["country"]
        if row.get("ip") and not result["ip"]:
            result["ip"] = row["ip"]
    result["ports"] = sorted(ports)
    result["vulns"] = sorted(vulns)
    result["hostnames"] = sorted(hostnames)
    result["tags"] = sorted(tags)
    return result


# ─── Netlas (netlas.io) ────────────────────────────────────────────────────
def netlas_lookup(host: str) -> dict:
    """Netlas — requires NETLAS_API_KEY (free tier available)."""
    result = _empty_result("netlas", host)
    api_key = os.environ.get("NETLAS_API_KEY")
    if not api_key:
        return result

    headers = {"X-API-Key": api_key}
    data = _safe_get(
        "https://app.netlas.io/api/responses/",
        headers=headers,
        params={"q": f"host:{host}", "size": 50},
    )
    if not data or "items" not in data:
        return result

    items = data.get("items", [])
    result["raw"] = data
    ports, services, hostnames = set(), [], set()
    for item in items:
        node = item.get("data", {})
        port = node.get("port")
        if port:
            ports.add(port)
            services.append({
                "port": port,
                "protocol": node.get("protocol"),
                "host": node.get("host"),
            })
        if node.get("host"):
            hostnames.add(node["host"])
        if node.get("ip") and not result["ip"]:
            result["ip"] = node["ip"]
        geo = node.get("geo", {}) or {}
        if geo.get("country") and not result["country"]:
            result["country"] = geo["country"]
    result["ports"] = sorted(ports)
    result["services"] = services
    result["hostnames"] = sorted(hostnames)
    return result


# ─── FullHunt (fullhunt.io) ────────────────────────────────────────────────
def fullhunt_lookup(host: str) -> dict:
    """FullHunt — requires FULLHUNT_API_KEY (free tier available)."""
    result = _empty_result("fullhunt", host)
    api_key = os.environ.get("FULLHUNT_API_KEY")
    if not api_key:
        return result

    headers = {"X-API-KEY": api_key}
    data = _safe_get(
        f"https://fullhunt.io/api/v1/host/{host}", headers=headers
    )
    if not data or data.get("status") != 200:
        return result

    payload = data.get("results", {}) or data
    result["raw"] = data
    result["ip"] = payload.get("ip")
    result["ports"] = sorted(payload.get("ports", []) or [])
    result["hostnames"] = payload.get("dns", {}).get("a", []) or []
    result["tags"] = payload.get("tags", []) or []
    return result


# ─── LeakIX (leakix.net) ──────────────────────────────────────────────────
def leakix_lookup(host: str) -> dict:
    """LeakIX — public read tier; LEAKIX_API_KEY optional for higher quota."""
    result = _empty_result("leakix", host)
    headers = {"Accept": "application/json"}
    api_key = os.environ.get("LEAKIX_API_KEY")
    if api_key:
        headers["api-key"] = api_key

    data = _safe_get(f"https://leakix.net/host/{host}", headers=headers)
    if not data:
        return result

    services = data.get("Services", []) or []
    leaks = data.get("Leaks", []) or []
    result["raw"] = data
    ports = sorted({s.get("port") for s in services if s.get("port")})
    result["ports"] = ports
    result["services"] = [
        {"port": s.get("port"), "protocol": s.get("protocol"),
         "service": (s.get("service") or {}).get("name")}
        for s in services
    ]
    result["vulns"] = [leak.get("event_source") for leak in leaks if leak.get("event_source")]
    transport_tags: set[str] = set()
    for svc in services:
        transport = svc.get("transport")
        if isinstance(transport, list):
            transport_tags.update(str(t) for t in transport)
        elif transport:
            transport_tags.add(str(transport))
    result["tags"] = sorted(transport_tags)
    return result


_PROVIDERS: dict[str, Callable[[str], dict]] = {
    "censys": censys_lookup,
    "zoomeye": zoomeye_lookup,
    "fofa": fofa_lookup,
    "onyphe": onyphe_lookup,
    "netlas": netlas_lookup,
    "fullhunt": fullhunt_lookup,
    "leakix": leakix_lookup,
}


def _normalize_target(target: str) -> str:
    """Strip scheme/path so providers receive bare host or IP."""
    if "://" in target:
        return urlparse(target).hostname or target
    return target.split("/")[0]


def lookup_all_providers(
    target: str,
    *,
    providers: list[str] | None = None,
    max_workers: int = 4,
) -> list[dict]:
    """Run all configured providers in parallel; return non-empty results only."""
    host = _normalize_target(target)
    selected = providers or list(_PROVIDERS.keys())
    funcs = {name: _PROVIDERS[name] for name in selected if name in _PROVIDERS}
    if not funcs:
        return []

    log_info(f"AssetSearch: querying {len(funcs)} providers for {host}")
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(fn, host): name for name, fn in funcs.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                res = future.result()
            except Exception as exc:
                log_warning(f"AssetSearch[{name}] failed: {exc}")
                continue
            if res and (res["ports"] or res["vulns"] or res["hostnames"] or res["raw"]):
                results.append(res)
                log_success(
                    f"AssetSearch[{name}]: {len(res['ports'])} ports, "
                    f"{len(res['vulns'])} vulns, {len(res['hostnames'])} hostnames"
                )
    return results


def merge_results(results: list[dict]) -> dict:
    """Collapse multi-provider results into a single union view."""
    merged = {
        "providers": [r["provider"] for r in results],
        "ips": sorted({r["ip"] for r in results if r.get("ip")}),
        "ports": sorted({p for r in results for p in r.get("ports", [])}),
        "vulns": sorted({v for r in results for v in r.get("vulns", [])}),
        "hostnames": sorted({h for r in results for h in r.get("hostnames", [])}),
        "tags": sorted({t for r in results for t in r.get("tags", [])}),
        "services": [s for r in results for s in r.get("services", [])],
        "by_provider": {r["provider"]: r for r in results},
    }
    return merged
