"""Multi-source subdomain enumeration orchestrator.

Replaces ``modules.recon.scan_subdomains`` (crt.sh only) with a union
over every passive source plus optional DNS brute. Each source is
opt-in via the ``sources`` parameter; missing binaries / API failures
are absorbed into ``SubdomainReport.source_errors`` rather than
breaking the run.

Discovery sources (passive — no traffic to target):
  * **crt.sh**       — Certificate Transparency (free, no API key)
  * **CertSpotter**  — SSLMate CT API (free tier, no key required)
  * **subfinder**    — ProjectDiscovery binary, dozens of upstreams
  * **amass**        — OWASP project, passive mode
  * **assetfinder**  — tomnomnom, focused on the common sources

Discovery sources (active — touches DNS):
  * **dns_brute**    — query each ``{word}.{domain}`` for an A record

Optional post-filter: ``live_resolve=True`` keeps only names that resolve
to an A record at scan time (deduplicates parked / stale CT entries).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from utils.colors import log_info, log_success, log_warning


DEFAULT_SOURCES: tuple[str, ...] = (
    "crtsh", "certspotter", "subfinder", "amass", "assetfinder",
)


@dataclass
class SubdomainReport:
    domain: str
    subdomains: frozenset[str] = field(default_factory=frozenset)
    per_source: dict[str, frozenset[str]] = field(default_factory=dict)
    source_errors: dict[str, str] = field(default_factory=dict)
    live_resolved: frozenset[str] = field(default_factory=frozenset)

    def union_in(self, source: str, names: Iterable[str]) -> None:
        bucket = frozenset(n for n in names if n)
        self.per_source[source] = bucket
        self.subdomains = self.subdomains | bucket


# ── Passive sources ─────────────────────────────────────────────────────────


def _query_crtsh(domain: str, *, http_get: Callable, timeout: float = 20.0) -> frozenset[str]:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    response = http_get(url, timeout=timeout)
    if getattr(response, "status_code", 0) != 200:
        return frozenset()
    try:
        data = response.json()
    except (ValueError, TypeError):
        return frozenset()
    out: set[str] = set()
    for cert in data or []:
        name_value = cert.get("name_value", "")
        for raw in str(name_value).split("\n"):
            name = raw.strip().lower()
            if name.startswith("*."):
                name = name[2:]
            if name and name.endswith(domain) and name != domain:
                out.add(name)
    return frozenset(out)


def _query_certspotter(domain: str, *, http_get: Callable, timeout: float = 20.0) -> frozenset[str]:
    url = (
        f"https://api.certspotter.com/v1/issuances?domain={domain}"
        "&include_subdomains=true&expand=dns_names"
    )
    response = http_get(url, timeout=timeout)
    if getattr(response, "status_code", 0) != 200:
        return frozenset()
    try:
        data = response.json()
    except (ValueError, TypeError):
        return frozenset()
    out: set[str] = set()
    for entry in data or []:
        for raw in entry.get("dns_names", []) or []:
            name = str(raw).strip().lower()
            if name.startswith("*."):
                name = name[2:]
            if name and name.endswith(domain) and name != domain:
                out.add(name)
    return frozenset(out)


# ── DNS brute ────────────────────────────────────────────────────────────────


def _dns_brute(
    domain: str,
    wordlist: Iterable[str],
    *,
    resolve_one: Callable[[str], bool],
) -> frozenset[str]:
    out: set[str] = set()
    for word in wordlist:
        candidate = f"{word.strip().lower()}.{domain}"
        if candidate == domain:
            continue
        if resolve_one(candidate):
            out.add(candidate)
    return frozenset(out)


def _default_resolve_one(name: str) -> bool:
    """Try an A lookup, return True if it resolves. Lazy import dns to keep
    test fixtures that monkeypatch resolve_one cheap."""
    try:
        import dns.resolver
        dns.resolver.Resolver().resolve(name, "A", lifetime=2)
        return True
    except Exception:  # noqa: BLE001
        return False


# ── Orchestrator ────────────────────────────────────────────────────────────


def enumerate_subdomains(
    domain: str,
    *,
    sources: Iterable[str] = DEFAULT_SOURCES,
    http_get: Optional[Callable] = None,
    brute_wordlist: Optional[Iterable[str]] = None,
    resolve_one: Optional[Callable[[str], bool]] = None,
    live_resolve: bool = False,
) -> SubdomainReport:
    """Union every requested source's findings into a single report.

    ``http_get`` is injectable so unit tests can drive the API parsers
    without real network. When omitted, an httpx Client is used.
    """
    domain = (domain or "").strip().lower().rstrip(".")
    report = SubdomainReport(domain=domain)

    if not domain or domain.replace(".", "").isnumeric():
        log_warning("Subdomain enum skipped (empty or IP target)")
        return report

    if http_get is None:
        import httpx
        client = httpx.Client(timeout=20.0, trust_env=False, follow_redirects=True)
        http_get = client.get
    else:
        client = None

    enabled = set(sources)

    try:
        if "crtsh" in enabled:
            try:
                report.union_in("crtsh", _query_crtsh(domain, http_get=http_get))
            except Exception as exc:  # noqa: BLE001
                report.source_errors["crtsh"] = f"{type(exc).__name__}: {exc}"

        if "certspotter" in enabled:
            try:
                report.union_in("certspotter", _query_certspotter(domain, http_get=http_get))
            except Exception as exc:  # noqa: BLE001
                report.source_errors["certspotter"] = f"{type(exc).__name__}: {exc}"

        if "subfinder" in enabled:
            from utils.recon_tools import run_subfinder
            result = run_subfinder(domain)
            report.union_in("subfinder", result.subdomains)
            if not result.succeeded and result.error:
                report.source_errors["subfinder"] = result.error

        if "amass" in enabled:
            from utils.recon_tools import run_amass
            result = run_amass(domain, passive=True)
            report.union_in("amass", result.subdomains)
            if not result.succeeded and result.error:
                report.source_errors["amass"] = result.error

        if "assetfinder" in enabled:
            from utils.recon_tools import run_assetfinder
            result = run_assetfinder(domain)
            report.union_in("assetfinder", result.subdomains)
            if not result.succeeded and result.error:
                report.source_errors["assetfinder"] = result.error

        if brute_wordlist:
            try:
                report.union_in(
                    "dns_brute",
                    _dns_brute(
                        domain,
                        brute_wordlist,
                        resolve_one=resolve_one or _default_resolve_one,
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                report.source_errors["dns_brute"] = f"{type(exc).__name__}: {exc}"

        if live_resolve and report.subdomains:
            checker = resolve_one or _default_resolve_one
            report.live_resolved = frozenset(
                name for name in report.subdomains if checker(name)
            )
    finally:
        if client is not None:
            client.close()

    if report.subdomains:
        log_success(
            f"Subdomain enum: {len(report.subdomains)} unique names from "
            f"{len([s for s in report.per_source if report.per_source[s]])} sources"
        )
    else:
        log_info("Subdomain enum: no names found")
    return report
