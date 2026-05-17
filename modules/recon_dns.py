"""Deep DNS enumeration — AXFR / SPF / DKIM / DMARC / CAA / records / reverse.

Most "subdomain enum" tools stop at A/CNAME resolution; the high-value
findings live in the metadata records:

* **AXFR** still surprisingly works on misconfigured internal zones.
* **SPF + DKIM + DMARC** misconfigurations enable email spoofing — high
  business impact, often invisible to non-email-focused scanners.
* **CAA** absence (or permissive policy) is a precondition for many
  cert-misissuance scenarios.

We model the output as a single ``DnsReport`` dataclass so downstream
modules (subdomain_enum, takeover, brand monitoring) can consume one
authoritative source instead of re-querying. The class also surfaces a
``security_findings`` list pre-shaped for the project's vuln-dict
pipeline (``type``, ``url``, ``severity``, ``evidence``).

Only stdlib + dnspython — no external binaries, no async (top-level
sync; if a caller wants concurrency they can wrap us in ScanExecutor).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

import dns.exception
import dns.query
import dns.rdatatype
import dns.resolver
import dns.reversename
import dns.zone


# Conservative defaults — the SecLists DKIM selectors list is long, this
# subset covers Google Workspace, M365, Mailchimp, SendGrid, Mailgun, etc.
_COMMON_DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2", "k1", "k2", "mail",
    "smtp", "mailgun", "mailchimp", "sendgrid", "everlytickey1",
    "everlytickey2", "dkim", "20161025", "s1", "s2", "ses",
)


@dataclass
class DnsReport:
    domain: str
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    mx_records: list[tuple[int, str]] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    soa: Optional[str] = None
    spf: Optional[str] = None
    spf_includes: list[str] = field(default_factory=list)
    dmarc: Optional[str] = None
    caa: list[str] = field(default_factory=list)
    dkim_selectors: dict[str, str] = field(default_factory=dict)
    axfr_results: dict[str, list[str]] = field(default_factory=dict)
    reverse_ptrs: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    security_findings: list[dict] = field(default_factory=list)

    def add_finding(
        self,
        type_: str,
        severity: str,
        evidence: str,
        cwe: str = "",
    ) -> None:
        self.security_findings.append({
            "type": type_,
            "url": self.domain,
            "severity": severity,
            "evidence": evidence,
            "cwe": cwe,
            "module": "recon_dns",
        })


def _resolve(
    resolver: dns.resolver.Resolver,
    name: str,
    rdtype: str,
) -> list:
    """Tolerant lookup — returns [] on NXDOMAIN/NoAnswer/timeout."""
    try:
        return list(resolver.resolve(name, rdtype, lifetime=5))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        return []
    except Exception:  # noqa: BLE001
        return []


def _attempt_axfr(domain: str, nameserver: str, timeout: float = 4.0) -> list[str]:
    """Try a zone transfer; return the list of names on success, [] on failure."""
    try:
        xfr = dns.query.xfr(nameserver, domain, lifetime=timeout)
        zone = dns.zone.from_xfr(xfr)
    except Exception:  # noqa: BLE001
        return []
    names = []
    for name, _node in zone.nodes.items():
        names.append(name.to_text())
    return names


def _parse_spf(txt_records: list[str]) -> tuple[Optional[str], list[str]]:
    """Return (spf_record, list_of_include_targets)."""
    for record in txt_records:
        normalised = record.strip().strip('"')
        if normalised.lower().startswith("v=spf1"):
            includes = re.findall(r"include:([^\s]+)", normalised, flags=re.IGNORECASE)
            return normalised, includes
    return None, []


def _parse_dmarc(txt_records: list[str]) -> Optional[str]:
    for record in txt_records:
        normalised = record.strip().strip('"')
        if normalised.lower().startswith("v=dmarc1"):
            return normalised
    return None


def _stringify_txt(rdata) -> str:
    """dnspython TXT rdata → cleaned string ('"chunk1" "chunk2"' → 'chunk1chunk2')."""
    try:
        parts = [s.decode("utf-8", "ignore") if isinstance(s, (bytes, bytearray))
                 else str(s) for s in rdata.strings]
        return "".join(parts)
    except AttributeError:
        return rdata.to_text().strip('"')


def deep_dns_enum(
    domain: str,
    *,
    resolver: Optional[dns.resolver.Resolver] = None,
    dkim_selectors: Optional[tuple[str, ...]] = None,
    attempt_axfr: bool = True,
    attempt_reverse: bool = True,
) -> DnsReport:
    """Single-call deep DNS report on ``domain``.

    The resolver is injectable for unit-test mocking. All network
    failures are caught and surfaced as ``errors`` rather than raised.
    """
    res = resolver or dns.resolver.Resolver()
    selectors = dkim_selectors or _COMMON_DKIM_SELECTORS
    report = DnsReport(domain=domain)

    # ── Basic record types ─────────────────────────────────────────────────
    for record_type in ("A", "AAAA", "NS", "MX", "TXT", "SOA", "CAA"):
        rdata = _resolve(res, domain, record_type)
        if not rdata:
            continue
        if record_type == "A":
            report.a_records = [r.address for r in rdata]
        elif record_type == "AAAA":
            report.aaaa_records = [r.address for r in rdata]
        elif record_type == "NS":
            report.ns_records = [r.target.to_text().rstrip(".") for r in rdata]
        elif record_type == "MX":
            report.mx_records = [
                (int(r.preference), r.exchange.to_text().rstrip("."))
                for r in rdata
            ]
        elif record_type == "TXT":
            report.txt_records = [_stringify_txt(r) for r in rdata]
        elif record_type == "SOA":
            report.soa = rdata[0].to_text()
        elif record_type == "CAA":
            report.caa = [r.to_text() for r in rdata]

    # ── SPF + DMARC ────────────────────────────────────────────────────────
    spf, includes = _parse_spf(report.txt_records)
    report.spf = spf
    report.spf_includes = includes

    if spf is None:
        report.add_finding(
            "Missing_SPF",
            "medium",
            f"No SPF record present on {domain}; permits email spoofing.",
            cwe="CWE-290",
        )
    elif "+all" in spf or spf.rstrip().endswith("?all"):
        report.add_finding(
            "Weak_SPF_Policy",
            "high",
            f"SPF policy ends with '+all' or '?all': {spf!r}",
            cwe="CWE-290",
        )

    dmarc_records = _resolve(res, f"_dmarc.{domain}", "TXT")
    if dmarc_records:
        dmarc_strings = [_stringify_txt(r) for r in dmarc_records]
        report.dmarc = _parse_dmarc(dmarc_strings)

    if not report.dmarc:
        report.add_finding(
            "Missing_DMARC",
            "medium",
            f"No DMARC record found at _dmarc.{domain}.",
            cwe="CWE-290",
        )
    elif "p=none" in report.dmarc.lower():
        report.add_finding(
            "Weak_DMARC_Policy",
            "low",
            f"DMARC policy is 'p=none' (monitor only): {report.dmarc!r}",
            cwe="CWE-290",
        )

    # ── DKIM selector brute ────────────────────────────────────────────────
    for selector in selectors:
        rdata = _resolve(res, f"{selector}._domainkey.{domain}", "TXT")
        if rdata:
            value = " ".join(_stringify_txt(r) for r in rdata)
            report.dkim_selectors[selector] = value

    # ── CAA absence is informational, not always a vuln ────────────────────
    if not report.caa:
        report.add_finding(
            "Missing_CAA",
            "low",
            f"No CAA record set on {domain}; any CA may issue certificates.",
            cwe="CWE-295",
        )

    # ── AXFR attempt on each nameserver ────────────────────────────────────
    if attempt_axfr:
        for ns in report.ns_records:
            try:
                ns_ips = _resolve(res, ns, "A")
                if not ns_ips:
                    continue
                names = _attempt_axfr(domain, ns_ips[0].address)
                if names:
                    report.axfr_results[ns] = names
                    report.add_finding(
                        "DNS_Zone_Transfer_Allowed",
                        "high",
                        f"AXFR succeeded against nameserver {ns} "
                        f"(exposed {len(names)} records).",
                        cwe="CWE-200",
                    )
            except Exception as exc:  # noqa: BLE001
                report.errors.append(f"AXFR error on {ns}: {exc}")

    # ── Reverse DNS for every A record ─────────────────────────────────────
    if attempt_reverse:
        for ip in report.a_records:
            try:
                rev = dns.reversename.from_address(ip)
                rdata = _resolve(res, rev.to_text(), "PTR")
                if rdata:
                    report.reverse_ptrs[ip] = rdata[0].target.to_text().rstrip(".")
            except Exception as exc:  # noqa: BLE001
                report.errors.append(f"PTR error on {ip}: {exc}")

    return report
