"""
cyberm4fia-scanner — Meta-Tooling Integration

Wraps external pentesting tools (nmap, sqlmap, nuclei) so the AI layer can
consume their output as structured Python objects instead of raw text.

Two layers per tool
-------------------
* ``parse_*`` functions take the raw stdout/file content and return a
  dataclass tree. They have no side effects and are easy to unit-test
  with fixture strings.
* ``run_*`` functions subprocess.run the binary if it's on PATH and then
  feed the output into the matching parser. They return ``None`` if the
  binary is missing rather than raising — meta-tooling is opt-in.

Adding a new tool: write the parser + an optional runner, expose them in
the public API at the bottom, and write fixture-based tests.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional


# ─── Nmap ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class NmapPort:
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""

    @property
    def is_open(self) -> bool:
        return self.state.lower() == "open"


@dataclass(frozen=True)
class NmapHost:
    address: str
    hostname: str = ""
    status: str = ""
    ports: tuple[NmapPort, ...] = ()

    @property
    def open_ports(self) -> tuple[NmapPort, ...]:
        return tuple(p for p in self.ports if p.is_open)


@dataclass(frozen=True)
class NmapScan:
    hosts: tuple[NmapHost, ...]
    args: str = ""

    @property
    def open_port_count(self) -> int:
        return sum(len(h.open_ports) for h in self.hosts)


def parse_nmap_xml(xml_text: str) -> NmapScan:
    """Parse ``nmap -oX`` XML output into a typed scan tree.

    Empty or malformed XML returns an empty scan (no hosts) rather than raising.
    """
    if not xml_text or not xml_text.strip():
        return NmapScan(hosts=(), args="")

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return NmapScan(hosts=(), args="")

    args = root.get("args", "")
    hosts: list[NmapHost] = []

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        status = status_el.get("state", "") if status_el is not None else ""

        addr_el = host_el.find("address")
        address = addr_el.get("addr", "") if addr_el is not None else ""

        hostname = ""
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        ports: list[NmapPort] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                service_el = port_el.find("service")
                try:
                    port_num = int(port_el.get("portid", "0"))
                except ValueError:
                    continue
                ports.append(NmapPort(
                    port=port_num,
                    protocol=port_el.get("protocol", "tcp"),
                    state=state_el.get("state", "") if state_el is not None else "",
                    service=service_el.get("name", "") if service_el is not None else "",
                    product=service_el.get("product", "") if service_el is not None else "",
                    version=service_el.get("version", "") if service_el is not None else "",
                ))

        hosts.append(NmapHost(
            address=address,
            hostname=hostname,
            status=status,
            ports=tuple(ports),
        ))

    return NmapScan(hosts=tuple(hosts), args=args)


def run_nmap(target: str, *, args: Optional[list[str]] = None,
             timeout: float = 60.0) -> Optional[NmapScan]:
    """Run nmap against ``target`` if the binary is present. Returns ``None``
    if nmap isn't installed or the run fails."""
    if not shutil.which("nmap"):
        return None
    cmd = ["nmap", "-oX", "-"]
    cmd.extend(args or ["-sV", "-T4"])
    cmd.append(target)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0 and not proc.stdout:
        return None
    return parse_nmap_xml(proc.stdout)


# ─── Nuclei ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class NucleiFinding:
    template_id: str
    name: str
    severity: str
    matched_at: str
    host: str = ""
    matcher_name: str = ""
    description: str = ""
    tags: tuple[str, ...] = ()
    cvss: float = 0.0
    raw: dict = field(default_factory=dict, hash=False, compare=False)

    @property
    def is_critical(self) -> bool:
        return self.severity.lower() in ("critical", "high")


def parse_nuclei_jsonl(jsonl_text: str) -> tuple[NucleiFinding, ...]:
    """Parse Nuclei ``-jsonl`` (one JSON object per line) into findings."""
    if not jsonl_text:
        return ()
    findings: list[NucleiFinding] = []
    for line in jsonl_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        info = obj.get("info") or {}
        classification = info.get("classification") or {}
        try:
            cvss = float(classification.get("cvss-score") or 0)
        except (TypeError, ValueError):
            cvss = 0.0
        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        findings.append(NucleiFinding(
            template_id=str(obj.get("template-id") or obj.get("templateID") or ""),
            name=str(info.get("name") or ""),
            severity=str(info.get("severity") or "info"),
            matched_at=str(obj.get("matched-at") or obj.get("matched") or ""),
            host=str(obj.get("host") or ""),
            matcher_name=str(obj.get("matcher-name") or ""),
            description=str(info.get("description") or ""),
            tags=tuple(str(t) for t in tags),
            cvss=cvss,
            raw=obj,
        ))
    return tuple(findings)


def run_nuclei(target: str, *, templates: Optional[list[str]] = None,
               timeout: float = 120.0) -> Optional[tuple[NucleiFinding, ...]]:
    """Run nuclei against ``target`` if installed. ``None`` on missing binary."""
    if not shutil.which("nuclei"):
        return None
    cmd = ["nuclei", "-u", target, "-jsonl", "-silent", "-disable-update-check"]
    if templates:
        for t in templates:
            cmd.extend(["-t", t])
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    return parse_nuclei_jsonl(proc.stdout or "")


# ─── SQLMap ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SqlmapInjection:
    parameter: str
    place: str
    technique: str
    payload: str = ""
    title: str = ""
    db_type: str = ""


@dataclass(frozen=True)
class SqlmapResult:
    target: str
    vulnerable: bool
    injections: tuple[SqlmapInjection, ...]
    db_type: str = ""

    @property
    def techniques_used(self) -> tuple[str, ...]:
        seen, out = set(), []
        for inj in self.injections:
            if inj.technique and inj.technique not in seen:
                seen.add(inj.technique)
                out.append(inj.technique)
        return tuple(out)


# Sqlmap doesn't emit a stable JSON file by default. The sustainable path is
# the API-mode JSON dump (``--results-file``/``--output-dir``) or the REST API.
# Both surface the same shape: a top-level dict with ``data``/``targets`` →
# ``injection`` arrays. We accept either the full API response or just the
# inner per-target dict.
def parse_sqlmap_json(json_text_or_obj) -> SqlmapResult:
    """Parse sqlmap API/log JSON into a structured result."""
    if isinstance(json_text_or_obj, (str, bytes)):
        try:
            data = json.loads(json_text_or_obj)
        except (json.JSONDecodeError, ValueError):
            return SqlmapResult(target="", vulnerable=False, injections=())
    else:
        data = json_text_or_obj

    if not isinstance(data, dict):
        return SqlmapResult(target="", vulnerable=False, injections=())

    # Drill into the most common envelopes.
    inner = data
    if "data" in data and isinstance(data["data"], dict):
        inner = data["data"]
    elif "targets" in data and isinstance(data["targets"], list) and data["targets"]:
        first = data["targets"][0]
        if isinstance(first, dict):
            inner = first

    target = str(inner.get("url") or inner.get("target") or data.get("url") or "")
    raw_injections = inner.get("injection") or inner.get("injections") or []
    if not isinstance(raw_injections, list):
        raw_injections = []

    injections: list[SqlmapInjection] = []
    db_type = str(inner.get("dbms") or inner.get("db") or "")

    for entry in raw_injections:
        if not isinstance(entry, dict):
            continue
        # sqlmap's per-injection shape varies slightly across versions;
        # we coalesce.
        techniques = entry.get("data") or {}
        if isinstance(techniques, dict):
            for tech_key, tech_val in techniques.items():
                if not isinstance(tech_val, dict):
                    continue
                injections.append(SqlmapInjection(
                    parameter=str(entry.get("parameter") or ""),
                    place=str(entry.get("place") or ""),
                    technique=str(tech_val.get("title") or tech_key),
                    payload=str(tech_val.get("payload") or ""),
                    title=str(tech_val.get("title") or ""),
                    db_type=db_type,
                ))
        else:
            injections.append(SqlmapInjection(
                parameter=str(entry.get("parameter") or ""),
                place=str(entry.get("place") or ""),
                technique=str(entry.get("technique") or ""),
                payload=str(entry.get("payload") or ""),
                title=str(entry.get("title") or ""),
                db_type=db_type,
            ))

    return SqlmapResult(
        target=target,
        vulnerable=bool(injections),
        injections=tuple(injections),
        db_type=db_type,
    )


# ─── AI-friendly summary helpers ─────────────────────────────────────────────


def summarize_for_ai(scan_or_findings) -> str:
    """Compact, model-readable summary for any of the structured outputs.

    Used as context inside `Intent.notes` so the LLM can plan exploit code
    without re-reading raw tool output.
    """
    if isinstance(scan_or_findings, NmapScan):
        lines = [f"Nmap: {len(scan_or_findings.hosts)} host(s), "
                 f"{scan_or_findings.open_port_count} open port(s)"]
        for host in scan_or_findings.hosts[:5]:
            for port in host.open_ports[:10]:
                tag = port.service or "?"
                if port.product:
                    tag = f"{tag} ({port.product} {port.version})".strip()
                lines.append(f"  {host.address}:{port.port}/{port.protocol} {tag}")
        return "\n".join(lines)

    if isinstance(scan_or_findings, tuple) and scan_or_findings and isinstance(
        scan_or_findings[0], NucleiFinding
    ):
        crit = [f for f in scan_or_findings if f.is_critical]
        lines = [
            f"Nuclei: {len(scan_or_findings)} finding(s), "
            f"{len(crit)} high/critical"
        ]
        for f in scan_or_findings[:10]:
            lines.append(
                f"  [{f.severity}] {f.template_id} → {f.matched_at}"
            )
        return "\n".join(lines)

    if isinstance(scan_or_findings, SqlmapResult):
        if not scan_or_findings.vulnerable:
            return f"SQLMap: {scan_or_findings.target} not vulnerable"
        lines = [
            f"SQLMap: {scan_or_findings.target} VULNERABLE "
            f"({scan_or_findings.db_type or 'unknown DB'}); "
            f"{len(scan_or_findings.injections)} injection(s)"
        ]
        for inj in scan_or_findings.injections[:5]:
            lines.append(
                f"  {inj.parameter}@{inj.place}: {inj.technique} → {inj.payload[:80]}"
            )
        return "\n".join(lines)

    return ""
