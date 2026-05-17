"""External recon binary wrappers — subfinder / amass / assetfinder / puredns.

These are the four Go-based passive/active subdomain enumerators most
modern recon stacks lean on. We treat each binary as opt-in: if it's not
on PATH, the wrapper returns ``None`` (or an empty set) so callers can
gracefully degrade to pure-Python sources (crt.sh, DNS brute).

Pattern (mirrors ``utils.meta_tools``):

* ``parse_*`` functions are stdout → dataclass/set, no side effects,
  trivially unit-testable from fixture strings.
* ``run_*`` functions ``shutil.which`` the binary, ``subprocess.run`` it,
  feed the output into the parser. Timeouts + binary-missing both
  return ``None`` instead of raising — never break the scan over a
  missing optional tool.

Public surface intentionally narrow — every wrapper returns the same
shape (``set[str]`` of discovered subdomains) so the
``modules.subdomain_enum`` orchestrator can union them cleanly.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Iterable, Optional


_DEFAULT_TIMEOUT = 300.0  # 5 min — passive sources are I/O-bound on the wire


@dataclass(frozen=True)
class ReconToolResult:
    """One tool invocation's output + diagnostics."""

    tool: str
    subdomains: frozenset[str] = field(default_factory=frozenset)
    succeeded: bool = False
    error: str = ""


# ─── Parsers ────────────────────────────────────────────────────────────────


def _normalise(raw: str) -> str:
    """Lower-case + strip + drop trailing dot. Reject obviously bogus values."""
    name = raw.strip().lower().rstrip(".")
    if not name or " " in name or "/" in name or name.startswith("*"):
        return ""
    return name


def parse_lines(stdout: str) -> frozenset[str]:
    """Generic one-host-per-line parser (subfinder/assetfinder/amass)."""
    out: set[str] = set()
    for line in (stdout or "").splitlines():
        name = _normalise(line)
        if name:
            out.add(name)
    return frozenset(out)


def parse_subfinder_jsonl(stdout: str) -> frozenset[str]:
    """Subfinder ``-oJ`` (newline-delimited JSON) parser."""
    out: set[str] = set()
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = obj.get("host") or obj.get("Host") or obj.get("subdomain")
        if host:
            name = _normalise(str(host))
            if name:
                out.add(name)
    return frozenset(out)


# ─── Runners ────────────────────────────────────────────────────────────────


def _run_binary(
    cmd: list[str],
    *,
    timeout: float,
) -> Optional[subprocess.CompletedProcess]:
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None


def run_subfinder(
    domain: str,
    *,
    sources: Optional[Iterable[str]] = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> ReconToolResult:
    """Run ProjectDiscovery's subfinder against ``domain``.

    Returns a ``ReconToolResult`` with ``succeeded=False`` and an empty
    ``subdomains`` set when the binary is missing or fails — never raises.
    """
    if not shutil.which("subfinder"):
        return ReconToolResult(tool="subfinder", error="binary not on PATH")
    cmd = ["subfinder", "-d", domain, "-silent", "-oJ"]
    if sources:
        cmd.extend(["-sources", ",".join(sources)])
    proc = _run_binary(cmd, timeout=timeout)
    if proc is None:
        return ReconToolResult(tool="subfinder", error="timeout or OSError")
    return ReconToolResult(
        tool="subfinder",
        subdomains=parse_subfinder_jsonl(proc.stdout),
        succeeded=proc.returncode == 0,
        error="" if proc.returncode == 0 else (proc.stderr or "").strip(),
    )


def run_amass(
    domain: str,
    *,
    passive: bool = True,
    timeout: float = _DEFAULT_TIMEOUT,
) -> ReconToolResult:
    """Run OWASP amass against ``domain``. Passive by default — flip to
    active scanning only when the user explicitly opts in (rate-limit risk).
    """
    if not shutil.which("amass"):
        return ReconToolResult(tool="amass", error="binary not on PATH")
    cmd = ["amass", "enum"]
    if passive:
        cmd.append("-passive")
    cmd.extend(["-d", domain])
    proc = _run_binary(cmd, timeout=timeout)
    if proc is None:
        return ReconToolResult(tool="amass", error="timeout or OSError")
    return ReconToolResult(
        tool="amass",
        subdomains=parse_lines(proc.stdout),
        succeeded=proc.returncode == 0,
        error="" if proc.returncode == 0 else (proc.stderr or "").strip(),
    )


def run_assetfinder(
    domain: str,
    *,
    subs_only: bool = True,
    timeout: float = _DEFAULT_TIMEOUT,
) -> ReconToolResult:
    """Run tomnomnom/assetfinder against ``domain``."""
    if not shutil.which("assetfinder"):
        return ReconToolResult(tool="assetfinder", error="binary not on PATH")
    cmd = ["assetfinder"]
    if subs_only:
        cmd.append("--subs-only")
    cmd.append(domain)
    proc = _run_binary(cmd, timeout=timeout)
    if proc is None:
        return ReconToolResult(tool="assetfinder", error="timeout or OSError")
    return ReconToolResult(
        tool="assetfinder",
        subdomains=parse_lines(proc.stdout),
        succeeded=proc.returncode == 0,
        error="" if proc.returncode == 0 else (proc.stderr or "").strip(),
    )


@dataclass(frozen=True)
class FuzzHit:
    """One discovered endpoint from ffuf/gobuster."""

    url: str
    status: int
    length: int = 0
    words: int = 0
    lines: int = 0


@dataclass(frozen=True)
class FuzzResult:
    tool: str
    hits: tuple[FuzzHit, ...] = ()
    succeeded: bool = False
    error: str = ""


def parse_ffuf_json(stdout: str) -> tuple[FuzzHit, ...]:
    """Parse ``ffuf -o - -of json`` output into a tuple of hits."""
    if not stdout:
        return ()
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return ()
    hits: list[FuzzHit] = []
    for entry in payload.get("results", []) or []:
        try:
            hits.append(
                FuzzHit(
                    url=str(entry.get("url", "")),
                    status=int(entry.get("status", 0) or 0),
                    length=int(entry.get("length", 0) or 0),
                    words=int(entry.get("words", 0) or 0),
                    lines=int(entry.get("lines", 0) or 0),
                )
            )
        except (TypeError, ValueError):
            continue
    return tuple(hits)


def parse_gobuster_lines(stdout: str) -> tuple[FuzzHit, ...]:
    """Parse gobuster's plain-text output: ``/path (Status: 200) [Size: 1234]``."""
    import re
    hits: list[FuzzHit] = []
    pattern = re.compile(
        r"^(?P<path>\S+)\s+\(Status:\s*(?P<status>\d+)\)"
        r"(?:\s+\[Size:\s*(?P<size>\d+)\])?",
        flags=re.IGNORECASE,
    )
    for line in (stdout or "").splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        hits.append(
            FuzzHit(
                url=match.group("path"),
                status=int(match.group("status")),
                length=int(match.group("size") or 0),
            )
        )
    return tuple(hits)


def run_ffuf(
    url: str,
    wordlist_path: str,
    *,
    fuzz_keyword: str = "FUZZ",
    match_codes: str = "200,204,301,302,307,401,403",
    extra_args: Optional[list[str]] = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> FuzzResult:
    """Run ffuf against ``url`` with the wordlist substituted at FUZZ."""
    if not shutil.which("ffuf"):
        return FuzzResult(tool="ffuf", error="binary not on PATH")
    if fuzz_keyword not in url:
        return FuzzResult(
            tool="ffuf",
            error=f"FUZZ keyword {fuzz_keyword!r} not present in URL",
        )
    cmd = [
        "ffuf",
        "-u", url,
        "-w", f"{wordlist_path}:{fuzz_keyword}",
        "-mc", match_codes,
        "-o", "-",
        "-of", "json",
        "-s",  # silent stdout for non-json chatter
    ]
    if extra_args:
        cmd.extend(extra_args)
    proc = _run_binary(cmd, timeout=timeout)
    if proc is None:
        return FuzzResult(tool="ffuf", error="timeout or OSError")
    hits = parse_ffuf_json(proc.stdout)
    return FuzzResult(
        tool="ffuf",
        hits=hits,
        succeeded=proc.returncode == 0,
        error="" if proc.returncode == 0 else (proc.stderr or "").strip(),
    )


def run_gobuster(
    target_url: str,
    wordlist_path: str,
    *,
    mode: str = "dir",
    extra_args: Optional[list[str]] = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> FuzzResult:
    """Run gobuster (``dir`` mode by default) and parse its plain output."""
    if not shutil.which("gobuster"):
        return FuzzResult(tool="gobuster", error="binary not on PATH")
    cmd = [
        "gobuster", mode,
        "-u", target_url,
        "-w", wordlist_path,
        "-q",  # quiet banner / progress
    ]
    if extra_args:
        cmd.extend(extra_args)
    proc = _run_binary(cmd, timeout=timeout)
    if proc is None:
        return FuzzResult(tool="gobuster", error="timeout or OSError")
    hits = parse_gobuster_lines(proc.stdout)
    return FuzzResult(
        tool="gobuster",
        hits=hits,
        succeeded=proc.returncode == 0,
        error="" if proc.returncode == 0 else (proc.stderr or "").strip(),
    )


def run_puredns_resolve(
    candidates_path: str,
    *,
    resolvers_path: Optional[str] = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> ReconToolResult:
    """Run d3mondev/puredns in resolve mode over a wordlist of candidates."""
    if not shutil.which("puredns"):
        return ReconToolResult(tool="puredns", error="binary not on PATH")
    cmd = ["puredns", "resolve", candidates_path, "--quiet"]
    if resolvers_path:
        cmd.extend(["--resolvers", resolvers_path])
    proc = _run_binary(cmd, timeout=timeout)
    if proc is None:
        return ReconToolResult(tool="puredns", error="timeout or OSError")
    return ReconToolResult(
        tool="puredns",
        subdomains=parse_lines(proc.stdout),
        succeeded=proc.returncode == 0,
        error="" if proc.returncode == 0 else (proc.stderr or "").strip(),
    )


__all__ = [
    "ReconToolResult",
    "FuzzHit",
    "FuzzResult",
    "parse_lines",
    "parse_subfinder_jsonl",
    "parse_ffuf_json",
    "parse_gobuster_lines",
    "run_subfinder",
    "run_amass",
    "run_assetfinder",
    "run_puredns_resolve",
    "run_ffuf",
    "run_gobuster",
]
