"""
cyberm4fia-scanner - Nuclei Template Runner

Wraps the projectdiscovery/nuclei binary to execute community templates
against a target, parses JSONL output, and emits Observation objects in
the scanner's native finding format.

Requires `nuclei` binary in PATH (https://github.com/projectdiscovery/nuclei).
Templates are auto-updated via `nuclei -ut` on first run.

Severity map: nuclei levels map directly to Observation severity.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import uuid
from typing import Iterable

from utils.colors import log_info, log_success, log_warning, log_error
from utils.finding import Observation


_SEVERITY_MAP = {
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
    "unknown": "info",
}

_DEFAULT_RATE_LIMIT = 50
_DEFAULT_CONCURRENCY = 25
_DEFAULT_TIMEOUT = 600  # seconds for the whole run


def is_nuclei_available() -> bool:
    return shutil.which("nuclei") is not None


def update_templates() -> bool:
    """Run `nuclei -ut` once to refresh community templates."""
    if not is_nuclei_available():
        return False
    try:
        proc = subprocess.run(
            ["nuclei", "-ut", "-silent"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, OSError) as exc:
        log_warning(f"Nuclei template update failed: {exc}")
        return False


def _build_command(
    target: str,
    *,
    severity: list[str] | None,
    tags: list[str] | None,
    templates: list[str] | None,
    rate_limit: int,
    concurrency: int,
    extra_args: list[str] | None,
) -> list[str]:
    cmd = [
        "nuclei",
        "-target", target,
        "-jsonl",
        "-silent",
        "-no-color",
        "-disable-update-check",
        "-rate-limit", str(rate_limit),
        "-concurrency", str(concurrency),
    ]
    if severity:
        cmd += ["-severity", ",".join(severity)]
    if tags:
        cmd += ["-tags", ",".join(tags)]
    if templates:
        for tpl in templates:
            cmd += ["-t", tpl]
    if extra_args:
        cmd += extra_args
    return cmd


def _parse_jsonl(stdout: str) -> Iterable[dict]:
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def _to_observation(record: dict, target: str) -> Observation:
    info = record.get("info", {}) or {}
    severity = _SEVERITY_MAP.get(
        (info.get("severity") or "info").lower(), "info"
    )
    template_id = record.get("template-id") or record.get("templateID") or "nuclei"
    matched_at = record.get("matched-at") or record.get("matched_at") or target
    name = info.get("name") or template_id
    description = info.get("description") or ""
    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]

    classification = info.get("classification", {}) or {}
    cve = classification.get("cve-id") or []
    if isinstance(cve, list) and cve:
        tags = list(tags) + [str(c) for c in cve]

    matcher_name = record.get("matcher-name") or record.get("matcher_name") or ""
    extracted = record.get("extracted-results") or record.get("extracted_results") or []

    evidence_parts = []
    if matcher_name:
        evidence_parts.append(f"matcher={matcher_name}")
    if extracted:
        evidence_parts.append(f"extracted={extracted[:3]}")
    if record.get("curl-command"):
        evidence_parts.append(f"repro={record['curl-command'][:300]}")
    evidence = " | ".join(evidence_parts) or json.dumps(record)[:400]

    return Observation(
        id=f"nuclei-{template_id}-{uuid.uuid4().hex[:8]}",
        observation_type=template_id,
        url=matched_at,
        module="nuclei_runner",
        asset_id=target,
        surface="http",
        description=f"{name}: {description}".strip(": "),
        severity=severity,
        confidence="high" if severity in {"high", "critical"} else "medium",
        evidence=evidence,
        tags=list(tags) if tags else None,
        raw=record,
    )


def run_nuclei(
    target: str,
    *,
    severity: list[str] | None = None,
    tags: list[str] | None = None,
    templates: list[str] | None = None,
    rate_limit: int = _DEFAULT_RATE_LIMIT,
    concurrency: int = _DEFAULT_CONCURRENCY,
    timeout: int = _DEFAULT_TIMEOUT,
    extra_args: list[str] | None = None,
) -> list[Observation]:
    """
    Execute nuclei against a single target and return Observation list.

    Defaults match a balanced safety profile (no `-tags kev,vkev` shortcut;
    caller decides scope to respect APTS scope-enforcement requirements).
    """
    if not is_nuclei_available():
        log_warning(
            "nuclei binary not found in PATH; skipping. "
            "Install via: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        )
        return []

    cmd = _build_command(
        target,
        severity=severity,
        tags=tags,
        templates=templates,
        rate_limit=rate_limit,
        concurrency=concurrency,
        extra_args=extra_args,
    )
    log_info(f"nuclei: {' '.join(cmd)}")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        log_error(f"nuclei timed out after {timeout}s for {target}")
        return []
    except OSError as exc:
        log_error(f"nuclei execution failed: {exc}")
        return []

    if proc.returncode not in (0, 1):  # 1 = findings present (varies by version)
        stderr = (proc.stderr or "").strip().splitlines()[-3:]
        log_warning(f"nuclei exit={proc.returncode}: {' / '.join(stderr)}")

    observations = [
        _to_observation(record, target)
        for record in _parse_jsonl(proc.stdout or "")
    ]
    log_success(f"nuclei: {len(observations)} findings for {target}")
    return observations


def scan_with_nuclei(target: str, options: dict | None = None) -> list[Observation]:
    """Module-runner compatible entrypoint."""
    options = options or {}
    return run_nuclei(
        target,
        severity=options.get("nuclei_severity"),
        tags=options.get("nuclei_tags"),
        templates=options.get("nuclei_templates"),
        rate_limit=options.get("nuclei_rate_limit", _DEFAULT_RATE_LIMIT),
        concurrency=options.get("nuclei_concurrency", _DEFAULT_CONCURRENCY),
        timeout=options.get("nuclei_timeout", _DEFAULT_TIMEOUT),
        extra_args=options.get("nuclei_extra_args"),
    )
