"""
cyberm4fia-scanner - Git History Secret Scanner

Scans the last N commits' patch output of a local git repository for
previously-committed secrets that remain recoverable from the .git
directory even after being removed from the working tree.

Two operation modes:

1. **Local repo (white-box)** — caller supplies a path to a local clone.
   This is the reliable, recommended mode for self-audits, on-prem
   reviews, and CI integration.

2. **Exposed .git (best-effort black-box)** — when the target webserver
   leaks `.git/config` and `.git/HEAD`, this module reports the leak as
   a CRITICAL finding. It does NOT attempt to dump the repo via HTTP
   (use a dedicated tool like git-dumper for that workflow); we only
   surface the exposure so the caller can run the dumper out-of-band.

Pattern source: shares `SECRET_PATTERNS` and `is_placeholder_value()`
from `modules.secrets_scanner` (single source of truth for regex DB).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import uuid

from utils.colors import log_info, log_success, log_warning, log_error
from utils.finding import Observation
from utils.request import smart_request, ScanExceptions

from modules.secrets_scanner import SECRET_PATTERNS, is_placeholder_value


_DEFAULT_MAX_COMMITS = 500
_DEFAULT_TIMEOUT = 120  # seconds for git log subprocess
_MAX_BUFFER_BYTES = 50 * 1024 * 1024  # cap stdout to avoid OOM on huge repos


def is_git_available() -> bool:
    return shutil.which("git") is not None


def is_git_repo(path: str) -> bool:
    return os.path.isdir(os.path.join(path, ".git"))


def _mask(value: str) -> str:
    if len(value) > 10 and "KEY-----" not in value:
        return value[:5] + "*" * (len(value) - 9) + value[-4:]
    return value


def _scan_blob_for_secrets(text: str, source: str) -> list[dict]:
    """Apply SECRET_PATTERNS to a blob of text. Returns dict per hit."""
    hits: list[dict] = []
    if not text:
        return hits
    for name, pattern in SECRET_PATTERNS.items():
        for raw in set(re.findall(pattern, text)):
            value = raw[0] if isinstance(raw, tuple) else raw
            if not value:
                continue
            if "PRIVATE KEY" not in name:
                idx = text.find(value)
                ctx = text[max(0, idx - 40) : idx + len(value) + 40] if idx != -1 else ""
                if is_placeholder_value(value, ctx):
                    continue
            hits.append({"secret_type": name, "value": _mask(value), "source": source})
    return hits


def _git_log_patches(repo_path: str, max_commits: int, timeout: int) -> str:
    """Stream git-log -p for the last N commits, capped at _MAX_BUFFER_BYTES."""
    cmd = [
        "git", "-C", repo_path, "log", "--all", "-p",
        f"--max-count={max_commits}",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        log_warning(f"git log timed out after {timeout}s")
        return ""
    except OSError as exc:
        log_error(f"git log failed: {exc}")
        return ""

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip().splitlines()[-2:]
        log_warning(f"git log exit={proc.returncode}: {' / '.join(stderr)}")

    output = proc.stdout or ""
    if len(output) > _MAX_BUFFER_BYTES:
        log_warning(
            f"git log output truncated to {_MAX_BUFFER_BYTES // 1024 // 1024} MiB"
        )
        output = output[:_MAX_BUFFER_BYTES]
    return output


def scan_local_repo(
    repo_path: str,
    *,
    max_commits: int = _DEFAULT_MAX_COMMITS,
    timeout: int = _DEFAULT_TIMEOUT,
) -> list[Observation]:
    """White-box mode: scan a local git repo's recent commit diffs for secrets."""
    if not is_git_available():
        log_warning("git binary not in PATH; skipping git-history scan")
        return []
    if not is_git_repo(repo_path):
        log_warning(f"Not a git repository: {repo_path}")
        return []

    log_info(f"Scanning last {max_commits} commits of {repo_path} for committed secrets")
    diff_text = _git_log_patches(repo_path, max_commits, timeout)
    if not diff_text:
        return []

    hits = _scan_blob_for_secrets(diff_text, source=repo_path)
    log_success(f"git-history scan: {len(hits)} secret hits")

    observations: list[Observation] = []
    for hit in hits:
        observations.append(
            Observation(
                id=f"git-history-{uuid.uuid4().hex[:8]}",
                observation_type=f"git_history_secret:{hit['secret_type']}",
                url=f"file://{os.path.abspath(repo_path)}",
                module="git_history_scan",
                asset_id=os.path.abspath(repo_path),
                surface="filesystem",
                description=(
                    f"{hit['secret_type']} found in git history "
                    f"(recoverable from .git/ even if removed from current files)"
                ),
                severity="high",
                confidence="high",
                evidence=f"value={hit['value']}",
                tags=["secrets", "git-history", "white-box"],
                raw=hit,
            )
        )
    return observations


def check_exposed_dotgit(target_url: str, *, delay: float = 0) -> list[Observation]:
    """
    Best-effort black-box check: does the target webserver leak `.git/`?

    Probes `/.git/HEAD` and `/.git/config`. If either responds 200 with
    plausible content, emits a CRITICAL Observation recommending an
    out-of-band repo dump (git-dumper, dvcs-ripper).
    """
    target_url = target_url.rstrip("/")
    observations: list[Observation] = []

    probes = {
        "/.git/HEAD": re.compile(r"^ref:\s+refs/", re.MULTILINE),
        "/.git/config": re.compile(r"\[core\]|\[remote ", re.IGNORECASE),
    }

    for path, expected in probes.items():
        url = f"{target_url}{path}"
        try:
            resp = smart_request("get", url, delay=delay, timeout=10)
        except ScanExceptions as exc:
            log_warning(f"git-dotgit probe {url} failed: {exc}")
            continue
        if resp.status_code != 200:
            continue
        body = resp.text or ""
        if not expected.search(body):
            continue
        observations.append(
            Observation(
                id=f"git-exposed-{uuid.uuid4().hex[:8]}",
                observation_type="exposed_dotgit",
                url=url,
                module="git_history_scan",
                asset_id=target_url,
                surface="http",
                description=(
                    f"Target exposes {path} — full git history is likely "
                    f"recoverable. Run `git-dumper` or `dvcs-ripper` to dump "
                    f"the repo, then re-run scan_local_repo() against the dump."
                ),
                severity="critical",
                confidence="high",
                evidence=f"first 200 chars: {body[:200]!r}",
                tags=["secrets", "git-exposure", "information-disclosure"],
                raw={"path": path, "status": resp.status_code},
            )
        )
        log_success(f"Exposed .git detected at {url}")
    return observations


def scan_git_history(
    target: str,
    *,
    options: dict | None = None,
) -> list[Observation]:
    """
    Module-runner compatible entrypoint.

    Behaviour:
      - If `options['git_history_path']` is set → white-box scan that path.
      - Otherwise treat `target` as a URL and run the exposed-.git probe.
    """
    options = options or {}
    local_path = options.get("git_history_path")
    if local_path:
        return scan_local_repo(
            local_path,
            max_commits=options.get("git_history_max_commits", _DEFAULT_MAX_COMMITS),
            timeout=options.get("git_history_timeout", _DEFAULT_TIMEOUT),
        )
    return check_exposed_dotgit(target, delay=options.get("delay", 0))
