"""GitHub-scoped secret hunter.

Two complementary modes:

1. **Repository scan** — clone a single repo (shallow), walk its files,
   apply ``modules.secrets_scanner.SECRET_PATTERNS`` against the
   contents. Reuses the project's existing detector so we don't rebuild
   regex lists.
2. **Org / user scan** — enumerate every public repo owned by an
   organisation or user via the GitHub REST API, then run the repo scan
   on each. Auth optional (``GITHUB_TOKEN`` env var lifts the rate
   limit from 60 → 5000 requests/hour).

External binary ``trufflehog`` is consulted opportunistically — when it
is present we use it for a second-opinion pass. Without it we still
produce reasonable findings via the regex layer.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from modules.secrets_scanner import SECRET_PATTERNS
from utils.colors import log_info, log_warning


# SECRET_PATTERNS values are raw regex strings — pre-compile once so we
# don't pay the cost per file (and to mirror the way secrets_scanner.py
# itself uses them internally).
_COMPILED_PATTERNS: dict[str, re.Pattern] = {
    name: re.compile(pattern) for name, pattern in SECRET_PATTERNS.items()
}


_GITHUB_API = "https://api.github.com"
_DEFAULT_TIMEOUT = 30.0


# ── Data shapes ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RepoSecretHit:
    repo: str
    path: str
    secret_type: str
    matched_value: str


@dataclass
class GithubScanReport:
    target: str
    repos_scanned: int = 0
    hits: list[RepoSecretHit] = field(default_factory=list)
    trufflehog_used: bool = False
    errors: list[str] = field(default_factory=list)

    def as_findings(self) -> list[dict]:
        return [
            {
                "type": "Exposed_Secret_GitHub",
                "url": f"https://github.com/{hit.repo}/blob/HEAD/{hit.path}",
                "param": "",
                "severity": "high",
                "evidence": (
                    f"{hit.secret_type} pattern matched in "
                    f"{hit.repo}:{hit.path} → {hit.matched_value[:60]}..."
                ),
                "module": "github_secrets",
                "secret_type": hit.secret_type,
            }
            for hit in self.hits
        ]


# ── GitHub API ──────────────────────────────────────────────────────────────


def _gh_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "cyberm4fia"}
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


def list_repos(
    owner: str,
    *,
    http_get: Callable,
    max_pages: int = 5,
) -> list[str]:
    """Return ``["owner/repo1", "owner/repo2", ...]`` for an org or user.

    Tries the ``/orgs/{owner}/repos`` endpoint first (org accounts);
    falls back to ``/users/{owner}/repos`` for individual users.
    """
    candidates_paths = (
        f"{_GITHUB_API}/orgs/{owner}/repos",
        f"{_GITHUB_API}/users/{owner}/repos",
    )
    repos: list[str] = []
    for url in candidates_paths:
        for page in range(1, max_pages + 1):
            response = http_get(
                f"{url}?per_page=100&page={page}",
                headers=_gh_headers(),
                timeout=_DEFAULT_TIMEOUT,
            )
            status = getattr(response, "status_code", 0)
            if status == 404:
                break  # try next candidate path
            if status != 200:
                break
            try:
                data = response.json()
            except (ValueError, TypeError):
                break
            if not isinstance(data, list) or not data:
                break
            for entry in data:
                full_name = entry.get("full_name")
                if full_name:
                    repos.append(full_name)
            if len(data) < 100:
                break
        if repos:
            return repos
    return repos


# ── File scanning ───────────────────────────────────────────────────────────


def _is_textlike(path: str, max_bytes: int = 1_000_000) -> bool:
    try:
        size = os.path.getsize(path)
    except OSError:
        return False
    if size > max_bytes:
        return False
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(2048)
    except OSError:
        return False
    if b"\x00" in chunk:
        return False
    return True


def _scan_file_for_secrets(path: str) -> list[tuple[str, str]]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
    except OSError:
        return []
    matches: list[tuple[str, str]] = []
    for secret_name, pattern in _COMPILED_PATTERNS.items():
        for match in pattern.findall(text)[:5]:
            value = match if isinstance(match, str) else "".join(match)
            matches.append((secret_name, value))
    return matches


def scan_local_repo_path(
    repo_full_name: str,
    repo_path: str,
    *,
    file_filter: Optional[Callable[[str], bool]] = None,
) -> list[RepoSecretHit]:
    """Walk every file under ``repo_path`` and apply SECRET_PATTERNS.

    ``file_filter(rel_path)`` may be passed to skip directories
    (``.git/``, ``node_modules/``, ``vendor/``…); the default skips
    nothing so the caller can drive policy.
    """
    hits: list[RepoSecretHit] = []
    repo_path = os.path.abspath(repo_path)
    for root, dirs, files in os.walk(repo_path):
        # Conservative built-in skips — purely VCS / dep noise.
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
        for filename in files:
            abs_path = os.path.join(root, filename)
            rel_path = os.path.relpath(abs_path, repo_path)
            if file_filter and not file_filter(rel_path):
                continue
            if not _is_textlike(abs_path):
                continue
            for secret_type, value in _scan_file_for_secrets(abs_path):
                hits.append(
                    RepoSecretHit(
                        repo=repo_full_name,
                        path=rel_path,
                        secret_type=secret_type,
                        matched_value=value,
                    )
                )
    return hits


def _clone_shallow(repo_full_name: str, target_dir: str, timeout: float) -> bool:
    """Clone ``owner/name`` (depth 1) into ``target_dir``. Returns success."""
    if not shutil.which("git"):
        return False
    url = f"https://github.com/{repo_full_name}.git"
    try:
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", url, target_dir],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return proc.returncode == 0


def _maybe_run_trufflehog(repo_path: str, timeout: float) -> list[dict]:
    """Best-effort second-opinion via trufflehog. Empty when not installed."""
    if not shutil.which("trufflehog"):
        return []
    try:
        proc = subprocess.run(
            ["trufflehog", "filesystem", repo_path, "--json", "--no-update"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    import json
    findings: list[dict] = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return findings


# ── Public API ─────────────────────────────────────────────────────────────


def scan_github_target(
    target: str,
    *,
    http_get: Callable,
    max_repos: int = 25,
    clone_timeout: float = 60.0,
    trufflehog_timeout: float = 120.0,
    fetch_repos: bool = True,
) -> GithubScanReport:
    """Enumerate ``target``'s repos and scan each for leaked secrets.

    ``target`` is either an org/user login (``"acme"``) or a fully
    qualified repo (``"acme/internal-tools"``). For org/user mode we
    discover up to ``max_repos`` repos via the GitHub API.
    """
    report = GithubScanReport(target=target)

    if "/" in target and fetch_repos:
        repos = [target]
    elif fetch_repos:
        try:
            repos = list_repos(target, http_get=http_get)[:max_repos]
        except Exception as exc:  # noqa: BLE001
            report.errors.append(f"list_repos: {type(exc).__name__}: {exc}")
            return report
    else:
        repos = [target]

    for repo in repos:
        with tempfile.TemporaryDirectory(prefix="ghs-") as tmp:
            if not _clone_shallow(repo, tmp, timeout=clone_timeout):
                report.errors.append(f"clone failed: {repo}")
                continue
            report.repos_scanned += 1
            hits = scan_local_repo_path(repo, tmp)
            report.hits.extend(hits)

            # trufflehog complements the regex layer when present.
            extra = _maybe_run_trufflehog(tmp, timeout=trufflehog_timeout)
            if extra:
                report.trufflehog_used = True

    if report.hits:
        log_info(
            f"GitHub secrets: {len(report.hits)} hits across "
            f"{report.repos_scanned} repo(s)"
        )
    elif report.repos_scanned:
        log_info(f"GitHub secrets: no hits across {report.repos_scanned} repos")
    else:
        log_warning(f"GitHub secrets: no repos scanned for {target!r}")
    return report
