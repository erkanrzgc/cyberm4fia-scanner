"""Tests for modules/github_secrets — repo listing + file scanning."""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from modules.github_secrets import (
    GithubScanReport,
    RepoSecretHit,
    list_repos,
    scan_github_target,
    scan_local_repo_path,
)


pytestmark = pytest.mark.unit


def _gh_response(payload, status_code: int = 200):
    return SimpleNamespace(
        status_code=status_code,
        json=lambda: payload,
    )


# ── list_repos pagination + fallback ────────────────────────────────────────


def test_list_repos_pages_until_short_page():
    calls: list[str] = []

    def fake_get(url, headers, timeout):
        calls.append(url)
        # Match "&page=N" or "?page=N" specifically to avoid the substring
        # collision with "per_page=100".
        if "orgs/acme/repos" in url and url.endswith("page=1"):
            return _gh_response(
                [{"full_name": f"acme/r{i}"} for i in range(100)]
            )
        if "orgs/acme/repos" in url and url.endswith("page=2"):
            return _gh_response([{"full_name": "acme/r100"}])  # short page
        return _gh_response([], status_code=404)

    repos = list_repos("acme", http_get=fake_get, max_pages=5)
    assert "acme/r0" in repos and "acme/r100" in repos
    assert len(repos) == 101


def test_list_repos_falls_back_to_users_endpoint():
    """When the org endpoint 404s we try /users/{owner}/repos."""

    def fake_get(url, headers, timeout):
        if "orgs/" in url:
            return _gh_response(None, status_code=404)
        if "users/alice/repos" in url and url.endswith("page=1"):
            return _gh_response([{"full_name": "alice/dotfiles"}])
        return _gh_response([], status_code=404)

    repos = list_repos("alice", http_get=fake_get)
    assert repos == ["alice/dotfiles"]


def test_list_repos_handles_api_failure():
    def fake_get(url, headers, timeout):
        return _gh_response(None, status_code=500)

    assert list_repos("anyone", http_get=fake_get) == []


# ── Local-repo file scanning ────────────────────────────────────────────────


def test_scan_local_repo_path_flags_aws_key(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "config.py").write_text(
        'AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        "OTHER = 'noise'\n"
    )
    hits = scan_local_repo_path("acme/test", str(repo))
    assert any(
        "AKIAIOSFODNN7EXAMPLE" in h.matched_value
        and h.repo == "acme/test"
        for h in hits
    )


def test_scan_local_repo_skips_git_directory(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".git" / "config").write_text(
        "AKIAIOSFODNN7EXAMPLE = bury inside .git"
    )
    (repo / "src.py").write_text("nothing to see here")
    hits = scan_local_repo_path("acme/test", str(repo))
    assert all(".git" not in h.path for h in hits)


def test_scan_local_repo_skips_binary_files(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    # A "binary" file is rejected by the NUL-byte heuristic.
    (repo / "blob.bin").write_bytes(b"AKIAIOSFODNN7EXAMPLE\x00\x00trailing")
    hits = scan_local_repo_path("acme/test", str(repo))
    assert hits == []


def test_scan_local_repo_skips_oversize_files(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    big = repo / "huge.txt"
    big.write_text("AKIAIOSFODNN7EXAMPLE\n" + ("padding\n" * 200_000))
    # _is_textlike default cap is 1_000_000 bytes; file is well over.
    hits = scan_local_repo_path("acme/test", str(repo))
    assert hits == []


def test_scan_local_repo_respects_file_filter(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "config.py").write_text('AWS = "AKIAIOSFODNN7EXAMPLE"')
    (repo / "vendor.py").write_text('AWS = "AKIAIOSFODNN7EXAMPLE"')

    hits = scan_local_repo_path(
        "acme/test",
        str(repo),
        file_filter=lambda rel: not rel.startswith("vendor"),
    )
    paths = {h.path for h in hits}
    assert "config.py" in paths
    assert "vendor.py" not in paths


# ── scan_github_target orchestration ────────────────────────────────────────


def test_full_repo_target_skips_listing(tmp_path):
    """When ``target`` is owner/repo, we don't hit the API for listing."""

    def fake_clone(repo, target_dir, timeout):
        # Pretend the clone produced a repo with a leaked key.
        os.makedirs(target_dir, exist_ok=True)
        with open(os.path.join(target_dir, "secrets.py"), "w") as fh:
            fh.write('aws = "AKIAIOSFODNN7EXAMPLE"')
        return True

    with patch("modules.github_secrets._clone_shallow", side_effect=fake_clone), \
         patch("modules.github_secrets._maybe_run_trufflehog", return_value=[]):
        report = scan_github_target(
            "acme/widgets",
            http_get=lambda *a, **kw: pytest.fail("API should not be hit"),
        )
    assert report.repos_scanned == 1
    assert report.hits
    assert report.hits[0].secret_type
    assert report.hits[0].repo == "acme/widgets"


def test_org_target_iterates_listed_repos():
    listing_calls = {"n": 0}

    def fake_get(url, headers, timeout):
        listing_calls["n"] += 1
        if "orgs/acme/repos" in url and url.endswith("page=1"):
            return _gh_response(
                [{"full_name": "acme/a"}, {"full_name": "acme/b"}]
            )
        return _gh_response([], status_code=404)

    def fake_clone(repo, target_dir, timeout):
        os.makedirs(target_dir, exist_ok=True)
        return True

    with patch("modules.github_secrets._clone_shallow", side_effect=fake_clone), \
         patch("modules.github_secrets._maybe_run_trufflehog", return_value=[]):
        report = scan_github_target("acme", http_get=fake_get)
    assert report.repos_scanned == 2
    assert listing_calls["n"] >= 1


def test_clone_failure_records_error_not_crash():
    def fake_get(url, headers, timeout):
        if url.endswith("page=1"):
            return _gh_response([{"full_name": "acme/a"}])
        return _gh_response([], status_code=404)

    with patch("modules.github_secrets._clone_shallow", return_value=False), \
         patch("modules.github_secrets._maybe_run_trufflehog", return_value=[]):
        report = scan_github_target("acme", http_get=fake_get)
    assert report.repos_scanned == 0
    assert any("clone failed" in e for e in report.errors)


# ── Finding shape ───────────────────────────────────────────────────────────


def test_as_findings_carries_repo_url_and_module():
    report = GithubScanReport(target="acme")
    report.hits = [
        RepoSecretHit(
            repo="acme/widgets",
            path="src/aws.py",
            secret_type="aws_access_key",
            matched_value="AKIAIOSFODNN7EXAMPLE",
        )
    ]
    findings = report.as_findings()
    assert len(findings) == 1
    f = findings[0]
    assert f["module"] == "github_secrets"
    assert f["url"] == "https://github.com/acme/widgets/blob/HEAD/src/aws.py"
    assert f["severity"] == "high"
    assert "AKIA" in f["evidence"]
