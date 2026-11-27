"""Integration tests: end-to-end module execution with mocked HTTP.

Each test spins up an in-process MockSCMServer (no live API calls), runs the
full covenant CLI dispatch path through covenant.cli.main(), and asserts on
the resulting JSON payload. The scope file authorizes the loopback mock server
address.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest


def _run(args: list[str], env_extra: dict | None = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.setdefault("COVENANT_TOKEN", "ghp_integrationtoken")
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "covenant", *args],
        capture_output=True,
        text=True,
        env=env,
    )


# ---------------------------------------------------------------------------
# recon-repo — all three SCMs
# ---------------------------------------------------------------------------


def test_github_recon_repo_returns_results(github_mock, scope_file):
    proc = _run([
        "github", "recon-repo",
        "--scope-file", scope_file,
        "--query", "spell",
        "--target-url", github_mock.base_url,
    ])
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert isinstance(data["results"], list)
    assert len(data["results"]) > 0


def test_gitlab_recon_repo_returns_results(gitlab_mock, scope_file):
    proc = _run([
        "gitlab", "recon-repo",
        "--scope-file", scope_file,
        "--query", "spell",
        "--target-url", gitlab_mock.base_url,
    ])
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert isinstance(data["results"], list)
    assert len(data["results"]) > 0


def test_bitbucket_recon_repo_returns_results(bitbucket_mock, scope_file):
    proc = _run([
        "bitbucket", "recon-repo",
        "--scope-file", scope_file,
        "--query", "spell",
        "--target-url", bitbucket_mock.base_url,
    ])
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert isinstance(data["results"], list)


# ---------------------------------------------------------------------------
# recon-code — all three SCMs
# ---------------------------------------------------------------------------


def test_github_recon_code_returns_results(github_mock, scope_file):
    proc = _run([
        "github", "recon-code",
        "--scope-file", scope_file,
        "--query", "api_key",
        "--target-url", github_mock.base_url,
    ])
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert "results" in data


def test_gitlab_recon_code_returns_results(gitlab_mock, scope_file):
    proc = _run([
        "gitlab", "recon-code",
        "--scope-file", scope_file,
        "--query", "api_key",
        "--target-url", gitlab_mock.base_url,
    ])
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert "results" in data


# ---------------------------------------------------------------------------
# validate-token — basic fields
# ---------------------------------------------------------------------------


def test_github_validate_token_fields(github_mock, scope_file):
    proc = _run([
        "github", "validate-token",
        "--scope-file", scope_file,
        "--target-url", github_mock.base_url,
    ])
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert "user" in data
    assert "scopes" in data
    assert "token_type" in data
    assert "token_type_confidence" in data


def test_gitlab_validate_token_fields(gitlab_mock, scope_file):
    proc = _run([
        "gitlab", "validate-token",
        "--scope-file", scope_file,
        "--target-url", gitlab_mock.base_url,
    ])
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert "user" in data


def test_bitbucket_validate_token_fields(bitbucket_mock, scope_file):
    proc = _run([
        "bitbucket", "validate-token",
        "--scope-file", scope_file,
        "--target-url", bitbucket_mock.base_url,
    ])
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert "user" in data


# ---------------------------------------------------------------------------
# --enumerate-orgs
# ---------------------------------------------------------------------------


def test_github_enumerate_orgs_adds_orgs_key(github_mock, scope_file):
    proc = _run([
        "github", "validate-token",
        "--scope-file", scope_file,
        "--target-url", github_mock.base_url,
        "--enumerate-orgs",
    ])
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert "orgs" in data
    assert isinstance(data["orgs"], list)


def test_gitlab_enumerate_orgs_adds_orgs_key(gitlab_mock, scope_file):
    proc = _run([
        "gitlab", "validate-token",
        "--scope-file", scope_file,
        "--target-url", gitlab_mock.base_url,
        "--enumerate-orgs",
    ])
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert "orgs" in data


# ---------------------------------------------------------------------------
# --enumerate-keys
# ---------------------------------------------------------------------------


def test_github_enumerate_keys_adds_keys_key(github_mock, scope_file):
    proc = _run([
        "github", "validate-token",
        "--scope-file", scope_file,
        "--target-url", github_mock.base_url,
        "--enumerate-keys",
    ])
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert "keys" in data
    assert isinstance(data["keys"], list)


# ---------------------------------------------------------------------------
# --audit-branch-protection
# ---------------------------------------------------------------------------


def test_github_audit_branch_protection_additive(github_mock, scope_file):
    proc = _run([
        "github", "validate-token",
        "--scope-file", scope_file,
        "--target-url", github_mock.base_url,
        "--audit-branch-protection",
    ])
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert "user" in data
    assert "branch_protection" in data
    assert isinstance(data["branch_protection"], list)


# ---------------------------------------------------------------------------
# --audit-repo-visibility
# ---------------------------------------------------------------------------


def test_github_audit_repo_visibility(github_mock, scope_file):
    proc = _run([
        "github", "validate-token",
        "--scope-file", scope_file,
        "--target-url", github_mock.base_url,
        "--audit-repo-visibility",
    ])
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert "repo_visibility" in data


# ---------------------------------------------------------------------------
# Pagination: multipage query returns multiple results
# ---------------------------------------------------------------------------


def test_github_recon_repo_multipage_walks_pages(github_mock, scope_file):
    proc = _run([
        "github", "recon-repo",
        "--scope-file", scope_file,
        "--query", "multipage",
        "--target-url", github_mock.base_url,
    ])
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert len(data["results"]) > 1, "multipage query must return more than one result"


# ---------------------------------------------------------------------------
# Rate-limit recovery: warnings key appears on exhausted retry budget
# ---------------------------------------------------------------------------


def test_github_recon_repo_ratelimit_warnings_key(github_mock, scope_file):
    proc = _run([
        "github", "recon-repo",
        "--scope-file", scope_file,
        "--query", "ratelimitforever",
        "--target-url", github_mock.base_url,
    ])
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert "warnings" in data
    assert any("rate" in w.lower() for w in data["warnings"])
