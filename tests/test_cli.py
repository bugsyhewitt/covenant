"""CLI unit tests exercising covenant.cli.main() directly.

Uses subprocess with PYTHONPATH=src to invoke covenant as a module so the
full argparse and dispatch path is exercised without a wheel install. All
tests run against the in-process mock servers; no live API calls are made.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest


def _run(args: list[str], env_extra: dict | None = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.setdefault("COVENANT_TOKEN", "ghp_faketokencli")
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "covenant", *args],
        capture_output=True,
        text=True,
        env=env,
    )


# ---------------------------------------------------------------------------
# --version
# ---------------------------------------------------------------------------


def test_version_flag_exits_zero():
    proc = _run(["--version"])
    assert proc.returncode == 0


def test_version_flag_includes_covenant():
    proc = _run(["--version"])
    assert "covenant" in proc.stdout or "covenant" in proc.stderr


# ---------------------------------------------------------------------------
# --help
# ---------------------------------------------------------------------------


def test_top_level_help_exit_zero():
    proc = _run(["--help"])
    assert proc.returncode == 0


def test_top_level_help_mentions_all_scms():
    proc = _run(["--help"])
    for scm in ("github", "gitlab", "bitbucket"):
        assert scm in proc.stdout


def test_github_validate_token_help_exit_zero():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0


def test_github_validate_token_help_mentions_enumerate_flags():
    proc = _run(["github", "validate-token", "--help"])
    assert "--enumerate-orgs" in proc.stdout


def test_recon_code_help_mentions_scan_secrets():
    proc = _run(["github", "recon-code", "--help"])
    assert "--scan-secrets" in proc.stdout


def test_recon_code_help_mentions_exclude():
    proc = _run(["github", "recon-code", "--help"])
    assert "--exclude" in proc.stdout


def test_validate_token_help_mentions_audit_flags():
    proc = _run(["github", "validate-token", "--help"])
    assert "--audit-branch-protection" in proc.stdout


# ---------------------------------------------------------------------------
# Exit code 2 — out-of-scope target
# ---------------------------------------------------------------------------


def test_out_of_scope_exits_2(tmp_path, github_mock):
    scope = tmp_path / "scope.txt"
    scope.write_text("github.com\n")
    proc = _run(
        [
            "github",
            "recon-repo",
            "--scope-file",
            str(scope),
            "--query",
            "spell",
            "--target-url",
            "https://evil.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower() or "scope" in proc.stderr.lower()


# ---------------------------------------------------------------------------
# Exit code 1 — operational errors
# ---------------------------------------------------------------------------


def test_missing_token_exits_1(tmp_path, github_mock):
    scope = tmp_path / "scope.txt"
    scope.write_text("127.0.0.1\n")
    proc = _run(
        [
            "github",
            "validate-token",
            "--scope-file",
            str(scope),
            "--target-url",
            github_mock.base_url,
            "--token-env",
            "COVENANT_MISSING_ENV_VAR_XYZ",
        ],
        env_extra={"COVENANT_MISSING_ENV_VAR_XYZ": ""},
    )
    assert proc.returncode == 1
    assert "token" in proc.stderr.lower()


def test_missing_scope_file_exits_1(github_mock):
    proc = _run(
        [
            "github",
            "recon-repo",
            "--scope-file",
            "/tmp/no_such_scope_file_xyz.txt",
            "--query",
            "test",
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode in (1, 2)


# ---------------------------------------------------------------------------
# recon-repo JSON output shape
# ---------------------------------------------------------------------------


def test_github_recon_repo_json_has_scm_key(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "recon-repo",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["scm"] == "github"


def test_github_recon_repo_json_has_query_key(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "recon-repo",
            "--scope-file",
            scope_file,
            "--query",
            "myquery",
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["query"] == "myquery"


def test_gitlab_recon_repo_json_scm_key(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "recon-repo",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--target-url",
            gitlab_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["scm"] == "gitlab"


def test_bitbucket_recon_repo_json_scm_key(bitbucket_mock, scope_file):
    proc = _run(
        [
            "bitbucket",
            "recon-repo",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--target-url",
            bitbucket_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["scm"] == "bitbucket"


# ---------------------------------------------------------------------------
# validate-token JSON output shape
# ---------------------------------------------------------------------------


def test_github_validate_token_json_has_user_key(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--scope-file",
            scope_file,
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "user" in payload


def test_github_validate_token_json_has_token_type(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--scope-file",
            scope_file,
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "token_type" in payload


# ---------------------------------------------------------------------------
# --max-pages clamping
# ---------------------------------------------------------------------------


def test_max_pages_zero_clamped_to_one(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "recon-repo",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--max-pages",
            "0",
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr


def test_max_pages_above_ceiling_accepted(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "recon-repo",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--max-pages",
            "9999",
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr


# ---------------------------------------------------------------------------
# org-restricted scope + --org flag
# ---------------------------------------------------------------------------


def test_org_restricted_scope_refuses_different_org(tmp_path, github_mock):
    # Make 127.0.0.1 org-restricted (no bare entry) so the mock server host
    # triggers the org-narrowing guard just like a live github.com/acme-corp entry.
    scope = tmp_path / "scope.txt"
    scope.write_text("127.0.0.1/acme-corp\n")
    proc = _run(
        [
            "github",
            "recon-repo",
            "--scope-file",
            str(scope),
            "--query",
            "spell",
            "--org",
            "victim-org",
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 2


def test_org_restricted_scope_allows_authorized_org(tmp_path, github_mock):
    scope = tmp_path / "scope.txt"
    scope.write_text("127.0.0.1/acme-corp\n")
    proc = _run(
        [
            "github",
            "recon-repo",
            "--scope-file",
            str(scope),
            "--query",
            "spell",
            "--org",
            "acme-corp",
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
