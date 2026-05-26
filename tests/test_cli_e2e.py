"""End-to-end smoke tests for the covenant CLI.

These invoke the installed ``covenant`` entry point as a subprocess against the
in-process mock SCM servers (no live API calls). Each test maps to a numbered
v0.1 completion criterion.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys


def _run(args: list[str], env_extra: dict | None = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.setdefault("COVENANT_TOKEN", "ghp_faketoken123")
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "covenant", *args],
        capture_output=True,
        text=True,
        env=env,
    )


# --- Criterion 2: help surface ------------------------------------------------


def test_top_level_help_lists_scm_subcommands():
    proc = _run(["--help"])
    assert proc.returncode == 0
    for sub in ("github", "gitlab", "bitbucket"):
        assert sub in proc.stdout


def test_github_help_lists_modules():
    proc = _run(["github", "--help"])
    assert proc.returncode == 0
    for module in ("recon-repo", "recon-code", "validate-token"):
        assert module in proc.stdout


def test_gitlab_help_lists_modules():
    proc = _run(["gitlab", "--help"])
    assert proc.returncode == 0
    for module in ("recon-repo", "recon-code", "validate-token"):
        assert module in proc.stdout


def test_bitbucket_help_lists_modules():
    proc = _run(["bitbucket", "--help"])
    assert proc.returncode == 0
    for module in ("recon-repo", "recon-code", "validate-token"):
        assert module in proc.stdout


# --- Criterion 3: github recon-repo against mock, JSON with repo keys ---------


def test_github_recon_repo_success(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "recon-repo",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["results"], "expected at least one repo result"
    first = payload["results"][0]
    for key in ("name", "visibility", "url"):
        assert key in first
        assert first[key]


# --- Criterion 4: out-of-scope target exits 2 --------------------------------


def test_github_recon_repo_out_of_scope(scope_file):
    proc = _run(
        [
            "github",
            "recon-repo",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


# --- Criterion 5: github validate-token --------------------------------------


def test_github_validate_token(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--token-env",
            "COVENANT_TOKEN",
            "--scope-file",
            scope_file,
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert isinstance(payload["scopes"], list)
    assert payload["user"]
    assert isinstance(payload["admin"], bool)


# --- Criterion 6 & 7: gitlab + bitbucket recon-repo parity -------------------


def test_gitlab_recon_repo_success(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "recon-repo",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            gitlab_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["results"]
    first = payload["results"][0]
    for key in ("name", "visibility", "url"):
        assert first[key]


def test_bitbucket_recon_repo_success(bitbucket_mock, scope_file):
    proc = _run(
        [
            "bitbucket",
            "recon-repo",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            bitbucket_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["results"]
    first = payload["results"][0]
    for key in ("name", "visibility", "url"):
        assert first[key]


# --- recon-code parity (module exists and works for github) ------------------


def test_github_recon_code_success(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "recon-code",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["results"]
    assert payload["results"][0]["name"]


# --- missing token handling --------------------------------------------------


def test_missing_token_env_exits_nonzero(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "recon-repo",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            github_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": ""},
    )
    assert proc.returncode != 0
    assert "token" in proc.stderr.lower()


# --- --scan-secrets: GitHub code search with text-match fragments ------------


def test_github_recon_code_scan_secrets(github_mock, scope_file):
    """--scan-secrets attaches secret_findings to each result."""
    proc = _run(
        [
            "github",
            "recon-code",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            github_mock.base_url,
            "--scan-secrets",
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["results"], "expected at least one code result"
    first = payload["results"][0]
    assert "secret_findings" in first, "expected secret_findings key"
    # The mock server injects an AWS key in the text-match fragment.
    findings = first["secret_findings"]
    assert isinstance(findings, list)
    assert any(f["rule_id"] == "aws-access-key-id" for f in findings), (
        f"expected aws-access-key-id finding; got: {findings}"
    )


def test_github_recon_code_scan_secrets_finding_shape(github_mock, scope_file):
    """Each finding has the expected keys from necromancer-patterns Match."""
    proc = _run(
        [
            "github",
            "recon-code",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            github_mock.base_url,
            "--scan-secrets",
        ]
    )
    assert proc.returncode == 0, proc.stderr
    findings = json.loads(proc.stdout)["results"][0]["secret_findings"]
    assert findings, "expected at least one finding"
    for f in findings:
        for key in ("rule_id", "description", "secret", "start", "end", "fragment_index"):
            assert key in f, f"finding missing key {key!r}: {f}"


def test_github_recon_code_no_scan_secrets_no_findings_key(github_mock, scope_file):
    """Without --scan-secrets, results must NOT have a secret_findings key."""
    proc = _run(
        [
            "github",
            "recon-code",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    first = payload["results"][0]
    assert "secret_findings" not in first, (
        "secret_findings should only appear when --scan-secrets is passed"
    )


# --- --scan-secrets: GitLab code search with data fragment -------------------


def test_gitlab_recon_code_scan_secrets(gitlab_mock, scope_file):
    """GitLab --scan-secrets uses the 'data' field fragment."""
    proc = _run(
        [
            "gitlab",
            "recon-code",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            gitlab_mock.base_url,
            "--scan-secrets",
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["results"], "expected at least one code result"
    first = payload["results"][0]
    assert "secret_findings" in first
    findings = first["secret_findings"]
    assert any(f["rule_id"] == "aws-access-key-id" for f in findings), (
        f"expected aws-access-key-id finding in GitLab result; got: {findings}"
    )
