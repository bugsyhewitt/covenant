"""Tests for validate-token --scan-commits (commit-message leak surface).

Covers the read-only scanning of the COMMIT-MESSAGE history of the repositories
a captured token can reach. Commit messages are a notorious, overlooked
secret-leak vector: a credential scrubbed from a tracked file routinely survives
verbatim in a ``git commit -m "rotate to AKIA..."`` subject or a revert/merge
body that quotes a diff. Where ``--scan-secrets`` (recon-code) only ever sees the
CURRENT file content the search API returns, ``--scan-commits`` maps the leak
surface in HISTORY, reusing the same ``necromancer-patterns`` scan machinery.

The feature is additive: the v0.1 validate-token fields stay intact and the
``commit_findings`` array only appears when ``--scan-commits`` is passed. Each
entry is ``{"repo", "sha", "author", "secret_findings"}`` and only commits whose
message actually matched a pattern are surfaced. Secrets are share-safe REDACTED
by default; ``--show-commit-secrets`` opts into the raw value. The commit diff is
never fetched and no author email is surfaced.

Two layers are exercised:
  * unit — each client's ``scan_commits`` against the in-process mock server,
    asserting the normalized ``{repo, sha, author, message}`` shape and that the
    author email never leaks;
  * e2e — the CLI flag end-to-end, asserting ``commit_findings`` is present only
    under the flag (and absent otherwise), that the leaked AWS key is detected
    and redacted by default but revealed under --show-commit-secrets, composes
    with the other --enumerate-*/--audit-* flags, respects the scope guardrail
    (exit 2), and is documented in --help.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from covenant.scms.bitbucket import BitbucketClient
from covenant.scms.github import GitHubClient
from covenant.scms.gitlab import GitLabClient

_COMMIT_FIELDS = {"repo", "sha", "author", "message"}
# Fields that must NEVER appear in a scan_commits record — covenant surfaces
# commit identity + the message it scans, never a contactable detail.
_FORBIDDEN_FIELDS = {"email", "author_email", "raw", "key", "token", "password"}
# The fake AWS key planted in the leaky commit message by the mock servers.
_FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


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


# --- unit: each client's scan_commits returns the normalized commit shape ---


def test_github_scan_commits_shape(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    commits = client.scan_commits()
    assert commits, "expected at least one commit"
    for c in commits:
        assert set(c.keys()) == _COMMIT_FIELDS
        assert not (_FORBIDDEN_FIELDS & set(c.keys()))
    by_repo = {c["repo"]: c for c in commits}
    # The spellbook repo's commit message leaks the fake AWS key.
    assert any(_FAKE_AWS_KEY in c["message"] for c in commits)
    assert "acme-corp/spellbook" in by_repo


def test_gitlab_scan_commits_shape(gitlab_mock):
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    commits = client.scan_commits()
    assert commits, "expected at least one commit"
    for c in commits:
        assert set(c.keys()) == _COMMIT_FIELDS
        assert not (_FORBIDDEN_FIELDS & set(c.keys()))
    assert any(_FAKE_AWS_KEY in c["message"] for c in commits)


def test_bitbucket_scan_commits_shape(bitbucket_mock):
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    commits = client.scan_commits()
    assert commits, "expected at least one commit"
    for c in commits:
        assert set(c.keys()) == _COMMIT_FIELDS
        assert not (_FORBIDDEN_FIELDS & set(c.keys()))
    assert any(_FAKE_AWS_KEY in c["message"] for c in commits)


def test_scan_commits_never_surfaces_author_email(
    github_mock, gitlab_mock, bitbucket_mock
):
    """The walk surfaces only commit identity + the message — never an author
    email. Bitbucket in particular carries a `raw` "Name <email>" string that
    must not leak into the normalized author field."""
    for client in (
        GitHubClient(token="ghp_x", base_url=github_mock.base_url),
        GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url),
        BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url),
    ):
        commits = client.scan_commits()
        assert commits
        for c in commits:
            assert "@" not in (c["author"] or ""), (
                "author identity must not carry an email address"
            )


# --- e2e: the CLI flag adds a 'commit_findings' array (only when requested) ---


def test_github_validate_token_scan_commits_cli(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--scan-commits",
            "--scope-file",
            scope_file,
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    # v0.1 fields untouched.
    assert "scopes" in payload and "user" in payload and "admin" in payload
    # New additive field present, and the leaky commit was detected.
    assert "commit_findings" in payload
    assert payload["commit_findings"], "expected the leaked-credential commit"
    leak = payload["commit_findings"][0]
    assert set(leak.keys()) == {"repo", "sha", "author", "secret_findings"}
    assert leak["repo"] == "acme-corp/spellbook"
    assert leak["secret_findings"], "expected a secret finding in the message"


def test_scan_commits_redacts_by_default(github_mock, scope_file):
    """By default the discovered secret is a share-safe redacted fingerprint —
    covenant's own output never becomes a new place the live credential leaks."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--scan-commits",
            "--scope-file",
            scope_file,
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    secrets = [
        f["secret"]
        for cf in payload["commit_findings"]
        for f in cf["secret_findings"]
    ]
    assert secrets
    # The raw value must NOT appear; the redacted fingerprint keeps a short
    # prefix + length + hash (the 'AKIA…[20 chars, sha256:...]' shape).
    assert all(_FAKE_AWS_KEY not in s for s in secrets)
    assert any("…[" in s for s in secrets)


def test_scan_commits_show_secrets_reveals_raw_value(github_mock, scope_file):
    """--show-commit-secrets opts into the full raw value (and implies the
    scan), for the operator who explicitly needs the live credential."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--show-commit-secrets",
            "--scope-file",
            scope_file,
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    secrets = [
        f["secret"]
        for cf in payload["commit_findings"]
        for f in cf["secret_findings"]
    ]
    assert any(_FAKE_AWS_KEY == s for s in secrets), (
        "expected the raw secret under --show-commit-secrets"
    )


def test_validate_token_without_flag_has_no_commit_findings_key(
    github_mock, scope_file
):
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
    assert "commit_findings" not in payload


def test_gitlab_validate_token_scan_commits_cli(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "validate-token",
            "--scan-commits",
            "--scope-file",
            scope_file,
            "--target-url",
            gitlab_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "glpat-" + "x" * 20},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "commit_findings" in payload
    assert payload["commit_findings"]


def test_bitbucket_validate_token_scan_commits_cli(bitbucket_mock, scope_file):
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--scan-commits",
            "--scope-file",
            scope_file,
            "--target-url",
            bitbucket_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "ATCTT" + "x" * 24},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "commit_findings" in payload
    assert payload["commit_findings"]


def test_scan_commits_pattern_set_validated(github_mock, scope_file):
    """--pattern-set is validated against the installed necromancer-patterns
    sets; an unknown set is a clean error (exit 1), not a crash."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--scan-commits",
            "--pattern-set",
            "does-not-exist",
            "--scope-file",
            scope_file,
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 1
    assert "unknown --pattern-set" in proc.stderr


def test_scan_commits_composes_with_other_enumerations(github_mock, scope_file):
    """--scan-commits composes with the other additive flags; all arrays
    appear together."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-orgs",
            "--enumerate-keys",
            "--enumerate-deploy-keys",
            "--enumerate-members",
            "--enumerate-collaborators",
            "--scan-commits",
            "--scope-file",
            scope_file,
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert (
        "orgs" in payload
        and "keys" in payload
        and "deploy_keys" in payload
        and "members" in payload
        and "collaborators" in payload
        and "commit_findings" in payload
    )


def test_scan_commits_respects_scope_guardrail(scope_file):
    """--scan-commits is still gated by the scope guardrail (exit 2)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--scan-commits",
            "--scope-file",
            scope_file,
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


def test_validate_token_help_documents_scan_commits():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0
    assert "--scan-commits" in proc.stdout
    assert "--show-commit-secrets" in proc.stdout
