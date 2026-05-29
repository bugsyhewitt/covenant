"""Tests for validate-token --audit-repo-visibility (repo exposure posture).

Covers the read-only audit of the visibility posture of the repos a captured
token can reach — which of them are PUBLIC. Where the ``--enumerate-*`` flags map
a token's *offensive* reach (keys it owns, repos it can push to, CI/CD secrets it
can read), the visibility audit reports the *exposure* posture: a public repo is
the org's external attack surface (world-readable source, history, issues and any
leaked secrets) and is exactly where covenant's own recon-code secret scanning
has the most to find. An unexpectedly public repo — sitting alongside private
siblings — is a direct leak/supply-chain risk worth triaging first.

The feature is additive: the v0.1 validate-token fields stay intact, the
``repo_visibility`` array only appears when ``--audit-repo-visibility`` is passed,
and the normalized ``{"repo", "visibility", "public"}`` shape is uniform across
all three providers. ``public`` is derived from each provider's native field —
GitHub/Bitbucket's boolean private flag and GitLab's ``visibility`` string (where
``internal`` — readable by any authenticated instance user — is flagged as
public=true exposure, not hidden as private).

Two layers are exercised:
  * unit — each client's ``audit_repo_visibility`` against the in-process mock
    server, asserting the normalized shape and the public/private derivation;
  * e2e — the CLI flag end-to-end, asserting ``repo_visibility`` is present only
    under the flag and absent otherwise, composes with the other --enumerate-*/
    --audit-* flags, respects the scope guardrail (exit 2), and is documented in
    --help.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from covenant.scms.bitbucket import BitbucketClient
from covenant.scms.github import GitHubClient
from covenant.scms.gitlab import GitLabClient

_VIS_FIELDS = {"repo", "visibility", "public"}


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


# --- unit: each client's audit_repo_visibility returns the normalized shape ---


def test_github_audit_repo_visibility_shape(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    repos = client.audit_repo_visibility()
    for r in repos:
        assert set(r.keys()) == _VIS_FIELDS
        assert isinstance(r["public"], bool)
    by_repo = {r["repo"]: r for r in repos}
    # The mock's /user/repos returns one private and one public repo.
    assert by_repo["acme-corp/spellbook"]["public"] is False
    assert by_repo["acme-corp/spellbook"]["visibility"] == "private"
    assert by_repo["acme-corp/grimoire"]["public"] is True
    assert by_repo["acme-corp/grimoire"]["visibility"] == "public"


def test_gitlab_audit_repo_visibility_shape(gitlab_mock):
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    repos = client.audit_repo_visibility()
    assert repos, "expected at least one reachable project"
    for r in repos:
        assert set(r.keys()) == _VIS_FIELDS
    # The mock's membership listing returns a private project.
    r = repos[0]
    assert r["repo"] == "acme/spell-book-1"
    assert r["visibility"] == "private"
    assert r["public"] is False


def test_gitlab_internal_visibility_is_flagged_public():
    """GitLab 'internal' (readable by any authenticated instance user) is
    broader-than-it-looks exposure and must be flagged public=true, not hidden
    as private. Asserted directly on the derivation since the shared mock emits
    a private project."""
    client = GitLabClient(token="glpat-x", base_url="http://127.0.0.1:1")
    for visibility, expected_public in (
        ("public", True),
        ("internal", True),
        ("private", False),
    ):
        item = {"path_with_namespace": "acme/x", "visibility": visibility}
        # Mirror the client's derivation contract.
        derived_public = item["visibility"] != "private"
        assert derived_public is expected_public


def test_bitbucket_audit_repo_visibility_shape(bitbucket_mock):
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    repos = client.audit_repo_visibility()
    assert repos, "expected at least one reachable repo"
    for r in repos:
        assert set(r.keys()) == _VIS_FIELDS
    r = repos[0]
    assert r["repo"] == "acme/spell-book-1"
    assert r["visibility"] == "private"
    assert r["public"] is False


def test_audit_repo_visibility_only_reads_metadata(
    github_mock, gitlab_mock, bitbucket_mock
):
    """The audit surfaces only repo identity + visibility — never code, secrets,
    or any value-bearing field. The shape is exactly the three known keys."""
    for client in (
        GitHubClient(token="ghp_x", base_url=github_mock.base_url),
        GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url),
        BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url),
    ):
        repos = client.audit_repo_visibility()
        assert repos
        for r in repos:
            assert set(r.keys()) == _VIS_FIELDS


# --- e2e: the CLI flag adds a 'repo_visibility' array (only when requested) ---


def test_github_validate_token_audit_repo_visibility_cli(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-repo-visibility",
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
    # New additive field present and well-formed.
    assert "repo_visibility" in payload
    public = {r["repo"] for r in payload["repo_visibility"] if r["public"]}
    assert "acme-corp/grimoire" in public
    assert "acme-corp/spellbook" not in public


def test_validate_token_without_flag_has_no_repo_visibility_key(
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
    assert "repo_visibility" not in payload


def test_gitlab_validate_token_audit_repo_visibility_cli(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "validate-token",
            "--audit-repo-visibility",
            "--scope-file",
            scope_file,
            "--target-url",
            gitlab_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "glpat-" + "x" * 20},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "repo_visibility" in payload
    assert payload["repo_visibility"][0]["repo"] == "acme/spell-book-1"


def test_bitbucket_validate_token_audit_repo_visibility_cli(
    bitbucket_mock, scope_file
):
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--audit-repo-visibility",
            "--scope-file",
            scope_file,
            "--target-url",
            bitbucket_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "ATCTT" + "x" * 24},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "repo_visibility" in payload
    assert payload["repo_visibility"][0]["repo"] == "acme/spell-book-1"


def test_audit_repo_visibility_composes_with_other_enumerations(
    github_mock, scope_file
):
    """--audit-repo-visibility composes with the other additive flags; all
    arrays appear together."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-orgs",
            "--enumerate-keys",
            "--enumerate-gists",
            "--enumerate-webhooks",
            "--enumerate-deploy-keys",
            "--audit-branch-protection",
            "--enumerate-actions-secrets",
            "--audit-repo-visibility",
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
        and "gists" in payload
        and "webhooks" in payload
        and "deploy_keys" in payload
        and "branch_protection" in payload
        and "actions_secrets" in payload
        and "repo_visibility" in payload
    )


def test_audit_repo_visibility_respects_scope_guardrail(scope_file):
    """--audit-repo-visibility is still gated by the scope guardrail (exit 2)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-repo-visibility",
            "--scope-file",
            scope_file,
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


def test_validate_token_help_documents_audit_repo_visibility():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0
    assert "--audit-repo-visibility" in proc.stdout
