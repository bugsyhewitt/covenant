"""Tests for validate-token --enumerate-collaborators (ghost-account surface).

Covers the read-only enumeration of the per-repo collaborator grants on the
repositories a captured token can reach. Where ``--enumerate-members`` maps the
people who share an ORG/group/workspace's reach, collaborator enumeration is
REPO-scoped and surfaces the higher-signal blast radius: personal accounts
granted access DIRECTLY on a specific repository — the classic ghost-account /
ex-employee / leftover-contractor vector (``outside=true``) that an org-member
audit misses and that survives long after the person leaves. A write-or-above
direct grant is a supply-chain and persistence risk.

The feature is additive: the v0.1 validate-token fields stay intact, the
``collaborators`` array only appears when ``--enumerate-collaborators`` is passed,
and the normalized ``{"repo", "username", "role", "outside"}`` shape is uniform
across all three providers. ``role`` is the highest-privilege level
(admin/maintain/write/triage/read), derived from each provider's native model —
GitHub's ``permissions`` map, GitLab's numeric ``access_level``, and Bitbucket's
``permission`` string.

Two layers are exercised:
  * unit — each client's ``enumerate_collaborators`` against the in-process mock
    server, asserting the normalized shape, the role mapping, the ``outside``
    flag, and that no email/key/credential field leaks;
  * e2e — the CLI flag end-to-end, asserting ``collaborators`` is present only
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

_COLLAB_FIELDS = {"repo", "username", "role", "outside"}
# Fields that must NEVER appear in a collaborator record — covenant surfaces
# identity + permission level only, never a credential or contactable detail.
_FORBIDDEN_FIELDS = {"email", "key", "token", "secret", "password", "access_token"}
_VALID_ROLES = {"admin", "maintain", "write", "triage", "read"}


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


# --- unit: each client's enumerate_collaborators returns the normalized shape ---


def test_github_enumerate_collaborators_shape(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    collabs = client.enumerate_collaborators()
    assert collabs, "expected at least one collaborator"
    for c in collabs:
        assert set(c.keys()) == _COLLAB_FIELDS
        assert c["role"] in _VALID_ROLES
        # affiliation=outside means every returned account is an outside grant.
        assert c["outside"] is True
    by_user = {c["username"]: c for c in collabs}
    # The spellbook repo has a WRITE outside collaborator (the high-signal,
    # ghost-account case); grimoire has a read-only one.
    assert "ex-contractor" in by_user
    assert by_user["ex-contractor"]["role"] == "write"
    assert "auditor" in by_user
    assert by_user["auditor"]["role"] == "read"


def test_gitlab_enumerate_collaborators_shape(gitlab_mock):
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    collabs = client.enumerate_collaborators()
    assert collabs, "expected at least one direct project member"
    for c in collabs:
        assert set(c.keys()) == _COLLAB_FIELDS
        assert c["role"] in _VALID_ROLES
        assert c["outside"] is True
    by_user = {c["username"]: c for c in collabs}
    # access_level 30 (Developer) -> write; 10 (Guest) -> read.
    assert by_user["ex-contractor"]["role"] == "write"
    assert by_user["auditor"]["role"] == "read"


def test_bitbucket_enumerate_collaborators_shape(bitbucket_mock):
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    collabs = client.enumerate_collaborators()
    assert collabs, "expected at least one repo user grant"
    for c in collabs:
        assert set(c.keys()) == _COLLAB_FIELDS
        assert c["role"] in _VALID_ROLES
        assert c["outside"] is True
    by_user = {c["username"]: c for c in collabs}
    # Bitbucket grades access as admin/write/read; surfaced verbatim.
    assert by_user["ex-contractor"]["role"] == "write"


def test_enumerate_collaborators_only_surfaces_identity_and_role(
    github_mock, gitlab_mock, bitbucket_mock
):
    """The enumeration surfaces only identity + permission level — never an
    email, key, or credential. The shape is exactly the four known keys."""
    for client in (
        GitHubClient(token="ghp_x", base_url=github_mock.base_url),
        GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url),
        BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url),
    ):
        collabs = client.enumerate_collaborators()
        assert collabs
        for c in collabs:
            assert set(c.keys()) == _COLLAB_FIELDS
            assert not (_FORBIDDEN_FIELDS & set(c.keys()))


# --- e2e: the CLI flag adds a 'collaborators' array (only when requested) ---


def test_github_validate_token_enumerate_collaborators_cli(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-collaborators",
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
    assert "collaborators" in payload
    writers = {
        c["username"]
        for c in payload["collaborators"]
        if c["role"] == "write" and c["outside"]
    }
    assert "ex-contractor" in writers, (
        "expected the writable outside collaborator (ghost-account signal)"
    )


def test_validate_token_without_flag_has_no_collaborators_key(
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
    assert "collaborators" not in payload


def test_gitlab_validate_token_enumerate_collaborators_cli(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "validate-token",
            "--enumerate-collaborators",
            "--scope-file",
            scope_file,
            "--target-url",
            gitlab_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "glpat-" + "x" * 20},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "collaborators" in payload
    assert any(c["role"] == "write" for c in payload["collaborators"])


def test_bitbucket_validate_token_enumerate_collaborators_cli(
    bitbucket_mock, scope_file
):
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--enumerate-collaborators",
            "--scope-file",
            scope_file,
            "--target-url",
            bitbucket_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "ATCTT" + "x" * 24},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "collaborators" in payload
    assert any(c["role"] == "write" for c in payload["collaborators"])


def test_enumerate_collaborators_composes_with_other_enumerations(
    github_mock, scope_file
):
    """--enumerate-collaborators composes with the other additive flags; all
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
            "--enumerate-members",
            "--enumerate-collaborators",
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
        and "members" in payload
        and "collaborators" in payload
    )


def test_enumerate_collaborators_respects_scope_guardrail(scope_file):
    """--enumerate-collaborators is still gated by the scope guardrail (exit 2)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-collaborators",
            "--scope-file",
            scope_file,
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


def test_validate_token_help_documents_enumerate_collaborators():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0
    assert "--enumerate-collaborators" in proc.stdout
