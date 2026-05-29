"""Tests for validate-token --enumerate-members (lateral-movement surface).

Covers the read-only enumeration of the OTHER members of the org/group/workspace
a captured token can reach. Where the rest of the ``--enumerate-*`` family maps
what *this* token reaches (its keys, repos, secrets), member enumeration maps the
*people* who share that reach: the additional identities an operator could target
to widen a foothold (phishing, credential reuse, a weaker teammate token) and,
for the org owners (``role=admin``), the accounts whose compromise grants
administrative control of the whole org.

The feature is additive: the v0.1 validate-token fields stay intact, the
``members`` array only appears when ``--enumerate-members`` is passed, and the
normalized ``{"scope", "owner", "username", "role"}`` shape is uniform across all
three providers. ``role`` is derived from each provider's native model — GitHub's
``?role=admin|member`` views, GitLab's numeric ``access_level`` (>= 50 Owner ->
admin), and Bitbucket's ``permission`` field (``owner`` -> admin).

Two layers are exercised:
  * unit — each client's ``enumerate_members`` against the in-process mock
    server, asserting the normalized shape, the admin/member role mapping, and
    that no email/key/credential field leaks;
  * e2e — the CLI flag end-to-end, asserting ``members`` is present only under
    the flag and absent otherwise, composes with the other --enumerate-*/
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

_MEMBER_FIELDS = {"scope", "owner", "username", "role"}
# Fields that must NEVER appear in a member record — covenant surfaces identity
# and role only, never a credential or contactable detail.
_FORBIDDEN_FIELDS = {"email", "key", "token", "secret", "password", "access_token"}


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


# --- unit: each client's enumerate_members returns the normalized shape ---


def test_github_enumerate_members_shape(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    members = client.enumerate_members()
    assert members, "expected at least one member"
    for m in members:
        assert set(m.keys()) == _MEMBER_FIELDS
        assert m["scope"] == "org"
        assert m["role"] in ("admin", "member")
    by_user = {m["username"]: m for m in members}
    # The mock returns one admin (owner) per org plus two members.
    admins = [m for m in members if m["role"] == "admin"]
    assert admins, "expected at least one admin (org owner)"
    assert all(m["username"].endswith("-owner") for m in admins)
    assert "spellcaster" in by_user
    assert by_user["spellcaster"]["role"] == "member"


def test_gitlab_enumerate_members_shape(gitlab_mock):
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    members = client.enumerate_members()
    assert members, "expected at least one group member"
    for m in members:
        assert set(m.keys()) == _MEMBER_FIELDS
        assert m["scope"] == "group"
    by_user = {m["username"]: m for m in members}
    # access_level 50 (Owner) -> admin, 30 (Developer) -> member.
    assert by_user["spellcaster"]["role"] == "admin"
    assert by_user["apprentice"]["role"] == "member"


def test_bitbucket_enumerate_members_shape(bitbucket_mock):
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    members = client.enumerate_members()
    assert members, "expected at least one workspace member"
    for m in members:
        assert set(m.keys()) == _MEMBER_FIELDS
        assert m["scope"] == "workspace"
    by_user = {m["username"]: m for m in members}
    # permission 'owner' -> admin, 'member' -> member.
    assert by_user["spellcaster"]["role"] == "admin"
    assert by_user["apprentice"]["role"] == "member"


def test_enumerate_members_only_surfaces_identity_and_role(
    github_mock, gitlab_mock, bitbucket_mock
):
    """The enumeration surfaces only membership identity + role — never an
    email, key, or credential. The shape is exactly the four known keys."""
    for client in (
        GitHubClient(token="ghp_x", base_url=github_mock.base_url),
        GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url),
        BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url),
    ):
        members = client.enumerate_members()
        assert members
        for m in members:
            assert set(m.keys()) == _MEMBER_FIELDS
            assert not (_FORBIDDEN_FIELDS & set(m.keys()))


# --- e2e: the CLI flag adds a 'members' array (only when requested) ---


def test_github_validate_token_enumerate_members_cli(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-members",
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
    assert "members" in payload
    admins = {m["username"] for m in payload["members"] if m["role"] == "admin"}
    assert admins, "expected at least one admin in the members array"


def test_validate_token_without_flag_has_no_members_key(github_mock, scope_file):
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
    assert "members" not in payload


def test_gitlab_validate_token_enumerate_members_cli(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "validate-token",
            "--enumerate-members",
            "--scope-file",
            scope_file,
            "--target-url",
            gitlab_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "glpat-" + "x" * 20},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "members" in payload
    assert any(m["role"] == "admin" for m in payload["members"])


def test_bitbucket_validate_token_enumerate_members_cli(
    bitbucket_mock, scope_file
):
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--enumerate-members",
            "--scope-file",
            scope_file,
            "--target-url",
            bitbucket_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "ATCTT" + "x" * 24},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "members" in payload
    assert any(m["role"] == "admin" for m in payload["members"])


def test_enumerate_members_composes_with_other_enumerations(
    github_mock, scope_file
):
    """--enumerate-members composes with the other additive flags; all arrays
    appear together."""
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
    )


def test_enumerate_members_respects_scope_guardrail(scope_file):
    """--enumerate-members is still gated by the scope guardrail (exit 2)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-members",
            "--scope-file",
            scope_file,
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


def test_validate_token_help_documents_enumerate_members():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0
    assert "--enumerate-members" in proc.stdout
