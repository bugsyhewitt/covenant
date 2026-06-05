"""Tests for validate-token --enumerate-teams (org/group team/subgroup inventory).

Covers the read-only enumeration of the teams/subgroups of each org/group the
captured token can reach.

GitHub: ``GET /orgs/{org}/teams`` — org teams with slug, privacy, parent.
GitLab: ``GET /api/v4/groups/{id}/subgroups`` — group subgroups.
Bitbucket Cloud: no sub-unit API; returns empty list + warning.

Normalized shape: ``{"scope", "owner", "team_name", "team_slug", "description",
"privacy", "parent_slug"}`` — only team metadata, never member identities or
credentials.

Two layers exercised:
  * unit — each client's ``enumerate_teams`` against the in-process mock server,
    asserting normalized shape, privacy/parent mapping, no-credential leak;
  * e2e — CLI flag end-to-end, asserting ``teams`` appears only under the flag,
    composes with other --enumerate-*/--audit-* flags, respects scope guardrail
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

_TEAM_FIELDS = {
    "scope",
    "owner",
    "team_name",
    "team_slug",
    "description",
    "privacy",
    "parent_slug",
}
# Fields that must NEVER appear in a team record.
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


# --- unit: each client's enumerate_teams returns the normalized shape ---


def test_github_enumerate_teams_shape(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    teams = client.enumerate_teams()
    assert teams, "expected at least one team from the mock GitHub server"
    for t in teams:
        assert set(t.keys()) == _TEAM_FIELDS, f"unexpected keys: {set(t.keys())}"
        assert t["scope"] == "org"
        assert isinstance(t["team_name"], str) and t["team_name"]
        assert isinstance(t["team_slug"], str) and t["team_slug"]
        assert isinstance(t["description"], str)
        assert isinstance(t["privacy"], str)
        # parent_slug is None for top-level teams, str for nested ones.
        assert t["parent_slug"] is None or isinstance(t["parent_slug"], str)


def test_github_enumerate_teams_privacy_values(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    teams = client.enumerate_teams()
    privacies = {t["privacy"] for t in teams}
    # The mock returns one "secret" and one "closed" team per org.
    assert "secret" in privacies
    assert "closed" in privacies


def test_github_enumerate_teams_parent_slug(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    teams = client.enumerate_teams()
    top_level = [t for t in teams if t["parent_slug"] is None]
    nested = [t for t in teams if t["parent_slug"] is not None]
    assert top_level, "expected at least one top-level team"
    assert nested, "expected at least one nested team"
    # The nested team's parent_slug should match a top-level team's slug.
    top_slugs = {t["team_slug"] for t in top_level}
    for nt in nested:
        assert nt["parent_slug"] in top_slugs, (
            f"nested team parent_slug {nt['parent_slug']!r} not found in "
            f"top-level slugs {top_slugs!r}"
        )


def test_gitlab_enumerate_teams_shape(gitlab_mock):
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    teams = client.enumerate_teams()
    assert teams, "expected at least one subgroup from the mock GitLab server"
    for t in teams:
        assert set(t.keys()) == _TEAM_FIELDS, f"unexpected keys: {set(t.keys())}"
        assert t["scope"] == "group"
        assert isinstance(t["team_name"], str) and t["team_name"]
        assert isinstance(t["team_slug"], str)
        # privacy maps GitLab visibility
        assert isinstance(t["privacy"], str)


def test_gitlab_enumerate_teams_parent_slug_is_group(gitlab_mock):
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    teams = client.enumerate_teams()
    # GitLab subgroups always have the parent group as parent_slug.
    for t in teams:
        assert t["parent_slug"] is not None, (
            "GitLab subgroups should always have a parent_slug (the containing group)"
        )
        assert isinstance(t["parent_slug"], str)


def test_bitbucket_enumerate_teams_is_empty_with_warning(bitbucket_mock):
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    teams = client.enumerate_teams()
    assert teams == [], "Bitbucket Cloud should return an empty teams list"
    assert any("team" in w.lower() for w in client.warnings), (
        "expected a warning entry explaining the empty result is a platform limitation"
    )


def test_enumerate_teams_no_credentials_leaked(github_mock, gitlab_mock):
    for client in (
        GitHubClient(token="ghp_x", base_url=github_mock.base_url),
        GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url),
    ):
        teams = client.enumerate_teams()
        assert teams
        for t in teams:
            assert set(t.keys()) == _TEAM_FIELDS
            assert not (_FORBIDDEN_FIELDS & set(t.keys()))


# --- e2e: the CLI flag adds a 'teams' array (only when requested) ---


def test_github_validate_token_enumerate_teams_cli(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-teams",
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
    assert "teams" in payload
    assert isinstance(payload["teams"], list)
    assert payload["teams"], "expected at least one team entry"
    for t in payload["teams"]:
        assert set(t.keys()) == _TEAM_FIELDS


def test_validate_token_without_flag_has_no_teams_key(github_mock, scope_file):
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
    assert "teams" not in payload


def test_gitlab_validate_token_enumerate_teams_cli(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "validate-token",
            "--enumerate-teams",
            "--scope-file",
            scope_file,
            "--target-url",
            gitlab_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "glpat-" + "x" * 20},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "teams" in payload
    assert isinstance(payload["teams"], list)


def test_bitbucket_validate_token_enumerate_teams_cli(bitbucket_mock, scope_file):
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--enumerate-teams",
            "--scope-file",
            scope_file,
            "--target-url",
            bitbucket_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "ATCTT" + "x" * 24},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "teams" in payload
    assert payload["teams"] == [], "Bitbucket teams should be empty"
    # The warning should propagate to the CLI output.
    assert "warnings" in payload
    assert any("team" in w.lower() for w in payload["warnings"])


def test_enumerate_teams_composes_with_other_enumerations(
    github_mock, scope_file
):
    """--enumerate-teams composes with the other additive flags; all arrays
    appear together."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-orgs",
            "--enumerate-keys",
            "--enumerate-members",
            "--enumerate-teams",
            "--scope-file",
            scope_file,
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "orgs" in payload
    assert "keys" in payload
    assert "members" in payload
    assert "teams" in payload


def test_enumerate_teams_respects_scope_guardrail(scope_file):
    """--enumerate-teams is still gated by the scope guardrail (exit 2)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-teams",
            "--scope-file",
            scope_file,
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


def test_validate_token_help_documents_enumerate_teams():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0
    assert "--enumerate-teams" in proc.stdout
