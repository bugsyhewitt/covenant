"""Tests for validate-token --enumerate-actions-secrets (CI/CD secret names).

Covers the read-only enumeration of the CI/CD secret NAMES a captured token can
reach — GitHub Actions org/repo secrets, GitLab group/project CI/CD variables,
and Bitbucket workspace/repo Pipelines variables. CI/CD secrets are the
credential surface that powers the build pipeline (cloud keys, registry
passwords, signing/deploy tokens), so a long list is a high-blast-radius
lateral-movement and supply-chain target: an attacker who can read or exfiltrate
them via a malicious workflow inherits exactly the pipeline's reach.

The decisive INVARIANT is name-only disclosure: covenant surfaces ONLY the
secret NAME and metadata, never the VALUE. The provider APIs deliberately omit
secured values, and covenant emits names only — these tests assert no
``value`` field and no planted ``shouldnotappear`` value ever reaches output.

The feature is additive: the v0.1 validate-token fields stay intact, the
``actions_secrets`` array only appears when ``--enumerate-actions-secrets`` is
passed, and the normalized ``{"scope", "owner", "name", "protected"}`` shape is
uniform across all three providers.

Two layers are exercised:
  * unit — each client's ``enumerate_actions_secrets`` against the in-process
    mock server, asserting the normalized shape, the org-vs-repo ``scope`` split,
    the ``protected`` flag mapping, and the no-value-leak invariant;
  * e2e — the CLI flag end-to-end, asserting ``actions_secrets`` is present only
    under the flag and absent otherwise, composes with the other --enumerate-*
    flags, respects the scope guardrail (exit 2), and is documented in --help.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from covenant.scms.bitbucket import BitbucketClient
from covenant.scms.github import GitHubClient
from covenant.scms.gitlab import GitLabClient

_SECRET_FIELDS = {"scope", "owner", "name", "protected"}


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


# --- unit: each client's enumerate_actions_secrets returns the normalized shape ---


def test_github_enumerate_actions_secrets_shape(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    secrets = client.enumerate_actions_secrets()
    for s in secrets:
        assert set(s.keys()) == _SECRET_FIELDS
        assert isinstance(s["protected"], bool)
    # 2 orgs x 2 org secrets + 2 repos x 1 repo secret = 6.
    assert len(secrets) == 6
    org_secrets = [s for s in secrets if s["scope"] == "org"]
    repo_secrets = [s for s in secrets if s["scope"] == "repo"]
    assert len(org_secrets) == 4
    assert len(repo_secrets) == 2
    # The selected-visibility org secret maps to protected=True.
    by_name = {s["name"] for s in org_secrets}
    assert by_name == {"ORG_AWS_KEY", "ORG_NPM_TOKEN"}
    npm = next(s for s in org_secrets if s["name"] == "ORG_NPM_TOKEN")
    aws = next(s for s in org_secrets if s["name"] == "ORG_AWS_KEY")
    assert npm["protected"] is True
    assert aws["protected"] is False
    # Repo secrets carry the owner/repo full name in 'owner'.
    assert {s["owner"] for s in repo_secrets} == {
        "acme-corp/spellbook",
        "acme-corp/grimoire",
    }
    assert all(s["name"] == "DEPLOY_TOKEN" for s in repo_secrets)


def test_gitlab_enumerate_actions_secrets_shape(gitlab_mock):
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    secrets = client.enumerate_actions_secrets()
    for s in secrets:
        assert set(s.keys()) == _SECRET_FIELDS
    # 2 groups x 2 group vars + 1 project x 1 project var = 5.
    assert len(secrets) == 5
    group_secrets = [s for s in secrets if s["scope"] == "org"]
    project_secrets = [s for s in secrets if s["scope"] == "repo"]
    assert len(group_secrets) == 4
    assert len(project_secrets) == 1
    protected = next(s for s in group_secrets if s["name"] == "GROUP_NPM_TOKEN")
    assert protected["protected"] is True
    assert project_secrets[0]["name"] == "DEPLOY_TOKEN"
    assert project_secrets[0]["owner"] == "acme/spell-book-1"


def test_bitbucket_enumerate_actions_secrets_shape(bitbucket_mock):
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    secrets = client.enumerate_actions_secrets()
    for s in secrets:
        assert set(s.keys()) == _SECRET_FIELDS
    # 2 workspaces x 2 vars + 1 repo x 1 var = 5.
    assert len(secrets) == 5
    ws_secrets = [s for s in secrets if s["scope"] == "org"]
    repo_secrets = [s for s in secrets if s["scope"] == "repo"]
    assert len(ws_secrets) == 4
    assert len(repo_secrets) == 1
    # A 'secured' Bitbucket variable maps to protected=True.
    secured = next(s for s in ws_secrets if s["name"] == "WS_NPM_TOKEN")
    assert secured["protected"] is True
    assert repo_secrets[0]["owner"] == "acme/spell-book-1"


def test_enumerate_actions_secrets_never_emits_values(
    github_mock, gitlab_mock, bitbucket_mock
):
    """The decisive invariant: only secret NAMES and metadata are surfaced —
    the secret VALUE is never read into the output. The mock servers plant a
    'shouldnotappear' value on every variable that has one; it must never reach
    covenant's output, and no 'value' field may be present."""
    for client in (
        GitHubClient(token="ghp_x", base_url=github_mock.base_url),
        GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url),
        BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url),
    ):
        secrets = client.enumerate_actions_secrets()
        assert secrets, "expected at least one secret name"
        for s in secrets:
            assert "value" not in s
            blob = json.dumps(s)
            assert "shouldnotappear" not in blob


# --- e2e: the CLI flag adds an 'actions_secrets' array (only when requested) ---


def test_github_validate_token_enumerate_actions_secrets_cli(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-actions-secrets",
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
    assert "actions_secrets" in payload
    names = {s["name"] for s in payload["actions_secrets"]}
    assert {"ORG_AWS_KEY", "ORG_NPM_TOKEN", "DEPLOY_TOKEN"} <= names
    # No secret value ever lands in the CLI output.
    assert "shouldnotappear" not in proc.stdout


def test_validate_token_without_flag_has_no_actions_secrets_key(
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
    assert "actions_secrets" not in payload


def test_gitlab_validate_token_enumerate_actions_secrets_cli(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "validate-token",
            "--enumerate-actions-secrets",
            "--scope-file",
            scope_file,
            "--target-url",
            gitlab_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "glpat-" + "x" * 20},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    names = {s["name"] for s in payload["actions_secrets"]}
    assert "GROUP_NPM_TOKEN" in names
    assert "shouldnotappear" not in proc.stdout


def test_bitbucket_validate_token_enumerate_actions_secrets_cli(
    bitbucket_mock, scope_file
):
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--enumerate-actions-secrets",
            "--scope-file",
            scope_file,
            "--target-url",
            bitbucket_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "ATCTT" + "x" * 24},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    names = {s["name"] for s in payload["actions_secrets"]}
    assert "WS_NPM_TOKEN" in names
    assert "shouldnotappear" not in proc.stdout


def test_enumerate_actions_secrets_composes_with_other_enumerations(
    github_mock, scope_file
):
    """--enumerate-actions-secrets composes with the other additive flags; all
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
    )


def test_enumerate_actions_secrets_respects_scope_guardrail(scope_file):
    """--enumerate-actions-secrets is still gated by the scope guardrail
    (exit 2)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-actions-secrets",
            "--scope-file",
            scope_file,
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


def test_validate_token_help_documents_enumerate_actions_secrets():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0
    assert "--enumerate-actions-secrets" in proc.stdout
