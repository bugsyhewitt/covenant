"""Tests for validate-token --audit-actions-environments (deploy-gate posture).

A deployment *environment* (GitHub Actions "Environments", GitLab project
environments, Bitbucket Pipelines deployment environments) is where the most
sensitive CI/CD secrets are scoped — production cloud keys, registry passwords,
deploy tokens. Its *protection rules* are the gate that decides whether a
workflow may deploy to it and thereby READ those secrets. This audit is the
environment-scoped, secret-exfiltration counterpart to
--audit-branch-protection: where branch protection gates code landing on a
branch, this gates deployments reaching the secrets.

The high-signal finding is an environment with ``required_reviewers=false`` and
a permissive ``branch_policy`` of ``"all"`` — any branch (including an
attacker's feature branch carrying a malicious workflow) can deploy and
exfiltrate the environment's secrets unreviewed.

The feature is additive: the v0.1 validate-token fields stay intact, the
``actions_environments`` array only appears when ``--audit-actions-environments``
is passed, and the normalized output shape is uniform across all three providers.

Two layers are exercised:
  * unit — each client's ``audit_actions_environments`` against the in-process
    mock server, asserting the normalized
    ``{"repo", "environment", "required_reviewers", "required_reviewer_count",
    "wait_timer", "branch_policy"}`` shape and that the weak-vs-strong posture is
    read correctly per provider;
  * e2e — the CLI flag end-to-end, asserting ``actions_environments`` is present
    only under ``--audit-actions-environments`` and absent otherwise, with no
    shape regression, that it composes with the other --enumerate-*/--audit-*
    flags, and that it respects the scope guardrail.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from covenant.scms.bitbucket import BitbucketClient
from covenant.scms.github import GitHubClient
from covenant.scms.gitlab import GitLabClient

_ENV_FIELDS = {
    "repo",
    "environment",
    "required_reviewers",
    "required_reviewer_count",
    "wait_timer",
    "branch_policy",
}


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


# --- unit: each client's audit_actions_environments returns the normalized shape


def test_github_audit_actions_environments_shape(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    envs = client.audit_actions_environments()
    # Two reachable repos, one 'production' environment each.
    assert len(envs) == 2
    for entry in envs:
        assert set(entry.keys()) == _ENV_FIELDS
        assert entry["environment"] == "production"
    by_repo = {e["repo"]: e for e in envs}
    assert set(by_repo) == {"acme-corp/spellbook", "acme-corp/grimoire"}
    # spellbook is WEAK — no protection rules, no branch policy: any branch can
    # deploy and read its secrets unreviewed (the high-signal supply-chain gap).
    weak = by_repo["acme-corp/spellbook"]
    assert weak["required_reviewers"] is False
    assert weak["required_reviewer_count"] == 0
    assert weak["wait_timer"] == 0
    assert weak["branch_policy"] == "all"
    # grimoire is STRONG — required reviewers, a wait timer, protected branches.
    strong = by_repo["acme-corp/grimoire"]
    assert strong["required_reviewers"] is True
    assert strong["required_reviewer_count"] == 2
    assert strong["wait_timer"] == 30
    assert strong["branch_policy"] == "protected"


def test_gitlab_audit_actions_environments_shape(gitlab_mock):
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    envs = client.audit_actions_environments()
    # One project, two environments: production (protected, 2 approvals) and
    # staging (not protected -> branch_policy 'all').
    assert len(envs) == 2
    for entry in envs:
        assert set(entry.keys()) == _ENV_FIELDS
        assert entry["repo"] == "acme/spell-book-1"
        # GitLab has no per-env deploy wait timer.
        assert entry["wait_timer"] == 0
    by_env = {e["environment"]: e for e in envs}
    assert set(by_env) == {"production", "staging"}
    prod = by_env["production"]
    assert prod["required_reviewers"] is True
    assert prod["required_reviewer_count"] == 2
    assert prod["branch_policy"] == "protected"
    stage = by_env["staging"]
    assert stage["required_reviewers"] is False
    assert stage["required_reviewer_count"] == 0
    assert stage["branch_policy"] == "all"


def test_bitbucket_audit_actions_environments_shape(bitbucket_mock):
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    envs = client.audit_actions_environments()
    # One repo, two environments: production (admin-only deploy gate) and
    # staging (no gate).
    assert len(envs) == 2
    for entry in envs:
        assert set(entry.keys()) == _ENV_FIELDS
        assert entry["repo"] == "acme/spell-book-1"
        # Bitbucket Cloud has no per-env reviewer count / wait timer / branch
        # policy, so those are constant for shape parity.
        assert entry["required_reviewer_count"] == 0
        assert entry["wait_timer"] == 0
        assert entry["branch_policy"] == "all"
    by_env = {e["environment"]: e for e in envs}
    assert set(by_env) == {"production", "staging"}
    # production deploy gate is admin-restricted -> required_reviewers True.
    assert by_env["production"]["required_reviewers"] is True
    # staging has no gate -> the weak, unreviewed-deploy case.
    assert by_env["staging"]["required_reviewers"] is False


def test_audit_actions_environments_never_leaks_secrets(
    github_mock, gitlab_mock, bitbucket_mock
):
    """The audit only reports policy metadata — no secret VALUES, tokens, or key
    material ever appear, and the field set is exactly the documented fields."""
    for client in (
        GitHubClient(token="ghp_x", base_url=github_mock.base_url),
        GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url),
        BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url),
    ):
        for entry in client.audit_actions_environments():
            assert set(entry.keys()) == _ENV_FIELDS
            blob = json.dumps(entry).lower()
            assert "secret" not in blob
            assert "token" not in blob
            assert "private key" not in blob


def test_github_branch_policy_helper():
    """The deployment_branch_policy -> flat label mapping covers all shapes."""
    from covenant.scms.github import _github_branch_policy

    # null / missing -> any branch may deploy (weakest).
    assert _github_branch_policy(None) == "all"
    assert _github_branch_policy({}) == "all"
    assert (
        _github_branch_policy(
            {"protected_branches": False, "custom_branch_policies": False}
        )
        == "all"
    )
    # protected-only.
    assert (
        _github_branch_policy(
            {"protected_branches": True, "custom_branch_policies": False}
        )
        == "protected"
    )
    # custom allow-list (reported as 'custom', and wins when both are set since a
    # custom allow-list can include unprotected patterns).
    assert (
        _github_branch_policy(
            {"protected_branches": False, "custom_branch_policies": True}
        )
        == "custom"
    )
    assert (
        _github_branch_policy(
            {"protected_branches": True, "custom_branch_policies": True}
        )
        == "custom"
    )


# --- e2e: the CLI flag adds an 'actions_environments' array (only when asked) ---


def test_github_validate_token_audit_actions_environments_cli(
    github_mock, scope_file
):
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-actions-environments",
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
    assert "actions_environments" in payload
    by_repo = {e["repo"]: e for e in payload["actions_environments"]}
    assert set(by_repo) == {"acme-corp/spellbook", "acme-corp/grimoire"}
    assert by_repo["acme-corp/spellbook"]["required_reviewers"] is False
    assert by_repo["acme-corp/spellbook"]["branch_policy"] == "all"


def test_validate_token_without_flag_has_no_actions_environments_key(
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
    assert "actions_environments" not in payload


def test_gitlab_validate_token_audit_actions_environments_cli(
    gitlab_mock, scope_file
):
    proc = _run(
        [
            "gitlab",
            "validate-token",
            "--audit-actions-environments",
            "--scope-file",
            scope_file,
            "--target-url",
            gitlab_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "glpat-" + "x" * 20},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    by_env = {e["environment"]: e for e in payload["actions_environments"]}
    assert by_env["production"]["required_reviewer_count"] == 2
    assert by_env["staging"]["branch_policy"] == "all"


def test_bitbucket_validate_token_audit_actions_environments_cli(
    bitbucket_mock, scope_file
):
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--audit-actions-environments",
            "--scope-file",
            scope_file,
            "--target-url",
            bitbucket_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "ATCTT" + "x" * 24},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    by_env = {e["environment"]: e for e in payload["actions_environments"]}
    assert by_env["production"]["required_reviewers"] is True
    assert by_env["staging"]["required_reviewers"] is False


def test_audit_actions_environments_composes_with_other_audits(
    github_mock, scope_file
):
    """--audit-actions-environments is an independent additive flag that may be
    requested alongside the other --enumerate-*/--audit-* flags; all arrays
    appear."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-actions-secrets",
            "--audit-branch-protection",
            "--audit-actions-environments",
            "--scope-file",
            scope_file,
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert (
        "actions_secrets" in payload
        and "branch_protection" in payload
        and "actions_environments" in payload
    )
    assert {e["repo"] for e in payload["actions_environments"]} == {
        "acme-corp/spellbook",
        "acme-corp/grimoire",
    }


def test_audit_actions_environments_respects_scope_guardrail(scope_file):
    """--audit-actions-environments is still gated by the scope guardrail (exit 2)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-actions-environments",
            "--scope-file",
            scope_file,
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


def test_validate_token_help_documents_audit_actions_environments():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0
    assert "--audit-actions-environments" in proc.stdout
