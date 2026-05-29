"""Tests for validate-token --audit-actions-permissions (CI execution posture).

Covers the read-only audit of the GitHub Actions execution-permission posture
of the repos a captured token can reach. Where ``--audit-actions-environments``
gates which DEPLOYMENTS reach an environment's secrets, this audits what a
workflow run may DO once it executes: whether Actions is enabled, and the
decisive supply-chain field — the default read/write permission of the automatic
``GITHUB_TOKEN`` granted to every run, plus whether a workflow may self-approve
pull requests. The two cross-provider invariants:

  * GitHub surfaces the real Actions-permission posture; GitLab and Bitbucket
    Cloud have no single per-repo equivalent, so the audit is empty there with
    an explanatory non-fatal warning (not a clean bill of health); and
  * a repo the token cannot administer (HTTP 403/404) is SKIPPED, not allowed to
    fail the whole audit, so a partial-permission token still reports every repo
    it can read.

The feature is additive: the v0.1 validate-token fields stay intact, the
``actions_permissions`` array only appears when ``--audit-actions-permissions``
is passed, and the normalized
``{"repo", "actions_enabled", "allowed_actions",
"default_workflow_permissions", "can_approve_pull_request_reviews"}`` shape is
uniform across providers. Only policy metadata is surfaced — never a credential.

Two layers are exercised:
  * unit — each client's ``audit_actions_permissions`` against the in-process
    mock server, asserting the normalized shape, the high-signal write posture,
    the disabled-repo handling, and the no-credential-leak invariant.
  * e2e — the CLI flag end-to-end, asserting ``actions_permissions`` is present
    only under the flag and absent otherwise, composes with the other
    --enumerate-*/--audit-* flags, respects the scope guardrail (exit 2), and is
    documented in --help.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from covenant.scms.bitbucket import BitbucketClient
from covenant.scms.github import GitHubClient
from covenant.scms.gitlab import GitLabClient

_AP_FIELDS = {
    "repo",
    "actions_enabled",
    "allowed_actions",
    "default_workflow_permissions",
    "can_approve_pull_request_reviews",
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


# --- unit: GitHub's audit_actions_permissions returns the normalized shape -----


def test_github_audit_actions_permissions_shape(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    records = client.audit_actions_permissions()
    # Both reachable repos are reported (Actions enabled on spellbook, disabled
    # on grimoire — disabled is still a reported posture, not a skip).
    by_repo = {r["repo"]: r for r in records}
    assert set(by_repo) == {"acme-corp/spellbook", "acme-corp/grimoire"}
    for r in records:
        assert set(r.keys()) == _AP_FIELDS


def test_github_audit_actions_permissions_surfaces_write_posture(github_mock):
    """The spellbook repo is the high-signal case: Actions enabled, a read/WRITE
    default GITHUB_TOKEN, and workflows allowed to self-approve PRs."""
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    by_repo = {r["repo"]: r for r in client.audit_actions_permissions()}
    spellbook = by_repo["acme-corp/spellbook"]
    assert spellbook["actions_enabled"] is True
    assert spellbook["allowed_actions"] == "all"
    assert spellbook["default_workflow_permissions"] == "write"
    assert spellbook["can_approve_pull_request_reviews"] is True


def test_github_audit_actions_permissions_disabled_repo_has_null_token_policy(
    github_mock,
):
    """A repo with Actions DISABLED has no workflow-token policy to read, so
    default_workflow_permissions is null and self-approval is false."""
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    by_repo = {r["repo"]: r for r in client.audit_actions_permissions()}
    grimoire = by_repo["acme-corp/grimoire"]
    assert grimoire["actions_enabled"] is False
    assert grimoire["default_workflow_permissions"] is None
    assert grimoire["can_approve_pull_request_reviews"] is False


def test_github_audit_actions_permissions_skips_unadministerable_repo():
    """A repo whose permissions endpoint answers 403/404 (token cannot administer
    it) is skipped, not fatal: the audit returns the repos it CAN read."""

    class _SkipClient(GitHubClient):
        def _reachable_repos(self, max_pages=10):
            return ["acme-corp/locked", "acme-corp/open"]

        def _actions_permissions_for_repo(self, full_name):
            if full_name.endswith("/locked"):
                return None  # mirrors the 403/404 skip path
            return {
                "repo": full_name,
                "actions_enabled": True,
                "allowed_actions": "all",
                "default_workflow_permissions": "read",
                "can_approve_pull_request_reviews": False,
            }

    client = _SkipClient(token="ghp_x", base_url="http://127.0.0.1:1")
    records = client.audit_actions_permissions()
    repos = {r["repo"] for r in records}
    assert "acme-corp/locked" not in repos
    assert "acme-corp/open" in repos


def test_gitlab_audit_actions_permissions_is_empty_with_warning(gitlab_mock):
    """GitLab has no single per-project Actions-permission API: the audit returns
    an empty list and records an explanatory non-fatal warning."""
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    records = client.audit_actions_permissions()
    assert records == []
    assert any("unsupported on GitLab" in w for w in client.warnings)


def test_bitbucket_audit_actions_permissions_is_empty_with_warning(bitbucket_mock):
    """Bitbucket Cloud has no per-repo Pipelines-permission API: the audit returns
    an empty list and records an explanatory non-fatal warning."""
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    records = client.audit_actions_permissions()
    assert records == []
    assert any("unsupported on Bitbucket" in w for w in client.warnings)


def test_audit_actions_permissions_never_surfaces_a_credential(github_mock):
    """The audit surfaces only policy metadata — the shape is exactly the five
    known keys; no token/secret value is ever present."""
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    records = client.audit_actions_permissions()
    assert records
    for r in records:
        assert set(r.keys()) == _AP_FIELDS
        # default_workflow_permissions is a policy label, never a value.
        assert r["default_workflow_permissions"] in (None, "read", "write")


# --- e2e: the CLI flag adds an 'actions_permissions' array (only when requested)


def test_github_validate_token_audit_actions_permissions_cli(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-actions-permissions",
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
    assert "actions_permissions" in payload
    by_repo = {r["repo"]: r for r in payload["actions_permissions"]}
    assert by_repo["acme-corp/spellbook"]["default_workflow_permissions"] == "write"
    assert by_repo["acme-corp/spellbook"]["can_approve_pull_request_reviews"] is True
    assert by_repo["acme-corp/grimoire"]["actions_enabled"] is False


def test_validate_token_without_flag_has_no_actions_permissions_key(
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
    assert "actions_permissions" not in payload


def test_gitlab_validate_token_audit_actions_permissions_cli(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "validate-token",
            "--audit-actions-permissions",
            "--scope-file",
            scope_file,
            "--target-url",
            gitlab_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "glpat-" + "x" * 20},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    # Empty array, but the explanatory warning surfaces in the payload.
    assert payload["actions_permissions"] == []
    assert "warnings" in payload
    assert any("unsupported on GitLab" in w for w in payload["warnings"])


def test_bitbucket_validate_token_audit_actions_permissions_cli(
    bitbucket_mock, scope_file
):
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--audit-actions-permissions",
            "--scope-file",
            scope_file,
            "--target-url",
            bitbucket_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "ATCTT" + "x" * 24},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["actions_permissions"] == []
    assert "warnings" in payload
    assert any("unsupported on Bitbucket" in w for w in payload["warnings"])


def test_audit_actions_permissions_composes_with_other_audits(github_mock, scope_file):
    """--audit-actions-permissions composes with the other additive flags; all
    arrays appear together."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-actions-environments",
            "--audit-code-scanning-alerts",
            "--audit-actions-permissions",
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
        "actions_environments" in payload
        and "code_scanning_alerts" in payload
        and "actions_permissions" in payload
        and "collaborators" in payload
    )


def test_audit_actions_permissions_respects_scope_guardrail(scope_file):
    """--audit-actions-permissions is still gated by the scope guardrail (exit 2)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-actions-permissions",
            "--scope-file",
            scope_file,
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


def test_validate_token_help_documents_audit_actions_permissions():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0
    assert "--audit-actions-permissions" in proc.stdout
