"""Tests for validate-token --audit-branch-protection (defensive posture).

Branch protection is the DEFENSIVE counterpart to the --enumerate-* family:
where the enumerations map a captured token's offensive reach (keys it owns,
repos it can push to, webhooks it can redirect), this audit reports whether a
writable foothold would actually be stopped before code lands on a protected
branch. A protected branch that does not require pull-request review, does not
require signed commits, and/or does not enforce its rules on admins is a
supply-chain weak point — the high-signal finding is ``required_reviews=false``
on a reachable repo, meaning an attacker who can push can do so unreviewed.

The feature is additive: the v0.1 validate-token fields stay intact, the
``branch_protection`` array only appears when ``--audit-branch-protection`` is
passed, and the normalized output shape is uniform across all three providers.

Two layers are exercised:
  * unit — each client's ``audit_branch_protection`` against the in-process mock
    server, asserting the normalized
    ``{"repo", "branch", "required_reviews", "required_review_count",
    "dismiss_stale_reviews", "require_signed_commits", "enforce_admins"}`` shape
    and that the weak-vs-strong posture is read correctly per provider;
  * e2e — the CLI flag end-to-end, asserting ``branch_protection`` is present
    only under ``--audit-branch-protection`` and absent otherwise, with no shape
    regression, that it composes with the --enumerate-* flags, and that it
    respects the scope guardrail.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from covenant.scms.bitbucket import BitbucketClient
from covenant.scms.github import GitHubClient
from covenant.scms.gitlab import GitLabClient

_BP_FIELDS = {
    "repo",
    "branch",
    "required_reviews",
    "required_review_count",
    "dismiss_stale_reviews",
    "require_signed_commits",
    "enforce_admins",
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


# --- unit: each client's audit_branch_protection returns the normalized shape --


def test_github_audit_branch_protection_shape(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    bp = client.audit_branch_protection()
    # Two reachable repos, one protected branch ('main') each.
    assert len(bp) == 2
    for entry in bp:
        assert set(entry.keys()) == _BP_FIELDS
        assert entry["branch"] == "main"
    by_repo = {e["repo"]: e for e in bp}
    assert set(by_repo) == {"acme-corp/spellbook", "acme-corp/grimoire"}
    # spellbook is the WEAK branch — no required reviews, no signed commits,
    # admins not enforced (the high-signal supply-chain gap).
    weak = by_repo["acme-corp/spellbook"]
    assert weak["required_reviews"] is False
    assert weak["required_review_count"] == 0
    assert weak["require_signed_commits"] is False
    assert weak["enforce_admins"] is False
    # grimoire is the STRONG branch.
    strong = by_repo["acme-corp/grimoire"]
    assert strong["required_reviews"] is True
    assert strong["required_review_count"] == 2
    assert strong["dismiss_stale_reviews"] is True
    assert strong["require_signed_commits"] is True
    assert strong["enforce_admins"] is True


def test_gitlab_audit_branch_protection_shape(gitlab_mock):
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    bp = client.audit_branch_protection()
    assert len(bp) == 1
    entry = bp[0]
    assert set(entry.keys()) == _BP_FIELDS
    assert entry["repo"] == "acme/spell-book-1"
    assert entry["branch"] == "main"
    # 2 approvals required (from project approvals), so required_reviews is True.
    assert entry["required_reviews"] is True
    assert entry["required_review_count"] == 2
    # reset_approvals_on_push -> dismiss_stale_reviews.
    assert entry["dismiss_stale_reviews"] is True
    # reject_unsigned_commits push rule -> require_signed_commits.
    assert entry["require_signed_commits"] is True
    # allow_force_push False -> enforce_admins True.
    assert entry["enforce_admins"] is True


def test_bitbucket_audit_branch_protection_shape(bitbucket_mock):
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    bp = client.audit_branch_protection()
    assert len(bp) == 1
    entry = bp[0]
    assert set(entry.keys()) == _BP_FIELDS
    assert entry["repo"] == "acme/spell-book-1"
    # Restrictions are aggregated per pattern; 'main' is the pattern.
    assert entry["branch"] == "main"
    assert entry["required_reviews"] is True
    assert entry["required_review_count"] == 2
    assert entry["dismiss_stale_reviews"] is True
    # Bitbucket Cloud has no signed-commit restriction kind.
    assert entry["require_signed_commits"] is False
    # A 'force' restriction is present -> enforce_admins True.
    assert entry["enforce_admins"] is True


def test_audit_branch_protection_never_alters_or_leaks(
    github_mock, gitlab_mock, bitbucket_mock
):
    """The audit only reports policy metadata — no secrets, tokens, or key
    material ever appear in the normalized output, and the field set is exactly
    the documented policy fields (nothing extra leaks through)."""
    for client in (
        GitHubClient(token="ghp_x", base_url=github_mock.base_url),
        GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url),
        BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url),
    ):
        for entry in client.audit_branch_protection():
            assert set(entry.keys()) == _BP_FIELDS
            blob = json.dumps(entry).lower()
            assert "secret" not in blob
            assert "token" not in blob
            assert "private key" not in blob


# --- e2e: the CLI flag adds a 'branch_protection' array (only when requested) --


def test_github_validate_token_audit_branch_protection_cli(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-branch-protection",
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
    assert "branch_protection" in payload
    by_repo = {e["repo"]: e for e in payload["branch_protection"]}
    assert set(by_repo) == {"acme-corp/spellbook", "acme-corp/grimoire"}
    assert by_repo["acme-corp/spellbook"]["required_reviews"] is False


def test_validate_token_without_flag_has_no_branch_protection_key(
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
    assert "branch_protection" not in payload


def test_gitlab_validate_token_audit_branch_protection_cli(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "validate-token",
            "--audit-branch-protection",
            "--scope-file",
            scope_file,
            "--target-url",
            gitlab_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "glpat-" + "x" * 20},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["branch_protection"][0]["required_review_count"] == 2


def test_bitbucket_validate_token_audit_branch_protection_cli(
    bitbucket_mock, scope_file
):
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--audit-branch-protection",
            "--scope-file",
            scope_file,
            "--target-url",
            bitbucket_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "ATCTT" + "x" * 24},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["branch_protection"][0]["repo"] == "acme/spell-book-1"
    assert payload["branch_protection"][0]["require_signed_commits"] is False


def test_audit_branch_protection_composes_with_enumerations(github_mock, scope_file):
    """--audit-branch-protection is an independent additive flag that may be
    requested alongside the --enumerate-* flags; all arrays appear."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-orgs",
            "--enumerate-deploy-keys",
            "--audit-branch-protection",
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
        and "deploy_keys" in payload
        and "branch_protection" in payload
    )
    assert {e["repo"] for e in payload["branch_protection"]} == {
        "acme-corp/spellbook",
        "acme-corp/grimoire",
    }


def test_audit_branch_protection_respects_scope_guardrail(scope_file):
    """--audit-branch-protection is still gated by the scope guardrail (exit 2)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-branch-protection",
            "--scope-file",
            scope_file,
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


def test_validate_token_help_documents_audit_branch_protection():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0
    assert "--audit-branch-protection" in proc.stdout
