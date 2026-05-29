"""Tests for validate-token --audit-codeowners (owner-review coverage posture).

Covers the read-only audit of the CODEOWNERS coverage of the repos a captured
token can reach. CODEOWNERS is the control that routes MANDATORY review to a
named owner per path, so it is the partner to ``--audit-branch-protection``: a
protected branch's require-code-owner-review gate only bites for paths a
CODEOWNERS rule matches. The two high-signal findings:

  * a reachable repo with ``present=false`` has NO owner-review gate at all; and
  * a repo whose CODEOWNERS has rules but ``has_global_owner=false`` leaves every
    path matched by no rule — including a file an attacker newly adds — with no
    required owner, a gap a branch-protection audit alone does not reveal.

The feature is additive: the v0.1 validate-token fields stay intact, the
``codeowners`` array only appears when ``--audit-codeowners`` is passed, and the
normalized ``{"repo", "present", "path", "rule_count", "has_global_owner"}`` shape
is uniform across all three providers. Only the rule COUNT and the presence of a
catch-all ``*`` are surfaced — the owner handles themselves are never echoed and
no other repository content is read.

Two layers are exercised:
  * unit — each client's ``audit_codeowners`` against the in-process mock server,
    asserting the normalized shape, the present/absent derivation, the rule count,
    and the catch-all detection; plus a pure-parser unit test for the
    ``parse_codeowners`` helper and the no-owner-leak invariant.
  * e2e — the CLI flag end-to-end, asserting ``codeowners`` is present only under
    the flag and absent otherwise, composes with the other --enumerate-*/--audit-*
    flags, respects the scope guardrail (exit 2), and is documented in --help.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from covenant.scms.base import parse_codeowners
from covenant.scms.bitbucket import BitbucketClient
from covenant.scms.github import GitHubClient
from covenant.scms.gitlab import GitLabClient

_CO_FIELDS = {"repo", "present", "path", "rule_count", "has_global_owner"}


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


# --- unit: the pure CODEOWNERS parser ---------------------------------------


def test_parse_codeowners_counts_rules_and_detects_global_owner():
    text = (
        "# comment line is ignored\n"
        "\n"  # blank line is ignored
        "*       @org/maintainers\n"
        "src/    @org/backend\n"
        "docs/   @org/docs-team\n"
    )
    summary = parse_codeowners(text)
    assert summary["rule_count"] == 3
    assert summary["has_global_owner"] is True


def test_parse_codeowners_without_catch_all_flags_partial_coverage():
    text = "# ownership\nsrc/ @backend\ndocs/ @docs-team\n"
    summary = parse_codeowners(text)
    assert summary["rule_count"] == 2
    assert summary["has_global_owner"] is False


def test_parse_codeowners_empty_file_is_zero_rules():
    summary = parse_codeowners("# only comments\n\n")
    assert summary["rule_count"] == 0
    assert summary["has_global_owner"] is False


# --- unit: each client's audit_codeowners returns the normalized shape ------


def test_github_audit_codeowners_shape(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    records = client.audit_codeowners()
    assert records, "expected at least one reachable repo"
    for r in records:
        assert set(r.keys()) == _CO_FIELDS
        assert isinstance(r["present"], bool)
        assert isinstance(r["has_global_owner"], bool)
    by_repo = {r["repo"]: r for r in records}
    # spellbook: PARTIAL CODEOWNERS at .github/CODEOWNERS (rules, no '*').
    spellbook = by_repo["acme-corp/spellbook"]
    assert spellbook["present"] is True
    assert spellbook["path"] == ".github/CODEOWNERS"
    assert spellbook["rule_count"] == 2
    assert spellbook["has_global_owner"] is False
    # grimoire: COMPLETE CODEOWNERS at the repo root (has a '*' catch-all).
    grimoire = by_repo["acme-corp/grimoire"]
    assert grimoire["present"] is True
    assert grimoire["path"] == "CODEOWNERS"
    assert grimoire["has_global_owner"] is True


def test_github_audit_codeowners_absent_repo_reports_present_false():
    """A repo with no CODEOWNERS at any probed location reports present=false
    with zeroed coverage fields. Asserted via a client pointed at a mock whose
    repo serves no CODEOWNERS file (every /contents/ probe 404s)."""

    class _NoCodeownersClient(GitHubClient):
        def _reachable_repos(self, max_pages=10):
            return ["acme-corp/bare"]

        def _fetch_file_content(self, path):  # always absent
            return None

    client = _NoCodeownersClient(token="ghp_x", base_url="http://127.0.0.1:1")
    records = client.audit_codeowners()
    assert len(records) == 1
    r = records[0]
    assert r["repo"] == "acme-corp/bare"
    assert r["present"] is False
    assert r["path"] is None
    assert r["rule_count"] == 0
    assert r["has_global_owner"] is False


def test_gitlab_audit_codeowners_shape(gitlab_mock):
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    records = client.audit_codeowners()
    assert records, "expected at least one reachable project"
    for r in records:
        assert set(r.keys()) == _CO_FIELDS
    r = records[0]
    assert r["repo"] == "acme/spell-book-1"
    assert r["present"] is True
    assert r["path"] == ".gitlab/CODEOWNERS"
    assert r["rule_count"] == 2
    assert r["has_global_owner"] is False


def test_bitbucket_audit_codeowners_shape(bitbucket_mock):
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    records = client.audit_codeowners()
    assert records, "expected at least one reachable repo"
    for r in records:
        assert set(r.keys()) == _CO_FIELDS
    r = records[0]
    assert r["repo"] == "acme/spell-book-1"
    assert r["present"] is True
    assert r["path"] == "CODEOWNERS"
    assert r["rule_count"] == 2
    assert r["has_global_owner"] is False


def test_audit_codeowners_never_surfaces_owner_handles(
    github_mock, gitlab_mock, bitbucket_mock
):
    """The audit surfaces only the rule count and the catch-all flag — never the
    owner account/team handles or any other repository content. The shape is
    exactly the five known keys and carries no owner string."""
    for client in (
        GitHubClient(token="ghp_x", base_url=github_mock.base_url),
        GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url),
        BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url),
    ):
        records = client.audit_codeowners()
        assert records
        for r in records:
            assert set(r.keys()) == _CO_FIELDS
            # No field carries an owner handle (no '@' string anywhere).
            for value in r.values():
                assert "@" not in str(value)


# --- e2e: the CLI flag adds a 'codeowners' array (only when requested) ------


def test_github_validate_token_audit_codeowners_cli(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-codeowners",
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
    assert "codeowners" in payload
    by_repo = {r["repo"]: r for r in payload["codeowners"]}
    # The repo with rules-but-no-'*' is the high-signal partial-coverage gap.
    assert by_repo["acme-corp/spellbook"]["has_global_owner"] is False
    assert by_repo["acme-corp/grimoire"]["has_global_owner"] is True


def test_validate_token_without_flag_has_no_codeowners_key(github_mock, scope_file):
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
    assert "codeowners" not in payload


def test_gitlab_validate_token_audit_codeowners_cli(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "validate-token",
            "--audit-codeowners",
            "--scope-file",
            scope_file,
            "--target-url",
            gitlab_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "glpat-" + "x" * 20},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "codeowners" in payload
    assert payload["codeowners"][0]["repo"] == "acme/spell-book-1"
    assert payload["codeowners"][0]["present"] is True


def test_bitbucket_validate_token_audit_codeowners_cli(bitbucket_mock, scope_file):
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--audit-codeowners",
            "--scope-file",
            scope_file,
            "--target-url",
            bitbucket_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "ATCTT" + "x" * 24},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "codeowners" in payload
    assert payload["codeowners"][0]["repo"] == "acme/spell-book-1"
    assert payload["codeowners"][0]["present"] is True


def test_audit_codeowners_composes_with_other_audits(github_mock, scope_file):
    """--audit-codeowners composes with the other additive flags; all arrays
    appear together."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-branch-protection",
            "--audit-repo-visibility",
            "--audit-codeowners",
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
        "branch_protection" in payload
        and "repo_visibility" in payload
        and "codeowners" in payload
        and "collaborators" in payload
    )


def test_audit_codeowners_respects_scope_guardrail(scope_file):
    """--audit-codeowners is still gated by the scope guardrail (exit 2)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-codeowners",
            "--scope-file",
            scope_file,
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


def test_validate_token_help_documents_audit_codeowners():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0
    assert "--audit-codeowners" in proc.stdout
