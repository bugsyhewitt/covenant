"""Tests for validate-token --audit-branch-ruleset (named rule-collection audit).

Covers the read-only audit of the NEWER named-rule-collection model that
coexists with classic branch protection across the repos a captured token can
reach. Where ``--audit-branch-protection`` walks each protected branch's
CLASSIC settings, this surfaces the POSTURE of the newer model — enforcement
mode, the SET of rule types present, and the bypass-actor count — so an
operator can spot a configured-but-inactive ruleset (a paper tiger) or a
permissive bypass-actor list that routes around the gates.

The cross-provider invariants:

  * GitHub native branch rulesets, GitLab push rules (the closest
    per-project rule-collection analogue), and Bitbucket Cloud (no-op +
    warning, no equivalent API) each surface the audit in the same
    normalized ``{repo, ruleset_id, name, enforcement, target, rule_types,
    bypass_actor_count}`` shape so the audit composes cross-SCM;
  * a repo whose rulesets endpoint answers 403/404 (rulesets unavailable on
    the plan / token lacks scope / project has no push rule) is SKIPPED, not
    allowed to fail the whole audit; and
  * only ruleset POSTURE is surfaced — bypass-actor IDENTITIES are NEVER
    echoed (only the count is the audit's signal) and rule PARAMETER values
    (regex patterns, exact reviewer counts) are NEVER read beyond their
    presence in ``rule_types``.

The feature is additive: the v0.1 validate-token fields stay intact, the
``branch_rulesets`` array only appears when ``--audit-branch-ruleset`` is
passed, and it composes with the rest of the ``--enumerate-*``/``--audit-*``
family.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from covenant.scms.bitbucket import BitbucketClient
from covenant.scms.github import GitHubClient
from covenant.scms.gitlab import GitLabClient

_RULESET_FIELDS = {
    "repo",
    "ruleset_id",
    "name",
    "enforcement",
    "target",
    "rule_types",
    "bypass_actor_count",
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


# --- unit: GitHub returns the normalized shape and surfaces posture --------


def test_github_audit_branch_ruleset_shape(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    records = client.audit_branch_ruleset()
    # Two rulesets from the spellbook repo (strong + weak); the grimoire repo
    # answers 404 (rulesets unavailable) and is skipped.
    assert records
    for r in records:
        assert set(r.keys()) == _RULESET_FIELDS
    repos = {r["repo"] for r in records}
    assert repos == {"acme-corp/spellbook"}


def test_github_audit_branch_ruleset_surfaces_strong_and_weak(github_mock):
    """The spellbook repo's two rulesets demonstrate the high-signal posture:
    one strong (active enforcement, core gates present, no bypass actors) and
    one weak (evaluate enforcement, missing core gates, multiple bypass
    actors). The audit must surface both so the operator can spot the weak
    one."""
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    by_id = {r["ruleset_id"]: r for r in client.audit_branch_ruleset()}

    strong = by_id[600]
    assert strong["enforcement"] == "active"
    assert strong["target"] == "branch"
    assert strong["bypass_actor_count"] == 0
    # Core gates ALL present and sorted.
    assert strong["rule_types"] == sorted(
        ["pull_request", "required_signatures", "non_fast_forward", "deletion"]
    )

    weak = by_id[601]
    # The "paper tiger" finding: configured but not actively blocking.
    assert weak["enforcement"] == "evaluate"
    # Three bypass actors (Team + Integration + RepositoryRole) — the
    # bypass-set finding. The IDENTITIES are deliberately not surfaced.
    assert weak["bypass_actor_count"] == 3
    # Missing every core gate (only "creation" present) — the coverage gap.
    assert weak["rule_types"] == ["creation"]
    assert "pull_request" not in weak["rule_types"]
    assert "required_signatures" not in weak["rule_types"]


def test_github_audit_branch_ruleset_skips_404_repo(github_mock):
    """A repo whose rulesets endpoint answers 404 (rulesets unavailable /
    token lacks admin scope) is skipped — the audit returns the rulesets from
    the repos it CAN read, never aborting the whole walk on a single 404."""
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    repos = {r["repo"] for r in client.audit_branch_ruleset()}
    assert "acme-corp/grimoire" not in repos


# --- unit: GitLab returns the normalized shape from push_rule ---------------


def test_gitlab_audit_branch_ruleset_shape(gitlab_mock):
    """GitLab's push-rule object is mapped to the same normalized shape as
    GitHub rulesets — one entry per project that has a push rule."""
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    records = client.audit_branch_ruleset()
    assert records
    for r in records:
        assert set(r.keys()) == _RULESET_FIELDS


def test_gitlab_audit_branch_ruleset_maps_push_rule_gates(gitlab_mock):
    """The push-rule fields covenant treats as enabled gates appear in the
    sorted ``rule_types`` list; fields that are False / None / 0 do not.
    ``enforcement`` is fixed to ``"active"`` (push rules have no dry-run
    mode), ``target`` is ``"branch"``, and ``bypass_actor_count`` is ``0``
    (push rules have no bypass-actor allow-list)."""
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    records = client.audit_branch_ruleset()
    assert len(records) == 1
    record = records[0]
    assert record["enforcement"] == "active"
    assert record["target"] == "branch"
    assert record["bypass_actor_count"] == 0
    assert record["name"] == "push_rule"
    # The mock enables: commit_message_regex, branch_name_regex,
    # prevent_secrets, reject_unsigned_commits, member_check, max_file_size.
    # Disabled / None: commit_message_negative_regex, author_email_regex,
    # file_name_regex, reject_non_dco_commits, commit_committer_check.
    assert record["rule_types"] == sorted(
        [
            "commit_message_regex",
            "branch_name_regex",
            "prevent_secrets",
            "reject_unsigned_commits",
            "member_check",
            "max_file_size",
        ]
    )
    assert "commit_message_negative_regex" not in record["rule_types"]
    assert "reject_non_dco_commits" not in record["rule_types"]


# --- unit: Bitbucket no-op + warning ----------------------------------------


def test_bitbucket_audit_branch_ruleset_is_noop_with_warning(bitbucket_mock):
    """Bitbucket Cloud has no named-ruleset API (its policy lives in
    branch-restrictions, covered by --audit-branch-protection). The method
    exists for shape parity, returns an empty list, and records a single
    non-fatal warning so the empty result is not misread as a clean bill of
    health."""
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    records = client.audit_branch_ruleset()
    assert records == []
    assert any(
        "branch-ruleset" in w and "Bitbucket" in w for w in client.warnings
    )
    # The warning explicitly points to the equivalent surface.
    assert any("branch-restrictions" in w for w in client.warnings)


# --- invariant: bypass-actor identities + rule parameter values NEVER leak --


def test_audit_branch_ruleset_never_surfaces_bypass_identities_or_params(
    github_mock, gitlab_mock, bitbucket_mock
):
    """The mock plants a ``shouldnotappear`` placeholder in fields covenant
    is contractually obligated NOT to surface — bypass-actor identities
    (the GitHub mock's ``shouldnotappear-team``/``shouldnotappear-bot``/
    ``shouldnotappear-role`` actor names) and rule parameter values (the
    GitHub mock's ``shouldnotappear-regex`` pattern and GitLab's
    ``shouldnotappear-msg-regex``/``shouldnotappear-branch-regex``). The
    string must never appear in the audit output across any SCM, and only
    the seven known keys are present."""
    forbidden = {
        "bypass_actors",
        "actors",
        "actor_id",
        "actor_type",
        "rules",
        "parameters",
        "pattern",
        "regex",
        "commit_message_regex",
        "branch_name_regex",
        "secret",
        "token",
    }
    for client in (
        GitHubClient(token="ghp_x", base_url=github_mock.base_url),
        GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url),
        BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url),
    ):
        records = client.audit_branch_ruleset()
        # Bitbucket is empty by design; GitHub/GitLab have records to check.
        for r in records:
            assert set(r.keys()) == _RULESET_FIELDS
            assert not (set(r.keys()) & forbidden)
            # No "shouldnotappear" string anywhere in the serialized record.
            assert "shouldnotappear" not in json.dumps(r)


# --- e2e: the CLI flag adds a 'branch_rulesets' array (only when requested) -


def test_github_validate_token_audit_branch_ruleset_cli(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-branch-ruleset",
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
    assert "branch_rulesets" in payload
    by_id = {r["ruleset_id"]: r for r in payload["branch_rulesets"]}
    assert by_id[600]["enforcement"] == "active"
    assert by_id[601]["enforcement"] == "evaluate"
    assert by_id[601]["bypass_actor_count"] == 3


def test_validate_token_without_flag_has_no_branch_rulesets_key(
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
    assert "branch_rulesets" not in payload


def test_gitlab_validate_token_audit_branch_ruleset_cli(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "validate-token",
            "--audit-branch-ruleset",
            "--scope-file",
            scope_file,
            "--target-url",
            gitlab_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "glpat-" + "x" * 20},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "branch_rulesets" in payload
    assert len(payload["branch_rulesets"]) == 1
    record = payload["branch_rulesets"][0]
    assert record["enforcement"] == "active"
    assert "prevent_secrets" in record["rule_types"]


def test_bitbucket_validate_token_audit_branch_ruleset_cli(
    bitbucket_mock, scope_file
):
    """Bitbucket emits an empty array + an explanatory warning, never a hard
    error — the audit still completes with exit 0."""
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--audit-branch-ruleset",
            "--scope-file",
            scope_file,
            "--target-url",
            bitbucket_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "ATCTT" + "x" * 24},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["branch_rulesets"] == []
    # The warning surfaces so the operator does not misread the empty list.
    assert "warnings" in payload
    assert any(
        "branch-ruleset" in w and "Bitbucket" in w for w in payload["warnings"]
    )


def test_audit_branch_ruleset_composes_with_other_audits(github_mock, scope_file):
    """--audit-branch-ruleset composes with the other additive flags; all
    arrays appear together. Audits the older + newer rule models side by
    side, which is the headline use-case."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-branch-protection",
            "--audit-branch-ruleset",
            "--audit-workflow-runs",
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
        and "branch_rulesets" in payload
        and "workflow_runs" in payload
        and "collaborators" in payload
    )


def test_audit_branch_ruleset_respects_scope_guardrail(scope_file):
    """--audit-branch-ruleset is still gated by the scope guardrail (exit 2)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-branch-ruleset",
            "--scope-file",
            scope_file,
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


def test_validate_token_help_documents_audit_branch_ruleset():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0
    assert "--audit-branch-ruleset" in proc.stdout
