"""Tests for validate-token --audit-workflow-runs (CI activity audit).

Covers the read-only audit of recent CI/CD pipeline runs across the repos a
captured token can reach. Where ``--audit-actions-permissions`` and
``--audit-actions-environments`` report POLICY posture (what a workflow run is
ALLOWED to do), this surfaces observed ACTIVITY (what the pipeline actually
ran), so an operator can spot anomalous CI patterns before they escalate. The
cross-provider invariants:

  * GitHub, GitLab, and Bitbucket each surface their pipeline runs in the same
    normalized ``{repo, run_id, name, event, status, conclusion, created_at}``
    shape so the audit composes cross-SCM;
  * a repo with Actions/Pipelines disabled or out of the token's scope (HTTP
    403/404) is SKIPPED, not allowed to fail the whole audit; and
  * only run METADATA is surfaced — logs, artifact URLs, and any CI/CD
    variable values the run saw are NEVER fetched.

The feature is additive: the v0.1 validate-token fields stay intact, the
``workflow_runs`` array only appears when ``--audit-workflow-runs`` is passed,
and it composes with the rest of the ``--enumerate-*``/``--audit-*`` family.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from covenant.scms.bitbucket import BitbucketClient
from covenant.scms.github import GitHubClient
from covenant.scms.gitlab import GitLabClient

_RUN_FIELDS = {
    "repo",
    "run_id",
    "name",
    "event",
    "status",
    "conclusion",
    "created_at",
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


# --- unit: GitHub returns the normalized shape and surfaces anomalies --------


def test_github_audit_workflow_runs_shape(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    records = client.audit_workflow_runs()
    # Three runs from the spellbook repo; the grimoire repo is skipped (404).
    assert records
    for r in records:
        assert set(r.keys()) == _RUN_FIELDS
    repos = {r["repo"] for r in records}
    assert repos == {"acme-corp/spellbook"}


def test_github_audit_workflow_runs_surfaces_anomalies(github_mock):
    """The spellbook repo's recent runs include a FAILED conclusion (active
    attack/broken-CI signal), a CANCELLED conclusion (operator intervention),
    and a workflow_dispatch / schedule trigger (CI-misuse signal)."""
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    by_id = {r["run_id"]: r for r in client.audit_workflow_runs()}
    assert by_id[900]["conclusion"] == "failure"
    assert by_id[900]["event"] == "push"
    assert by_id[901]["conclusion"] == "cancelled"
    assert by_id[901]["event"] == "workflow_dispatch"
    # In-progress run: conclusion is None (not yet terminal).
    assert by_id[902]["status"] == "in_progress"
    assert by_id[902]["conclusion"] is None
    assert by_id[902]["event"] == "schedule"


def test_github_audit_workflow_runs_skips_disabled_repo(github_mock):
    """A repo whose runs endpoint answers 404 (Actions disabled / token lacks
    scope) is skipped — the audit returns the runs from repos it CAN read."""
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    records = client.audit_workflow_runs()
    # spellbook contributes runs; grimoire contributes none (skipped, not fatal).
    repos = {r["repo"] for r in records}
    assert "acme-corp/grimoire" not in repos


# --- unit: GitLab returns the normalized shape and maps status/conclusion ----


def test_gitlab_audit_workflow_runs_shape(gitlab_mock):
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    records = client.audit_workflow_runs()
    assert records
    for r in records:
        assert set(r.keys()) == _RUN_FIELDS


def test_gitlab_audit_workflow_runs_maps_terminal_and_running(gitlab_mock):
    """GitLab's flat 'status' is split into the normalized status/conclusion
    pair: a terminal status (success/failed/canceled/skipped/manual) becomes
    status='completed' + conclusion=<original>; a non-terminal status
    (running/pending/...) becomes status=<original> + conclusion=None."""
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    by_id = {r["run_id"]: r for r in client.audit_workflow_runs()}
    # 800 = failed (terminal)
    assert by_id[800]["status"] == "completed"
    assert by_id[800]["conclusion"] == "failed"
    assert by_id[800]["event"] == "push"
    # 801 = canceled (terminal) — operator intervention signal
    assert by_id[801]["status"] == "completed"
    assert by_id[801]["conclusion"] == "canceled"
    # 802 = running (in-flight) — schedule-trigger signal
    assert by_id[802]["status"] == "running"
    assert by_id[802]["conclusion"] is None
    assert by_id[802]["event"] == "schedule"


# --- unit: Bitbucket returns the normalized shape ----------------------------


def test_bitbucket_audit_workflow_runs_shape(bitbucket_mock):
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    records = client.audit_workflow_runs()
    assert records
    for r in records:
        assert set(r.keys()) == _RUN_FIELDS


def test_bitbucket_audit_workflow_runs_surfaces_anomalies(bitbucket_mock):
    """Bitbucket's COMPLETED state + nested result name carries the
    terminal outcome (FAILED, STOPPED); the IN_PROGRESS state has no result, so
    conclusion is None. The trigger name (PUSH/MANUAL/SCHEDULE) is the event."""
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    by_id = {r["run_id"]: r for r in client.audit_workflow_runs()}
    assert by_id["{run-900}"]["status"] == "COMPLETED"
    assert by_id["{run-900}"]["conclusion"] == "FAILED"
    assert by_id["{run-900}"]["event"] == "PUSH"
    assert by_id["{run-901}"]["conclusion"] == "STOPPED"
    assert by_id["{run-901}"]["event"] == "MANUAL"
    assert by_id["{run-902}"]["status"] == "IN_PROGRESS"
    assert by_id["{run-902}"]["conclusion"] is None
    assert by_id["{run-902}"]["event"] == "SCHEDULE"


# --- invariant: no logs / artifact URLs / CI variable values ----------------


def test_audit_workflow_runs_never_surfaces_logs_or_artifacts(
    github_mock, gitlab_mock, bitbucket_mock
):
    """Only the seven known run-metadata keys are surfaced; logs, artifact
    URLs, and any CI variable values the run saw are never present."""
    forbidden = {
        "logs",
        "logs_url",
        "artifacts",
        "artifacts_url",
        "env",
        "variables",
        "value",
        "secret",
        "token",
    }
    for client in (
        GitHubClient(token="ghp_x", base_url=github_mock.base_url),
        GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url),
        BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url),
    ):
        records = client.audit_workflow_runs()
        assert records
        for r in records:
            assert set(r.keys()) == _RUN_FIELDS
            assert not (set(r.keys()) & forbidden)


# --- e2e: the CLI flag adds a 'workflow_runs' array (only when requested) ----


def test_github_validate_token_audit_workflow_runs_cli(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-workflow-runs",
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
    assert "workflow_runs" in payload
    by_id = {r["run_id"]: r for r in payload["workflow_runs"]}
    assert by_id[900]["conclusion"] == "failure"
    assert by_id[901]["event"] == "workflow_dispatch"


def test_validate_token_without_flag_has_no_workflow_runs_key(
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
    assert "workflow_runs" not in payload


def test_gitlab_validate_token_audit_workflow_runs_cli(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "validate-token",
            "--audit-workflow-runs",
            "--scope-file",
            scope_file,
            "--target-url",
            gitlab_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "glpat-" + "x" * 20},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "workflow_runs" in payload
    by_id = {r["run_id"]: r for r in payload["workflow_runs"]}
    assert by_id[800]["conclusion"] == "failed"
    assert by_id[802]["status"] == "running"


def test_bitbucket_validate_token_audit_workflow_runs_cli(
    bitbucket_mock, scope_file
):
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--audit-workflow-runs",
            "--scope-file",
            scope_file,
            "--target-url",
            bitbucket_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "ATCTT" + "x" * 24},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "workflow_runs" in payload
    by_id = {r["run_id"]: r for r in payload["workflow_runs"]}
    assert by_id["{run-900}"]["conclusion"] == "FAILED"
    assert by_id["{run-902}"]["event"] == "SCHEDULE"


def test_audit_workflow_runs_composes_with_other_audits(github_mock, scope_file):
    """--audit-workflow-runs composes with the other additive flags; all
    arrays appear together."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-actions-environments",
            "--audit-actions-permissions",
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
        "actions_environments" in payload
        and "actions_permissions" in payload
        and "workflow_runs" in payload
        and "collaborators" in payload
    )


def test_audit_workflow_runs_respects_scope_guardrail(scope_file):
    """--audit-workflow-runs is still gated by the scope guardrail (exit 2)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-workflow-runs",
            "--scope-file",
            scope_file,
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


def test_validate_token_help_documents_audit_workflow_runs():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0
    assert "--audit-workflow-runs" in proc.stdout
