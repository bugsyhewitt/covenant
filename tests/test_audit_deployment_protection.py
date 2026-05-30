"""Tests for validate-token --audit-deployment-protection.

Custom deployment-protection rules are the third-party GitHub Apps an
environment delegates its deploy gate to: each app returns approve/reject
and a deploy lands or is held on the app's verdict. Where
``--audit-actions-environments`` reports the *built-in* environment gate
(required reviewers, wait timer, branch policy), this audit lists the
*delegated third-party* gates — a supply-chain trust surface the built-in
posture does not cover. The high-signal findings are: (a) every installed
custom rule (the operator should know which third parties hold their deploy
keys), and (b) a rule whose ``enabled=false`` — a gate the operator thinks
they have but does not.

GitLab and Bitbucket Cloud have no per-environment custom-rule-app API, so
the audit is a no-op there (empty array + an explanatory ``warnings`` note),
the same pattern as ``--audit-actions-permissions`` and
``--audit-advisory-alerts``.

The feature is additive: the v0.1 ``validate-token`` fields stay intact,
the ``deployment_protection`` array only appears when
``--audit-deployment-protection`` is passed, and the normalized output shape
is uniform across all three providers.

Two layers are exercised:
  * unit — each client's ``audit_deployment_protection`` against the
    in-process mock, asserting the normalized
    ``{"repo", "environment", "rule_id", "app_slug", "app_id", "enabled"}``
    shape and the enabled/disabled split per provider;
  * e2e — the CLI flag end-to-end, asserting ``deployment_protection`` is
    present only under ``--audit-deployment-protection`` and absent
    otherwise, that it composes with the other --enumerate-*/--audit-* flags,
    and that it respects the scope guardrail.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from covenant.scms.bitbucket import BitbucketClient
from covenant.scms.github import GitHubClient
from covenant.scms.gitlab import GitLabClient

_RULE_FIELDS = {
    "repo",
    "environment",
    "rule_id",
    "app_slug",
    "app_id",
    "enabled",
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


# --- unit: each client's audit_deployment_protection returns the normalized shape


def test_github_audit_deployment_protection_shape(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    rules = client.audit_deployment_protection()
    # spellbook 'production' has TWO custom rules (one enabled, one disabled);
    # grimoire 'production' has none and contributes nothing.
    assert len(rules) == 2
    for entry in rules:
        assert set(entry.keys()) == _RULE_FIELDS
        assert entry["repo"] == "acme-corp/spellbook"
        assert entry["environment"] == "production"
        assert isinstance(entry["rule_id"], int)
        assert isinstance(entry["app_id"], int)
        assert isinstance(entry["app_slug"], str) and entry["app_slug"]
        assert isinstance(entry["enabled"], bool)
    by_slug = {e["app_slug"]: e for e in rules}
    assert set(by_slug) == {"third-party-gate", "stale-gate"}
    # The third-party-gate rule is the ACTIVE delegated gate the operator
    # should know holds their deploy keys.
    assert by_slug["third-party-gate"]["enabled"] is True
    # The stale-gate rule is the high-signal "gate the operator thinks they
    # have but does not" case — installed, but enabled=false.
    assert by_slug["stale-gate"]["enabled"] is False


def test_gitlab_audit_deployment_protection_is_noop(gitlab_mock):
    """GitLab has no per-environment custom-rule-app API: empty list +
    explanatory warning, same pattern as audit_actions_permissions."""
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    rules = client.audit_deployment_protection()
    assert rules == []
    assert any(
        "deployment-protection" in w.lower() and "unsupported" in w.lower()
        for w in client.warnings
    )


def test_bitbucket_audit_deployment_protection_is_noop(bitbucket_mock):
    """Bitbucket Cloud has no per-environment custom-rule-app API: empty list +
    explanatory warning, same pattern as audit_actions_permissions."""
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    rules = client.audit_deployment_protection()
    assert rules == []
    assert any(
        "deployment-protection" in w.lower() and "unsupported" in w.lower()
        for w in client.warnings
    )


def test_audit_deployment_protection_never_leaks_credentials(
    github_mock, gitlab_mock, bitbucket_mock
):
    """Only rule + app identity metadata is surfaced — no installation token,
    webhook secret, app private key, or other credential ever appears, and the
    field set is exactly the documented fields."""
    for client in (
        GitHubClient(token="ghp_x", base_url=github_mock.base_url),
        GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url),
        BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url),
    ):
        for entry in client.audit_deployment_protection():
            assert set(entry.keys()) == _RULE_FIELDS
            blob = json.dumps(entry).lower()
            assert "token" not in blob
            assert "client_secret" not in blob
            assert "private_key" not in blob
            assert "webhook_secret" not in blob
            # the 'secret' substring would appear in 'secret_value' etc; the
            # word should not appear at all in a metadata-only record.
            assert "secret" not in blob


# --- e2e: the CLI flag adds a 'deployment_protection' array (only when asked) ---


def test_github_validate_token_audit_deployment_protection_cli(
    github_mock, scope_file
):
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-deployment-protection",
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
    assert "deployment_protection" in payload
    rules = payload["deployment_protection"]
    assert len(rules) == 2
    by_slug = {r["app_slug"]: r for r in rules}
    assert by_slug["third-party-gate"]["enabled"] is True
    assert by_slug["stale-gate"]["enabled"] is False
    for r in rules:
        assert set(r.keys()) == _RULE_FIELDS
        assert r["repo"] == "acme-corp/spellbook"
        assert r["environment"] == "production"


def test_validate_token_without_flag_has_no_deployment_protection_key(
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
    assert "deployment_protection" not in payload


def test_gitlab_validate_token_audit_deployment_protection_cli_is_noop(
    gitlab_mock, scope_file
):
    proc = _run(
        [
            "gitlab",
            "validate-token",
            "--audit-deployment-protection",
            "--scope-file",
            scope_file,
            "--target-url",
            gitlab_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "glpat-" + "x" * 20},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["deployment_protection"] == []
    assert "warnings" in payload
    assert any(
        "deployment-protection" in w.lower() and "gitlab" in w.lower()
        for w in payload["warnings"]
    )


def test_bitbucket_validate_token_audit_deployment_protection_cli_is_noop(
    bitbucket_mock, scope_file
):
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--audit-deployment-protection",
            "--scope-file",
            scope_file,
            "--target-url",
            bitbucket_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "ATCTT" + "x" * 24},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["deployment_protection"] == []
    assert "warnings" in payload
    assert any(
        "deployment-protection" in w.lower() and "bitbucket" in w.lower()
        for w in payload["warnings"]
    )


def test_audit_deployment_protection_composes_with_other_audits(
    github_mock, scope_file
):
    """--audit-deployment-protection is an independent additive flag that may
    be requested alongside the other --enumerate-*/--audit-* flags; all arrays
    appear."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-actions-environments",
            "--audit-deployment-protection",
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
        "actions_environments" in payload
        and "deployment_protection" in payload
        and "branch_protection" in payload
    )
    # The composed audit still surfaces both rules under
    # deployment_protection without touching the other arrays.
    assert {r["app_slug"] for r in payload["deployment_protection"]} == {
        "third-party-gate",
        "stale-gate",
    }


def test_audit_deployment_protection_respects_scope_guardrail(scope_file):
    """--audit-deployment-protection is still gated by the scope guardrail
    (exit 2)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-deployment-protection",
            "--scope-file",
            scope_file,
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


def test_validate_token_help_documents_audit_deployment_protection():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0
    assert "--audit-deployment-protection" in proc.stdout
