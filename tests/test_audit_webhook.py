"""Tests for validate-token --audit-webhook.

Where ``--enumerate-webhooks`` maps the destination URLs of the
org/group/workspace webhooks a token can reach (the exfil/SSRF surface),
``--audit-webhook`` audits the defensive POSTURE of each hook — the three
controls that decide whether a captured-URL hook is actually trustable:

  * ``has_secret`` — whether the hook was wired with an HMAC shared secret
    (the receiver's only way to verify the POST really came from the SCM).
    GitHub returns ``config.secret`` as the ``"********"`` placeholder when
    one is set and omits the field when it is not; covenant surfaces ONLY
    the boolean presence, never the placeholder.
  * ``insecure_ssl`` — whether TLS certificate verification is disabled on
    deliveries (an attacker-in-the-middle vector).
  * an ``active`` hook with ``wildcard_events`` true (``events=["*"]``) —
    the widest possible event subscription, the widest exfil channel.

GitLab and Bitbucket Cloud have no per-hook posture record covenant can
surface uniformly, so the audit is a no-op there (empty array + an
explanatory ``warnings`` note), the same pattern as
``--audit-deployment-protection`` and ``--audit-actions-permissions``.

The feature is additive: the v0.1 ``validate-token`` fields stay intact,
the ``webhook_configuration`` array only appears when ``--audit-webhook``
is passed, and the normalized output shape is uniform across all three
providers.

Two layers are exercised:
  * unit — each client's ``audit_webhook`` against the in-process mock,
    asserting the normalized
    ``{"scope", "owner", "id", "url", "has_secret", "insecure_ssl",
    "active", "events", "wildcard_events"}`` shape and the
    weak/strong split per provider;
  * e2e — the CLI flag end-to-end, asserting ``webhook_configuration`` is
    present only under ``--audit-webhook`` and absent otherwise, that it
    composes with the other --enumerate-*/--audit-* flags, and that it
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

_WEBHOOK_AUDIT_FIELDS = {
    "scope",
    "owner",
    "id",
    "url",
    "has_secret",
    "insecure_ssl",
    "active",
    "events",
    "wildcard_events",
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


# --- unit: each client's audit_webhook returns the normalized shape -----------


def test_github_audit_webhook_shape(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    entries = client.audit_webhook()
    # Two reachable orgs (acme-corp strong, wizards-inc weak), one hook each.
    assert len(entries) == 2
    for e in entries:
        assert set(e.keys()) == _WEBHOOK_AUDIT_FIELDS
        assert e["scope"] == "org"
        assert e["id"] == 100
        assert isinstance(e["events"], list)
        assert isinstance(e["has_secret"], bool)
        assert isinstance(e["insecure_ssl"], bool)
        assert isinstance(e["active"], bool)
        assert isinstance(e["wildcard_events"], bool)
    by_owner = {e["owner"]: e for e in entries}
    assert set(by_owner) == {"acme-corp", "wizards-inc"}

    strong = by_owner["acme-corp"]
    assert strong["has_secret"] is True
    assert strong["insecure_ssl"] is False
    assert strong["active"] is True
    assert strong["wildcard_events"] is False
    assert strong["events"] == ["push", "pull_request"]
    assert strong["url"] == "https://hooks.example.com/acme-corp"

    weak = by_owner["wizards-inc"]
    # The three high-signal findings the audit exists to surface, all on a
    # single hook.
    assert weak["has_secret"] is False
    assert weak["insecure_ssl"] is True
    assert weak["active"] is True
    assert weak["wildcard_events"] is True
    assert weak["events"] == ["*"]


def test_gitlab_audit_webhook_is_noop(gitlab_mock):
    """GitLab's group-hook API exposes no uniform per-hook posture record to a
    recon-grade token: empty list + explanatory warning, same pattern as
    audit_deployment_protection."""
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    entries = client.audit_webhook()
    assert entries == []
    assert any(
        "webhook-configuration" in w.lower() and "unsupported" in w.lower()
        for w in client.warnings
    )


def test_bitbucket_audit_webhook_is_noop(bitbucket_mock):
    """Bitbucket Cloud's workspace-hook API exposes no per-hook posture
    record: empty list + explanatory warning, same pattern as
    audit_deployment_protection."""
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    entries = client.audit_webhook()
    assert entries == []
    assert any(
        "webhook-configuration" in w.lower() and "unsupported" in w.lower()
        for w in client.warnings
    )


def test_audit_webhook_never_leaks_secret_value(github_mock):
    """The hook's HMAC secret value (and GitHub's ``"********"`` placeholder)
    must never appear in the normalized output — only the BOOLEAN presence is
    surfaced, and the field set is exactly the documented fields."""
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    for entry in client.audit_webhook():
        assert set(entry.keys()) == _WEBHOOK_AUDIT_FIELDS
        blob = json.dumps(entry)
        assert "********" not in blob
        # The literal ``"secret"`` key should not appear — only ``has_secret``,
        # the boolean reduction, does. (A substring check still passes because
        # ``has_secret`` contains ``secret``; assert specifically that no
        # ``"secret"`` key was emitted.)
        assert '"secret"' not in blob
        assert '"token"' not in blob


# --- e2e: the CLI flag adds a 'webhook_configuration' array (only when asked) -


def test_github_validate_token_audit_webhook_cli(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-webhook",
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
    assert "webhook_configuration" in payload
    entries = payload["webhook_configuration"]
    assert len(entries) == 2
    by_owner = {e["owner"]: e for e in entries}
    assert by_owner["wizards-inc"]["has_secret"] is False
    assert by_owner["wizards-inc"]["insecure_ssl"] is True
    assert by_owner["wizards-inc"]["wildcard_events"] is True
    assert by_owner["acme-corp"]["has_secret"] is True
    assert by_owner["acme-corp"]["insecure_ssl"] is False
    assert by_owner["acme-corp"]["wildcard_events"] is False
    for e in entries:
        assert set(e.keys()) == _WEBHOOK_AUDIT_FIELDS
        assert e["scope"] == "org"


def test_validate_token_without_flag_has_no_webhook_configuration_key(
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
    assert "webhook_configuration" not in payload


def test_gitlab_validate_token_audit_webhook_cli_is_noop(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "validate-token",
            "--audit-webhook",
            "--scope-file",
            scope_file,
            "--target-url",
            gitlab_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "glpat-" + "x" * 20},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["webhook_configuration"] == []
    assert "warnings" in payload
    assert any(
        "webhook-configuration" in w.lower() and "gitlab" in w.lower()
        for w in payload["warnings"]
    )


def test_bitbucket_validate_token_audit_webhook_cli_is_noop(
    bitbucket_mock, scope_file
):
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--audit-webhook",
            "--scope-file",
            scope_file,
            "--target-url",
            bitbucket_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "ATCTT" + "x" * 24},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["webhook_configuration"] == []
    assert "warnings" in payload
    assert any(
        "webhook-configuration" in w.lower() and "bitbucket" in w.lower()
        for w in payload["warnings"]
    )


def test_audit_webhook_composes_with_other_audits(github_mock, scope_file):
    """--audit-webhook is an independent additive flag that may be requested
    alongside --enumerate-webhooks and other --audit-* flags; all arrays appear
    and neither displaces the other."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-webhooks",
            "--audit-webhook",
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
        "webhooks" in payload
        and "webhook_configuration" in payload
        and "branch_protection" in payload
    )
    # Same hooks surface in both arrays but the audit array also carries the
    # posture fields the enumeration does not.
    enum_owners = {h["owner"] for h in payload["webhooks"]}
    audit_owners = {e["owner"] for e in payload["webhook_configuration"]}
    assert enum_owners == audit_owners == {"acme-corp", "wizards-inc"}
    for e in payload["webhook_configuration"]:
        assert "has_secret" in e
        assert "insecure_ssl" in e
        assert "wildcard_events" in e


def test_audit_webhook_respects_scope_guardrail(scope_file):
    """--audit-webhook is still gated by the scope guardrail (exit 2)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-webhook",
            "--scope-file",
            scope_file,
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


def test_validate_token_help_documents_audit_webhook():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0
    assert "--audit-webhook" in proc.stdout
