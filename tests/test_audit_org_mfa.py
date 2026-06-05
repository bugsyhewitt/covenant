"""Tests for validate-token --audit-org-mfa.

Multi-factor authentication requirement is the identity authentication
baseline that underpins every other org-level control: branch protection,
IP allowlist, and environment gates are all meaningless if a member account
can be taken over with a single stolen password. ``--audit-org-mfa`` audits
whether each reachable org/group REQUIRES MFA for its members, surfacing
only the boolean enforcement flag — never member identity, credential, or
recovery-code metadata.

GitHub orgs expose ``two_factor_requirement_enabled`` on the standard
``GET /orgs/{org}`` payload the client already uses for other audits.
GitLab groups expose ``require_two_factor_authentication`` on
``GET /api/v4/groups/{id}``. Bitbucket Cloud's workspace two-step-
verification enforcement has no public REST endpoint a recon-grade token
can query, so the audit is a no-op there (empty array + explanatory
``warnings`` note), the same pattern as ``--audit-ip-allowlist`` on
Bitbucket.

The feature is additive: the v0.1 ``validate-token`` fields stay intact,
the ``org_mfa`` array only appears when ``--audit-org-mfa`` is passed, and
the normalized output shape ``{"scope", "owner", "two_factor_required"}``
is uniform across all three providers.

Two layers are exercised:
  * unit — each client's ``audit_org_mfa`` against the in-process mock,
    asserting the normalized shape and the strong/weak split per provider;
  * e2e — the CLI flag end-to-end, asserting ``org_mfa`` is present only
    under ``--audit-org-mfa`` and absent otherwise, that it composes with
    other ``--audit-*`` flags, and that it respects the scope guardrail.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from covenant.scms.bitbucket import BitbucketClient
from covenant.scms.github import GitHubClient
from covenant.scms.gitlab import GitLabClient

_ORG_MFA_FIELDS = {"scope", "owner", "two_factor_required"}


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


# --- unit: each client's audit_org_mfa returns the normalized shape -----------


def test_github_audit_org_mfa_shape(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    entries = client.audit_org_mfa()
    # One entry per reachable org (acme-corp required, wizards-inc not).
    assert len(entries) == 2
    for e in entries:
        assert set(e.keys()) == _ORG_MFA_FIELDS
        assert e["scope"] == "org"
        assert isinstance(e["two_factor_required"], bool)
    by_owner = {e["owner"]: e for e in entries}
    assert set(by_owner) == {"acme-corp", "wizards-inc"}


def test_github_audit_org_mfa_strong_weak_split(github_mock):
    """acme-corp requires MFA (strong posture); wizards-inc does not
    (the high-signal finding the audit exists to surface)."""
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    by_owner = {e["owner"]: e for e in client.audit_org_mfa()}
    assert by_owner["acme-corp"]["two_factor_required"] is True
    assert by_owner["wizards-inc"]["two_factor_required"] is False


def test_gitlab_audit_org_mfa_shape(gitlab_mock):
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    entries = client.audit_org_mfa()
    assert len(entries) == 2
    for e in entries:
        assert set(e.keys()) == _ORG_MFA_FIELDS
        assert e["scope"] == "group"
        assert isinstance(e["two_factor_required"], bool)


def test_gitlab_audit_org_mfa_strong_weak_split(gitlab_mock):
    """acme-corp requires MFA (strong posture); acme-corp/wizards does not
    (the high-signal finding the audit exists to surface)."""
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    entries = client.audit_org_mfa()
    by_owner = {e["owner"]: e for e in entries}
    # acme-corp: require_two_factor_authentication=True in the mock
    assert by_owner["acme-corp"]["two_factor_required"] is True
    # acme-corp/wizards: require_two_factor_authentication=False in the mock
    acme_wizards_key = next(
        (k for k in by_owner if "wizards" in k.lower()), None
    )
    assert acme_wizards_key is not None
    assert by_owner[acme_wizards_key]["two_factor_required"] is False


def test_bitbucket_audit_org_mfa_is_noop(bitbucket_mock):
    """Bitbucket Cloud's workspace two-step-verification enforcement has no
    public REST endpoint: empty list + explanatory warning."""
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    entries = client.audit_org_mfa()
    assert entries == []
    assert any(
        "org-mfa" in w.lower() and "unsupported" in w.lower()
        for w in client.warnings
    )


def test_audit_org_mfa_never_leaks_member_identity(github_mock):
    """The audit must surface ONLY the boolean enforcement flag — never
    member usernames, emails, recovery codes, or any other identity metadata.
    The field set is exactly the three documented fields."""
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    for entry in client.audit_org_mfa():
        assert set(entry.keys()) == _ORG_MFA_FIELDS
        blob = json.dumps(entry)
        # No member identity or credential fields.
        assert '"username"' not in blob
        assert '"email"' not in blob
        assert '"recovery"' not in blob
        assert '"token"' not in blob


# --- e2e: the CLI flag adds an 'org_mfa' array (only when asked) -------------


def test_github_validate_token_audit_org_mfa_cli(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-org-mfa",
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
    assert "org_mfa" in payload
    entries = payload["org_mfa"]
    assert len(entries) == 2
    by_owner = {e["owner"]: e for e in entries}
    assert by_owner["acme-corp"]["two_factor_required"] is True
    assert by_owner["wizards-inc"]["two_factor_required"] is False
    for e in entries:
        assert set(e.keys()) == _ORG_MFA_FIELDS
        assert e["scope"] == "org"


def test_validate_token_without_flag_has_no_org_mfa_key(github_mock, scope_file):
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
    assert "org_mfa" not in payload


def test_gitlab_validate_token_audit_org_mfa_cli(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "validate-token",
            "--audit-org-mfa",
            "--scope-file",
            scope_file,
            "--target-url",
            gitlab_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "glpat-" + "x" * 20},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "org_mfa" in payload
    entries = payload["org_mfa"]
    assert len(entries) == 2
    for e in entries:
        assert set(e.keys()) == _ORG_MFA_FIELDS
        assert e["scope"] == "group"


def test_bitbucket_validate_token_audit_org_mfa_cli_is_noop(
    bitbucket_mock, scope_file
):
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--audit-org-mfa",
            "--scope-file",
            scope_file,
            "--target-url",
            bitbucket_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "ATCTT" + "x" * 24},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["org_mfa"] == []
    assert "warnings" in payload
    assert any(
        "org-mfa" in w.lower() and "bitbucket" in w.lower()
        for w in payload["warnings"]
    )


def test_audit_org_mfa_composes_with_other_audits(github_mock, scope_file):
    """--audit-org-mfa is an independent additive flag that may be requested
    alongside other --audit-* flags; all arrays appear and neither displaces
    the other. Verified alongside --audit-ip-allowlist (both are org-level
    posture audits reading from the same /orgs/{org} endpoint) and
    --audit-branch-protection (a repo-internal posture audit, to confirm
    the org/repo axes coexist)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-org-mfa",
            "--audit-ip-allowlist",
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
        "org_mfa" in payload
        and "ip_allowlist" in payload
        and "branch_protection" in payload
    )
    # Both org-level audits cover the same set of reachable orgs.
    mfa_owners = {e["owner"] for e in payload["org_mfa"]}
    ip_owners = {e["owner"] for e in payload["ip_allowlist"]}
    assert mfa_owners == ip_owners == {"acme-corp", "wizards-inc"}


def test_audit_org_mfa_respects_scope_guardrail(scope_file):
    """--audit-org-mfa is still gated by the scope guardrail (exit 2)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-org-mfa",
            "--scope-file",
            scope_file,
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


def test_validate_token_help_documents_audit_org_mfa():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0
    assert "--audit-org-mfa" in proc.stdout
