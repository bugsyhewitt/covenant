"""Tests for validate-token --audit-ip-allowlist.

Where the existing ``--audit-*`` flags report repo-internal posture (branch
protection, environment gates, webhook hygiene, CODEOWNERS, etc.),
``--audit-ip-allowlist`` reports the org-level NETWORK perimeter — GitHub's
IP-allowlist setting and the often-overlooked installed-apps gate that is
off by default even when the org-wide allowlist itself is on. A captured
token authenticating from an unexpected source IP, or a compromised GitHub
App reaching the org from the vendor's network, is exactly the threat this
perimeter defends against; the high-signal findings are
``ip_allow_list_enabled=False`` (no perimeter at all) and
``ip_allow_list_enabled_for_installed_apps=False`` (perimeter present but
bypassable via installed apps).

GitLab (the IP perimeter setting lives at the instance / SAML-SSO level,
not a per-group field a recon-grade token can read) and Bitbucket Cloud
(the workspace IP allowlist is admin-UI only with no public REST endpoint)
have no equivalent surface, so the audit is a no-op there (empty array +
explanatory ``warnings`` note), the same pattern as ``--audit-webhook`` on
those providers.

The feature is additive: the v0.1 ``validate-token`` fields stay intact,
the ``ip_allowlist`` array only appears when ``--audit-ip-allowlist`` is
passed, and the normalized output shape is uniform across all three
providers.

Two layers are exercised:
  * unit — each client's ``audit_ip_allowlist`` against the in-process
    mock, asserting the normalized
    ``{"scope", "owner", "ip_allow_list_enabled",
    "ip_allow_list_enabled_for_installed_apps"}`` shape and the
    strong/weak split per provider;
  * e2e — the CLI flag end-to-end, asserting ``ip_allowlist`` is present
    only under ``--audit-ip-allowlist`` and absent otherwise, that it
    composes with other --enumerate-*/--audit-* flags, and that it
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

_IP_ALLOWLIST_FIELDS = {
    "scope",
    "owner",
    "ip_allow_list_enabled",
    "ip_allow_list_enabled_for_installed_apps",
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


# --- unit: each client's audit_ip_allowlist returns the normalized shape -----


def test_github_audit_ip_allowlist_shape(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    entries = client.audit_ip_allowlist()
    # One entry per reachable org (acme-corp strong, wizards-inc weak).
    assert len(entries) == 2
    for e in entries:
        assert set(e.keys()) == _IP_ALLOWLIST_FIELDS
        assert e["scope"] == "org"
        assert isinstance(e["ip_allow_list_enabled"], bool)
        assert isinstance(e["ip_allow_list_enabled_for_installed_apps"], bool)
    by_owner = {e["owner"]: e for e in entries}
    assert set(by_owner) == {"acme-corp", "wizards-inc"}

    strong = by_owner["acme-corp"]
    assert strong["ip_allow_list_enabled"] is True
    assert strong["ip_allow_list_enabled_for_installed_apps"] is True

    weak = by_owner["wizards-inc"]
    # Both perimeter signals off — the highest-signal finding the audit
    # exists to surface.
    assert weak["ip_allow_list_enabled"] is False
    assert weak["ip_allow_list_enabled_for_installed_apps"] is False


def test_gitlab_audit_ip_allowlist_is_noop(gitlab_mock):
    """GitLab's IP-perimeter setting lives at the instance / SAML-SSO level,
    not a per-group field a recon-grade token can read: empty list +
    explanatory warning, same pattern as audit_webhook on GitLab."""
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    entries = client.audit_ip_allowlist()
    assert entries == []
    assert any(
        "ip-allowlist" in w.lower() and "unsupported" in w.lower()
        for w in client.warnings
    )


def test_bitbucket_audit_ip_allowlist_is_noop(bitbucket_mock):
    """Bitbucket Cloud's workspace IP-allowlist is admin-UI only with no
    public REST endpoint: empty list + explanatory warning, same pattern
    as audit_webhook on Bitbucket."""
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    entries = client.audit_ip_allowlist()
    assert entries == []
    assert any(
        "ip-allowlist" in w.lower() and "unsupported" in w.lower()
        for w in client.warnings
    )


def test_audit_ip_allowlist_never_leaks_cidr_entries(github_mock):
    """The audit must surface only the BOOLEAN posture — never the
    allowlist's CIDR entries (vendor netblocks, office subnets, VPN egress
    ranges are sensitive operational metadata). The field set is exactly
    the documented fields and nothing else."""
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    for entry in client.audit_ip_allowlist():
        assert set(entry.keys()) == _IP_ALLOWLIST_FIELDS
        blob = json.dumps(entry)
        # No CIDR / IP shapes; no entries array.
        assert "/32" not in blob
        assert '"cidr"' not in blob
        assert '"entries"' not in blob
        assert '"ip_address"' not in blob


# --- e2e: the CLI flag adds an 'ip_allowlist' array (only when asked) --------


def test_github_validate_token_audit_ip_allowlist_cli(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-ip-allowlist",
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
    assert "ip_allowlist" in payload
    entries = payload["ip_allowlist"]
    assert len(entries) == 2
    by_owner = {e["owner"]: e for e in entries}
    assert by_owner["acme-corp"]["ip_allow_list_enabled"] is True
    assert (
        by_owner["acme-corp"]["ip_allow_list_enabled_for_installed_apps"]
        is True
    )
    assert by_owner["wizards-inc"]["ip_allow_list_enabled"] is False
    assert (
        by_owner["wizards-inc"]["ip_allow_list_enabled_for_installed_apps"]
        is False
    )
    for e in entries:
        assert set(e.keys()) == _IP_ALLOWLIST_FIELDS
        assert e["scope"] == "org"


def test_validate_token_without_flag_has_no_ip_allowlist_key(
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
    assert "ip_allowlist" not in payload


def test_gitlab_validate_token_audit_ip_allowlist_cli_is_noop(
    gitlab_mock, scope_file
):
    proc = _run(
        [
            "gitlab",
            "validate-token",
            "--audit-ip-allowlist",
            "--scope-file",
            scope_file,
            "--target-url",
            gitlab_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "glpat-" + "x" * 20},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ip_allowlist"] == []
    assert "warnings" in payload
    assert any(
        "ip-allowlist" in w.lower() and "gitlab" in w.lower()
        for w in payload["warnings"]
    )


def test_bitbucket_validate_token_audit_ip_allowlist_cli_is_noop(
    bitbucket_mock, scope_file
):
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--audit-ip-allowlist",
            "--scope-file",
            scope_file,
            "--target-url",
            bitbucket_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "ATCTT" + "x" * 24},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ip_allowlist"] == []
    assert "warnings" in payload
    assert any(
        "ip-allowlist" in w.lower() and "bitbucket" in w.lower()
        for w in payload["warnings"]
    )


def test_audit_ip_allowlist_composes_with_other_audits(github_mock, scope_file):
    """--audit-ip-allowlist is an independent additive flag that may be
    requested alongside other --audit-* flags; all arrays appear and neither
    displaces the other. Verified alongside --audit-webhook (the closest
    sibling — both are org-level perimeter posture audits) and
    --audit-branch-protection (a repo-internal posture audit, to confirm
    the org/repo axes coexist)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-ip-allowlist",
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
        "ip_allowlist" in payload
        and "webhook_configuration" in payload
        and "branch_protection" in payload
    )
    # The org axis covers the same set of reachable owners across the two
    # org-level audits.
    ip_owners = {e["owner"] for e in payload["ip_allowlist"]}
    hook_owners = {e["owner"] for e in payload["webhook_configuration"]}
    assert ip_owners == hook_owners == {"acme-corp", "wizards-inc"}


def test_audit_ip_allowlist_respects_scope_guardrail(scope_file):
    """--audit-ip-allowlist is still gated by the scope guardrail (exit 2)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-ip-allowlist",
            "--scope-file",
            scope_file,
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


def test_validate_token_help_documents_audit_ip_allowlist():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0
    assert "--audit-ip-allowlist" in proc.stdout
