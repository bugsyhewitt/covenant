"""Tests for validate-token --enumerate-webhooks (webhook exfil/SSRF surface).

Covers the read-only enumeration of the org/group/workspace webhooks a captured
token can reach (GitHub org hooks, GitLab group hooks, Bitbucket workspace
hooks) — the next blast-radius axis after --enumerate-orgs/-keys/-gists. A
webhook's destination URL is where event payloads (repo content and metadata)
are POSTed, which makes it both a data-exfiltration channel and an SSRF
primitive when the URL points at internal infrastructure. covenant surfaces the
destination URL (the recon signal) but never requests or echoes the hook secret.

The feature is additive: the v0.1 validate-token fields stay intact, the
``webhooks`` array only appears when ``--enumerate-webhooks`` is passed, and the
normalized output shape is uniform across all three providers.

Two layers are exercised:
  * unit — each client's ``enumerate_webhooks`` against the in-process mock
    server, asserting the normalized
    ``{"scope", "owner", "id", "url", "events", "active"}`` shape and that the
    hook secret never leaks into the output;
  * e2e — the CLI flag end-to-end, asserting ``webhooks`` is present only under
    ``--enumerate-webhooks`` and absent otherwise, with no shape regression,
    that it composes with the other --enumerate-* flags, and that it respects
    the scope guardrail.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from covenant.scms.bitbucket import BitbucketClient
from covenant.scms.github import GitHubClient
from covenant.scms.gitlab import GitLabClient

_WEBHOOK_FIELDS = {"scope", "owner", "id", "url", "events", "active"}


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


# --- unit: each client's enumerate_webhooks returns the normalized shape ------


def test_github_enumerate_webhooks_shape(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    hooks = client.enumerate_webhooks()
    # Two reachable orgs (acme-corp, wizards-inc), one hook each.
    assert len(hooks) == 2
    for h in hooks:
        assert set(h.keys()) == _WEBHOOK_FIELDS
        assert h["scope"] == "org"
        assert h["id"] == 100
        assert isinstance(h["events"], list)
        assert h["active"] is True
    owners = {h["owner"] for h in hooks}
    assert owners == {"acme-corp", "wizards-inc"}
    by_owner = {h["owner"]: h for h in hooks}
    assert by_owner["acme-corp"]["url"] == "https://hooks.example.com/acme-corp"
    assert by_owner["acme-corp"]["events"] == ["push", "pull_request"]


def test_gitlab_enumerate_webhooks_shape(gitlab_mock):
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    hooks = client.enumerate_webhooks()
    assert len(hooks) == 2
    for h in hooks:
        assert set(h.keys()) == _WEBHOOK_FIELDS
        assert h["scope"] == "group"
        assert h["id"] == 200
    by_owner = {h["owner"]: h for h in hooks}
    # GitLab per-event booleans are normalized to a sorted event list; the
    # disabled issues_events flag must NOT appear.
    assert by_owner["acme-corp"]["events"] == ["merge_requests", "push"]
    assert "issues" not in by_owner["acme-corp"]["events"]
    # owner is the group full path; the subgroup path is URL-encoded onto the
    # wire and decoded back into the result owner.
    assert "acme-corp/wizards" in by_owner


def test_bitbucket_enumerate_webhooks_shape(bitbucket_mock):
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    hooks = client.enumerate_webhooks()
    assert len(hooks) == 2
    for h in hooks:
        assert set(h.keys()) == _WEBHOOK_FIELDS
        assert h["scope"] == "workspace"
        assert h["active"] is True
    by_owner = {h["owner"]: h for h in hooks}
    assert by_owner["acme"]["events"] == ["repo:push", "pullrequest:created"]
    assert by_owner["acme"]["url"] == "https://hooks.example.com/acme"


def test_enumerate_webhooks_never_emits_hook_secret(
    github_mock, gitlab_mock, bitbucket_mock
):
    """The hook secret/token must never appear in the normalized output — only
    the destination URL (the recon signal) is surfaced."""
    for client in (
        GitHubClient(token="ghp_x", base_url=github_mock.base_url),
        GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url),
        BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url),
    ):
        for h in client.enumerate_webhooks():
            blob = json.dumps(h)
            assert "secret" not in blob
            assert "token" not in blob
            assert "********" not in blob


# --- e2e: the CLI flag adds a 'webhooks' array (and only when requested) ------


def test_github_validate_token_enumerate_webhooks_cli(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-webhooks",
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
    assert "webhooks" in payload
    assert {h["owner"] for h in payload["webhooks"]} == {
        "acme-corp",
        "wizards-inc",
    }


def test_validate_token_without_flag_has_no_webhooks_key(github_mock, scope_file):
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
    assert "webhooks" not in payload


def test_gitlab_validate_token_enumerate_webhooks_cli(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "validate-token",
            "--enumerate-webhooks",
            "--scope-file",
            scope_file,
            "--target-url",
            gitlab_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "glpat-" + "x" * 20},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert {h["owner"] for h in payload["webhooks"]} == {
        "acme-corp",
        "acme-corp/wizards",
    }


def test_bitbucket_validate_token_enumerate_webhooks_cli(bitbucket_mock, scope_file):
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--enumerate-webhooks",
            "--scope-file",
            scope_file,
            "--target-url",
            bitbucket_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "ATCTT" + "x" * 24},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert {h["owner"] for h in payload["webhooks"]} == {"acme", "wizards"}


def test_enumerate_webhooks_composes_with_other_enumerations(github_mock, scope_file):
    """--enumerate-webhooks, -gists, -keys and -orgs are independent additive
    flags that may be requested together; all four arrays appear."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-orgs",
            "--enumerate-keys",
            "--enumerate-gists",
            "--enumerate-webhooks",
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
        and "keys" in payload
        and "gists" in payload
        and "webhooks" in payload
    )
    assert {h["owner"] for h in payload["webhooks"]} == {
        "acme-corp",
        "wizards-inc",
    }


def test_enumerate_webhooks_respects_scope_guardrail(scope_file):
    """--enumerate-webhooks is still gated by the scope guardrail (exit 2)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-webhooks",
            "--scope-file",
            scope_file,
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


def test_validate_token_help_documents_enumerate_webhooks():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0
    assert "--enumerate-webhooks" in proc.stdout
