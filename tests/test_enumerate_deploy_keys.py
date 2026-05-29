"""Tests for validate-token --enumerate-deploy-keys (repo-scoped persistence).

Covers the read-only enumeration of the deploy keys on the repositories a
captured token can reach — the repo-scoped complement to --enumerate-keys
(which covers the account's own SSH/GPG keys). A deploy key grants Git access to
a SINGLE repository independent of any human credential and often carries WRITE
access, which makes a writable one a persistence and supply-chain foothold: an
attacker can push to the repo as the repo itself, surviving a user's password
reset or off-boarding. covenant surfaces the public key metadata and the
decisive ``read_only`` flag but never reads private key material.

The feature is additive: the v0.1 validate-token fields stay intact, the
``deploy_keys`` array only appears when ``--enumerate-deploy-keys`` is passed,
and the normalized output shape is uniform across all three providers.

Two layers are exercised:
  * unit — each client's ``enumerate_deploy_keys`` against the in-process mock
    server, asserting the normalized
    ``{"repo", "id", "title", "read_only", "fingerprint"}`` shape, that the
    ``read_only`` flag tracks the provider's write semantics, and that no
    private key material leaks into the output;
  * e2e — the CLI flag end-to-end, asserting ``deploy_keys`` is present only
    under ``--enumerate-deploy-keys`` and absent otherwise, with no shape
    regression, that it composes with the other --enumerate-* flags, and that it
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

_DEPLOY_KEY_FIELDS = {"repo", "id", "title", "read_only", "fingerprint"}


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


# --- unit: each client's enumerate_deploy_keys returns the normalized shape ---


def test_github_enumerate_deploy_keys_shape(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    keys = client.enumerate_deploy_keys()
    # Two reachable repos, one deploy key each.
    assert len(keys) == 2
    for k in keys:
        assert set(k.keys()) == _DEPLOY_KEY_FIELDS
        assert k["id"] == 300
        assert isinstance(k["read_only"], bool)
    by_repo = {k["repo"]: k for k in keys}
    assert set(by_repo) == {"acme-corp/spellbook", "acme-corp/grimoire"}
    # spellbook's key is WRITABLE — the high-signal persistence case.
    assert by_repo["acme-corp/spellbook"]["read_only"] is False
    assert by_repo["acme-corp/grimoire"]["read_only"] is True


def test_gitlab_enumerate_deploy_keys_shape(gitlab_mock):
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    keys = client.enumerate_deploy_keys()
    assert len(keys) == 1
    k = keys[0]
    assert set(k.keys()) == _DEPLOY_KEY_FIELDS
    assert k["id"] == 301
    # GitLab can_push=true inverts to read_only=false.
    assert k["read_only"] is False
    assert k["fingerprint"] == "SHA256:deploykey301"
    assert k["repo"] == "acme/spell-book-1"


def test_bitbucket_enumerate_deploy_keys_shape(bitbucket_mock):
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    keys = client.enumerate_deploy_keys()
    assert len(keys) == 1
    k = keys[0]
    assert set(k.keys()) == _DEPLOY_KEY_FIELDS
    assert k["id"] == 401
    # Bitbucket Cloud access keys are read-only by design.
    assert k["read_only"] is True
    assert k["repo"] == "acme/spell-book-1"
    assert k["title"] == "ci-deploy"


def test_enumerate_deploy_keys_never_emits_private_material(
    github_mock, gitlab_mock, bitbucket_mock
):
    """Only PUBLIC key metadata is surfaced — no private key material, and no
    secret/token strings, ever appear in the normalized output. The fingerprint
    is the public key (or a hash), which is the recon signal."""
    for client in (
        GitHubClient(token="ghp_x", base_url=github_mock.base_url),
        GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url),
        BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url),
    ):
        for k in client.enumerate_deploy_keys():
            blob = json.dumps(k)
            assert "PRIVATE KEY" not in blob
            assert "BEGIN OPENSSH PRIVATE" not in blob
            assert "secret" not in blob.lower()


# --- e2e: the CLI flag adds a 'deploy_keys' array (and only when requested) ---


def test_github_validate_token_enumerate_deploy_keys_cli(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-deploy-keys",
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
    assert "deploy_keys" in payload
    assert {k["repo"] for k in payload["deploy_keys"]} == {
        "acme-corp/spellbook",
        "acme-corp/grimoire",
    }


def test_validate_token_without_flag_has_no_deploy_keys_key(github_mock, scope_file):
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
    assert "deploy_keys" not in payload


def test_gitlab_validate_token_enumerate_deploy_keys_cli(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "validate-token",
            "--enumerate-deploy-keys",
            "--scope-file",
            scope_file,
            "--target-url",
            gitlab_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "glpat-" + "x" * 20},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["deploy_keys"][0]["read_only"] is False


def test_bitbucket_validate_token_enumerate_deploy_keys_cli(bitbucket_mock, scope_file):
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--enumerate-deploy-keys",
            "--scope-file",
            scope_file,
            "--target-url",
            bitbucket_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "ATCTT" + "x" * 24},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["deploy_keys"][0]["repo"] == "acme/spell-book-1"
    assert payload["deploy_keys"][0]["read_only"] is True


def test_enumerate_deploy_keys_composes_with_other_enumerations(
    github_mock, scope_file
):
    """--enumerate-deploy-keys, -webhooks, -gists, -keys and -orgs are
    independent additive flags that may be requested together; all arrays
    appear."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-orgs",
            "--enumerate-keys",
            "--enumerate-gists",
            "--enumerate-webhooks",
            "--enumerate-deploy-keys",
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
        and "deploy_keys" in payload
    )
    assert {k["repo"] for k in payload["deploy_keys"]} == {
        "acme-corp/spellbook",
        "acme-corp/grimoire",
    }


def test_enumerate_deploy_keys_respects_scope_guardrail(scope_file):
    """--enumerate-deploy-keys is still gated by the scope guardrail (exit 2)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-deploy-keys",
            "--scope-file",
            scope_file,
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


def test_validate_token_help_documents_enumerate_deploy_keys():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0
    assert "--enumerate-deploy-keys" in proc.stdout
