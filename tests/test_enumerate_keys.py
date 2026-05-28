"""Tests for validate-token --enumerate-keys (SSH/GPG key blast radius).

Covers the read-only enumeration of the SSH and GPG public keys attached to a
captured token's account — a persistence/trust blast-radius signal that
complements --enumerate-orgs. SSH keys reveal which machines can push as the
identity; GPG keys reveal which keys can sign "Verified" commits in its name.

The feature is additive: the v0.1 validate-token fields stay intact, the ``keys``
array only appears when ``--enumerate-keys`` is passed, and only PUBLIC key
metadata is emitted (covenant never reads or echoes private key material).

Two layers are exercised:
  * unit — each client's ``enumerate_keys`` against the in-process mock server,
    asserting the normalized ``{"type", "id", "title", "fingerprint"}`` shape;
  * e2e — the CLI flag end-to-end, asserting ``keys`` is present only under
    ``--enumerate-keys`` and absent otherwise, with no shape regression, and
    that it composes with ``--enumerate-orgs``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from covenant.scms.bitbucket import BitbucketClient
from covenant.scms.github import GitHubClient
from covenant.scms.gitlab import GitLabClient

_KEY_FIELDS = {"type", "id", "title", "fingerprint"}


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


# --- unit: each client's enumerate_keys returns the normalized shape ----------


def test_github_enumerate_keys_shape(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    keys = client.enumerate_keys()
    types = sorted(k["type"] for k in keys)
    # Two SSH keys + one GPG key from the mock.
    assert types == ["gpg", "ssh", "ssh"]
    for key in keys:
        assert set(key.keys()) == _KEY_FIELDS
        assert key["id"] is not None
    titles = {k["title"] for k in keys}
    assert "laptop" in titles and "ci-runner" in titles
    # The GPG entry carries the key_id as its fingerprint.
    gpg = next(k for k in keys if k["type"] == "gpg")
    assert gpg["fingerprint"] == "ABCDEF0123456789"


def test_gitlab_enumerate_keys_shape(gitlab_mock):
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    keys = client.enumerate_keys()
    types = sorted(k["type"] for k in keys)
    assert types == ["gpg", "ssh", "ssh"]
    for key in keys:
        assert set(key.keys()) == _KEY_FIELDS
        assert key["id"] is not None
    ssh = [k for k in keys if k["type"] == "ssh"]
    assert {k["fingerprint"] for k in ssh} == {
        "SHA256:abc123laptop",
        "SHA256:def456ci",
    }


def test_gitlab_gpg_fingerprint_is_truncated_not_full_armor(gitlab_mock):
    """GitLab returns only the multi-line armored body; we expose a short,
    share-safe prefix rather than dumping the whole PGP block."""
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    gpg = next(k for k in client.enumerate_keys() if k["type"] == "gpg")
    assert gpg["fingerprint"] is not None
    # Truncated to <=64 chars and contains no embedded newline (single line).
    assert len(gpg["fingerprint"]) <= 64
    assert "\n" not in gpg["fingerprint"]


def test_bitbucket_enumerate_keys_shape(bitbucket_mock):
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    keys = client.enumerate_keys()
    # Bitbucket Cloud has no GPG-key API — SSH only.
    assert all(k["type"] == "ssh" for k in keys)
    assert len(keys) == 2
    for key in keys:
        assert set(key.keys()) == _KEY_FIELDS
        assert key["id"] is not None
    assert {k["title"] for k in keys} == {"laptop", "ci-runner"}


def test_enumerate_keys_never_emits_private_material(
    github_mock, gitlab_mock, bitbucket_mock
):
    """No finding field may contain a private-key marker; the public-key/armor
    bodies are also kept out of the compact output."""
    for client in (
        GitHubClient(token="ghp_x", base_url=github_mock.base_url),
        GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url),
        BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url),
    ):
        for key in client.enumerate_keys():
            blob = json.dumps(key).upper()
            assert "PRIVATE KEY" not in blob


# --- e2e: the CLI flag adds a 'keys' array (and only when requested) ----------


def test_github_validate_token_enumerate_keys_cli(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-keys",
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
    assert "keys" in payload
    assert sorted(k["type"] for k in payload["keys"]) == ["gpg", "ssh", "ssh"]


def test_validate_token_without_flag_has_no_keys_key(github_mock, scope_file):
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
    assert "keys" not in payload


def test_gitlab_validate_token_enumerate_keys_cli(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "validate-token",
            "--enumerate-keys",
            "--scope-file",
            scope_file,
            "--target-url",
            gitlab_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "glpat-" + "x" * 20},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert sorted(k["type"] for k in payload["keys"]) == ["gpg", "ssh", "ssh"]


def test_bitbucket_validate_token_enumerate_keys_cli(bitbucket_mock, scope_file):
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--enumerate-keys",
            "--scope-file",
            scope_file,
            "--target-url",
            bitbucket_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "ATCTT" + "x" * 24},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert {k["title"] for k in payload["keys"]} == {"laptop", "ci-runner"}
    assert all(k["type"] == "ssh" for k in payload["keys"])


def test_enumerate_keys_composes_with_enumerate_orgs(github_mock, scope_file):
    """--enumerate-keys and --enumerate-orgs are independent additive flags
    that may be requested together; both arrays appear."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-orgs",
            "--enumerate-keys",
            "--scope-file",
            scope_file,
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "orgs" in payload and "keys" in payload
    assert {o["name"] for o in payload["orgs"]} == {"acme-corp", "wizards-inc"}
    assert sorted(k["type"] for k in payload["keys"]) == ["gpg", "ssh", "ssh"]


def test_enumerate_keys_respects_scope_guardrail(scope_file):
    """--enumerate-keys is still gated by the scope guardrail (exit 2)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-keys",
            "--scope-file",
            scope_file,
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


def test_validate_token_help_documents_enumerate_keys():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0
    assert "--enumerate-keys" in proc.stdout
