"""Tests for validate-token --enumerate-orgs (organizational blast radius).

Covers the new read-only org/group/workspace enumeration that maps which
organizations (GitHub), groups (GitLab), and workspaces (Bitbucket) a captured
token can reach. The feature is additive: the v0.1 validate-token fields stay
intact and the ``orgs`` array only appears when ``--enumerate-orgs`` is passed.

Two layers are exercised:
  * unit — each client's ``enumerate_orgs`` against the in-process mock server,
    asserting the normalized ``{"name", "url"}`` shape;
  * e2e — the CLI flag end-to-end, asserting the ``orgs`` array is present only
    under ``--enumerate-orgs`` and absent otherwise, with no shape regression.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from covenant.scms.bitbucket import BitbucketClient
from covenant.scms.github import GitHubClient
from covenant.scms.gitlab import GitLabClient


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


# --- unit: each client's enumerate_orgs returns the normalized shape ----------


def test_github_enumerate_orgs_shape(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    orgs = client.enumerate_orgs()
    names = {o["name"] for o in orgs}
    assert names == {"acme-corp", "wizards-inc"}
    for org in orgs:
        assert set(org.keys()) == {"name", "url"}
        assert org["url"]


def test_gitlab_enumerate_orgs_shape(gitlab_mock):
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    orgs = client.enumerate_orgs()
    names = {o["name"] for o in orgs}
    # GitLab groups normalize to their full_path so nested groups are unambiguous.
    assert names == {"acme-corp", "acme-corp/wizards"}
    for org in orgs:
        assert set(org.keys()) == {"name", "url"}
        assert org["url"]


def test_bitbucket_enumerate_orgs_shape(bitbucket_mock):
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    orgs = client.enumerate_orgs()
    names = {o["name"] for o in orgs}
    # Bitbucket normalizes to the workspace slug — the value --workspace wants.
    assert names == {"acme", "wizards"}
    for org in orgs:
        assert set(org.keys()) == {"name", "url"}
        assert org["url"]


# --- e2e: the CLI flag adds an 'orgs' array (and only when requested) ---------


def test_github_validate_token_enumerate_orgs_cli(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-orgs",
            "--token-env",
            "COVENANT_TOKEN",
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
    assert "orgs" in payload
    assert {o["name"] for o in payload["orgs"]} == {"acme-corp", "wizards-inc"}


def test_validate_token_without_flag_has_no_orgs_key(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--token-env",
            "COVENANT_TOKEN",
            "--scope-file",
            scope_file,
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    # The 'orgs' key must be absent unless --enumerate-orgs is given.
    assert "orgs" not in payload


def test_gitlab_validate_token_enumerate_orgs_cli(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "validate-token",
            "--enumerate-orgs",
            "--token-env",
            "COVENANT_TOKEN",
            "--scope-file",
            scope_file,
            "--target-url",
            gitlab_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "glpat-" + "x" * 20},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert {o["name"] for o in payload["orgs"]} == {
        "acme-corp",
        "acme-corp/wizards",
    }


def test_bitbucket_validate_token_enumerate_orgs_cli(bitbucket_mock, scope_file):
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--enumerate-orgs",
            "--token-env",
            "COVENANT_TOKEN",
            "--scope-file",
            scope_file,
            "--target-url",
            bitbucket_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "ATCTT" + "x" * 24},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert {o["name"] for o in payload["orgs"]} == {"acme", "wizards"}


def test_enumerate_orgs_respects_scope_guardrail(scope_file):
    """--enumerate-orgs is still gated by the scope guardrail (exit 2)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-orgs",
            "--scope-file",
            scope_file,
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


def test_validate_token_help_documents_enumerate_orgs():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0
    assert "--enumerate-orgs" in proc.stdout
