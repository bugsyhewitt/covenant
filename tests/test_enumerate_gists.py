"""Tests for validate-token --enumerate-gists (gist/snippet leak surface).

Covers the read-only enumeration of the gists (GitHub) / snippets (GitLab,
Bitbucket) owned by a captured token's account — a leaked-credential blast-radius
signal that complements --enumerate-keys and --enumerate-orgs. Gists and snippets
routinely carry pasted config and ``.env`` excerpts; the FILENAMES are surfaced as
the leak signal (e.g. ``.env``, ``credentials.json``) but file CONTENT is never
read or echoed — covenant maps the attack surface, it does not exfiltrate it.

The feature is additive: the v0.1 validate-token fields stay intact, the ``gists``
array only appears when ``--enumerate-gists`` is passed, and the normalized output
shape is uniform across all three providers.

Two layers are exercised:
  * unit — each client's ``enumerate_gists`` against the in-process mock server,
    asserting the normalized ``{"id", "description", "visibility", "url", "files"}``
    shape and that file content never leaks into the output;
  * e2e — the CLI flag end-to-end, asserting ``gists`` is present only under
    ``--enumerate-gists`` and absent otherwise, with no shape regression, and that
    it composes with the other --enumerate-* flags and respects the scope guardrail.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from covenant.scms.bitbucket import BitbucketClient
from covenant.scms.github import GitHubClient
from covenant.scms.gitlab import GitLabClient

_GIST_FIELDS = {"id", "description", "visibility", "url", "files"}


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


# --- unit: each client's enumerate_gists returns the normalized shape ---------


def test_github_enumerate_gists_shape(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    gists = client.enumerate_gists()
    assert len(gists) == 2
    for g in gists:
        assert set(g.keys()) == _GIST_FIELDS
        assert g["id"]
        assert isinstance(g["files"], list)
    by_id = {g["id"]: g for g in gists}
    assert by_id["gist1"]["visibility"] == "public"
    # public=False maps to the share-safe-but-honest "secret" (gists are never
    # truly private — anyone with the URL can read a "secret" gist).
    assert by_id["gist2"]["visibility"] == "secret"
    assert by_id["gist2"]["files"] == [".env", "notes.md"]


def test_gitlab_enumerate_gists_shape(gitlab_mock):
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    gists = client.enumerate_gists()
    assert len(gists) == 2
    for g in gists:
        assert set(g.keys()) == _GIST_FIELDS
        assert g["id"] is not None
    by_id = {g["id"]: g for g in gists}
    # Newer `files` array shape.
    assert by_id[51]["files"] == ["deploy.sh"]
    assert by_id[51]["visibility"] == "public"
    # Legacy single `file_name` shape; description falls back when present.
    assert by_id[52]["files"] == [".env"]
    assert by_id[52]["visibility"] == "private"
    assert by_id[52]["description"] == "private creds"


def test_gitlab_gist_description_falls_back_to_title(gitlab_mock):
    """When a GitLab snippet has no description, the title is used so the
    'description' field is never null where a human-readable label exists."""
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    by_id = {g["id"]: g for g in client.enumerate_gists()}
    assert by_id[51]["description"] == "deploy helper"  # title, no description


def test_bitbucket_enumerate_gists_shape(bitbucket_mock):
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    gists = client.enumerate_gists()
    assert len(gists) == 2
    for g in gists:
        assert set(g.keys()) == _GIST_FIELDS
        assert g["id"]
    by_id = {g["id"]: g for g in gists}
    assert by_id["snip1"]["visibility"] == "public"
    assert by_id["snip2"]["visibility"] == "private"
    assert by_id["snip2"]["files"] == [".env", "notes.md"]


def test_enumerate_gists_never_emits_file_content(
    github_mock, gitlab_mock, bitbucket_mock
):
    """Only filenames are surfaced; the seeded file content markers (raw_url,
    file links) must never appear in the normalized output."""
    for client in (
        GitHubClient(token="ghp_x", base_url=github_mock.base_url),
        GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url),
        BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url),
    ):
        for g in client.enumerate_gists():
            blob = json.dumps(g)
            assert "raw_url" not in blob
            assert "raw" not in blob.replace("scratch", "")  # no raw content link


# --- e2e: the CLI flag adds a 'gists' array (and only when requested) ---------


def test_github_validate_token_enumerate_gists_cli(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-gists",
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
    assert "gists" in payload
    assert {g["id"] for g in payload["gists"]} == {"gist1", "gist2"}


def test_validate_token_without_flag_has_no_gists_key(github_mock, scope_file):
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
    assert "gists" not in payload


def test_gitlab_validate_token_enumerate_gists_cli(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "validate-token",
            "--enumerate-gists",
            "--scope-file",
            scope_file,
            "--target-url",
            gitlab_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "glpat-" + "x" * 20},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert {g["id"] for g in payload["gists"]} == {51, 52}


def test_bitbucket_validate_token_enumerate_gists_cli(bitbucket_mock, scope_file):
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--enumerate-gists",
            "--scope-file",
            scope_file,
            "--target-url",
            bitbucket_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "ATCTT" + "x" * 24},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert {g["id"] for g in payload["gists"]} == {"snip1", "snip2"}


def test_enumerate_gists_composes_with_other_enumerations(github_mock, scope_file):
    """--enumerate-gists, --enumerate-keys and --enumerate-orgs are independent
    additive flags that may be requested together; all three arrays appear."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-orgs",
            "--enumerate-keys",
            "--enumerate-gists",
            "--scope-file",
            scope_file,
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "orgs" in payload and "keys" in payload and "gists" in payload
    assert {g["id"] for g in payload["gists"]} == {"gist1", "gist2"}


def test_enumerate_gists_respects_scope_guardrail(scope_file):
    """--enumerate-gists is still gated by the scope guardrail (exit 2)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-gists",
            "--scope-file",
            scope_file,
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


def test_validate_token_help_documents_enumerate_gists():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0
    assert "--enumerate-gists" in proc.stdout
