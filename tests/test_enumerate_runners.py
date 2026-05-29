"""Tests for validate-token --enumerate-runners (self-hosted pipeline runners).

Covers the read-only enumeration of the self-hosted CI/CD runners a captured
token can reach — GitHub Actions org/repo self-hosted runners, GitLab
group/project runners, Bitbucket workspace/repo Pipelines runners. A
self-hosted runner is a distinct, high-signal blast-radius surface: every job
dispatched to the runner executes on its host and sees that run's GITHUB_TOKEN
/ CI variables / checked-out source, so a compromised or planted runner is a
persistence and lateral-movement foothold. A runner registered at
org/group/workspace scope is broadest (any repo in the org can dispatch to it).

The decisive INVARIANT is identity-and-labels-only disclosure: covenant
surfaces ONLY the runner id, name, and labels — never a registration token,
OAuth client secret, or any credential.

The feature is additive: the v0.1 validate-token fields stay intact, the
``runners`` array only appears when ``--enumerate-runners`` is passed, and the
normalized ``{"scope", "owner", "id", "name", "labels", "self_hosted"}`` shape
is uniform across all three providers. For GitHub and Bitbucket the listing
endpoints are self-hosted-only by design, so ``self_hosted`` is always True;
for GitLab it is False on the platform-managed shared SaaS runner
(``is_shared`` true) and True on org/project-attached runners.

Two layers are exercised:
  * unit — each client's ``enumerate_runners`` against the in-process mock
    server, asserting the normalized shape, the org-vs-repo ``scope`` split,
    the ``self_hosted`` mapping, and the no-credential-leak invariant;
  * e2e — the CLI flag end-to-end, asserting ``runners`` is present only under
    the flag and absent otherwise, composes with the other --enumerate-* flags,
    respects the scope guardrail (exit 2), and is documented in --help.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from covenant.scms.bitbucket import BitbucketClient
from covenant.scms.github import GitHubClient
from covenant.scms.gitlab import GitLabClient

_RUNNER_FIELDS = {"scope", "owner", "id", "name", "labels", "self_hosted"}


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


# --- unit: each client's enumerate_runners returns the normalized shape ---


def test_github_enumerate_runners_shape(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    runners = client.enumerate_runners()
    for r in runners:
        assert set(r.keys()) == _RUNNER_FIELDS
        assert isinstance(r["labels"], list)
        assert all(isinstance(label, str) for label in r["labels"])
        assert isinstance(r["self_hosted"], bool)
    # 2 orgs x 2 org runners + 2 repos x (spellbook=1, grimoire=0) = 5.
    assert len(runners) == 5
    org_runners = [r for r in runners if r["scope"] == "org"]
    repo_runners = [r for r in runners if r["scope"] == "repo"]
    assert len(org_runners) == 4
    assert len(repo_runners) == 1
    # GitHub Actions runners API by definition lists only self-hosted runners.
    assert all(r["self_hosted"] is True for r in runners)
    # Org runner labels are reduced from {id,name,type} dicts to bare names.
    org_one = next(r for r in org_runners if r["name"] == "acme-org-runner-1")
    assert set(org_one["labels"]) >= {"self-hosted", "linux", "production"}
    # The single repo runner attaches to spellbook.
    assert repo_runners[0]["owner"] == "acme-corp/spellbook"
    assert repo_runners[0]["name"] == "spellbook-repo-runner"


def test_gitlab_enumerate_runners_shape(gitlab_mock):
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    runners = client.enumerate_runners()
    for r in runners:
        assert set(r.keys()) == _RUNNER_FIELDS
        assert isinstance(r["labels"], list)
    # 2 groups x 2 group runners + 1 project x 1 project runner = 5.
    assert len(runners) == 5
    group_runners = [r for r in runners if r["scope"] == "org"]
    project_runners = [r for r in runners if r["scope"] == "repo"]
    assert len(group_runners) == 4
    assert len(project_runners) == 1
    # Group runners: the platform-managed shared SaaS runner maps to
    # self_hosted=False; the attached group runner maps to True.
    shared = [r for r in group_runners if r["name"] == "shared-saas-runner"]
    attached = [r for r in group_runners if r["name"] == "acme-group-runner"]
    assert shared and all(r["self_hosted"] is False for r in shared)
    assert attached and all(r["self_hosted"] is True for r in attached)
    # tag_list is surfaced verbatim as labels.
    assert "self-hosted" in attached[0]["labels"]
    # Project runner attaches to the spell-book-1 project.
    assert project_runners[0]["owner"] == "acme/spell-book-1"
    assert project_runners[0]["self_hosted"] is True


def test_bitbucket_enumerate_runners_shape(bitbucket_mock):
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    runners = client.enumerate_runners()
    for r in runners:
        assert set(r.keys()) == _RUNNER_FIELDS
        assert isinstance(r["labels"], list)
    # 2 workspaces x 2 runners + 1 repo x 1 runner = 5.
    assert len(runners) == 5
    ws_runners = [r for r in runners if r["scope"] == "org"]
    repo_runners = [r for r in runners if r["scope"] == "repo"]
    assert len(ws_runners) == 4
    assert len(repo_runners) == 1
    # Bitbucket Pipelines runners are self-hosted by design.
    assert all(r["self_hosted"] is True for r in runners)
    # Labels surface verbatim from Bitbucket's flat list.
    a_ws = next(r for r in ws_runners if r["name"] == "acme-workspace-runner")
    assert "self.hosted" in a_ws["labels"]
    assert "linux" in a_ws["labels"]
    # Repo runner attaches to the spell-book-1 repo.
    assert repo_runners[0]["owner"] == "acme/spell-book-1"


def test_enumerate_runners_never_emits_credentials(
    github_mock, gitlab_mock, bitbucket_mock
):
    """The decisive invariant: only runner identity and labels are surfaced —
    never a registration token, OAuth client secret, or any credential. The
    output is asserted to carry no fields beyond the normalized shape."""
    for client in (
        GitHubClient(token="ghp_x", base_url=github_mock.base_url),
        GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url),
        BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url),
    ):
        runners = client.enumerate_runners()
        assert runners, "expected at least one runner"
        for r in runners:
            assert set(r.keys()) == _RUNNER_FIELDS
            # No credential-bearing keys (defense in depth against future
            # provider responses that might add such fields verbatim).
            for forbidden in (
                "token",
                "registration_token",
                "oauth_client",
                "client_secret",
                "secret",
                "value",
            ):
                assert forbidden not in r


def test_github_runner_labels_reduced_to_bare_names(github_mock):
    """GitHub returns each label as {id, name, type=read-only|custom}; covenant
    surfaces only the human-readable label name — never the numeric id or the
    admin metadata."""
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    runners = client.enumerate_runners()
    for r in runners:
        for label in r["labels"]:
            assert isinstance(label, str)


def test_gitlab_shared_runner_flagged_not_self_hosted(gitlab_mock):
    """A GitLab.com SaaS shared runner is the platform-managed compute, not
    org-controlled infrastructure; covenant maps is_shared=true to
    self_hosted=false so the user can distinguish the two."""
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    runners = client.enumerate_runners()
    shared = [r for r in runners if r["name"] == "shared-saas-runner"]
    assert shared
    assert all(r["self_hosted"] is False for r in shared)


# --- e2e: the CLI flag adds a 'runners' array (only when requested) ---


def test_github_validate_token_enumerate_runners_cli(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-runners",
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
    assert "runners" in payload
    names = {r["name"] for r in payload["runners"]}
    assert {"acme-org-runner-1", "spellbook-repo-runner"} <= names
    # Defense-in-depth: no credential-bearing string ever lands in CLI output.
    assert "registration_token" not in proc.stdout


def test_validate_token_without_flag_has_no_runners_key(github_mock, scope_file):
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
    assert "runners" not in payload


def test_gitlab_validate_token_enumerate_runners_cli(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "validate-token",
            "--enumerate-runners",
            "--scope-file",
            scope_file,
            "--target-url",
            gitlab_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "glpat-" + "x" * 20},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    runners = payload["runners"]
    names = {r["name"] for r in runners}
    assert "acme-group-runner" in names
    # The shared SaaS runner is reported but flagged self_hosted=false.
    shared = [r for r in runners if r["name"] == "shared-saas-runner"]
    assert shared and shared[0]["self_hosted"] is False


def test_bitbucket_validate_token_enumerate_runners_cli(
    bitbucket_mock, scope_file
):
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--enumerate-runners",
            "--scope-file",
            scope_file,
            "--target-url",
            bitbucket_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "ATCTT" + "x" * 24},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    runners = payload["runners"]
    names = {r["name"] for r in runners}
    assert "acme-workspace-runner" in names
    assert all(r["self_hosted"] is True for r in runners)


def test_enumerate_runners_composes_with_other_enumerations(
    github_mock, scope_file
):
    """--enumerate-runners composes with the other additive flags; all arrays
    appear together."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-orgs",
            "--enumerate-keys",
            "--enumerate-gists",
            "--enumerate-webhooks",
            "--enumerate-deploy-keys",
            "--audit-branch-protection",
            "--enumerate-actions-secrets",
            "--enumerate-runners",
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
        and "branch_protection" in payload
        and "actions_secrets" in payload
        and "runners" in payload
    )


def test_enumerate_runners_respects_scope_guardrail(scope_file):
    """--enumerate-runners is still gated by the scope guardrail (exit 2)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--enumerate-runners",
            "--scope-file",
            scope_file,
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


def test_validate_token_help_documents_enumerate_runners():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0
    assert "--enumerate-runners" in proc.stdout
