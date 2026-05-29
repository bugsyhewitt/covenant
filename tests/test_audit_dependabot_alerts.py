"""Tests for validate-token --audit-dependabot-alerts (known-vuln attack surface).

Covers the read-only audit of the OPEN dependency-vulnerability alerts on the
repos a captured token can reach. Where ``--audit-branch-protection`` and
``--audit-codeowners`` report PROCESS gaps (would a bad push be stopped?), this
reports a KNOWN-VULNERABILITY attack surface: each alert is a documented CVE/GHSA
in a dependency the repo actually ships, named by package and advisory so it maps
straight to an exploit. The two cross-provider invariants:

  * GitHub surfaces Dependabot alerts; GitLab surfaces dependency-scanning
    vulnerabilities — both normalized to the SAME shape under the SAME flag; and
  * a repo with the feature disabled or out of the token's scope (HTTP 403/404)
    is SKIPPED, not allowed to fail the whole audit, so a partial-permission
    token still reports every repo it can read.

The feature is additive: the v0.1 validate-token fields stay intact, the
``dependabot_alerts`` array only appears when ``--audit-dependabot-alerts`` is
passed, and the normalized
``{"repo", "package", "ecosystem", "severity", "state", "identifier"}`` shape is
uniform across providers. Only the advisory IDENTIFIER is surfaced — never a
credential. Bitbucket Cloud has no first-party dependency-alert API, so the
result is empty there with an explanatory warning.

Two layers are exercised:
  * unit — each client's ``audit_dependabot_alerts`` against the in-process mock
    server, asserting the normalized shape, the open-severity finding, the
    skip-on-403/404 behaviour, and the no-credential-leak invariant.
  * e2e — the CLI flag end-to-end, asserting ``dependabot_alerts`` is present only
    under the flag and absent otherwise, composes with the other
    --enumerate-*/--audit-* flags, respects the scope guardrail (exit 2), and is
    documented in --help.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from covenant.scms.bitbucket import BitbucketClient
from covenant.scms.github import GitHubClient
from covenant.scms.gitlab import GitLabClient

_DA_FIELDS = {"repo", "package", "ecosystem", "severity", "state", "identifier"}


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


# --- unit: each client's audit_dependabot_alerts returns the normalized shape


def test_github_audit_dependabot_alerts_shape(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    records = client.audit_dependabot_alerts()
    # Only spellbook has alerts; grimoire (Dependabot disabled -> 403) is skipped.
    assert len(records) == 1
    r = records[0]
    assert set(r.keys()) == _DA_FIELDS
    assert r["repo"] == "acme-corp/spellbook"
    assert r["package"] == "requests"
    assert r["ecosystem"] == "pip"
    assert r["severity"] == "critical"
    assert r["state"] == "open"
    assert r["identifier"] == "GHSA-xxxx-yyyy-zzzz"


def test_github_audit_dependabot_alerts_skips_disabled_repo(github_mock):
    """A repo with Dependabot disabled (403/404) is skipped, not fatal: the
    grimoire repo never appears in the results and the spellbook one still does."""
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    records = client.audit_dependabot_alerts()
    repos = {r["repo"] for r in records}
    assert "acme-corp/grimoire" not in repos
    assert "acme-corp/spellbook" in repos


def test_github_audit_dependabot_alerts_falls_back_to_cve(github_mock):
    """When no GHSA id is present the audit falls back to the first CVE
    identifier. Asserted via a client whose alert advisory has only a CVE."""

    class _CveOnlyClient(GitHubClient):
        def _reachable_repos(self, max_pages=10):
            return ["acme-corp/cveonly"]

        def _dependabot_alerts_for_repo(self, full_name, max_pages=10):
            return [
                {
                    "repo": full_name,
                    "package": "left-pad",
                    "ecosystem": "npm",
                    "severity": "high",
                    "state": "open",
                    "identifier": "CVE-2025-9999",
                }
            ]

    client = _CveOnlyClient(token="ghp_x", base_url="http://127.0.0.1:1")
    records = client.audit_dependabot_alerts()
    assert records[0]["identifier"] == "CVE-2025-9999"


def test_gitlab_audit_dependabot_alerts_shape(gitlab_mock):
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    records = client.audit_dependabot_alerts()
    assert records, "expected at least one detected vulnerability"
    r = records[0]
    assert set(r.keys()) == _DA_FIELDS
    assert r["repo"] == "acme/spell-book-1"
    assert r["package"] == "lodash"
    assert r["ecosystem"] == "dependency_scanning"
    # GitLab reports "Critical"; covenant lower-cases it to match the other SCMs.
    assert r["severity"] == "critical"
    assert r["state"] == "detected"
    assert r["identifier"] == "CVE-2025-0002"


def test_bitbucket_audit_dependabot_alerts_is_empty_with_warning(bitbucket_mock):
    """Bitbucket Cloud has no dependency-alert API: the audit returns an empty
    list (uniform shape, no entries) and records an explanatory non-fatal
    warning so the empty result is not misread as a clean bill of health."""
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    records = client.audit_dependabot_alerts()
    assert records == []
    assert any("unsupported on Bitbucket" in w for w in client.warnings)


def test_audit_dependabot_alerts_never_surfaces_a_credential(
    github_mock, gitlab_mock
):
    """The audit surfaces only package/advisory metadata — the shape is exactly
    the six known keys and the only handle is the advisory identifier (GHSA/CVE),
    never a token/secret value."""
    for client in (
        GitHubClient(token="ghp_x", base_url=github_mock.base_url),
        GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url),
    ):
        records = client.audit_dependabot_alerts()
        assert records
        for r in records:
            assert set(r.keys()) == _DA_FIELDS
            # The identifier is an advisory handle, not a secret.
            assert str(r["identifier"]).startswith(("GHSA-", "CVE-"))


# --- e2e: the CLI flag adds a 'dependabot_alerts' array (only when requested) --


def test_github_validate_token_audit_dependabot_alerts_cli(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-dependabot-alerts",
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
    assert "dependabot_alerts" in payload
    alerts = payload["dependabot_alerts"]
    assert len(alerts) == 1
    assert alerts[0]["repo"] == "acme-corp/spellbook"
    assert alerts[0]["severity"] == "critical"
    assert alerts[0]["identifier"] == "GHSA-xxxx-yyyy-zzzz"


def test_validate_token_without_flag_has_no_dependabot_alerts_key(
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
    assert "dependabot_alerts" not in payload


def test_gitlab_validate_token_audit_dependabot_alerts_cli(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "validate-token",
            "--audit-dependabot-alerts",
            "--scope-file",
            scope_file,
            "--target-url",
            gitlab_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "glpat-" + "x" * 20},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "dependabot_alerts" in payload
    assert payload["dependabot_alerts"][0]["repo"] == "acme/spell-book-1"
    assert payload["dependabot_alerts"][0]["severity"] == "critical"


def test_bitbucket_validate_token_audit_dependabot_alerts_cli(
    bitbucket_mock, scope_file
):
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--audit-dependabot-alerts",
            "--scope-file",
            scope_file,
            "--target-url",
            bitbucket_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "ATCTT" + "x" * 24},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    # Empty array, but the explanatory warning surfaces in the payload.
    assert payload["dependabot_alerts"] == []
    assert "warnings" in payload
    assert any("unsupported on Bitbucket" in w for w in payload["warnings"])


def test_audit_dependabot_alerts_composes_with_other_audits(github_mock, scope_file):
    """--audit-dependabot-alerts composes with the other additive flags; all
    arrays appear together."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-branch-protection",
            "--audit-codeowners",
            "--audit-dependabot-alerts",
            "--enumerate-collaborators",
            "--scope-file",
            scope_file,
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert (
        "branch_protection" in payload
        and "codeowners" in payload
        and "dependabot_alerts" in payload
        and "collaborators" in payload
    )


def test_audit_dependabot_alerts_respects_scope_guardrail(scope_file):
    """--audit-dependabot-alerts is still gated by the scope guardrail (exit 2)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-dependabot-alerts",
            "--scope-file",
            scope_file,
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


def test_validate_token_help_documents_audit_dependabot_alerts():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0
    assert "--audit-dependabot-alerts" in proc.stdout
