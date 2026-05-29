"""Tests for validate-token --audit-advisory-alerts (published repo advisories).

Covers the read-only audit of the PUBLISHED repository advisory alerts on the
repos a captured token can reach. This is distinct from the other security-
triage flags: where ``--audit-dependabot-alerts`` reports a repo CONSUMING the
global advisory database (a known CVE in a third-party DEPENDENCY) and
``--audit-code-scanning-alerts`` reports static-analyzer findings in the repo's
OWN source, this reports the repo as a PUBLISHER of advisories — the GHSAs the
org's own maintainers wrote up against their OWN product. The two
cross-provider invariants:

  * GitHub surfaces repository security advisories; GitLab and Bitbucket have no
    per-repo maintainer-authored advisory API, so the result is empty there with
    an explanatory warning; and
  * a repo with no advisories, the feature unavailable, or out of the token's
    scope (HTTP 403/404) is SKIPPED, not allowed to fail the whole audit, so a
    partial-permission token still reports every repo it can read.

The feature is additive: the v0.1 validate-token fields stay intact, the
``advisory_alerts`` array only appears when ``--audit-advisory-alerts`` is
passed, and the normalized
``{"repo", "ghsa_id", "cve_id", "summary", "severity", "state", "html_url"}``
shape is uniform across providers. Only advisory metadata + the advisory URL are
surfaced — never a credential.

Two layers are exercised:
  * unit — each client's ``audit_advisory_alerts`` against the in-process mock
    server, asserting the normalized shape, the published advisory, the
    skip-on-403/404 behaviour, and the no-credential-leak invariant.
  * e2e — the CLI flag end-to-end, asserting ``advisory_alerts`` is present only
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

_ADV_FIELDS = {
    "repo",
    "ghsa_id",
    "cve_id",
    "summary",
    "severity",
    "state",
    "html_url",
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


# --- unit: each client's audit_advisory_alerts returns normalized shape --------


def test_github_audit_advisory_alerts_shape(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    records = client.audit_advisory_alerts()
    # Only spellbook has advisories; grimoire (feature unavailable -> 404) skipped.
    assert len(records) == 1
    r = records[0]
    assert set(r.keys()) == _ADV_FIELDS
    assert r["repo"] == "acme-corp/spellbook"
    assert r["ghsa_id"] == "GHSA-spel-lboo-k123"
    assert r["cve_id"] == "CVE-2024-13337"
    assert "bypass" in r["summary"].lower()
    assert r["severity"] == "critical"
    assert r["state"] == "published"
    assert r["html_url"].endswith("/advisories/GHSA-spel-lboo-k123")


def test_github_audit_advisory_alerts_skips_repo_without_advisories(github_mock):
    """A repo with the advisory feature unavailable (404) is skipped, not fatal:
    grimoire never appears in the results and spellbook still does."""
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    records = client.audit_advisory_alerts()
    repos = {r["repo"] for r in records}
    assert "acme-corp/grimoire" not in repos
    assert "acme-corp/spellbook" in repos


def test_github_audit_advisory_alerts_handles_missing_cve():
    """An advisory without a CVE mapping yields cve_id=None and the rest of the
    normalized shape intact."""

    class _NoCveClient(GitHubClient):
        def _reachable_repos(self, max_pages=10):
            return ["acme-corp/nocve"]

        def _advisory_alerts_for_repo(self, full_name, max_pages=10):
            return [
                {
                    "repo": full_name,
                    "ghsa_id": "GHSA-aaaa-bbbb-cccc",
                    "cve_id": None,
                    "summary": "Stored XSS",
                    "severity": "high",
                    "state": "published",
                    "html_url": "https://example/advisories/1",
                }
            ]

    client = _NoCveClient(token="ghp_x", base_url="http://127.0.0.1:1")
    records = client.audit_advisory_alerts()
    assert records[0]["cve_id"] is None
    assert records[0]["ghsa_id"] == "GHSA-aaaa-bbbb-cccc"


def test_gitlab_audit_advisory_alerts_is_empty_with_warning(gitlab_mock):
    """GitLab has no per-project maintainer-authored advisory API: the audit
    returns an empty list and records an explanatory non-fatal warning so the
    empty result is not misread as a clean bill of health."""
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    records = client.audit_advisory_alerts()
    assert records == []
    assert any("unsupported on GitLab" in w for w in client.warnings)


def test_bitbucket_audit_advisory_alerts_is_empty_with_warning(bitbucket_mock):
    """Bitbucket Cloud has no repository advisory API: the audit returns an empty
    list and records an explanatory non-fatal warning."""
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    records = client.audit_advisory_alerts()
    assert records == []
    assert any("unsupported on Bitbucket" in w for w in client.warnings)


def test_audit_advisory_alerts_never_surfaces_a_credential(github_mock):
    """The audit surfaces only advisory metadata — the shape is exactly the seven
    known keys; the only string handles are the GHSA/CVE id, a summary, and an
    advisory URL, never a token/secret value."""
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    records = client.audit_advisory_alerts()
    assert records
    for r in records:
        assert set(r.keys()) == _ADV_FIELDS
        # The html_url points at the advisory, not at a credential.
        assert str(r["html_url"]).startswith("http")


# --- e2e: the CLI flag adds an 'advisory_alerts' array (only when requested) ----


def test_github_validate_token_audit_advisory_alerts_cli(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-advisory-alerts",
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
    assert "advisory_alerts" in payload
    alerts = payload["advisory_alerts"]
    assert len(alerts) == 1
    assert alerts[0]["repo"] == "acme-corp/spellbook"
    assert alerts[0]["severity"] == "critical"
    assert alerts[0]["ghsa_id"] == "GHSA-spel-lboo-k123"
    assert alerts[0]["cve_id"] == "CVE-2024-13337"


def test_validate_token_without_flag_has_no_advisory_alerts_key(
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
    assert "advisory_alerts" not in payload


def test_gitlab_validate_token_audit_advisory_alerts_cli(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "validate-token",
            "--audit-advisory-alerts",
            "--scope-file",
            scope_file,
            "--target-url",
            gitlab_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "glpat-" + "x" * 20},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    # Empty array, but the explanatory warning surfaces in the payload.
    assert payload["advisory_alerts"] == []
    assert "warnings" in payload
    assert any("unsupported on GitLab" in w for w in payload["warnings"])


def test_bitbucket_validate_token_audit_advisory_alerts_cli(
    bitbucket_mock, scope_file
):
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--audit-advisory-alerts",
            "--scope-file",
            scope_file,
            "--target-url",
            bitbucket_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "ATCTT" + "x" * 24},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["advisory_alerts"] == []
    assert "warnings" in payload
    assert any("unsupported on Bitbucket" in w for w in payload["warnings"])


def test_audit_advisory_alerts_composes_with_other_audits(github_mock, scope_file):
    """--audit-advisory-alerts composes with the other additive flags; all arrays
    appear together."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-dependabot-alerts",
            "--audit-code-scanning-alerts",
            "--audit-advisory-alerts",
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
        "dependabot_alerts" in payload
        and "code_scanning_alerts" in payload
        and "advisory_alerts" in payload
        and "collaborators" in payload
    )


def test_audit_advisory_alerts_respects_scope_guardrail(scope_file):
    """--audit-advisory-alerts is still gated by the scope guardrail (exit 2)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-advisory-alerts",
            "--scope-file",
            scope_file,
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


def test_validate_token_help_documents_audit_advisory_alerts():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0
    assert "--audit-advisory-alerts" in proc.stdout
