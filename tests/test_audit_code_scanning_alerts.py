"""Tests for validate-token --audit-code-scanning-alerts (first-party code flaws).

Covers the read-only audit of the OPEN code-scanning alerts on the repos a
captured token can reach. Where ``--audit-dependabot-alerts`` reports a
KNOWN-VULNERABILITY surface in a repo's third-party DEPENDENCIES and
``--audit-secret-scanning`` reports already-detected leaked credentials, this
reports the static-analyzer findings in the repo's OWN first-party source (an
injection sink, a crypto misuse, a path-traversal) — a bug in code the org
itself controls, named by rule and source location. The two cross-provider
invariants:

  * GitHub surfaces code-scanning/CodeQL alerts; GitLab surfaces SAST findings —
    both normalized to the SAME shape under the SAME flag; and
  * a repo with the feature disabled, never analyzed, or out of the token's
    scope (HTTP 403/404) is SKIPPED, not allowed to fail the whole audit, so a
    partial-permission token still reports every repo it can read.

The feature is additive: the v0.1 validate-token fields stay intact, the
``code_scanning_alerts`` array only appears when ``--audit-code-scanning-alerts``
is passed, and the normalized
``{"repo", "rule_id", "rule_name", "severity", "state", "html_url"}`` shape is
uniform across providers. Only rule metadata + the alert URL are surfaced —
never a credential. Bitbucket Cloud has no first-party static-analysis-alert
API, so the result is empty there with an explanatory warning.

Two layers are exercised:
  * unit — each client's ``audit_code_scanning_alerts`` against the in-process
    mock server, asserting the normalized shape, the open finding, the
    skip-on-403/404 behaviour, and the no-credential-leak invariant.
  * e2e — the CLI flag end-to-end, asserting ``code_scanning_alerts`` is present
    only under the flag and absent otherwise, composes with the other
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

_CS_FIELDS = {"repo", "rule_id", "rule_name", "severity", "state", "html_url"}


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


# --- unit: each client's audit_code_scanning_alerts returns normalized shape ----


def test_github_audit_code_scanning_alerts_shape(github_mock):
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    records = client.audit_code_scanning_alerts()
    # Only spellbook has alerts; grimoire (code scanning never-run -> 404) skipped.
    assert len(records) == 1
    r = records[0]
    assert set(r.keys()) == _CS_FIELDS
    assert r["repo"] == "acme-corp/spellbook"
    assert r["rule_id"] == "py/sql-injection"
    assert "SQL" in r["rule_name"]
    # The security-severity band is preferred over the generic 'error' severity.
    assert r["severity"] == "critical"
    assert r["state"] == "open"
    assert r["html_url"].endswith("/code-scanning/42")


def test_github_audit_code_scanning_alerts_skips_disabled_repo(github_mock):
    """A repo with code scanning disabled/never-run (404) is skipped, not fatal:
    grimoire never appears in the results and spellbook still does."""
    client = GitHubClient(token="ghp_x", base_url=github_mock.base_url)
    records = client.audit_code_scanning_alerts()
    repos = {r["repo"] for r in records}
    assert "acme-corp/grimoire" not in repos
    assert "acme-corp/spellbook" in repos


def test_github_audit_code_scanning_alerts_falls_back_to_generic_severity():
    """When no security_severity_level is present the audit falls back to the
    rule's generic severity (error/warning/note)."""

    class _NoBandClient(GitHubClient):
        def _reachable_repos(self, max_pages=10):
            return ["acme-corp/nobands"]

        def _code_scanning_alerts_for_repo(self, full_name, max_pages=10):
            return [
                {
                    "repo": full_name,
                    "rule_id": "js/xss",
                    "rule_name": "Reflected XSS",
                    "severity": "warning",
                    "state": "open",
                    "html_url": "https://example/1",
                }
            ]

    client = _NoBandClient(token="ghp_x", base_url="http://127.0.0.1:1")
    records = client.audit_code_scanning_alerts()
    assert records[0]["severity"] == "warning"


def test_gitlab_audit_code_scanning_alerts_shape(gitlab_mock):
    client = GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url)
    records = client.audit_code_scanning_alerts()
    assert records, "expected at least one detected SAST finding"
    r = records[0]
    assert set(r.keys()) == _CS_FIELDS
    assert r["repo"] == "acme/spell-book-1"
    assert r["rule_id"] == "rules.sql_injection"
    assert r["rule_name"] == "SQL Injection"
    # GitLab reports "Critical"; covenant lower-cases it to match the other SCMs.
    assert r["severity"] == "critical"
    assert r["state"] == "detected"
    assert r["html_url"].endswith("/vulnerabilities/9200")


def test_bitbucket_audit_code_scanning_alerts_is_empty_with_warning(bitbucket_mock):
    """Bitbucket Cloud has no static-analysis-alert API: the audit returns an
    empty list (uniform shape, no entries) and records an explanatory non-fatal
    warning so the empty result is not misread as a clean bill of health."""
    client = BitbucketClient(token="ATCTTx", base_url=bitbucket_mock.base_url)
    records = client.audit_code_scanning_alerts()
    assert records == []
    assert any("unsupported on Bitbucket" in w for w in client.warnings)


def test_audit_code_scanning_alerts_never_surfaces_a_credential(
    github_mock, gitlab_mock
):
    """The audit surfaces only rule/location metadata — the shape is exactly the
    six known keys; the only string handles are a rule id/name and an alert URL,
    never a token/secret value."""
    for client in (
        GitHubClient(token="ghp_x", base_url=github_mock.base_url),
        GitLabClient(token="glpat-x", base_url=gitlab_mock.base_url),
    ):
        records = client.audit_code_scanning_alerts()
        assert records
        for r in records:
            assert set(r.keys()) == _CS_FIELDS
            # The html_url points at the alert/finding, not at a credential.
            assert str(r["html_url"]).startswith("http")


# --- e2e: the CLI flag adds a 'code_scanning_alerts' array (only when requested)


def test_github_validate_token_audit_code_scanning_alerts_cli(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-code-scanning-alerts",
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
    assert "code_scanning_alerts" in payload
    alerts = payload["code_scanning_alerts"]
    assert len(alerts) == 1
    assert alerts[0]["repo"] == "acme-corp/spellbook"
    assert alerts[0]["severity"] == "critical"
    assert alerts[0]["rule_id"] == "py/sql-injection"


def test_validate_token_without_flag_has_no_code_scanning_alerts_key(
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
    assert "code_scanning_alerts" not in payload


def test_gitlab_validate_token_audit_code_scanning_alerts_cli(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "validate-token",
            "--audit-code-scanning-alerts",
            "--scope-file",
            scope_file,
            "--target-url",
            gitlab_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "glpat-" + "x" * 20},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "code_scanning_alerts" in payload
    assert payload["code_scanning_alerts"][0]["repo"] == "acme/spell-book-1"
    assert payload["code_scanning_alerts"][0]["severity"] == "critical"


def test_bitbucket_validate_token_audit_code_scanning_alerts_cli(
    bitbucket_mock, scope_file
):
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--audit-code-scanning-alerts",
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
    assert payload["code_scanning_alerts"] == []
    assert "warnings" in payload
    assert any("unsupported on Bitbucket" in w for w in payload["warnings"])


def test_audit_code_scanning_alerts_composes_with_other_audits(github_mock, scope_file):
    """--audit-code-scanning-alerts composes with the other additive flags; all
    arrays appear together."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-dependabot-alerts",
            "--audit-secret-scanning",
            "--audit-code-scanning-alerts",
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
        and "secret_scanning" in payload
        and "code_scanning_alerts" in payload
        and "collaborators" in payload
    )


def test_audit_code_scanning_alerts_respects_scope_guardrail(scope_file):
    """--audit-code-scanning-alerts is still gated by the scope guardrail (exit 2)."""
    proc = _run(
        [
            "github",
            "validate-token",
            "--audit-code-scanning-alerts",
            "--scope-file",
            scope_file,
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


def test_validate_token_help_documents_audit_code_scanning_alerts():
    proc = _run(["github", "validate-token", "--help"])
    assert proc.returncode == 0
    assert "--audit-code-scanning-alerts" in proc.stdout
