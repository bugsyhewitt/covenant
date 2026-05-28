"""End-to-end smoke tests for the covenant CLI.

These invoke the installed ``covenant`` entry point as a subprocess against the
in-process mock SCM servers (no live API calls). Each test maps to a numbered
v0.1 completion criterion.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys


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


# --- Criterion 2: help surface ------------------------------------------------


def test_top_level_help_lists_scm_subcommands():
    proc = _run(["--help"])
    assert proc.returncode == 0
    for sub in ("github", "gitlab", "bitbucket"):
        assert sub in proc.stdout


def test_github_help_lists_modules():
    proc = _run(["github", "--help"])
    assert proc.returncode == 0
    for module in ("recon-repo", "recon-code", "validate-token"):
        assert module in proc.stdout


def test_gitlab_help_lists_modules():
    proc = _run(["gitlab", "--help"])
    assert proc.returncode == 0
    for module in ("recon-repo", "recon-code", "validate-token"):
        assert module in proc.stdout


def test_bitbucket_help_lists_modules():
    proc = _run(["bitbucket", "--help"])
    assert proc.returncode == 0
    for module in ("recon-repo", "recon-code", "validate-token"):
        assert module in proc.stdout


# --- Criterion 3: github recon-repo against mock, JSON with repo keys ---------


def test_github_recon_repo_success(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "recon-repo",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["results"], "expected at least one repo result"
    first = payload["results"][0]
    for key in ("name", "visibility", "url"):
        assert key in first
        assert first[key]


# --- Criterion 4: out-of-scope target exits 2 --------------------------------


def test_github_recon_repo_out_of_scope(scope_file):
    proc = _run(
        [
            "github",
            "recon-repo",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--target-url",
            "https://api.example.com",
        ]
    )
    assert proc.returncode == 2
    assert "out of scope" in proc.stderr.lower()


# --- Default-URL scope guardrail: web-host scope file authorizes the API host -


def test_github_default_url_passes_scope_guardrail(scope_file):
    """A web-host scope file (github.com) must not trip the scope guardrail for
    the default api.github.com target.

    Regression for the API-host vs web-host mismatch: covenant talks to
    api.github.com by default, but operators list github.com. Previously this
    exited 2 (out of scope), making default GitHub recon impossible. The run
    here has no live server, so it must NOT exit 2 — any other failure (network)
    is fine; what matters is the scope guardrail let it through.
    """
    proc = _run(
        [
            "github",
            "recon-repo",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            # No --target-url: exercise the real default api.github.com.
        ]
    )
    assert proc.returncode != 2, proc.stderr
    assert "out of scope" not in proc.stderr.lower()


def test_bitbucket_default_url_passes_scope_guardrail(scope_file):
    """bitbucket.org in scope must authorize the default api.bitbucket.org."""
    proc = _run(
        [
            "bitbucket",
            "recon-repo",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
        ]
    )
    assert proc.returncode != 2, proc.stderr
    assert "out of scope" not in proc.stderr.lower()


# --- Criterion 5: github validate-token --------------------------------------


def test_github_validate_token(github_mock, scope_file):
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
    assert isinstance(payload["scopes"], list)
    assert payload["user"]
    assert isinstance(payload["admin"], bool)


# --- Item 4: validate-token reports token_type fingerprint -------------------


def test_github_validate_token_reports_token_type(github_mock, scope_file):
    """validate-token output carries a token_type fingerprint (POST_V01 Item 4)."""
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
        ],
        env_extra={"COVENANT_TOKEN": "ghp_" + "A" * 36},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["token_type"] == "github-pat-classic"
    # Original v0.1 fields are still present (no shape regression).
    assert "scopes" in payload and "user" in payload and "admin" in payload
    # The raw token must never be echoed back into the payload.
    assert ("A" * 36) not in json.dumps(payload)


def test_gitlab_validate_token_reports_token_type_and_role_note(
    gitlab_mock, scope_file
):
    proc = _run(
        [
            "gitlab",
            "validate-token",
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
    assert payload["token_type"] == "gitlab-pat"
    # GitLab payloads must surface the scopes-AND-roles caveat.
    assert "role" in payload.get("token_note", "").lower()


def test_bitbucket_validate_token_reports_token_type(bitbucket_mock, scope_file):
    proc = _run(
        [
            "bitbucket",
            "validate-token",
            "--token-env",
            "COVENANT_TOKEN",
            "--scope-file",
            scope_file,
            "--target-url",
            bitbucket_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": "ATBB" + "x" * 24},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["token_type"] == "bitbucket-app-password"
    assert "deprecat" in payload.get("token_note", "").lower()


# --- Criterion 6 & 7: gitlab + bitbucket recon-repo parity -------------------


def test_gitlab_recon_repo_success(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "recon-repo",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            gitlab_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["results"]
    first = payload["results"][0]
    for key in ("name", "visibility", "url"):
        assert first[key]


def test_bitbucket_recon_repo_success(bitbucket_mock, scope_file):
    proc = _run(
        [
            "bitbucket",
            "recon-repo",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            bitbucket_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["results"]
    first = payload["results"][0]
    for key in ("name", "visibility", "url"):
        assert first[key]


# --- recon-code parity (module exists and works for github) ------------------


def test_github_recon_code_success(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "recon-code",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["results"]
    assert payload["results"][0]["name"]


# --- missing token handling --------------------------------------------------


def test_missing_token_env_exits_nonzero(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "recon-repo",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            github_mock.base_url,
        ],
        env_extra={"COVENANT_TOKEN": ""},
    )
    assert proc.returncode != 0
    assert "token" in proc.stderr.lower()


# --- --scan-secrets: GitHub code search with text-match fragments ------------


def test_github_recon_code_scan_secrets(github_mock, scope_file):
    """--scan-secrets attaches secret_findings to each result."""
    proc = _run(
        [
            "github",
            "recon-code",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            github_mock.base_url,
            "--scan-secrets",
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["results"], "expected at least one code result"
    first = payload["results"][0]
    assert "secret_findings" in first, "expected secret_findings key"
    # The mock server injects an AWS key in the text-match fragment.
    findings = first["secret_findings"]
    assert isinstance(findings, list)
    assert any(f["rule_id"] == "aws-access-key-id" for f in findings), (
        f"expected aws-access-key-id finding; got: {findings}"
    )


def test_github_recon_code_scan_secrets_finding_shape(github_mock, scope_file):
    """Each finding has the expected keys from necromancer-patterns Match."""
    proc = _run(
        [
            "github",
            "recon-code",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            github_mock.base_url,
            "--scan-secrets",
        ]
    )
    assert proc.returncode == 0, proc.stderr
    findings = json.loads(proc.stdout)["results"][0]["secret_findings"]
    assert findings, "expected at least one finding"
    for f in findings:
        for key in ("rule_id", "description", "secret", "start", "end", "fragment_index"):
            assert key in f, f"finding missing key {key!r}: {f}"


def test_github_recon_code_scan_secrets_redacted_by_default(github_mock, scope_file):
    """Without --show-secrets, the secret field is a redacted fingerprint."""
    proc = _run(
        [
            "github",
            "recon-code",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            github_mock.base_url,
            "--scan-secrets",
        ]
    )
    assert proc.returncode == 0, proc.stderr
    # The raw injected key must NOT appear anywhere in the output.
    assert "AKIAIOSFODNN7EXAMPLE" not in proc.stdout
    findings = json.loads(proc.stdout)["results"][0]["secret_findings"]
    aws = next(f for f in findings if f["rule_id"] == "aws-access-key-id")
    assert aws["secret"].startswith("AKIA"), aws["secret"]
    assert "sha256:" in aws["secret"]


def test_github_recon_code_show_secrets_reveals_raw(github_mock, scope_file):
    """--show-secrets opts back into the full raw value and implies scanning."""
    proc = _run(
        [
            "github",
            "recon-code",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            github_mock.base_url,
            "--show-secrets",
        ]
    )
    assert proc.returncode == 0, proc.stderr
    # --show-secrets implies --scan-secrets, so findings appear...
    findings = json.loads(proc.stdout)["results"][0]["secret_findings"]
    aws = next(f for f in findings if f["rule_id"] == "aws-access-key-id")
    # ...and the raw value is present.
    assert aws["secret"] == "AKIAIOSFODNN7EXAMPLE"


def test_github_recon_code_no_scan_secrets_no_findings_key(github_mock, scope_file):
    """Without --scan-secrets, results must NOT have a secret_findings key."""
    proc = _run(
        [
            "github",
            "recon-code",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    first = payload["results"][0]
    assert "secret_findings" not in first, (
        "secret_findings should only appear when --scan-secrets is passed"
    )


# --- --scan-secrets: GitLab code search with data fragment -------------------


def test_gitlab_recon_code_scan_secrets(gitlab_mock, scope_file):
    """GitLab --scan-secrets uses the 'data' field fragment."""
    proc = _run(
        [
            "gitlab",
            "recon-code",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            gitlab_mock.base_url,
            "--scan-secrets",
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["results"], "expected at least one code result"
    first = payload["results"][0]
    assert "secret_findings" in first
    findings = first["secret_findings"]
    assert any(f["rule_id"] == "aws-access-key-id" for f in findings), (
        f"expected aws-access-key-id finding in GitLab result; got: {findings}"
    )


# --- --scan-secrets: Bitbucket code search with content_matches fragments ----


def test_bitbucket_recon_code_success(bitbucket_mock, scope_file):
    """Bitbucket recon-code returns real code results (path/name), not repos."""
    proc = _run(
        [
            "bitbucket",
            "recon-code",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            bitbucket_mock.base_url,
            "--workspace",
            "acme",
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["results"], "expected at least one code result"
    first = payload["results"][0]
    # Should be a code result: has a path, not a repo name with visibility
    assert "path" in first, f"expected path key in code result: {first}"
    assert first["path"], "path should be non-empty"
    assert first["name"], "name should be non-empty (basename of path)"
    # Must NOT look like a repo result (recon_repo returns 'visibility')
    assert first.get("path") != first.get("name") or "/" in first.get("path", ""), (
        "code result path should contain a directory separator"
    )


def test_bitbucket_recon_code_no_workspace_errors(bitbucket_mock, scope_file):
    """recon-code without --workspace exits with an error, not silent fallback."""
    proc = _run(
        [
            "bitbucket",
            "recon-code",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            bitbucket_mock.base_url,
        ]
    )
    assert proc.returncode != 0
    assert "workspace" in proc.stderr.lower(), (
        f"expected 'workspace' in error message; got: {proc.stderr!r}"
    )


def test_bitbucket_recon_code_scan_secrets(bitbucket_mock, scope_file):
    """Bitbucket --scan-secrets uses content_matches fragments."""
    proc = _run(
        [
            "bitbucket",
            "recon-code",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            bitbucket_mock.base_url,
            "--workspace",
            "acme",
            "--scan-secrets",
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["results"], "expected at least one code result"
    first = payload["results"][0]
    assert "secret_findings" in first, "expected secret_findings key"
    findings = first["secret_findings"]
    assert isinstance(findings, list)
    assert any(f["rule_id"] == "aws-access-key-id" for f in findings), (
        f"expected aws-access-key-id finding in Bitbucket result; got: {findings}"
    )


def test_bitbucket_recon_code_scan_secrets_finding_shape(bitbucket_mock, scope_file):
    """Each Bitbucket secret finding has the expected keys."""
    proc = _run(
        [
            "bitbucket",
            "recon-code",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            bitbucket_mock.base_url,
            "--workspace",
            "acme",
            "--scan-secrets",
        ]
    )
    assert proc.returncode == 0, proc.stderr
    findings = json.loads(proc.stdout)["results"][0]["secret_findings"]
    assert findings, "expected at least one finding"
    for f in findings:
        for key in ("rule_id", "description", "secret", "start", "end", "fragment_index"):
            assert key in f, f"finding missing key {key!r}: {f}"


def test_bitbucket_recon_code_no_scan_secrets_no_findings_key(bitbucket_mock, scope_file):
    """Without --scan-secrets, Bitbucket results must NOT have a secret_findings key."""
    proc = _run(
        [
            "bitbucket",
            "recon-code",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            bitbucket_mock.base_url,
            "--workspace",
            "acme",
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    first = payload["results"][0]
    assert "secret_findings" not in first, (
        "secret_findings should only appear when --scan-secrets is passed"
    )


# --- Item 7: --exclude appends NOT qualifiers to the outgoing query ----------


def test_github_recon_code_exclude_adds_not_qualifier(github_mock, scope_file):
    """--exclude TERM appends 'NOT TERM' to the query that hits the API."""
    proc = _run(
        [
            "github",
            "recon-code",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            github_mock.base_url,
            "--exclude",
            "example",
            "--exclude",
            "test",
        ]
    )
    assert proc.returncode == 0, proc.stderr
    # The mock recorded the raw query string it received.
    received = github_mock._server.received_queries
    assert received, "mock did not record any code-search query"
    assert received[-1] == "spell NOT example NOT test", received
    # The payload echoes the operator's ORIGINAL query, not the augmented one.
    payload = json.loads(proc.stdout)
    assert payload["query"] == "spell"


def test_gitlab_recon_code_exclude_adds_not_qualifier(gitlab_mock, scope_file):
    proc = _run(
        [
            "gitlab",
            "recon-code",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            gitlab_mock.base_url,
            "--exclude",
            "localhost",
        ]
    )
    assert proc.returncode == 0, proc.stderr
    received = gitlab_mock._server.received_queries
    assert received and received[-1] == "spell NOT localhost", received


def test_recon_code_no_exclude_query_unchanged(github_mock, scope_file):
    """Without --exclude the outgoing query is exactly the operator's query."""
    proc = _run(
        [
            "github",
            "recon-code",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    received = github_mock._server.received_queries
    assert received and received[-1] == "spell", received


# --- Item 7: --pattern-set selection -----------------------------------------


def test_github_recon_code_pattern_set_aws_detects_aws(github_mock, scope_file):
    """--pattern-set aws still detects the planted AWS key."""
    proc = _run(
        [
            "github",
            "recon-code",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            github_mock.base_url,
            "--scan-secrets",
            "--pattern-set",
            "aws",
        ]
    )
    assert proc.returncode == 0, proc.stderr
    findings = json.loads(proc.stdout)["results"][0]["secret_findings"]
    assert any(f["rule_id"] == "aws-access-key-id" for f in findings), findings


def test_recon_code_invalid_pattern_set_errors(github_mock, scope_file):
    """An unknown --pattern-set exits non-zero with a helpful message."""
    proc = _run(
        [
            "github",
            "recon-code",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            github_mock.base_url,
            "--scan-secrets",
            "--pattern-set",
            "does-not-exist",
        ]
    )
    assert proc.returncode != 0
    assert "pattern-set" in proc.stderr.lower()
    assert "does-not-exist" in proc.stderr


def test_recon_code_help_lists_item7_flags(github_mock, scope_file):
    """recon-code --help advertises the new --pattern-set and --exclude flags."""
    proc = _run(["github", "recon-code", "--help"])
    assert proc.returncode == 0
    assert "--pattern-set" in proc.stdout
    assert "--exclude" in proc.stdout


# --- Item 8: org/workspace-level scope narrowing -----------------------------


def _org_scope_file(tmp_path, line: str) -> str:
    """Write a scope file authorizing the loopback host only for one org."""
    f = tmp_path / "org_scope.txt"
    f.write_text(line + "\n")
    return str(f)


def test_bitbucket_workspace_out_of_scope_refused(bitbucket_mock, tmp_path):
    """An org-restricted host refuses a --workspace naming a different org.

    The scope file authorizes the loopback host only for the 'acme' workspace.
    Searching '--workspace victim' must exit 2 (out of scope) and make no
    network call — the host alone is no longer sufficient authorization.
    """
    scope = _org_scope_file(tmp_path, "127.0.0.1/acme")
    proc = _run(
        [
            "bitbucket",
            "recon-code",
            "--scope-file",
            scope,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            bitbucket_mock.base_url,
            "--workspace",
            "victim",
        ]
    )
    assert proc.returncode == 2, (proc.returncode, proc.stderr)
    assert "victim" in proc.stderr
    assert "scope" in proc.stderr.lower()


def test_bitbucket_workspace_in_scope_allowed(bitbucket_mock, tmp_path):
    """The authorized workspace on an org-restricted host is allowed."""
    scope = _org_scope_file(tmp_path, "127.0.0.1/acme")
    proc = _run(
        [
            "bitbucket",
            "recon-code",
            "--scope-file",
            scope,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            bitbucket_mock.base_url,
            "--workspace",
            "acme",
        ]
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "results" in payload


def test_bare_host_authorizes_any_workspace(bitbucket_mock, scope_file):
    """A bare host entry (the shared fixture) authorizes any workspace.

    This proves backward compatibility: the v0.1 host-wide scope model is
    unchanged when no org path is listed.
    """
    proc = _run(
        [
            "bitbucket",
            "recon-code",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            bitbucket_mock.base_url,
            "--workspace",
            "any-workspace-at-all",
        ]
    )
    assert proc.returncode == 0, proc.stderr
