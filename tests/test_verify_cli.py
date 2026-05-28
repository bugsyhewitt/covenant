"""End-to-end-ish tests for the ``--verify-secrets`` CLI wiring (Item 5).

These call ``covenant.cli.main()`` in-process (rather than as a subprocess) so
we can monkeypatch the AWS provider default URL to point at the mock-provider
server — the CLI flag deliberately exposes no provider-URL override, since in
production it must hit the real provider. The recon side still talks to the mock
SCM server, which plants a fake AWS key (``AKIAIOSFODNN7EXAMPLE``) in its
code-search fragments.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout

import covenant.verify as vmod
from covenant.cli import main
from mock_provider_server import MockProviderServer

_PLANTED_AWS = "AKIAIOSFODNN7EXAMPLE"


def _run_recon_code(args: list[str]) -> tuple[int, dict]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(args)
    out = buf.getvalue()
    payload = json.loads(out) if out.strip() else {}
    return rc, payload


def _all_findings(payload: dict) -> list[dict]:
    findings = []
    for result in payload.get("results", []):
        findings.extend(result.get("secret_findings", []))
    return findings


def test_verify_secrets_marks_live_key_verified(
    github_mock, scope_file, monkeypatch
):
    monkeypatch.setenv("COVENANT_TOKEN", "ghp_faketoken123")
    with MockProviderServer([_PLANTED_AWS]) as provider:
        monkeypatch.setattr(vmod, "AWS_STS_DEFAULT_URL", provider.base_url)
        rc, payload = _run_recon_code(
            [
                "github",
                "recon-code",
                "--scope-file",
                scope_file,
                "--query",
                "spell",
                "--target-url",
                github_mock.base_url,
                "--verify-secrets",
            ]
        )
    assert rc == 0
    findings = _all_findings(payload)
    aws = [f for f in findings if f["rule_id"] == "aws-access-key-id"]
    assert aws, "expected the planted AWS key to be detected"
    assert all(f["verified"] is True for f in aws)


def test_verify_secrets_marks_dead_key_false(
    github_mock, scope_file, monkeypatch
):
    monkeypatch.setenv("COVENANT_TOKEN", "ghp_faketoken123")
    # Provider knows no live secrets → the planted key is rejected (401 → False).
    with MockProviderServer([]) as provider:
        monkeypatch.setattr(vmod, "AWS_STS_DEFAULT_URL", provider.base_url)
        rc, payload = _run_recon_code(
            [
                "github",
                "recon-code",
                "--scope-file",
                scope_file,
                "--query",
                "spell",
                "--target-url",
                github_mock.base_url,
                "--verify-secrets",
            ]
        )
    assert rc == 0
    aws = [f for f in _all_findings(payload) if f["rule_id"] == "aws-access-key-id"]
    assert aws
    assert all(f["verified"] is False for f in aws)


def test_verify_secrets_redacts_output_without_show_secrets(
    github_mock, scope_file, monkeypatch
):
    """--verify-secrets alone must probe the raw key but emit a redacted value."""
    monkeypatch.setenv("COVENANT_TOKEN", "ghp_faketoken123")
    with MockProviderServer([_PLANTED_AWS]) as provider:
        monkeypatch.setattr(vmod, "AWS_STS_DEFAULT_URL", provider.base_url)
        rc, payload = _run_recon_code(
            [
                "github",
                "recon-code",
                "--scope-file",
                scope_file,
                "--query",
                "spell",
                "--target-url",
                github_mock.base_url,
                "--verify-secrets",
            ]
        )
    assert rc == 0
    aws = [f for f in _all_findings(payload) if f["rule_id"] == "aws-access-key-id"]
    assert aws
    for f in aws:
        # Verified live, but the raw key must not appear in the output.
        assert f["verified"] is True
        assert f["secret"] != _PLANTED_AWS
        assert _PLANTED_AWS not in f["secret"]
        assert "sha256:" in f["secret"]


def test_verify_secrets_with_show_secrets_reveals_raw(
    github_mock, scope_file, monkeypatch
):
    monkeypatch.setenv("COVENANT_TOKEN", "ghp_faketoken123")
    with MockProviderServer([_PLANTED_AWS]) as provider:
        monkeypatch.setattr(vmod, "AWS_STS_DEFAULT_URL", provider.base_url)
        rc, payload = _run_recon_code(
            [
                "github",
                "recon-code",
                "--scope-file",
                scope_file,
                "--query",
                "spell",
                "--target-url",
                github_mock.base_url,
                "--verify-secrets",
                "--show-secrets",
            ]
        )
    assert rc == 0
    aws = [f for f in _all_findings(payload) if f["rule_id"] == "aws-access-key-id"]
    assert aws
    assert any(f["secret"] == _PLANTED_AWS for f in aws)
    assert all(f["verified"] is True for f in aws)


def test_scan_secrets_without_verify_has_no_verified_field(
    github_mock, scope_file, monkeypatch
):
    """Plain --scan-secrets must not add a 'verified' field (no behavior change)."""
    monkeypatch.setenv("COVENANT_TOKEN", "ghp_faketoken123")
    rc, payload = _run_recon_code(
        [
            "github",
            "recon-code",
            "--scope-file",
            scope_file,
            "--query",
            "spell",
            "--target-url",
            github_mock.base_url,
            "--scan-secrets",
        ]
    )
    assert rc == 0
    findings = _all_findings(payload)
    assert findings
    assert all("verified" not in f for f in findings)


def test_verify_secrets_implies_scan(github_mock, scope_file, monkeypatch):
    """--verify-secrets with no --scan-secrets still produces findings."""
    monkeypatch.setenv("COVENANT_TOKEN", "ghp_faketoken123")
    with MockProviderServer([_PLANTED_AWS]) as provider:
        monkeypatch.setattr(vmod, "AWS_STS_DEFAULT_URL", provider.base_url)
        rc, payload = _run_recon_code(
            [
                "github",
                "recon-code",
                "--scope-file",
                scope_file,
                "--query",
                "spell",
                "--target-url",
                github_mock.base_url,
                "--verify-secrets",
            ]
        )
    assert rc == 0
    assert _all_findings(payload), "verify implies scan, so findings must exist"


def test_verify_secrets_in_help():
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            main(["github", "recon-code", "--help"])
    except SystemExit:
        pass
    assert "--verify-secrets" in buf.getvalue()
