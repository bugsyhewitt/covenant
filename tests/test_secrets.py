"""Unit tests for covenant.secrets — client-side secret scanning."""

from __future__ import annotations

import hashlib

import pytest

from covenant.secrets import redact, scan_fragments, SecretScanUnavailable

_AWS_EXAMPLE = "AKIAIOSFODNN7EXAMPLE"


def test_scan_fragments_empty():
    assert scan_fragments([]) == []


def test_scan_fragments_no_secrets():
    findings = scan_fragments(["hello world", "no secrets here"])
    assert findings == []


def test_scan_fragments_aws_key():
    fragment = "AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE\n"
    findings = scan_fragments([fragment])
    assert findings, "expected at least one finding"
    rule_ids = [f["rule_id"] for f in findings]
    assert "aws-access-key-id" in rule_ids


# --- redact() unit tests -----------------------------------------------------


def test_redact_empty_string():
    assert redact("") == ""


def test_redact_preserves_type_prefix():
    """The first 4 chars (the credential-type prefix) survive redaction."""
    out = redact(_AWS_EXAMPLE)
    assert out.startswith("AKIA"), out


def test_redact_includes_length_and_hash():
    out = redact(_AWS_EXAMPLE)
    digest = hashlib.sha256(_AWS_EXAMPLE.encode()).hexdigest()[:4]
    assert f"{len(_AWS_EXAMPLE)} chars" in out
    assert f"sha256:{digest}" in out


def test_redact_does_not_leak_full_secret():
    """The raw secret value must not appear verbatim in the fingerprint."""
    out = redact(_AWS_EXAMPLE)
    assert _AWS_EXAMPLE not in out


def test_redact_is_deterministic():
    assert redact(_AWS_EXAMPLE) == redact(_AWS_EXAMPLE)


def test_redact_short_secret_kept_whole():
    """A secret no longer than the prefix has nothing to hide."""
    out = redact("abc")
    assert out.startswith("abc")


def test_redact_distinguishes_different_secrets():
    a = redact("AKIAIOSFODNN7EXAMPLE")
    b = redact("AKIAXXXXXXXXXXXXXXXX")
    # Same prefix, but the hash must differ.
    assert a != b


# --- redaction policy in scan_fragments --------------------------------------


def test_scan_fragments_redacts_by_default():
    fragment = "AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE\n"
    findings = scan_fragments([fragment])
    assert findings
    f = findings[0]
    assert f["secret"] != _AWS_EXAMPLE, "default output must be redacted"
    assert _AWS_EXAMPLE not in f["secret"]
    assert f["secret"].startswith("AKIA")
    assert "sha256:" in f["secret"]


def test_scan_fragments_reveal_returns_raw_secret():
    fragment = "AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE\n"
    findings = scan_fragments([fragment], reveal=True)
    assert findings
    assert findings[0]["secret"] == _AWS_EXAMPLE


def test_scan_fragments_finding_shape_default():
    """Redaction changes only the secret value, not the finding shape."""
    fragment = "AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE\n"
    findings = scan_fragments([fragment])
    assert findings
    f = findings[0]
    for key in ("rule_id", "description", "secret", "start", "end", "fragment_index"):
        assert key in f, f"missing key {key!r}: {f}"


def test_scan_fragments_finding_shape():
    # Test the shape of a finding using the AWS key rule (avoids Stripe key
    # literals that trigger VCS push protection).
    fragment = "AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE\n"
    findings = scan_fragments([fragment])
    assert findings, "expected at least one finding"
    f = findings[0]
    assert "rule_id" in f
    assert "description" in f
    assert "secret" in f
    assert isinstance(f["start"], int)
    assert isinstance(f["end"], int)
    assert "fragment_index" in f
    assert f["fragment_index"] == 0


def test_scan_fragments_fragment_index():
    """fragment_index tracks which fragment a finding came from."""
    findings = scan_fragments([
        "no secrets here",
        "AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE\n",
    ])
    assert findings
    assert all(f["fragment_index"] == 1 for f in findings)


def test_scan_fragments_multiple_fragments_multiple_hits():
    findings = scan_fragments([
        "AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE\n",
        "ANOTHER_KEY = AKIAIOSFODNN7EXAMPLE\n",
    ])
    assert len(findings) >= 2
    indices = {f["fragment_index"] for f in findings}
    assert 0 in indices
    assert 1 in indices
