"""Unit tests for covenant.secrets — client-side secret scanning."""

from __future__ import annotations

import pytest

from covenant.secrets import scan_fragments, SecretScanUnavailable


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
