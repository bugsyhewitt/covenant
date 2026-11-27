"""Tests for covenant.classifier -- secret type classification."""

from __future__ import annotations

import pytest

from covenant.classifier import (
    ClassifiedSecret,
    SecretType,
    classify_secret,
    shannon_entropy,
)

# --- shannon_entropy() -------------------------------------------------------


def test_entropy_empty_string():
    assert shannon_entropy("") == 0.0


def test_entropy_single_char():
    # One distinct symbol -> 0 bits of uncertainty.
    assert shannon_entropy("aaaa") == pytest.approx(0.0)


def test_entropy_real_secret_high():
    # A realistic AWS key has high entropy.
    assert shannon_entropy("AKIAIOSFODNN7EXAMPLE") > 3.5


def test_entropy_simple_password_low():
    # 'password123' is low-entropy by real-secret standards.
    assert shannon_entropy("password123") < 3.5


# --- classify_secret() -- known patterns -------------------------------------


def test_aws_key_classified():
    result = classify_secret("AKIAIOSFODNN7EXAMPLE")
    assert result.secret_type == SecretType.AWS_KEY
    assert result.severity == "critical"
    assert result.confidence >= 0.9


def test_slack_token_classified():
    # Construct dynamically to avoid VCS push-protection triggering on the literal.
    slack = "xoxb" + "-" + "9" * 9 + "-" + "a" * 14
    result = classify_secret(slack)
    assert result.secret_type == SecretType.SLACK_TOKEN
    assert result.severity == "critical"
    assert result.confidence >= 0.9


def test_github_pat_classified():
    pat = "ghp_" + "A" * 36
    result = classify_secret(pat)
    assert result.secret_type == SecretType.GITHUB_PAT
    assert result.severity == "critical"
    assert result.confidence >= 0.9


def test_jwt_classified():
    # Minimal structurally valid JWT shape (header.payload -- no sig needed for
    # pattern match).
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0"
    result = classify_secret(jwt)
    assert result.secret_type == SecretType.JWT
    assert result.severity == "high"
    assert result.confidence >= 0.9


def test_private_key_classified():
    pem_header = "-----BEGIN RSA PRIVATE KEY-----"
    result = classify_secret(pem_header)
    assert result.secret_type == SecretType.PRIVATE_KEY
    assert result.severity == "critical"
    assert result.confidence >= 0.9


def test_database_url_classified():
    result = classify_secret("postgres://user:password@db.host/mydb")
    assert result.secret_type == SecretType.DATABASE_URL
    assert result.severity == "high"
    assert result.confidence >= 0.8


def test_stripe_key_classified():
    stripe = "sk_live_" + "A" * 24
    result = classify_secret(stripe)
    assert result.secret_type == SecretType.STRIPE_KEY
    assert result.severity == "critical"
    assert result.confidence >= 0.9


def test_sendgrid_key_classified():
    sg = "SG." + "A" * 22 + "." + "B" * 43
    result = classify_secret(sg)
    assert result.secret_type == SecretType.SENDGRID_KEY
    assert result.severity == "critical"
    assert result.confidence >= 0.9


# --- classify_secret() -- unknown / fallback ---------------------------------


def test_random_low_entropy_is_unknown():
    result = classify_secret("password123")
    assert result.secret_type == SecretType.UNKNOWN
    assert result.confidence < 0.5


def test_high_entropy_unknown_string():
    # A random-looking string that matches no pattern should still get a
    # medium confidence bump from entropy alone.
    high_entropy = "aB3kX9mQ2zT7vN1pW8sY4fU6rL0jH5dE"
    result = classify_secret(high_entropy)
    assert result.secret_type == SecretType.UNKNOWN
    assert result.entropy > 3.5
    assert result.confidence > 0.1


# --- entropy field on ClassifiedSecret ---------------------------------------


def test_entropy_field_populated():
    result = classify_secret("AKIAIOSFODNN7EXAMPLE")
    assert isinstance(result.entropy, float)
    assert result.entropy > 3.5


def test_entropy_field_low_for_simple_password():
    result = classify_secret("password123")
    assert result.entropy < 3.5


# --- confidence values reasonable --------------------------------------------


def test_confidence_in_range():
    for secret in [
        "AKIAIOSFODNN7EXAMPLE",
        "xoxb-1-abc",
        "ghp_" + "X" * 36,
        "password123",
    ]:
        c = classify_secret(secret)
        assert 0.0 <= c.confidence <= 1.0, f"confidence out of range for {secret!r}"


# --- scan_fragments integration -- classification keys present ---------------


def test_scan_fragments_includes_classification_keys():
    """scan_fragments output must carry secret_type, severity, confidence, entropy."""
    from covenant.secrets import scan_fragments

    fragment = "AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE\n"
    findings = scan_fragments([fragment])
    assert findings, "expected at least one finding"
    f = findings[0]
    for key in ("secret_type", "severity", "confidence", "entropy"):
        assert key in f, f"missing key {key!r} in finding: {f}"
    assert f["secret_type"] == SecretType.AWS_KEY.value
    assert f["severity"] == "critical"
    assert 0.0 <= f["confidence"] <= 1.0
    assert isinstance(f["entropy"], float)
