"""Tests for covenant.verify — optional live secret verification (Item 5).

The probe code path is exercised against the in-process mock-provider servers
(``tests/mock_provider_server.py``), which speak the same auth surfaces covenant
hits in production (AWS STS GetCallerIdentity, Stripe GET /v1/balance) on an
ephemeral port. The same code path that would talk to a live provider talks to
the mock, via the injectable ``base_urls`` override.
"""

from __future__ import annotations

from covenant.secrets import redact
from covenant.verify import supported_rule_ids, verify_findings
from mock_provider_server import MockProviderServer

_AWS_LIVE = "AKIAIOSFODNN7EXAMPLE"
_AWS_DEAD = "AKIADEADBEEFDEADBEEF"


def _aws_finding(secret: str) -> dict:
    return {
        "rule_id": "aws-access-key-id",
        "description": "AWS Access Key ID",
        "secret": secret,
        "start": 0,
        "end": len(secret),
        "fragment_index": 0,
    }


# --- registry ----------------------------------------------------------------


def test_supported_rule_ids_includes_aws_and_stripe():
    rules = supported_rule_ids()
    assert "aws-access-key-id" in rules
    assert "stripe-secret-key" in rules


# --- core verdicts -----------------------------------------------------------


def test_live_secret_verifies_true():
    with MockProviderServer([_AWS_LIVE]) as srv:
        findings = [_aws_finding(_AWS_LIVE)]
        verify_findings(findings, base_urls={"aws-access-key-id": srv.base_url})
    assert findings[0]["verified"] is True


def test_dead_secret_verifies_false():
    with MockProviderServer([_AWS_LIVE]) as srv:
        findings = [_aws_finding(_AWS_DEAD)]
        verify_findings(findings, base_urls={"aws-access-key-id": srv.base_url})
    assert findings[0]["verified"] is False


def test_rate_limited_credential_counts_as_live():
    """A 429 means the provider recognized the credential — still live."""
    with MockProviderServer([_AWS_LIVE], valid_status=429) as srv:
        findings = [_aws_finding(_AWS_LIVE)]
        verify_findings(findings, base_urls={"aws-access-key-id": srv.base_url})
    assert findings[0]["verified"] is True


def test_indeterminate_status_maps_to_none():
    """A 500 (or any non-auth status) yields an undetermined verdict."""
    with MockProviderServer([_AWS_LIVE], force_status=500) as srv:
        findings = [_aws_finding(_AWS_LIVE)]
        verify_findings(findings, base_urls={"aws-access-key-id": srv.base_url})
    assert findings[0]["verified"] is None


def test_network_error_maps_to_none():
    """An unreachable endpoint yields None, never an exception."""
    findings = [_aws_finding(_AWS_LIVE)]
    # Port 1 is reserved and refuses connections fast.
    verify_findings(
        findings, base_urls={"aws-access-key-id": "http://127.0.0.1:1"}
    )
    assert findings[0]["verified"] is None


# --- type handling -----------------------------------------------------------


def test_unsupported_rule_id_is_none_and_not_probed():
    findings = [
        {
            "rule_id": "generic-high-entropy",
            "description": "entropy",
            "secret": "some-random-blob-1234567890",
            "start": 0,
            "end": 10,
            "fragment_index": 0,
        }
    ]
    verify_findings(findings)
    assert findings[0]["verified"] is None


def test_redacted_secret_is_never_probed():
    """A redacted fingerprint must never be transmitted to a provider."""
    fingerprint = redact(_AWS_LIVE)
    finding = _aws_finding(fingerprint)
    # Point at an always-200 server: if covenant (wrongly) probed the redacted
    # value, it could come back True. It must short-circuit to None instead.
    with MockProviderServer([fingerprint], valid_status=200) as srv:
        verify_findings([finding], base_urls={"aws-access-key-id": srv.base_url})
    assert finding["verified"] is None


def test_empty_secret_is_none():
    finding = _aws_finding("")
    verify_findings([finding])
    assert finding["verified"] is None


# --- dedupe ------------------------------------------------------------------


def test_duplicate_secrets_probed_once():
    """50 copies of one key = 1 probe; all copies get the same verdict."""

    class CountingServer(MockProviderServer):
        pass

    # Use a subclass-free approach: wrap verify with a counting verifier via a
    # mock server that records hits. We count by reusing the server and asserting
    # the verdict is consistent; to prove single-probe we patch the registry.
    calls = {"n": 0}

    import covenant.verify as vmod

    real = vmod._verify_aws

    def counting(secret, *, base_url=vmod.AWS_STS_DEFAULT_URL):  # noqa: ANN001
        calls["n"] += 1
        return True

    vmod._VERIFIERS["aws-access-key-id"] = counting
    try:
        findings = [_aws_finding(_AWS_LIVE) for _ in range(50)]
        verify_findings(findings)
    finally:
        vmod._VERIFIERS["aws-access-key-id"] = real

    assert calls["n"] == 1, "duplicate secrets must be probed exactly once"
    assert all(f["verified"] is True for f in findings)


def test_distinct_secrets_probed_separately():
    import covenant.verify as vmod

    real = vmod._verify_aws
    seen = []

    def recording(secret, *, base_url=vmod.AWS_STS_DEFAULT_URL):  # noqa: ANN001
        seen.append(secret)
        return secret == _AWS_LIVE

    vmod._VERIFIERS["aws-access-key-id"] = recording
    try:
        findings = [_aws_finding(_AWS_LIVE), _aws_finding(_AWS_DEAD)]
        verify_findings(findings)
    finally:
        vmod._VERIFIERS["aws-access-key-id"] = real

    assert set(seen) == {_AWS_LIVE, _AWS_DEAD}
    assert findings[0]["verified"] is True
    assert findings[1]["verified"] is False


# --- return contract ---------------------------------------------------------


def test_verify_findings_returns_same_list():
    findings = [_aws_finding(_AWS_LIVE)]
    out = verify_findings(
        findings, base_urls={"aws-access-key-id": "http://127.0.0.1:1"}
    )
    assert out is findings


def test_empty_findings_list():
    assert verify_findings([]) == []
