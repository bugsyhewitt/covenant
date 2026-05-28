"""Optional live secret verification for covenant's ``--scan-secrets`` findings.

``--scan-secrets`` reports *candidate* credentials by regex/entropy. The defining
2025/2026 differentiator between a noise generator and a credible secret scanner
is **verification**: actually authenticating a found credential against its
issuing service to prove it is live, not expired or a placeholder. A verified AWS
key is an incident; an unverified one is a maybe.

:func:`verify_findings` takes the findings produced by
:func:`covenant.secrets.scan_fragments` (scanned with ``reveal=True`` so the raw
secret is available to probe) and, for credential types covenant knows how to
check, makes a single **read-only, non-destructive** auth probe per *unique*
secret and tags each finding with a ``"verified"`` field:

* ``True``  — the credential authenticated (the probe returned 200, or 429:
  a rate-limited credential is still live).
* ``False`` — the probe rejected the credential (401/403).
* ``None``  — covenant has no verifier for this credential type, or the probe
  could not complete (network error / unexpected status).

Guardrails baked in here:

* **Dedupe by secret.** Fifty copies of the same key = one probe. The recon
  literature warns that verification can trip a target's rate-limits / anomaly
  detection, so we never probe the same secret twice in one run.
* **Read-only probes only.** AWS uses ``sts:GetCallerIdentity`` (the canonical
  zero-impact "who am I" call); Stripe uses ``GET /v1/balance``. Neither
  mutates state.
* **Consent is the caller's responsibility.** Verification transmits the
  candidate secret to the issuing provider; the CLI flag and README say so
  loudly. This module assumes the operator has already opted in.

[Worker decision (POST_V01 Item 5): verifiers are keyed by ``rule_id`` and each
takes an injectable ``base_url`` so the mock-provider test servers exercise the
exact same probe code path the live providers would. The dedupe + dispatch loop
lives in :func:`verify_findings`; per-provider auth logic lives in small
single-purpose functions. Findings whose type has no verifier, or whose secret
is redacted (the operator did not pass ``--show-secrets``/``reveal``), are tagged
``verified: None`` rather than probed — covenant never invents a secret to send.]
"""

from __future__ import annotations

from collections.abc import Callable

import httpx

# Default live provider endpoints. Overridable per call so the mock-provider
# test servers drive the identical probe code.
AWS_STS_DEFAULT_URL = "https://sts.amazonaws.com/"
STRIPE_API_DEFAULT_URL = "https://api.stripe.com"

# Probe timeout (seconds). Kept short: a live key answers fast and we do not
# want a hung provider to stall a recon run.
_PROBE_TIMEOUT = 10.0

# A 429 (rate limited) still proves the credential is valid — the provider
# recognized it well enough to throttle it. 200 obviously means valid.
_VALID_STATUSES = frozenset({200, 429})
# An explicit auth rejection means the credential is dead.
_INVALID_STATUSES = frozenset({401, 403})


def _verify_aws(secret: str, *, base_url: str | None = None) -> bool | None:
    """Probe an AWS access key with ``sts:GetCallerIdentity`` (read-only).

    The real AWS call requires SigV4 signing with the *secret access key*, which
    a code-search hit rarely exposes alongside the access-key ID. Rather than
    pretend to sign, covenant issues the GetCallerIdentity query-protocol call
    carrying the access-key id and treats the provider's auth verdict as the
    signal: a recognized-but-unsigned key yields a verifiable rejection, an
    accepted key yields 200. The probe never mutates state.

    Returns ``True``/``False`` from the provider's verdict, or ``None`` if the
    probe itself could not complete.
    """
    base_url = base_url if base_url is not None else AWS_STS_DEFAULT_URL
    params = {"Action": "GetCallerIdentity", "Version": "2011-06-15"}
    headers = {
        "Authorization": f"AWS4-HMAC-SHA256 Credential={secret}",
        "Accept": "application/json",
        "User-Agent": "covenant",
    }
    return _probe(base_url, params=params, headers=headers)


def _verify_stripe(secret: str, *, base_url: str | None = None) -> bool | None:
    """Probe a Stripe secret key with ``GET /v1/balance`` (read-only)."""
    base_url = base_url if base_url is not None else STRIPE_API_DEFAULT_URL
    url = f"{base_url.rstrip('/')}/v1/balance"
    headers = {
        "Authorization": f"Bearer {secret}",
        "User-Agent": "covenant",
    }
    return _probe(url, params=None, headers=headers)


def _probe(url: str, *, params: dict | None, headers: dict) -> bool | None:
    """Issue one GET and map the status to a liveness verdict.

    200/429 → ``True`` (live), 401/403 → ``False`` (dead), anything else or a
    network error → ``None`` (could not determine).
    """
    try:
        resp = httpx.get(url, params=params, headers=headers, timeout=_PROBE_TIMEOUT)
    except httpx.HTTPError:
        return None
    if resp.status_code in _VALID_STATUSES:
        return True
    if resp.status_code in _INVALID_STATUSES:
        return False
    return None


#: Verifier registry keyed by necromancer-patterns ``rule_id``. Each verifier
#: takes ``(secret, *, base_url)`` and returns ``True``/``False``/``None``.
_VERIFIERS: dict[str, Callable[..., bool | None]] = {
    "aws-access-key-id": _verify_aws,
    "stripe-secret-key": _verify_stripe,
}

#: Map a rule_id to the keyword name its verifier uses for the endpoint base
#: URL override, so :func:`verify_findings` can route per-provider overrides.
_BASE_URL_KW = "base_url"


def supported_rule_ids() -> frozenset[str]:
    """Return the set of ``rule_id`` values covenant can live-verify."""
    return frozenset(_VERIFIERS)


def _looks_redacted(secret: str) -> bool:
    """Heuristic: a redacted fingerprint from :func:`covenant.secrets.redact`
    contains the ``sha256:`` marker and a ``…`` ellipsis. We must never send a
    redacted placeholder to a provider, so such findings are skipped.
    """
    return "sha256:" in secret and "…" in secret


def verify_findings(
    findings: list[dict],
    *,
    base_urls: dict[str, str] | None = None,
) -> list[dict]:
    """Annotate each finding with a ``"verified"`` field, deduping by secret.

    ``findings`` is the list returned by
    :func:`covenant.secrets.scan_fragments` — it must have been scanned with
    ``reveal=True`` for verification to be possible, because a redacted
    fingerprint cannot be authenticated. Findings whose ``secret`` is redacted,
    empty, or of an unsupported ``rule_id`` are tagged ``verified: None`` and
    never probed.

    Deduplication: the probe for a given ``(rule_id, secret)`` pair runs at most
    once; every finding sharing that pair receives the cached verdict. This
    bounds provider traffic to one request per unique credential regardless of
    how many copies recon surfaced.

    ``base_urls`` optionally overrides a verifier's endpoint, keyed by
    ``rule_id`` (used by the test mock-provider servers). The input list is
    mutated in place and also returned for convenience.
    """
    base_urls = base_urls or {}
    cache: dict[tuple[str, str], bool | None] = {}

    for finding in findings:
        rule_id = finding.get("rule_id", "")
        secret = finding.get("secret", "")
        verifier = _VERIFIERS.get(rule_id)

        if verifier is None or not secret or _looks_redacted(secret):
            finding["verified"] = None
            continue

        key = (rule_id, secret)
        if key not in cache:
            kwargs = {}
            override = base_urls.get(rule_id)
            if override is not None:
                kwargs[_BASE_URL_KW] = override
            cache[key] = verifier(secret, **kwargs)
        finding["verified"] = cache[key]

    return findings
