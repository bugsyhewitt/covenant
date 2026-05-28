"""Client-side secret scanning for covenant recon results.

Wraps ``necromancer-patterns`` to scan text fragments returned by SCM code
search APIs.  The dependency is optional: if ``necromancer_patterns`` is not
installed, :func:`scan_fragments` raises :class:`SecretScanUnavailable` with
a helpful install hint rather than crashing with an ImportError.

Usage::

    from covenant.secrets import scan_fragments, SecretScanUnavailable

    findings = scan_fragments(["export AWS_KEY=AKIAIOSFODNN7EXAMPLE"])
    # [{"rule_id": "aws-access-key-id", "description": "...", "secret": "AKIA...",
    #   "start": 17, "end": 37}]
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

# Number of leading characters of a secret preserved in the redacted
# fingerprint. The prefix encodes the credential type (e.g. ``AKIA``,
# ``ghp_``, ``sk_l``) so an operator can still tell what *kind* of credential
# a finding is without exposing the live value.
_PREFIX_LEN = 4

# Number of hex chars of the SHA-256 digest kept in the fingerprint. Enough to
# correlate identical secrets across findings without being reversible.
_HASH_LEN = 4


#: Pattern set used when the caller does not select one explicitly. ``full``
#: runs every rule (including the generic high-entropy detector), preserving
#: the pre-Item-7 behaviour so existing callers and tests are unaffected.
DEFAULT_PATTERN_SET = "full"


class SecretScanUnavailable(Exception):
    """Raised when necromancer-patterns is not installed."""


def available_pattern_sets() -> list[str]:
    """Return the pattern-set names exposed by ``necromancer-patterns``.

    Thin pass-through over ``necromancer_patterns.available_pattern_sets()``
    so the CLI can validate ``--pattern-set`` against the live library rather
    than a hard-coded list that could drift from the dependency. Raises
    :class:`SecretScanUnavailable` (with the same install hint as
    :func:`scan_fragments`) when the optional ``scan`` extra is not installed.
    """
    try:
        from necromancer_patterns import (  # type: ignore[import]
            available_pattern_sets as _sets,
        )
    except ImportError as exc:
        raise SecretScanUnavailable(
            "secret scanning requires the 'scan' extra: "
            "pip install 'covenant[scan]'"
        ) from exc
    return list(_sets())


def redact(secret: str) -> str:
    """Return a share-safe fingerprint of a discovered secret.

    The fingerprint keeps a short prefix (which encodes the credential type),
    the secret's length, and a truncated SHA-256 digest -- enough for an
    operator to recognize the credential type and correlate duplicate findings,
    but not enough to reconstruct the live value. For example::

        redact("AKIAIOSFODNN7EXAMPLE")
        # 'AKIA…[20 chars, sha256:9f3a]'

    Secrets shorter than the preserved prefix are kept whole (there is nothing
    meaningful to hide), and an empty string redacts to an empty string.
    """
    if not secret:
        return ""
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:_HASH_LEN]
    length = len(secret)
    if length <= _PREFIX_LEN:
        prefix = secret
    else:
        prefix = secret[:_PREFIX_LEN]
    return f"{prefix}…[{length} chars, sha256:{digest}]"


def scan_fragments(
    fragments: list[str],
    *,
    reveal: bool = False,
    pattern_set: str = DEFAULT_PATTERN_SET,
) -> list[dict]:
    """Scan a list of text fragments for credential patterns.

    Returns a flat list of finding dicts (one per match across all fragments).
    Each dict has keys: ``rule_id``, ``description``, ``secret``,
    ``start``, ``end``, ``fragment_index``.

    By default the ``secret`` field is redacted to a share-safe fingerprint
    (see :func:`redact`) so covenant's own output never becomes a new place a
    live credential leaks to. Pass ``reveal=True`` to emit the full raw secret
    value -- only do this when the operator has explicitly opted in.

    ``pattern_set`` selects which rule bundle ``necromancer-patterns`` applies
    (e.g. ``minimal``, ``aws``, ``full``); it defaults to ``full`` to preserve
    the pre-Item-7 behaviour. Narrowing the set (e.g. ``aws`` for an
    AWS-focused engagement) drops the generic high-entropy rule and the false
    positives it produces. See :func:`available_pattern_sets`.

    Raises :class:`SecretScanUnavailable` if ``necromancer-patterns`` is not
    installed in the current environment.
    """
    try:
        from necromancer_patterns import match  # type: ignore[import]
    except ImportError as exc:
        raise SecretScanUnavailable(
            "secret scanning requires the 'scan' extra: "
            "pip install 'covenant[scan]'"
        ) from exc

    results: list[dict] = []
    for idx, fragment in enumerate(fragments):
        for m in match(fragment, pattern_set=pattern_set):
            d = m.to_dict()
            d["fragment_index"] = idx
            if not reveal:
                d["secret"] = redact(d.get("secret", ""))
            results.append(d)
    return results
