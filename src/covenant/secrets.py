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

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


class SecretScanUnavailable(Exception):
    """Raised when necromancer-patterns is not installed."""


def scan_fragments(fragments: list[str]) -> list[dict]:
    """Scan a list of text fragments for credential patterns.

    Returns a flat list of finding dicts (one per match across all fragments).
    Each dict has keys: ``rule_id``, ``description``, ``secret``,
    ``start``, ``end``, ``fragment_index``.

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
        for m in match(fragment):
            d = m.to_dict()
            d["fragment_index"] = idx
            results.append(d)
    return results
