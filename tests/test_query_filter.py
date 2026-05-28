"""Unit tests for Item 7 — pattern-set selection and query noise-filtering.

Covers the pure ``build_query`` query-augmentation helper (``--exclude`` ->
``NOT <term>`` qualifiers, per-SCM) and the ``pattern_set`` plumbing through
``covenant.secrets`` (``--pattern-set`` -> ``necromancer_patterns.match``).
"""

from __future__ import annotations

import pytest

from covenant.cli import build_query
from covenant.secrets import (
    DEFAULT_PATTERN_SET,
    available_pattern_sets,
    scan_fragments,
)

_AWS_FRAGMENT = "AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE\n"


# --- build_query (--exclude) -------------------------------------------------


def test_build_query_no_excludes_passes_through():
    assert build_query("spell", None, "github") == "spell"
    assert build_query("spell", [], "github") == "spell"


def test_build_query_single_exclude_github():
    assert build_query("spell", ["example"], "github") == "spell NOT example"


def test_build_query_multiple_excludes_preserve_order():
    out = build_query("spell", ["example", "test", "localhost"], "github")
    assert out == "spell NOT example NOT test NOT localhost"


def test_build_query_gitlab_also_gets_not_qualifiers():
    assert build_query("spell", ["test"], "gitlab") == "spell NOT test"


def test_build_query_bitbucket_ignores_excludes():
    # Bitbucket's code-search grammar is different; --exclude is a no-op there.
    assert build_query("spell", ["example", "test"], "bitbucket") == "spell"


def test_build_query_blank_terms_are_skipped():
    out = build_query("spell", ["", "  ", "test"], "github")
    assert out == "spell NOT test"


def test_build_query_strips_surrounding_whitespace():
    out = build_query("spell", ["  example  "], "github")
    assert out == "spell NOT example"


def test_build_query_empty_query_with_excludes():
    # Degenerate but well-defined: no base term, only qualifiers.
    out = build_query("", ["example"], "github")
    assert out == "NOT example"


# --- pattern-set plumbing through scan_fragments -----------------------------


def test_available_pattern_sets_includes_known_sets():
    sets = available_pattern_sets()
    assert "full" in sets
    assert "minimal" in sets
    assert "aws" in sets


def test_default_pattern_set_constant_is_full():
    assert DEFAULT_PATTERN_SET == "full"


def test_scan_fragments_default_pattern_set_detects_aws():
    findings = scan_fragments([_AWS_FRAGMENT])
    assert any(f["rule_id"] == "aws-access-key-id" for f in findings)


def test_scan_fragments_aws_set_detects_aws_key():
    """The narrow 'aws' set still detects an AWS access key."""
    findings = scan_fragments([_AWS_FRAGMENT], pattern_set="aws")
    assert any(f["rule_id"] == "aws-access-key-id" for f in findings), findings


def test_scan_fragments_aws_set_is_no_wider_than_full():
    """Narrowing to 'aws' never produces MORE findings than 'full'."""
    full = scan_fragments([_AWS_FRAGMENT], pattern_set="full")
    aws = scan_fragments([_AWS_FRAGMENT], pattern_set="aws")
    assert len(aws) <= len(full)


def test_scan_fragments_minimal_set_runs():
    """The 'minimal' set is accepted and returns a (possibly empty) list."""
    findings = scan_fragments([_AWS_FRAGMENT], pattern_set="minimal")
    assert isinstance(findings, list)


def test_scan_fragments_pattern_set_does_not_change_shape():
    findings = scan_fragments([_AWS_FRAGMENT], pattern_set="aws")
    for f in findings:
        for key in ("rule_id", "description", "secret", "start", "end", "fragment_index"):
            assert key in f, f"missing key {key!r}: {f}"
