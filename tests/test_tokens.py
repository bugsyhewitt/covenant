"""Unit tests for covenant.tokens.classify_token (POST_V01 Item 4).

``classify_token`` is a pure, offline function: it inspects the *shape* of a
credential string (prefix taxonomy, hex form) and returns a ``token_type``
label, a human-readable ``note``, and a ``confidence``. No network calls, so
these tests have no mock servers — just the string contract.
"""

from __future__ import annotations

import pytest

from covenant.tokens import classify_token


# --- GitHub prefix taxonomy --------------------------------------------------


@pytest.mark.parametrize(
    "token,expected_type",
    [
        ("ghp_" + "A" * 36, "github-pat-classic"),
        ("gho_" + "A" * 36, "github-oauth"),
        ("ghu_" + "A" * 36, "github-app-user"),
        ("ghs_" + "A" * 36, "github-app-installation"),
        ("ghr_" + "A" * 36, "github-refresh"),
        ("github_pat_" + "A" * 22 + "_" + "B" * 59, "github-pat-fine-grained"),
        ("a" * 40, "github-pat-legacy"),  # bare 40-hex legacy PAT
    ],
)
def test_github_token_prefixes(token, expected_type):
    result = classify_token(token, "github")
    assert result["token_type"] == expected_type
    assert result["note"]  # always carries a human-readable note
    assert result["confidence"] in ("high", "medium", "low")


def test_github_app_installation_note_flags_app_reach():
    result = classify_token("ghs_" + "A" * 36, "github")
    assert "app" in result["note"].lower()


def test_github_unknown_shape_is_low_confidence():
    result = classify_token("totally-not-a-github-token", "github")
    assert result["token_type"] == "unknown"
    assert result["confidence"] == "low"


def test_github_40_char_non_hex_is_not_legacy_pat():
    # 40 chars but contains non-hex characters -> not a legacy hex PAT.
    result = classify_token("z" * 40, "github")
    assert result["token_type"] == "unknown"


# --- GitLab prefix taxonomy --------------------------------------------------


@pytest.mark.parametrize(
    "token,expected_type",
    [
        ("glpat-" + "x" * 20, "gitlab-pat"),
        ("gloas-" + "x" * 20, "gitlab-oauth"),
        ("glptt-" + "x" * 20, "gitlab-pipeline-trigger"),
    ],
)
def test_gitlab_token_prefixes(token, expected_type):
    result = classify_token(token, "gitlab")
    assert result["token_type"] == expected_type


def test_gitlab_note_warns_scopes_and_roles():
    # A GitLab note must remind the operator that effective access is bounded
    # by scopes AND the user's role — a permissive scope list is not a grant.
    result = classify_token("glpat-" + "x" * 20, "gitlab")
    assert "role" in result["note"].lower()


def test_gitlab_unknown_shape_is_low_confidence():
    result = classify_token("not-a-gitlab-token", "gitlab")
    assert result["token_type"] == "unknown"
    assert result["confidence"] == "low"


# --- Bitbucket taxonomy ------------------------------------------------------


def test_bitbucket_api_token_prefix():
    result = classify_token("ATCTT" + "x" * 30, "bitbucket")
    assert result["token_type"] == "bitbucket-api-token"


def test_bitbucket_app_password_flagged_deprecated():
    # App-password-shaped credentials (the legacy form) should be flagged as
    # deprecated given the 2025/2026 cutover timeline.
    result = classify_token("ATBB" + "x" * 24, "bitbucket")
    assert result["token_type"] == "bitbucket-app-password"
    assert "deprecat" in result["note"].lower()


def test_bitbucket_unknown_shape_is_low_confidence():
    result = classify_token("plainsecret", "bitbucket")
    assert result["token_type"] == "unknown"
    assert result["confidence"] == "low"


# --- Hygiene / edge cases ----------------------------------------------------


def test_empty_token_is_unknown_not_a_crash():
    result = classify_token("", "github")
    assert result["token_type"] == "unknown"
    assert result["confidence"] == "low"


def test_whitespace_is_stripped_before_classification():
    result = classify_token("  ghp_" + "A" * 36 + "  ", "github")
    assert result["token_type"] == "github-pat-classic"


def test_unknown_scm_returns_unknown():
    result = classify_token("ghp_" + "A" * 36, "subversion")
    assert result["token_type"] == "unknown"


def test_classify_never_returns_the_raw_token():
    # The classifier reasons about shape; it must never echo the secret back in
    # any field — output is safe to print alongside redacted findings.
    secret = "ghp_" + "S3cretValue" + "A" * 25
    result = classify_token(secret, "github")
    for value in result.values():
        assert secret not in str(value)


def test_result_keys_are_stable():
    result = classify_token("ghp_" + "A" * 36, "github")
    assert set(result) == {"token_type", "note", "confidence"}
