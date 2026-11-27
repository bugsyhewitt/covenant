"""Deep unit tests for covenant's core logic modules.

Covers scope (scope.py), token fingerprinting (tokens.py), and the
pure CLI helper functions (build_query / apply_org in cli.py). No network
calls, no mock servers — these tests run entirely in-process.
"""

from __future__ import annotations

import pytest

from covenant.scope import (
    Scope,
    ScopeError,
    _canonical_host,
    _host_of,
    _split_host_org,
)
from covenant.tokens import classify_token
from covenant.cli import apply_org, build_query


# ---------------------------------------------------------------------------
# _canonical_host
# ---------------------------------------------------------------------------


def test_canonical_host_api_github_collapses():
    assert _canonical_host("api.github.com") == "github.com"


def test_canonical_host_api_bitbucket_collapses():
    assert _canonical_host("api.bitbucket.org") == "bitbucket.org"


def test_canonical_host_gitlab_unchanged():
    assert _canonical_host("gitlab.com") == "gitlab.com"


def test_canonical_host_lowercased():
    assert _canonical_host("GitHub.COM") == "github.com"


def test_canonical_host_none_passthrough():
    assert _canonical_host(None) is None


def test_canonical_host_empty_string_passthrough():
    assert _canonical_host("") == ""


def test_canonical_host_unknown_passthrough():
    assert _canonical_host("example.com") == "example.com"


# ---------------------------------------------------------------------------
# _split_host_org
# ---------------------------------------------------------------------------


def test_split_host_org_bare_host():
    host, org = _split_host_org("github.com")
    assert host == "github.com"
    assert org is None


def test_split_host_org_host_with_org():
    host, org = _split_host_org("github.com/acme-corp")
    assert host == "github.com"
    assert org == "acme-corp"


def test_split_host_org_full_url_https():
    host, org = _split_host_org("https://gitlab.com/acme/repo")
    assert host == "gitlab.com"
    assert org == "acme"


def test_split_host_org_api_subdomain():
    host, org = _split_host_org("https://api.github.com")
    assert host == "api.github.com"
    assert org is None


def test_split_host_org_empty_line():
    host, org = _split_host_org("")
    assert host is None
    assert org is None


def test_split_host_org_whitespace_only():
    host, org = _split_host_org("   ")
    assert host is None
    assert org is None


def test_split_host_org_case_lowercased():
    host, org = _split_host_org("GitHub.COM/AcmeCorp")
    assert host == "github.com"
    assert org == "acmecorp"


def test_host_of_bare_host():
    assert _host_of("github.com") == "github.com"


def test_host_of_full_url():
    assert _host_of("https://api.bitbucket.org/2.0/repositories") == "api.bitbucket.org"


# ---------------------------------------------------------------------------
# Scope.from_file
# ---------------------------------------------------------------------------


def _write_scope(tmp_path, text: str) -> str:
    f = tmp_path / "scope.txt"
    f.write_text(text)
    return str(f)


def test_scope_from_file_bare_hosts(tmp_path):
    path = _write_scope(tmp_path, "github.com\ngitlab.com\n")
    scope = Scope.from_file(path)
    assert "github.com" in scope.hosts
    assert "gitlab.com" in scope.hosts


def test_scope_from_file_ignores_comments_and_blanks(tmp_path):
    path = _write_scope(tmp_path, "# comment\n\n  github.com\n")
    scope = Scope.from_file(path)
    assert scope.hosts == {"github.com"}


def test_scope_from_file_empty_raises(tmp_path):
    path = _write_scope(tmp_path, "# only comments\n\n")
    with pytest.raises(ScopeError, match="lists no authorized hosts"):
        Scope.from_file(path)


def test_scope_from_file_api_alias_resolved(tmp_path):
    path = _write_scope(tmp_path, "api.github.com\n")
    scope = Scope.from_file(path)
    assert "github.com" in scope.hosts


def test_scope_host_wide_when_bare(tmp_path):
    path = _write_scope(tmp_path, "bitbucket.org\n")
    scope = Scope.from_file(path)
    assert "bitbucket.org" in scope.host_wide


def test_scope_org_restricted_when_path_only(tmp_path):
    path = _write_scope(tmp_path, "bitbucket.org/acme\n")
    scope = Scope.from_file(path)
    assert scope.is_host_org_restricted("bitbucket.org")
    assert not scope.is_host_org_restricted("github.com")


def test_scope_assert_in_scope_pass(tmp_path):
    path = _write_scope(tmp_path, "github.com\n")
    scope = Scope.from_file(path)
    scope.assert_in_scope("https://api.github.com/repos")


def test_scope_assert_in_scope_fail(tmp_path):
    path = _write_scope(tmp_path, "github.com\n")
    scope = Scope.from_file(path)
    with pytest.raises(ScopeError, match="out of scope"):
        scope.assert_in_scope("https://evil.example.com")


def test_scope_org_in_scope_host_wide(tmp_path):
    path = _write_scope(tmp_path, "github.com\n")
    scope = Scope.from_file(path)
    assert scope.is_org_in_scope("https://github.com", "any-org")
    assert scope.is_org_in_scope("https://github.com", None)


def test_scope_org_restricted_authorized_org_passes(tmp_path):
    path = _write_scope(tmp_path, "github.com/acme-corp\n")
    scope = Scope.from_file(path)
    assert scope.is_org_in_scope("https://github.com", "acme-corp")


def test_scope_org_restricted_unauthorized_org_fails(tmp_path):
    path = _write_scope(tmp_path, "github.com/acme-corp\n")
    scope = Scope.from_file(path)
    assert not scope.is_org_in_scope("https://github.com", "victim-org")


def test_scope_org_restricted_none_org_fails(tmp_path):
    path = _write_scope(tmp_path, "github.com/acme-corp\n")
    scope = Scope.from_file(path)
    assert not scope.is_org_in_scope("https://github.com", None)


def test_scope_assert_org_in_scope_raises_for_wrong_org(tmp_path):
    path = _write_scope(tmp_path, "github.com/acme-corp\n")
    scope = Scope.from_file(path)
    with pytest.raises(ScopeError, match="acme-corp"):
        scope.assert_org_in_scope("https://github.com", "other-org")


def test_scope_assert_org_in_scope_raises_for_no_org_on_restricted_host(tmp_path):
    path = _write_scope(tmp_path, "github.com/acme-corp\n")
    scope = Scope.from_file(path)
    with pytest.raises(ScopeError, match="names no org"):
        scope.assert_org_in_scope("https://github.com", None)


def test_scope_mixed_bare_and_org_entry_is_host_wide(tmp_path):
    # If ANY entry for the host is bare, the whole host is host-wide.
    path = _write_scope(tmp_path, "github.com\ngithub.com/acme\n")
    scope = Scope.from_file(path)
    assert not scope.is_host_org_restricted("github.com")
    assert scope.is_org_in_scope("https://github.com", "other-org")


# ---------------------------------------------------------------------------
# classify_token — GitHub
# ---------------------------------------------------------------------------


def test_classify_github_ghp_prefix():
    result = classify_token("ghp_abc123", "github")
    assert result["token_type"] == "github-pat-classic"
    assert result["confidence"] == "high"


def test_classify_github_gho_prefix():
    result = classify_token("gho_abc123", "github")
    assert result["token_type"] == "github-oauth"
    assert result["confidence"] == "high"


def test_classify_github_ghu_prefix():
    result = classify_token("ghu_abc123", "github")
    assert result["token_type"] == "github-app-user"
    assert result["confidence"] == "high"


def test_classify_github_ghs_prefix():
    result = classify_token("ghs_abc123", "github")
    assert result["token_type"] == "github-app-installation"
    assert result["confidence"] == "high"


def test_classify_github_ghr_prefix():
    result = classify_token("ghr_abc123", "github")
    assert result["token_type"] == "github-refresh"
    assert result["confidence"] == "high"


def test_classify_github_fine_grained_prefix():
    result = classify_token("github_pat_abcdef", "github")
    assert result["token_type"] == "github-pat-fine-grained"
    assert result["confidence"] == "high"


def test_classify_github_legacy_40hex():
    hex_token = "a" * 40
    result = classify_token(hex_token, "github")
    assert result["token_type"] == "github-pat-legacy"
    assert result["confidence"] == "medium"


def test_classify_github_unknown_shape():
    result = classify_token("notaknowntoken123", "github")
    assert result["token_type"] == "unknown"
    assert result["confidence"] == "low"


def test_classify_github_empty_token():
    result = classify_token("", "github")
    assert result["token_type"] == "unknown"


# ---------------------------------------------------------------------------
# classify_token — GitLab
# ---------------------------------------------------------------------------


def test_classify_gitlab_glpat_prefix():
    result = classify_token("glpat-xyz", "gitlab")
    assert result["token_type"] == "gitlab-pat"
    assert result["confidence"] == "high"
    assert "GitLab" in result["note"]


def test_classify_gitlab_gloas_prefix():
    result = classify_token("gloas-xyz", "gitlab")
    assert result["token_type"] == "gitlab-oauth"
    assert result["confidence"] == "high"


def test_classify_gitlab_glptt_prefix():
    result = classify_token("glptt-xyz", "gitlab")
    assert result["token_type"] == "gitlab-pipeline-trigger"
    assert result["confidence"] == "high"


def test_classify_gitlab_role_caveat_in_note():
    result = classify_token("glpat-xyz", "gitlab")
    assert "role" in result["note"].lower() or "scopes" in result["note"].lower()


def test_classify_gitlab_unknown():
    result = classify_token("notgitlab", "gitlab")
    assert result["token_type"] == "unknown"


# ---------------------------------------------------------------------------
# classify_token — Bitbucket
# ---------------------------------------------------------------------------


def test_classify_bitbucket_atctt_prefix():
    result = classify_token("ATCTTabcdef", "bitbucket")
    assert result["token_type"] == "bitbucket-api-token"
    assert result["confidence"] == "high"


def test_classify_bitbucket_atbb_deprecated():
    result = classify_token("ATBBxyz", "bitbucket")
    assert result["token_type"] == "bitbucket-app-password"
    assert result["confidence"] == "high"
    assert "DEPRECATED" in result["note"]


def test_classify_bitbucket_unknown():
    result = classify_token("notbitbucket", "bitbucket")
    assert result["token_type"] == "unknown"


def test_classify_unknown_scm():
    result = classify_token("ghp_abc", "unknown_scm")
    assert result["token_type"] == "unknown"
    assert result["confidence"] == "low"


# ---------------------------------------------------------------------------
# build_query (cli.py)
# ---------------------------------------------------------------------------


def test_build_query_no_excludes():
    assert build_query("api_key", None, "github") == "api_key"


def test_build_query_empty_excludes_list():
    assert build_query("api_key", [], "github") == "api_key"


def test_build_query_single_exclude():
    result = build_query("api_key", ["example"], "github")
    assert result == "api_key NOT example"


def test_build_query_multiple_excludes():
    result = build_query("AKIA", ["example", "test"], "github")
    assert result == "AKIA NOT example NOT test"


def test_build_query_exclude_passthrough_for_bitbucket():
    result = build_query("api_key", ["example"], "bitbucket")
    assert result == "api_key"


def test_build_query_blank_exclude_term_skipped():
    result = build_query("api_key", ["", "test", "  "], "github")
    assert result == "api_key NOT test"


def test_build_query_gitlab_honors_excludes():
    result = build_query("secret", ["localhost"], "gitlab")
    assert result == "secret NOT localhost"


# ---------------------------------------------------------------------------
# apply_org (cli.py)
# ---------------------------------------------------------------------------


def test_apply_org_github_appends_qualifier():
    result = apply_org("api_key", "acme-corp", "github")
    assert result == "api_key org:acme-corp"


def test_apply_org_gitlab_unchanged():
    result = apply_org("api_key", "acme-corp", "gitlab")
    assert result == "api_key"


def test_apply_org_bitbucket_unchanged():
    result = apply_org("api_key", "acme-workspace", "bitbucket")
    assert result == "api_key"


def test_apply_org_none_org_passthrough():
    result = apply_org("api_key", None, "github")
    assert result == "api_key"


def test_apply_org_empty_string_org_passthrough():
    result = apply_org("api_key", "", "github")
    assert result == "api_key"


def test_apply_org_whitespace_only_org_passthrough():
    result = apply_org("api_key", "   ", "github")
    assert result == "api_key"


def test_apply_org_empty_query_github():
    result = apply_org("", "acme", "github")
    assert result == "org:acme"


def test_apply_org_combines_with_build_query():
    q = build_query("secret", ["example"], "github")
    q = apply_org(q, "acme", "github")
    assert "NOT example" in q
    assert "org:acme" in q
