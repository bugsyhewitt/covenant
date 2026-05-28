"""Unit tests for covenant's scope enforcement."""

from __future__ import annotations

import pytest

from covenant.scope import Scope, ScopeError


def test_loopback_in_default_scope(scope_file):
    scope = Scope.from_file(scope_file)
    scope.assert_in_scope("http://127.0.0.1:54321")
    scope.assert_in_scope("https://github.com")


def test_out_of_scope_raises(scope_file):
    scope = Scope.from_file(scope_file)
    with pytest.raises(ScopeError):
        scope.assert_in_scope("https://api.example.com")


def test_org_and_repo_entries_match(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("github.com/acme\n")
    scope = Scope.from_file(str(f))
    scope.assert_in_scope("https://github.com")  # host listed via org entry
    with pytest.raises(ScopeError):
        scope.assert_in_scope("https://gitlab.com")


def test_comments_and_blanks_ignored(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("# comment\n\n   \ngithub.com\n")
    scope = Scope.from_file(str(f))
    assert scope.hosts == {"github.com"}


# --- Org/workspace-level scope narrowing -------------------------------------


def _scope(tmp_path, text: str) -> Scope:
    f = tmp_path / "scope.txt"
    f.write_text(text)
    return Scope.from_file(str(f))


def test_bare_host_is_host_wide_any_org_in_scope(tmp_path):
    """A bare host entry authorizes any org on that host (v0.1 behaviour)."""
    scope = _scope(tmp_path, "bitbucket.org\n")
    assert not scope.is_host_org_restricted("bitbucket.org")
    assert scope.is_org_in_scope("https://bitbucket.org", "anything")
    assert scope.is_org_in_scope("https://bitbucket.org", None)


def test_org_entry_restricts_host_to_that_org(tmp_path):
    """An org-only entry restricts the host to the listed org(s)."""
    scope = _scope(tmp_path, "bitbucket.org/acme\n")
    assert scope.is_host_org_restricted("bitbucket.org")
    assert scope.orgs["bitbucket.org"] == {"acme"}
    # The authorized org passes; a sibling org on the same host does not.
    scope.assert_org_in_scope("https://bitbucket.org", "acme")
    with pytest.raises(ScopeError):
        scope.assert_org_in_scope("https://bitbucket.org", "victim")


def test_org_restricted_host_refuses_unnamed_org(tmp_path):
    """On an org-restricted host, a target naming no org is refused."""
    scope = _scope(tmp_path, "bitbucket.org/acme\n")
    assert not scope.is_org_in_scope("https://bitbucket.org", None)
    with pytest.raises(ScopeError):
        scope.assert_org_in_scope("https://bitbucket.org", None)


def test_bare_entry_overrides_org_entry_to_host_wide(tmp_path):
    """If a host appears bare anywhere it is host-wide even with org entries."""
    scope = _scope(tmp_path, "bitbucket.org/acme\nbitbucket.org\n")
    assert not scope.is_host_org_restricted("bitbucket.org")
    scope.assert_org_in_scope("https://bitbucket.org", "victim")


def test_org_match_is_case_insensitive(tmp_path):
    scope = _scope(tmp_path, "bitbucket.org/Acme\n")
    scope.assert_org_in_scope("https://bitbucket.org", "ACME")


def test_multiple_orgs_on_one_host(tmp_path):
    scope = _scope(tmp_path, "bitbucket.org/acme\nbitbucket.org/beta\n")
    assert scope.orgs["bitbucket.org"] == {"acme", "beta"}
    scope.assert_org_in_scope("https://bitbucket.org", "beta")
    with pytest.raises(ScopeError):
        scope.assert_org_in_scope("https://bitbucket.org", "gamma")


def test_org_out_of_scope_for_host_not_in_scope(tmp_path):
    """An org on a host that isn't authorized at all is out of scope."""
    scope = _scope(tmp_path, "github.com/acme\n")
    assert not scope.is_org_in_scope("https://gitlab.com", "acme")
    with pytest.raises(ScopeError):
        scope.assert_org_in_scope("https://gitlab.com", "acme")


# --- is_url_org_restricted (URL-keyed companion for --org) -------------------


def test_is_url_org_restricted_true_for_org_only_host(tmp_path):
    """A GitHub host listed only with an org is URL-org-restricted."""
    scope = _scope(tmp_path, "github.com/acme\n")
    assert scope.is_url_org_restricted("https://api.github.com")


def test_is_url_org_restricted_false_for_bare_host(tmp_path):
    """A bare host entry is host-wide, so not URL-org-restricted."""
    scope = _scope(tmp_path, "github.com\n")
    assert not scope.is_url_org_restricted("https://api.github.com")


def test_is_url_org_restricted_false_for_unlisted_host(tmp_path):
    scope = _scope(tmp_path, "github.com/acme\n")
    assert not scope.is_url_org_restricted("https://gitlab.com")


# --- API-host ⇄ web-host canonicalization ------------------------------------


def test_web_host_scope_authorizes_github_api_host(tmp_path):
    """Listing github.com authorizes the api.github.com the client talks to.

    Without alias canonicalization the default GitHub recon run (which targets
    api.github.com) was refused as out-of-scope against a natural scope file.
    """
    scope = _scope(tmp_path, "github.com\n")
    assert scope.is_in_scope("https://api.github.com")
    scope.assert_in_scope("https://api.github.com")


def test_web_host_scope_authorizes_bitbucket_api_host(tmp_path):
    scope = _scope(tmp_path, "bitbucket.org\n")
    assert scope.is_in_scope("https://api.bitbucket.org")
    scope.assert_in_scope("https://api.bitbucket.org")


def test_listing_api_host_form_also_works(tmp_path):
    """Canonicalization is symmetric: listing the api.* form is accepted too."""
    scope = _scope(tmp_path, "api.github.com\n")
    assert scope.hosts == {"github.com"}
    scope.assert_in_scope("https://github.com")
    scope.assert_in_scope("https://api.github.com")


def test_gitlab_host_unaffected_by_aliasing(tmp_path):
    """GitLab's API and web host are identical; aliasing leaves it untouched."""
    scope = _scope(tmp_path, "gitlab.com\n")
    assert scope.is_in_scope("https://gitlab.com")
    with pytest.raises(ScopeError):
        scope.assert_in_scope("https://api.gitlab.com")


def test_unrelated_api_host_still_out_of_scope(tmp_path):
    """Aliasing only maps the two known SCM API hosts; others don't collapse."""
    scope = _scope(tmp_path, "github.com\n")
    with pytest.raises(ScopeError):
        scope.assert_in_scope("https://api.example.com")


def test_org_restriction_holds_against_api_host(tmp_path):
    """Item 8's org guardrail must survive canonicalization.

    A bitbucket.org/acme scope entry must still refuse --workspace victim even
    though the CLI scope-checks against api.bitbucket.org.
    """
    scope = _scope(tmp_path, "bitbucket.org/acme\n")
    assert scope.is_host_org_restricted("api.bitbucket.org")
    assert scope.is_org_in_scope("https://api.bitbucket.org", "acme")
    assert not scope.is_org_in_scope("https://api.bitbucket.org", "victim")
    scope.assert_org_in_scope("https://api.bitbucket.org", "acme")
    with pytest.raises(ScopeError):
        scope.assert_org_in_scope("https://api.bitbucket.org", "victim")
