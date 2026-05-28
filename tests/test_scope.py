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
