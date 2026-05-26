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
