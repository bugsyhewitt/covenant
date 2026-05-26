"""Shared pytest fixtures for covenant's end-to-end smoke tests."""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from mock_scm_server import MockSCMServer  # noqa: E402

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
SCOPE_FILE = str(FIXTURES / "scope.txt")


@pytest.fixture
def github_mock():
    with MockSCMServer("github") as server:
        yield server


@pytest.fixture
def gitlab_mock():
    with MockSCMServer("gitlab") as server:
        yield server


@pytest.fixture
def bitbucket_mock():
    with MockSCMServer("bitbucket") as server:
        yield server


@pytest.fixture
def scope_file() -> str:
    return SCOPE_FILE
