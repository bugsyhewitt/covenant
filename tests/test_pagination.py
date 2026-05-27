"""Pagination end-to-end tests (POST_V01.md Item 1).

These prove covenant walks past the first API page for each SCM, that
``--max-pages`` bounds the walk, and that a single-page response stops after
one page. The mock servers (see ``mock_scm_server.py``) emit multi-page
responses for any query starting with ``MULTIPAGE_PREFIX``:

  - GitHub:    RFC-5988 ``Link: <...>; rel="next"`` header
  - GitLab:    ``X-Next-Page`` header (offset pagination)
  - Bitbucket: ``next`` URL key in the ``{"values": [...], "next": ...}`` envelope

Each mock walks exactly ``TOTAL_PAGES`` pages and returns one distinct item per
page, so a full walk yields ``TOTAL_PAGES`` results.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from mock_scm_server import TOTAL_PAGES


def _run(args: list[str], env_extra: dict | None = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.setdefault("COVENANT_TOKEN", "ghp_faketoken123")
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "covenant", *args],
        capture_output=True,
        text=True,
        env=env,
    )


def _recon_repo(scm: str, base_url: str, scope_file: str, query: str, *extra):
    return _run(
        [
            scm,
            "recon-repo",
            "--scope-file",
            scope_file,
            "--query",
            query,
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            base_url,
            *extra,
        ]
    )


# --- (a) GitHub pagination via RFC-5988 Link header --------------------------


def test_github_pagination_follows_link_header(github_mock, scope_file):
    proc = _recon_repo("github", github_mock.base_url, scope_file, "multipage")
    assert proc.returncode == 0, proc.stderr
    results = json.loads(proc.stdout)["results"]
    assert len(results) == TOTAL_PAGES, (
        f"expected {TOTAL_PAGES} results across pages; got {len(results)}"
    )
    # Each page contributes a distinct, page-stamped item — proves the walk
    # actually advanced rather than re-reading page one.
    names = {r["name"] for r in results}
    assert len(names) == TOTAL_PAGES, f"results not distinct per page: {names}"


def test_github_recon_code_pagination(github_mock, scope_file):
    proc = _run(
        [
            "github",
            "recon-code",
            "--scope-file",
            scope_file,
            "--query",
            "multipage",
            "--token-env",
            "COVENANT_TOKEN",
            "--target-url",
            github_mock.base_url,
        ]
    )
    assert proc.returncode == 0, proc.stderr
    results = json.loads(proc.stdout)["results"]
    assert len(results) == TOTAL_PAGES


# --- (b) GitLab pagination via X-Next-Page header ----------------------------


def test_gitlab_pagination_follows_x_next_page(gitlab_mock, scope_file):
    proc = _recon_repo("gitlab", gitlab_mock.base_url, scope_file, "multipage")
    assert proc.returncode == 0, proc.stderr
    results = json.loads(proc.stdout)["results"]
    assert len(results) == TOTAL_PAGES, (
        f"expected {TOTAL_PAGES} GitLab results across pages; got {len(results)}"
    )
    names = {r["name"] for r in results}
    assert len(names) == TOTAL_PAGES


# --- (c) Bitbucket pagination via `next` envelope key ------------------------


def test_bitbucket_pagination_follows_next_key(bitbucket_mock, scope_file):
    proc = _recon_repo("bitbucket", bitbucket_mock.base_url, scope_file, "multipage")
    assert proc.returncode == 0, proc.stderr
    results = json.loads(proc.stdout)["results"]
    assert len(results) == TOTAL_PAGES, (
        f"expected {TOTAL_PAGES} Bitbucket results across pages; got {len(results)}"
    )
    names = {r["name"] for r in results}
    assert len(names) == TOTAL_PAGES


# --- (d) --max-pages 1 caps the walk at a single page ------------------------


def test_max_pages_one_caps_github(github_mock, scope_file):
    proc = _recon_repo(
        "github", github_mock.base_url, scope_file, "multipage", "--max-pages", "1"
    )
    assert proc.returncode == 0, proc.stderr
    results = json.loads(proc.stdout)["results"]
    assert len(results) == 1, f"--max-pages 1 should yield one page; got {len(results)}"


def test_max_pages_one_caps_gitlab(gitlab_mock, scope_file):
    proc = _recon_repo(
        "gitlab", gitlab_mock.base_url, scope_file, "multipage", "--max-pages", "1"
    )
    assert proc.returncode == 0, proc.stderr
    assert len(json.loads(proc.stdout)["results"]) == 1


def test_max_pages_one_caps_bitbucket(bitbucket_mock, scope_file):
    proc = _recon_repo(
        "bitbucket", bitbucket_mock.base_url, scope_file, "multipage", "--max-pages", "1"
    )
    assert proc.returncode == 0, proc.stderr
    assert len(json.loads(proc.stdout)["results"]) == 1


def test_max_pages_two_caps_at_two(github_mock, scope_file):
    """A --max-pages below the available total stops mid-walk."""
    proc = _recon_repo(
        "github", github_mock.base_url, scope_file, "multipage", "--max-pages", "2"
    )
    assert proc.returncode == 0, proc.stderr
    results = json.loads(proc.stdout)["results"]
    assert len(results) == 2


# --- (e) Single-page response: walk stops naturally after page one -----------


def test_single_page_stops_after_one_github(github_mock, scope_file):
    """A plain (non-multipage) query returns exactly one page even with the
    default --max-pages of 10, because the server advertises no next page."""
    proc = _recon_repo("github", github_mock.base_url, scope_file, "spell")
    assert proc.returncode == 0, proc.stderr
    assert len(json.loads(proc.stdout)["results"]) == 1


def test_single_page_stops_after_one_gitlab(gitlab_mock, scope_file):
    proc = _recon_repo("gitlab", gitlab_mock.base_url, scope_file, "spell")
    assert proc.returncode == 0, proc.stderr
    assert len(json.loads(proc.stdout)["results"]) == 1


def test_single_page_stops_after_one_bitbucket(bitbucket_mock, scope_file):
    proc = _recon_repo("bitbucket", bitbucket_mock.base_url, scope_file, "spell")
    assert proc.returncode == 0, proc.stderr
    assert len(json.loads(proc.stdout)["results"]) == 1


# --- hard ceiling: --max-pages above HARD_MAX_PAGES is clamped, not rejected -


def test_max_pages_above_ceiling_is_clamped(github_mock, scope_file):
    proc = _recon_repo(
        "github", github_mock.base_url, scope_file, "multipage", "--max-pages", "9999"
    )
    assert proc.returncode == 0, proc.stderr
    # Clamped to 100, but the mock only offers TOTAL_PAGES — walk stops there.
    assert len(json.loads(proc.stdout)["results"]) == TOTAL_PAGES
