"""Rate-limit and transient-failure handling tests (POST_V01.md Item 6).

These prove covenant treats a 403/429 rate-limit response as "wait and retry"
rather than a hard failure:

  - End-to-end (all three SCMs): a recoverable rate-limit (N x 429 then 200) is
    retried with backoff and ultimately yields results, exit code 0.
  - End-to-end: an unrecoverable rate-limit (429 forever) exhausts the bounded
    retry budget, surfaces a non-fatal ``warnings`` array in the payload, and
    keeps whatever partial results were gathered instead of aborting the run.
  - Unit: ``_parse_retry_after`` honors ``Retry-After``, the ``X-RateLimit-Reset``
    / ``RateLimit-Reset`` epoch headers, the exponential-backoff fallback, and
    clamps every result to ``[0, MAX_BACKOFF_SECONDS]``.
  - Unit: ``_request_with_retry`` actually sleeps once per retry and stops after
    the configured ``max_retries``, recording a warning on exhaustion.

The mock servers (see ``mock_scm_server.py``) advertise ``Retry-After: 0`` /
a reset epoch of "now" so the backoff sleep is a no-op and tests stay fast.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import httpx
import pytest

from covenant.scms.base import (
    BASE_BACKOFF_SECONDS,
    MAX_BACKOFF_SECONDS,
    BaseSCMClient,
    _parse_retry_after,
)

from mock_scm_server import RATELIMIT_FAILS


# --------------------------------------------------------------------------- #
# End-to-end: covenant retries a recoverable rate-limit and succeeds          #
# --------------------------------------------------------------------------- #


def _run(args: list[str]) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.setdefault("COVENANT_TOKEN", "ghp_faketoken123")
    return subprocess.run(
        [sys.executable, "-m", "covenant", *args],
        capture_output=True,
        text=True,
        env=env,
    )


def _recon_repo(scm: str, base_url: str, scope_file: str, query: str):
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
        ]
    )


def test_github_retries_recoverable_rate_limit(github_mock, scope_file):
    proc = _recon_repo("github", github_mock.base_url, scope_file, "ratelimit")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert len(payload["results"]) == 1, "should succeed after retrying 429s"
    assert "warnings" not in payload, "recovered run should carry no warnings"


def test_gitlab_retries_recoverable_rate_limit(gitlab_mock, scope_file):
    proc = _recon_repo("gitlab", gitlab_mock.base_url, scope_file, "ratelimit")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert len(payload["results"]) == 1
    assert "warnings" not in payload


def test_bitbucket_retries_recoverable_rate_limit(bitbucket_mock, scope_file):
    proc = _recon_repo("bitbucket", bitbucket_mock.base_url, scope_file, "ratelimit")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert len(payload["results"]) == 1
    assert "warnings" not in payload


# --------------------------------------------------------------------------- #
# End-to-end: budget exhausted -> non-fatal warnings, partial results kept     #
# --------------------------------------------------------------------------- #


def test_github_exhausted_budget_surfaces_warning(github_mock, scope_file):
    proc = _recon_repo("github", github_mock.base_url, scope_file, "ratelimitforever")
    # The run does not crash — it stops cleanly and reports the truncation.
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["results"] == [], "no page ever succeeded"
    assert "warnings" in payload and payload["warnings"], "must surface a warning"
    assert "rate limited" in payload["warnings"][0]
    assert "partial" in payload["warnings"][0]


def test_gitlab_exhausted_budget_surfaces_warning(gitlab_mock, scope_file):
    proc = _recon_repo("gitlab", gitlab_mock.base_url, scope_file, "ratelimitforever")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "warnings" in payload and payload["warnings"]


def test_bitbucket_exhausted_budget_surfaces_warning(bitbucket_mock, scope_file):
    proc = _recon_repo(
        "bitbucket", bitbucket_mock.base_url, scope_file, "ratelimitforever"
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "warnings" in payload and payload["warnings"]


# --------------------------------------------------------------------------- #
# Unit: _parse_retry_after header parsing + clamping                           #
# --------------------------------------------------------------------------- #


def _resp(headers: dict) -> httpx.Response:
    return httpx.Response(429, headers=headers)


def test_parse_retry_after_honors_retry_after_header():
    assert _parse_retry_after(_resp({"Retry-After": "5"}), attempt=0) == 5.0


def test_parse_retry_after_clamps_huge_retry_after():
    huge = str(int(MAX_BACKOFF_SECONDS) + 10_000)
    assert _parse_retry_after(_resp({"Retry-After": huge}), attempt=0) == MAX_BACKOFF_SECONDS


def test_parse_retry_after_negative_retry_after_floors_at_zero():
    assert _parse_retry_after(_resp({"Retry-After": "-3"}), attempt=0) == 0.0


def test_parse_retry_after_uses_github_reset_epoch():
    reset = int(time.time()) + 7
    wait = _parse_retry_after(_resp({"X-RateLimit-Reset": str(reset)}), attempt=0)
    # ~7s in the future, allowing a little wall-clock slack.
    assert 5.0 <= wait <= 7.5


def test_parse_retry_after_uses_gitlab_reset_epoch():
    reset = int(time.time()) + 4
    wait = _parse_retry_after(_resp({"RateLimit-Reset": str(reset)}), attempt=0)
    assert 2.5 <= wait <= 4.5


def test_parse_retry_after_past_reset_floors_at_zero():
    reset = int(time.time()) - 100
    assert _parse_retry_after(_resp({"X-RateLimit-Reset": str(reset)}), attempt=0) == 0.0


def test_parse_retry_after_falls_back_to_exponential_backoff():
    # No retry hint at all -> BASE * 2**attempt.
    assert _parse_retry_after(_resp({}), attempt=0) == BASE_BACKOFF_SECONDS
    assert _parse_retry_after(_resp({}), attempt=1) == BASE_BACKOFF_SECONDS * 2
    assert _parse_retry_after(_resp({}), attempt=2) == BASE_BACKOFF_SECONDS * 4


def test_parse_retry_after_backoff_is_clamped():
    # A large attempt number would overflow the cap; it must clamp.
    assert _parse_retry_after(_resp({}), attempt=20) == MAX_BACKOFF_SECONDS


def test_parse_retry_after_ignores_unparseable_header_and_backs_off():
    assert _parse_retry_after(_resp({"Retry-After": "soon"}), attempt=0) == BASE_BACKOFF_SECONDS


# --------------------------------------------------------------------------- #
# Unit: _request_with_retry sleeps per retry and stops at max_retries          #
# --------------------------------------------------------------------------- #


class _FakeClient(BaseSCMClient):
    default_base_url = "http://example.invalid"

    def _headers(self) -> dict:
        return {"Authorization": "token x"}


def test_request_with_retry_sleeps_then_succeeds(monkeypatch):
    """Two 429s then a 200: covenant sleeps twice and returns the 200."""
    client = _FakeClient(token="t", max_retries=3)
    slept: list[float] = []
    monkeypatch.setattr(client, "_sleep", lambda s: slept.append(s))

    responses = [
        httpx.Response(429, headers={"Retry-After": "0"}),
        httpx.Response(429, headers={"Retry-After": "0"}),
        httpx.Response(200, json={"ok": True}),
    ]
    calls = {"n": 0}

    def fake_get(url, params=None, headers=None, timeout=None):
        r = responses[calls["n"]]
        calls["n"] += 1
        return r

    monkeypatch.setattr(httpx, "get", fake_get)

    resp = client._request_with_retry("http://example.invalid/x", None, {})
    assert resp.status_code == 200
    assert len(slept) == 2, "should sleep once per 429 before the success"
    assert client.warnings == [], "a recovered request records no warning"


def test_request_with_retry_exhausts_budget_and_warns(monkeypatch):
    """429 forever: covenant retries max_retries times then warns and returns."""
    client = _FakeClient(token="t", max_retries=2)
    slept: list[float] = []
    monkeypatch.setattr(client, "_sleep", lambda s: slept.append(s))

    def always_429(url, params=None, headers=None, timeout=None):
        return httpx.Response(429, headers={"Retry-After": "0"})

    monkeypatch.setattr(httpx, "get", always_429)

    resp = client._request_with_retry("http://example.invalid/x", None, {})
    assert resp.status_code == 429
    assert len(slept) == 2, "max_retries=2 -> exactly two backoff sleeps"
    assert client.warnings, "exhaustion must record a warning"
    assert "retry budget of 2 exhausted" in client.warnings[0]


def test_max_retries_zero_does_not_retry(monkeypatch):
    """max_retries=0 means the very first 429 is final (still no crash)."""
    client = _FakeClient(token="t", max_retries=0)
    slept: list[float] = []
    monkeypatch.setattr(client, "_sleep", lambda s: slept.append(s))

    def always_429(url, params=None, headers=None, timeout=None):
        return httpx.Response(429, headers={"Retry-After": "0"})

    monkeypatch.setattr(httpx, "get", always_429)

    resp = client._request_with_retry("http://example.invalid/x", None, {})
    assert resp.status_code == 429
    assert slept == [], "no retries -> no sleeps"
    assert client.warnings, "still records the warning so recall truncation is visible"


def test_non_rate_limit_4xx_is_not_retried(monkeypatch):
    """A 404 is a hard failure, not a rate-limit; it must not be retried."""
    client = _FakeClient(token="t", max_retries=3)
    slept: list[float] = []
    monkeypatch.setattr(client, "_sleep", lambda s: slept.append(s))
    calls = {"n": 0}

    def fake_get(url, params=None, headers=None, timeout=None):
        calls["n"] += 1
        return httpx.Response(404, json={"message": "nope"})

    monkeypatch.setattr(httpx, "get", fake_get)

    resp = client._request_with_retry("http://example.invalid/x", None, {})
    assert resp.status_code == 404
    assert calls["n"] == 1, "a 404 is returned immediately, not retried"
    assert slept == []
    assert client.warnings == []
