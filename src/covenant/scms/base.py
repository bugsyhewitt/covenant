"""Common HTTP plumbing for covenant's SCM clients.

[Worker decision: covenant performs its API calls through a thin shared httpx
layer rather than driving PyGithub / python-gitlab / atlassian-python-api object
models directly. Those SDKs are still declared (and version-pinned) dependencies
per the criteria because they define the idiomatic surface a v0.2 can grow into,
but the v0.1 read-only recon path needs only a handful of GET endpoints. Talking
plain httpx to a configurable base URL keeps the live and mock-server paths
byte-for-byte identical, which is what the ephemeral-port smoke tests exercise.]
"""

from __future__ import annotations

import httpx


class SCMError(Exception):
    """Raised when an SCM API call fails or returns an unexpected shape."""


class BaseSCMClient:
    #: Default API base URL for the live service; overridden by --target-url.
    default_base_url: str = ""

    def __init__(self, token: str, base_url: str | None = None, timeout: float = 15.0):
        self.token = token
        self.base_url = (base_url or self.default_base_url).rstrip("/")
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        raise NotImplementedError

    def _get(self, path: str, params: dict | None = None) -> httpx.Response:
        url = f"{self.base_url}{path}"
        try:
            resp = httpx.get(
                url,
                params=params,
                headers=self._headers(),
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:  # network-level failure
            raise SCMError(f"request to {url} failed: {exc}") from exc
        if resp.status_code == 401:
            raise SCMError("authentication failed (401) — check the token")
        if resp.status_code >= 400:
            raise SCMError(
                f"{self.base_url} returned HTTP {resp.status_code} for {path}"
            )
        return resp
