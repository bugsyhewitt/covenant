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

from collections.abc import Callable

import httpx

#: Default page-walk ceiling exposed via the CLI ``--max-pages`` flag. Recon
#: callers may lower this; the hard ceiling is enforced in the CLI.
DEFAULT_MAX_PAGES = 10
#: Absolute upper bound on pages, chosen to respect GitHub's ~100-page search
#: cap. The CLI clamps ``--max-pages`` to this value.
HARD_MAX_PAGES = 100


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

    def _get(
        self,
        path: str,
        params: dict | None = None,
        extra_headers: dict | None = None,
    ) -> httpx.Response:
        url = f"{self.base_url}{path}"
        headers = {**self._headers(), **(extra_headers or {})}
        try:
            resp = httpx.get(
                url,
                params=params,
                headers=headers,
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

    def _get_paginated(
        self,
        path: str,
        params: dict | None = None,
        *,
        max_pages: int = DEFAULT_MAX_PAGES,
        extra_headers: dict | None = None,
        next_request: Callable[[httpx.Response], tuple[str, dict | None] | None],
    ):
        """Walk paginated GET responses, yielding one ``httpx.Response`` per page.

        The first page is fetched from ``path`` with ``params``. After each
        page, ``next_request`` is called with the just-received response; it
        returns either ``(next_path_or_url, next_params)`` to continue or
        ``None`` to stop. ``next_path_or_url`` may be an absolute URL (GitHub
        and Bitbucket hand back full ``next`` links) or a path/params pair
        (GitLab walks by incrementing ``page``).

        The loop is hard-bounded by ``max_pages`` regardless of what the server
        offers, so a misbehaving or hostile API can never make covenant walk
        forever. A ``max_pages`` of ``1`` fetches exactly one page — the
        pre-pagination behaviour.

        [Worker decision: pagination is a shared loop in base.py that delegates
        the SCM-specific "where's the next page?" parsing to a per-client
        ``next_request`` callback. This keeps the RFC-5988 Link-header walk
        (GitHub), the X-Next-Page walk (GitLab), and the ``next``-envelope walk
        (Bitbucket) in their respective clients while the bounding, HTTP
        plumbing, and error handling stay in one place. Yielding raw responses
        (not parsed items) lets each client keep its existing item-extraction
        code unchanged — it just loops over pages instead of reading one.]
        """
        if max_pages < 1:
            max_pages = 1
        if max_pages > HARD_MAX_PAGES:
            max_pages = HARD_MAX_PAGES

        next_path: str | None = path
        next_params = params
        pages = 0
        while next_path is not None and pages < max_pages:
            if next_path.startswith(("http://", "https://")):
                resp = self._get_absolute(next_path, next_params, extra_headers)
            else:
                resp = self._get(next_path, next_params, extra_headers)
            pages += 1
            yield resp
            advance = next_request(resp)
            if advance is None:
                break
            next_path, next_params = advance

    def _get_absolute(
        self,
        url: str,
        params: dict | None = None,
        extra_headers: dict | None = None,
    ) -> httpx.Response:
        """Like :meth:`_get` but ``url`` is already absolute.

        GitHub and Bitbucket return fully-qualified ``next`` URLs in their
        pagination metadata; we issue those verbatim rather than re-deriving a
        path against ``base_url``.
        """
        headers = {**self._headers(), **(extra_headers or {})}
        try:
            resp = httpx.get(
                url,
                params=params,
                headers=headers,
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:  # network-level failure
            raise SCMError(f"request to {url} failed: {exc}") from exc
        if resp.status_code == 401:
            raise SCMError("authentication failed (401) — check the token")
        if resp.status_code >= 400:
            raise SCMError(f"{url} returned HTTP {resp.status_code}")
        return resp

    # ------------------------------------------------------------------
    # recon_code_with_fragments — override in subclasses that support it
    # ------------------------------------------------------------------

    def recon_code_with_fragments(
        self, query: str, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """Like :meth:`recon_code` but each result also carries a
        ``"fragments"`` key (list of text snippets) that the caller can feed
        to :func:`covenant.secrets.scan_fragments`.

        Default implementation: call :meth:`recon_code` and attach an empty
        ``"fragments"`` list.  Subclasses that can cheaply retrieve snippet
        text from the same API response override this.
        """
        results = self.recon_code(query, max_pages=max_pages)
        for r in results:
            r.setdefault("fragments", [])
        return results
