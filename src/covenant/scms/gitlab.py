"""GitLab SCM client (cloud + self-hosted via --target-url)."""

from __future__ import annotations

import httpx

from ..tokens import classify_token
from .base import DEFAULT_MAX_PAGES, BaseSCMClient, SCMError

#: GitLab offset pagination page size — the API cap is 100 per page.
_PER_PAGE = 100


def _gitlab_next(path: str, base_params: dict):
    """Build a ``next_request`` callback that walks GitLab offset pages.

    GitLab returns the next page number in the ``X-Next-Page`` response header
    (empty string when the current page is the last). We re-issue the same
    ``path`` with the same query params plus an updated ``page``.
    """

    def _next(resp: httpx.Response) -> tuple[str, dict] | None:
        next_page = (resp.headers.get("X-Next-Page") or "").strip()
        if not next_page:
            return None
        try:
            page_num = int(next_page)
        except ValueError:
            return None
        if page_num <= 0:
            return None
        return (path, {**base_params, "page": page_num})

    return _next


class GitLabClient(BaseSCMClient):
    default_base_url = "https://gitlab.com"

    def _headers(self) -> dict[str, str]:
        return {"PRIVATE-TOKEN": self.token, "User-Agent": "covenant"}

    def recon_repo(self, query: str, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        path = "/api/v4/projects"
        params = {
            "search": query,
            "membership": "true",
            "per_page": _PER_PAGE,
            "page": 1,
        }
        results = []
        for resp in self._get_paginated(
            path,
            params=params,
            max_pages=max_pages,
            next_request=_gitlab_next(path, params),
        ):
            for item in resp.json():
                results.append(
                    {
                        "name": item.get("path_with_namespace") or item.get("name"),
                        "visibility": item.get("visibility", "private"),
                        "url": item.get("web_url"),
                        "description": item.get("description"),
                    }
                )
        return results

    def recon_code(self, query: str, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        path = "/api/v4/search"
        params = {
            "scope": "blobs",
            "search": query,
            "per_page": _PER_PAGE,
            "page": 1,
        }
        results = []
        for resp in self._get_paginated(
            path,
            params=params,
            max_pages=max_pages,
            next_request=_gitlab_next(path, params),
        ):
            for item in resp.json():
                results.append(
                    {
                        "name": item.get("filename") or item.get("path"),
                        "path": item.get("path"),
                        "visibility": "unknown",
                        "url": item.get("web_url") or item.get("ref"),
                        "repository": item.get("project_id"),
                    }
                )
        return results

    def recon_code_with_fragments(
        self, query: str, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """Code search carrying matched-content fragments for secret scanning.

        GitLab's blob search response includes a ``data`` field containing the
        file content excerpt that matched the query.  We expose it as
        ``result["fragments"]`` for the caller to feed to
        :func:`covenant.secrets.scan_fragments`.
        """
        path = "/api/v4/search"
        params = {
            "scope": "blobs",
            "search": query,
            "per_page": _PER_PAGE,
            "page": 1,
        }
        results = []
        for resp in self._get_paginated(
            path,
            params=params,
            max_pages=max_pages,
            next_request=_gitlab_next(path, params),
        ):
            for item in resp.json():
                # GitLab returns `data` as a string (the matched blob excerpt).
                fragment = item.get("data", "")
                fragments = [fragment] if fragment else []
                results.append(
                    {
                        "name": item.get("filename") or item.get("path"),
                        "path": item.get("path"),
                        "visibility": "unknown",
                        "url": item.get("web_url") or item.get("ref"),
                        "repository": item.get("project_id"),
                        "fragments": fragments,
                    }
                )
        return results

    def enumerate_orgs(self, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        """List the GitLab groups this token can reach (read-only blast radius).

        GitLab's organizational unit is the *group*; ``GET /api/v4/groups`` with
        a membership filter returns the groups the authenticated user belongs
        to. We walk it with the shared offset paginator and return a normalized
        list of ``{"name", "url"}`` dicts so the output shape matches the other
        SCMs' ``enumerate_orgs``.
        """
        path = "/api/v4/groups"
        params = {
            "min_access_level": 10,  # 10 = Guest; "any group I'm a member of"
            "per_page": _PER_PAGE,
            "page": 1,
        }
        results = []
        for resp in self._get_paginated(
            path,
            params=params,
            max_pages=max_pages,
            next_request=_gitlab_next(path, params),
        ):
            body = resp.json()
            if not isinstance(body, list):
                continue
            for item in body:
                name = item.get("full_path") or item.get("path") or item.get("name")
                if not name:
                    continue
                results.append(
                    {
                        "name": name,
                        "url": item.get("web_url")
                        or f"https://gitlab.com/{name}",
                    }
                )
        return results

    def validate_token(self) -> dict:
        user = self._get("/api/v4/user").json()
        username = user.get("username")
        if not username:
            raise SCMError("token validation returned no user identity")
        scopes: list[str] = []
        try:
            pat = self._get("/api/v4/personal_access_tokens/self").json()
            scopes = list(pat.get("scopes", []))
        except SCMError:
            # Older GitLab / token types may not expose this endpoint.
            scopes = []
        fingerprint = classify_token(self.token, "gitlab")
        return {
            "scopes": scopes,
            "user": username,
            "admin": bool(user.get("is_admin", False)),
            "token_type": fingerprint["token_type"],
            "token_note": fingerprint["note"],
            "token_type_confidence": fingerprint["confidence"],
        }
