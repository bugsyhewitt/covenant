"""Bitbucket Cloud SCM client (Bitbucket Server is EOL'd, out of scope)."""

from __future__ import annotations

import httpx

from ..tokens import classify_token
from .base import DEFAULT_MAX_PAGES, BaseSCMClient, SCMError


def _bitbucket_next(resp: httpx.Response) -> tuple[str, None] | None:
    """Follow the ``next`` URL key in Bitbucket's paged response envelope.

    Bitbucket Cloud paginates with ``{"values": [...], "next": "<url>"}``; the
    ``next`` key holds a fully-qualified URL (with the page cursor baked in)
    and is absent on the final page. We return ``(url, None)`` to continue or
    ``None`` to stop.
    """
    try:
        body = resp.json()
    except ValueError:
        return None
    next_url = body.get("next")
    if not next_url:
        return None
    return (next_url, None)


class BitbucketClient(BaseSCMClient):
    default_base_url = "https://api.bitbucket.org"

    def _headers(self) -> dict[str, str]:
        # Bitbucket Cloud accepts an app-password / token as a Bearer token.
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            "User-Agent": "covenant",
        }

    def recon_repo(self, query: str, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        results = []
        for resp in self._get_paginated(
            "/2.0/repositories",
            params={"q": f'name~"{query}"', "role": "member", "pagelen": 100},
            max_pages=max_pages,
            next_request=_bitbucket_next,
        ):
            for item in resp.json().get("values", []):
                links = item.get("links", {}).get("html", {})
                results.append(
                    {
                        "name": item.get("full_name") or item.get("name"),
                        "visibility": "private"
                        if item.get("is_private")
                        else "public",
                        "url": links.get("href"),
                        "description": item.get("description"),
                    }
                )
        return results

    def recon_code(
        self,
        query: str,
        max_pages: int = DEFAULT_MAX_PAGES,
        workspace: str | None = None,
    ) -> list[dict]:
        """Search code within a Bitbucket Cloud workspace.

        Uses the workspace-scoped code search endpoint::

            GET /2.0/workspaces/{workspace}/search/code?search_query=...

        ``workspace`` is required — Bitbucket's code search API has no
        cross-workspace equivalent.  If it is not supplied an :class:`SCMError`
        is raised rather than silently falling back to repo search.
        """
        if not workspace:
            raise SCMError(
                "Bitbucket code search requires a workspace; "
                "pass --workspace <slug> (e.g. the slug from "
                "bitbucket.org/<workspace>/...)"
            )
        results = []
        for resp in self._get_paginated(
            f"/2.0/workspaces/{workspace}/search/code",
            params={"search_query": query, "pagelen": 100},
            max_pages=max_pages,
            next_request=_bitbucket_next,
        ):
            for item in resp.json().get("values", []):
                file_info = item.get("file", {})
                path = file_info.get("path", "")
                name = path.rsplit("/", 1)[-1] if path else ""
                # path_matches gives character-level hit positions in the path;
                # content_matches gives the actual matching line text.
                content_matches = item.get("content_matches", [])
                results.append(
                    {
                        "name": name,
                        "path": path,
                        "url": None,  # Bitbucket code search doesn't return a direct URL
                        "repository": item.get("file", {}).get("commit", {}).get(
                            "repository", {}).get("full_name"),
                        "content_matches": content_matches,
                    }
                )
        return results

    def recon_code_with_fragments(
        self,
        query: str,
        max_pages: int = DEFAULT_MAX_PAGES,
        workspace: str | None = None,
    ) -> list[dict]:
        """Code search with inline text fragments for client-side secret scanning.

        Each result carries a ``"fragments"`` key (list of strings) built from
        ``content_matches[].lines[].segments[].text`` so that
        :func:`covenant.secrets.scan_fragments` has real code text to scan —
        unlike the stub that returned empty fragments.
        """
        if not workspace:
            raise SCMError(
                "Bitbucket code search requires a workspace; "
                "pass --workspace <slug>"
            )
        results = []
        for resp in self._get_paginated(
            f"/2.0/workspaces/{workspace}/search/code",
            params={"search_query": query, "pagelen": 100},
            max_pages=max_pages,
            next_request=_bitbucket_next,
        ):
            for item in resp.json().get("values", []):
                file_info = item.get("file", {})
                path = file_info.get("path", "")
                name = path.rsplit("/", 1)[-1] if path else ""
                content_matches = item.get("content_matches", [])
                # Collect text from all matching line segments as fragments.
                fragments: list[str] = []
                for cm in content_matches:
                    for line in cm.get("lines", []):
                        text = "".join(
                            seg.get("text", "")
                            for seg in line.get("segments", [])
                        )
                        if text:
                            fragments.append(text)
                results.append(
                    {
                        "name": name,
                        "path": path,
                        "url": None,
                        "repository": file_info.get("commit", {}).get(
                            "repository", {}).get("full_name"),
                        "content_matches": content_matches,
                        "fragments": fragments,
                    }
                )
        return results

    def enumerate_orgs(self, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        """List the Bitbucket workspaces this token can reach (blast radius).

        Bitbucket's organizational unit is the *workspace*; ``GET
        /2.0/workspaces`` returns the workspaces the authenticated token has
        access to. We walk it with the shared ``next``-envelope paginator and
        return a normalized list of ``{"name", "url"}`` dicts so the output
        shape matches the other SCMs' ``enumerate_orgs``. The workspace ``slug``
        is what feeds the ``--workspace`` flag of ``recon-code``, so this
        directly tells the operator which workspaces are searchable.
        """
        results = []
        for resp in self._get_paginated(
            "/2.0/workspaces",
            params={"pagelen": 100},
            max_pages=max_pages,
            next_request=_bitbucket_next,
        ):
            for item in resp.json().get("values", []):
                slug = item.get("slug") or item.get("name")
                if not slug:
                    continue
                links = item.get("links", {}).get("html", {})
                results.append(
                    {
                        "name": slug,
                        "url": links.get("href")
                        or f"https://bitbucket.org/{slug}",
                    }
                )
        return results

    def validate_token(self) -> dict:
        user = self._get("/2.0/user").json()
        username = user.get("username") or user.get("nickname")
        if not username:
            raise SCMError("token validation returned no user identity")
        admin = False
        scopes: list[str] = []
        try:
            perms = self._get("/2.0/user/permissions/repositories").json()
            for entry in perms.get("values", []):
                perm = entry.get("permission")
                if perm:
                    scopes.append(perm)
                if perm == "admin":
                    admin = True
        except SCMError:
            scopes = []
        fingerprint = classify_token(self.token, "bitbucket")
        return {
            "scopes": scopes,
            "user": username,
            "admin": admin,
            "token_type": fingerprint["token_type"],
            "token_note": fingerprint["note"],
            "token_type_confidence": fingerprint["confidence"],
        }
