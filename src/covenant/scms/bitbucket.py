"""Bitbucket Cloud SCM client (Bitbucket Server is EOL'd, out of scope)."""

from __future__ import annotations

import httpx

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

    def recon_code(self, query: str, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        # Bitbucket Cloud code search requires a workspace path; without one we
        # surface repos as the closest read-only equivalent for v0.1 parity.
        return self.recon_repo(query, max_pages=max_pages)

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
        return {"scopes": scopes, "user": username, "admin": admin}
