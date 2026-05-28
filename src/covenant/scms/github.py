"""GitHub SCM client (cloud GitHub for v0.1; GHE deferred to v0.2)."""

from __future__ import annotations

import httpx

from ..tokens import classify_token
from .base import DEFAULT_MAX_PAGES, BaseSCMClient, SCMError

# GitHub's text-match Accept header requests snippet fragments alongside code
# search results so we can scan them for secrets without a separate fetch.
_TEXT_MATCH_ACCEPT = "application/vnd.github.text-match+json"


def _next_link(resp: httpx.Response) -> tuple[str, None] | None:
    """Parse the RFC-5988 ``Link`` header and return the ``rel="next"`` target.

    GitHub paginates ``/search/*`` with a ``Link`` header such as::

        <https://api.github.com/search/code?q=foo&page=2>; rel="next",
        <https://api.github.com/search/code?q=foo&page=34>; rel="last"

    We return ``(url, None)`` for the next page (the URL already carries all
    query params) or ``None`` when there is no further page.
    """
    link = resp.headers.get("Link") or resp.headers.get("link")
    if not link:
        return None
    for part in link.split(","):
        segments = part.split(";")
        if len(segments) < 2:
            continue
        url = segments[0].strip().lstrip("<").rstrip(">").strip()
        for attr in segments[1:]:
            attr = attr.strip()
            if attr in ('rel="next"', "rel=next"):
                return (url, None)
    return None


class GitHubClient(BaseSCMClient):
    default_base_url = "https://api.github.com"

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "covenant",
        }

    def recon_repo(self, query: str, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        results = []
        for resp in self._get_paginated(
            "/search/repositories",
            params={"q": query, "per_page": 100},
            max_pages=max_pages,
            next_request=_next_link,
        ):
            for item in resp.json().get("items", []):
                results.append(
                    {
                        "name": item.get("full_name") or item.get("name"),
                        "visibility": item.get(
                            "visibility",
                            "private" if item.get("private") else "public",
                        ),
                        "url": item.get("html_url"),
                        "description": item.get("description"),
                    }
                )
        return results

    def recon_code(self, query: str, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        results = []
        for resp in self._get_paginated(
            "/search/code",
            params={"q": query, "per_page": 100},
            max_pages=max_pages,
            next_request=_next_link,
        ):
            for item in resp.json().get("items", []):
                repo = item.get("repository", {})
                results.append(
                    {
                        "name": item.get("name"),
                        "path": item.get("path"),
                        "visibility": "private" if repo.get("private") else "public",
                        "url": item.get("html_url"),
                        "repository": repo.get("name"),
                    }
                )
        return results

    def recon_code_with_fragments(
        self, query: str, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """Code search with text-match fragments for client-side secret scanning.

        Requests ``Accept: application/vnd.github.text-match+json`` so that
        GitHub returns inline snippet fragments alongside each result.  Those
        fragments are exposed as ``result["fragments"]`` for the caller to
        feed to :func:`covenant.secrets.scan_fragments`.
        """
        results = []
        for resp in self._get_paginated(
            "/search/code",
            params={"q": query, "per_page": 100},
            max_pages=max_pages,
            extra_headers={"Accept": _TEXT_MATCH_ACCEPT},
            next_request=_next_link,
        ):
            for item in resp.json().get("items", []):
                repo = item.get("repository", {})
                # text_matches is a list of {object_type, object_url, matches,
                # property, fragment} dicts.  We collect the fragment strings.
                fragments = [
                    tm.get("fragment", "")
                    for tm in item.get("text_matches", [])
                    if tm.get("fragment")
                ]
                results.append(
                    {
                        "name": item.get("name"),
                        "path": item.get("path"),
                        "visibility": "private" if repo.get("private") else "public",
                        "url": item.get("html_url"),
                        "repository": repo.get("name"),
                        "fragments": fragments,
                    }
                )
        return results

    def enumerate_orgs(self, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        """List the organizations this token can reach (read-only blast radius).

        Walks ``GET /user/orgs`` (the orgs the authenticated user is a member
        of) with the shared paginator, returning a normalized list of
        ``{"name", "url"}`` dicts. This is the actionable "what can this
        credential touch?" signal that complements the identity/scopes already
        reported by :meth:`validate_token`: a permissive scope list on a token
        that belongs to no interesting org has a very different blast radius
        from the same scopes on a token inside the target's org.
        """
        results = []
        for resp in self._get_paginated(
            "/user/orgs",
            params={"per_page": 100},
            max_pages=max_pages,
            next_request=_next_link,
        ):
            body = resp.json()
            if not isinstance(body, list):
                continue
            for item in body:
                login = item.get("login")
                if not login:
                    continue
                results.append(
                    {
                        "name": login,
                        "url": item.get("url")
                        or f"https://github.com/{login}",
                    }
                )
        return results

    def enumerate_keys(self, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        """List the SSH and GPG public keys attached to this token's account.

        Walks ``GET /user/keys`` (SSH authentication keys) and
        ``GET /user/gpg_keys`` (commit-signing keys) with the shared paginator,
        returning a normalized list of
        ``{"type", "id", "title", "fingerprint"}`` dicts. This is a persistence
        and trust blast-radius signal that complements
        :meth:`enumerate_orgs`: an account's registered SSH keys reveal which
        machines can push as this identity, and its GPG keys reveal which keys
        can produce "Verified" commits in its name. Only PUBLIC key metadata is
        returned — covenant never reads or echoes private key material (the API
        does not expose it, and the public-key/armor body is deliberately
        omitted from the output to keep findings compact and share-safe).
        """
        results: list[dict] = []
        for resp in self._get_paginated(
            "/user/keys",
            params={"per_page": 100},
            max_pages=max_pages,
            next_request=_next_link,
        ):
            body = resp.json()
            if not isinstance(body, list):
                continue
            for item in body:
                key_id = item.get("id")
                if key_id is None:
                    continue
                results.append(
                    {
                        "type": "ssh",
                        "id": key_id,
                        "title": item.get("title"),
                        "fingerprint": item.get("key"),
                    }
                )
        for resp in self._get_paginated(
            "/user/gpg_keys",
            params={"per_page": 100},
            max_pages=max_pages,
            next_request=_next_link,
        ):
            body = resp.json()
            if not isinstance(body, list):
                continue
            for item in body:
                key_id = item.get("key_id")
                if not key_id:
                    continue
                results.append(
                    {
                        "type": "gpg",
                        "id": key_id,
                        "title": item.get("name") or item.get("key_id"),
                        "fingerprint": item.get("key_id"),
                    }
                )
        return results

    def validate_token(self) -> dict:
        resp = self._get("/user")
        user = resp.json()
        scope_header = resp.headers.get("X-OAuth-Scopes", "")
        scopes = [s.strip() for s in scope_header.split(",") if s.strip()]
        login = user.get("login")
        if not login:
            raise SCMError("token validation returned no user identity")
        fingerprint = classify_token(self.token, "github")
        return {
            "scopes": scopes,
            "user": login,
            "admin": bool(user.get("site_admin", False)),
            "token_type": fingerprint["token_type"],
            "token_note": fingerprint["note"],
            "token_type_confidence": fingerprint["confidence"],
        }
