"""GitLab SCM client (cloud + self-hosted via --target-url)."""

from __future__ import annotations

from urllib.parse import quote

import httpx

from ..tokens import classify_token
from .base import DEFAULT_MAX_PAGES, BaseSCMClient, SCMError

#: GitLab offset pagination page size — the API cap is 100 per page.
_PER_PAGE = 100


def _gpg_fingerprint(armor: str | None) -> str | None:
    """Reduce a GitLab armored GPG public key to a single-line, share-safe
    prefix. GitLab's GPG-key API returns only the multi-line PGP armor (no
    explicit fingerprint field), so we collapse all whitespace to single
    spaces and take a bounded prefix rather than dumping the whole block into
    the output."""
    if not armor:
        return None
    collapsed = " ".join(armor.split())
    return collapsed[:64] or None


def _group_id(group: str) -> str:
    """URL-encode a GitLab group path for use as a path-id segment.

    GitLab accepts a group's full path (``acme/platform``) as the ``:id``
    segment of group-scoped endpoints provided it is URL-encoded (the ``/``
    becomes ``%2F``). A numeric id is left unchanged by encoding.
    """
    return quote(group.strip(), safe="")


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

    def recon_repo(
        self,
        query: str,
        max_pages: int = DEFAULT_MAX_PAGES,
        group: str | None = None,
    ) -> list[dict]:
        if group:
            # Group-scoped project listing: GET /groups/:id/projects narrows the
            # search to a single group (and its subgroups), the GitLab analogue
            # of GitHub's ``org:`` qualifier.
            path = f"/api/v4/groups/{_group_id(group)}/projects"
            params = {
                "search": query,
                "include_subgroups": "true",
                "per_page": _PER_PAGE,
                "page": 1,
            }
        else:
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

    def recon_code(
        self,
        query: str,
        max_pages: int = DEFAULT_MAX_PAGES,
        group: str | None = None,
    ) -> list[dict]:
        # Group-scoped blob search (GET /groups/:id/search) narrows code recon
        # to one group; the global /search endpoint is used otherwise.
        path = (
            f"/api/v4/groups/{_group_id(group)}/search"
            if group
            else "/api/v4/search"
        )
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
        self,
        query: str,
        max_pages: int = DEFAULT_MAX_PAGES,
        group: str | None = None,
    ) -> list[dict]:
        """Code search carrying matched-content fragments for secret scanning.

        GitLab's blob search response includes a ``data`` field containing the
        file content excerpt that matched the query.  We expose it as
        ``result["fragments"]`` for the caller to feed to
        :func:`covenant.secrets.scan_fragments`. When ``group`` is supplied the
        group-scoped search endpoint is used (matching :meth:`recon_code`).
        """
        path = (
            f"/api/v4/groups/{_group_id(group)}/search"
            if group
            else "/api/v4/search"
        )
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

    def enumerate_keys(self, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        """List the SSH and GPG public keys attached to this token's account.

        Walks ``GET /api/v4/user/keys`` (SSH keys) and
        ``GET /api/v4/user/gpg_keys`` (commit-signing keys) with the shared
        offset paginator, returning a normalized list of
        ``{"type", "id", "title", "fingerprint"}`` dicts so the output shape
        matches the other SCMs' :meth:`enumerate_keys`. Only PUBLIC key metadata
        is returned — covenant never reads or echoes private key material.
        """
        results: list[dict] = []

        ssh_path = "/api/v4/user/keys"
        ssh_params = {"per_page": _PER_PAGE, "page": 1}
        for resp in self._get_paginated(
            ssh_path,
            params=ssh_params,
            max_pages=max_pages,
            next_request=_gitlab_next(ssh_path, ssh_params),
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
                        "fingerprint": item.get("fingerprint") or item.get("key"),
                    }
                )

        gpg_path = "/api/v4/user/gpg_keys"
        gpg_params = {"per_page": _PER_PAGE, "page": 1}
        for resp in self._get_paginated(
            gpg_path,
            params=gpg_params,
            max_pages=max_pages,
            next_request=_gitlab_next(gpg_path, gpg_params),
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
                        "type": "gpg",
                        "id": key_id,
                        "title": str(key_id),
                        # GitLab returns only the armored public key; expose a
                        # short, single-line, share-safe prefix rather than the
                        # full multi-line PGP block. Collapse all whitespace
                        # (newlines included) so the fingerprint is one line.
                        "fingerprint": _gpg_fingerprint(item.get("key")),
                    }
                )
        return results

    def enumerate_gists(self, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        """List the snippets owned by this token's account (leak surface).

        GitLab's analogue of a GitHub gist is the *snippet*; ``GET
        /api/v4/snippets`` returns the snippets owned by the authenticated user.
        We walk it with the shared offset paginator and return the same
        normalized ``{"id", "description", "visibility", "url", "files"}`` shape
        as the other SCMs' :meth:`enumerate_gists`, so the output is uniform
        across providers. Snippets, like gists, routinely carry pasted config
        and ``.env`` excerpts; we surface FILENAMES (the leak signal) but never
        the snippet CONTENT — covenant maps the attack surface, it does not
        exfiltrate it. ``title`` is used as the description when no explicit
        description is present (GitLab snippets always have a title).
        """
        path = "/api/v4/snippets"
        params = {"per_page": _PER_PAGE, "page": 1}
        results: list[dict] = []
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
                snippet_id = item.get("id")
                if snippet_id is None:
                    continue
                # Newer GitLab returns a `files` array of {path, raw_url};
                # older single-file snippets carry only `file_name`. Collect
                # the filenames from whichever is present (content is omitted).
                files = [
                    f.get("path")
                    for f in item.get("files", [])
                    if isinstance(f, dict) and f.get("path")
                ]
                if not files and item.get("file_name"):
                    files = [item["file_name"]]
                results.append(
                    {
                        "id": snippet_id,
                        "description": item.get("description")
                        or item.get("title"),
                        "visibility": item.get("visibility", "private"),
                        "url": item.get("web_url"),
                        "files": sorted(files),
                    }
                )
        return results

    def enumerate_deploy_keys(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """List the deploy keys on the projects this token can reach (persistence).

        GitLab's deploy key is a project-scoped SSH key (optionally with
        push/write access via ``can_push``) — the repo-scoped complement to the
        account keys surfaced by :meth:`enumerate_keys`. A writable deploy key is
        a persistence and supply-chain foothold: it grants Git access to one
        project independent of any human credential. We walk the projects the
        token is a member of (``GET /api/v4/projects?membership=true``) and, for
        each, list ``GET /api/v4/projects/{id}/deploy_keys``, returning the same
        normalized ``{"repo", "id", "title", "read_only", "fingerprint"}`` shape
        as the other SCMs. ``read_only`` is the inverse of GitLab's ``can_push``
        (``read_only == not can_push``) — ``False`` means the key can push. Only
        PUBLIC key metadata is returned; private key material is never read.
        """
        results: list[dict] = []
        for project in self._reachable_projects(max_pages=max_pages):
            project_id = project["id"]
            repo = project["repo"]
            keys_path = f"/api/v4/projects/{project_id}/deploy_keys"
            keys_params = {"per_page": _PER_PAGE, "page": 1}
            for resp in self._get_paginated(
                keys_path,
                params=keys_params,
                max_pages=max_pages,
                next_request=_gitlab_next(keys_path, keys_params),
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
                            "repo": repo,
                            "id": key_id,
                            "title": item.get("title"),
                            "read_only": not bool(item.get("can_push", False)),
                            "fingerprint": item.get("fingerprint")
                            or item.get("key"),
                        }
                    )
        return results

    def _reachable_projects(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """Return ``{"id", "repo"}`` for projects this token is a member of.

        Walks ``GET /api/v4/projects?membership=true`` with the shared offset
        paginator. Used by :meth:`enumerate_deploy_keys` to know which projects'
        deploy keys to inspect (the numeric id feeds the per-project endpoint and
        the path-with-namespace is the human-readable ``repo`` label).
        """
        path = "/api/v4/projects"
        params = {"membership": "true", "per_page": _PER_PAGE, "page": 1}
        out: list[dict] = []
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
                project_id = item.get("id")
                if project_id is None:
                    continue
                out.append(
                    {
                        "id": project_id,
                        "repo": item.get("path_with_namespace")
                        or item.get("name")
                        or str(project_id),
                    }
                )
        return out

    def enumerate_webhooks(self, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        """List the group-level webhooks this token can reach (exfil/SSRF surface).

        GitLab's analogue of a GitHub org webhook is the *group hook*; ``GET
        /api/v4/groups/{id}/hooks`` lists the webhooks configured on a group. We
        discover the groups the token belongs to (via :meth:`enumerate_orgs`)
        and walk each group's hooks with the shared offset paginator, returning
        the same normalized ``{"scope", "owner", "id", "url", "events",
        "active"}`` shape as the other SCMs' :meth:`enumerate_webhooks`.
        ``scope`` is ``"group"`` and ``owner`` is the group full path.

        GitLab encodes each subscribed event as a separate boolean flag
        (``push_events``, ``merge_requests_events``, ...) rather than an event
        array; we normalize the *enabled* flags into an ``events`` list (the
        flag names with the ``_events`` suffix stripped) so the output matches
        the other providers. The destination ``url`` is surfaced verbatim (it is
        the recon signal); the hook *token* is never requested or echoed.
        """
        results: list[dict] = []
        for group in self.enumerate_orgs(max_pages=max_pages):
            owner = group.get("name")
            if not owner:
                continue
            path = f"/api/v4/groups/{_group_id(owner)}/hooks"
            params = {"per_page": _PER_PAGE, "page": 1}
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
                    hook_id = item.get("id")
                    if hook_id is None:
                        continue
                    events = [
                        key[: -len("_events")]
                        for key, value in item.items()
                        if key.endswith("_events") and value is True
                    ]
                    results.append(
                        {
                            "scope": "group",
                            "owner": owner,
                            "id": hook_id,
                            "url": item.get("url"),
                            "events": sorted(events),
                            "active": True,
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
