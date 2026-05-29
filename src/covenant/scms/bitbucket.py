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

    def enumerate_keys(self, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        """List the SSH public keys attached to this token's account.

        Bitbucket Cloud's SSH-key endpoint is user-scoped:
        ``GET /2.0/users/{uuid}/ssh-keys``. We first resolve the authenticated
        user's UUID via ``GET /2.0/user`` (the same call :meth:`validate_token`
        uses), then walk the keys with the shared ``next``-envelope paginator,
        returning a normalized list of ``{"type", "id", "title", "fingerprint"}``
        dicts so the output shape matches the other SCMs' :meth:`enumerate_keys`.

        Bitbucket Cloud has no public GPG-key API, so only ``ssh`` entries are
        returned. Only PUBLIC key metadata is exposed — covenant never reads or
        echoes private key material.
        """
        user = self._get("/2.0/user").json()
        uuid = user.get("uuid")
        if not uuid:
            raise SCMError(
                "cannot enumerate SSH keys: token's user has no UUID"
            )
        results: list[dict] = []
        for resp in self._get_paginated(
            f"/2.0/users/{uuid}/ssh-keys",
            params={"pagelen": 100},
            max_pages=max_pages,
            next_request=_bitbucket_next,
        ):
            for item in resp.json().get("values", []):
                key_uuid = item.get("uuid")
                if not key_uuid:
                    continue
                results.append(
                    {
                        "type": "ssh",
                        "id": key_uuid,
                        "title": item.get("label") or item.get("comment"),
                        "fingerprint": item.get("key"),
                    }
                )
        return results

    def enumerate_gists(self, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        """List the snippets owned by this token's account (leak surface).

        Bitbucket's analogue of a GitHub gist is the *snippet*; ``GET
        /2.0/snippets`` returns the snippets the authenticated token owns. We
        walk it with the shared ``next``-envelope paginator and return the same
        normalized ``{"id", "description", "visibility", "url", "files"}`` shape
        as the other SCMs' :meth:`enumerate_gists`, so the output is uniform
        across providers. Snippets often carry pasted config and ``.env``
        excerpts; we surface FILENAMES (the leak signal) but never the snippet
        CONTENT — covenant maps the attack surface, it does not exfiltrate it.
        """
        results: list[dict] = []
        for resp in self._get_paginated(
            "/2.0/snippets",
            params={"pagelen": 100, "role": "owner"},
            max_pages=max_pages,
            next_request=_bitbucket_next,
        ):
            for item in resp.json().get("values", []):
                snippet_id = item.get("id")
                if not snippet_id:
                    continue
                links = item.get("links", {}).get("html", {})
                # `files` is an object keyed by filename; expose only the
                # filenames (the leak signal), never the file links/content.
                files = sorted((item.get("files") or {}).keys())
                results.append(
                    {
                        "id": snippet_id,
                        "description": item.get("title"),
                        "visibility": "private"
                        if item.get("is_private")
                        else "public",
                        "url": links.get("href"),
                        "files": files,
                    }
                )
        return results

    def enumerate_deploy_keys(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """List the deploy keys on the repos this token can reach (persistence).

        Bitbucket Cloud's *access key* is the repo-scoped SSH key analogue of a
        deploy key — the repo-scoped complement to the account keys surfaced by
        :meth:`enumerate_keys`. We walk the repositories the token is a member of
        (``GET /2.0/repositories?role=member``) and, for each, list
        ``GET /2.0/repositories/{full_name}/deploy-keys``, returning the same
        normalized ``{"repo", "id", "title", "read_only", "fingerprint"}`` shape
        as the other SCMs. Bitbucket Cloud access keys are **read-only** by
        design (there is no per-key push toggle), so ``read_only`` is always
        ``True`` here — the signal is the existence and reach of the key, not a
        push flag. Only PUBLIC key metadata is returned; private key material is
        never read.
        """
        results: list[dict] = []
        for full_name in self._reachable_repos(max_pages=max_pages):
            for resp in self._get_paginated(
                f"/2.0/repositories/{full_name}/deploy-keys",
                params={"pagelen": 100},
                max_pages=max_pages,
                next_request=_bitbucket_next,
            ):
                for item in resp.json().get("values", []):
                    key_id = item.get("id") or item.get("uuid")
                    if key_id is None:
                        continue
                    results.append(
                        {
                            "repo": full_name,
                            "id": key_id,
                            "title": item.get("label") or item.get("comment"),
                            "read_only": True,
                            "fingerprint": item.get("key"),
                        }
                    )
        return results

    def audit_branch_protection(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """Audit the branch-protection posture of the repos this token reaches.

        Branch protection is the defensive counterpart to the offensive
        enumeration methods: it tells the operator whether a writable foothold
        would be stopped before code lands on a protected branch. We walk the
        repositories the token is a member of
        (``GET /2.0/repositories?role=member``) and, for each, list its branch
        restrictions (``GET /2.0/repositories/{full_name}/branch-restrictions``),
        returning the same normalized
        ``{"repo", "branch", "required_reviews", "required_review_count",
        "dismiss_stale_reviews", "require_signed_commits", "enforce_admins"}``
        shape as the other SCMs.

        Bitbucket Cloud models protection as a flat list of *restriction* objects,
        each with a ``kind`` (e.g. ``require_approvals_to_merge``,
        ``reset_pullrequest_approvals_on_change``, ``force``, ``push``) and a
        branch ``pattern`` (e.g. ``main``, ``release/*``). There is no single
        per-branch policy object, so we aggregate the restrictions by ``pattern``
        and map them to covenant's normalized fields:

        * ``required_reviews`` / ``required_review_count`` come from a
          ``require_approvals_to_merge`` restriction and its ``value``.
        * ``dismiss_stale_reviews`` maps to the
          ``reset_pullrequest_approvals_on_change`` restriction.
        * ``require_signed_commits`` is always ``False`` — Bitbucket Cloud has no
          signed-commit branch restriction.
        * ``enforce_admins`` maps to the presence of a ``force`` restriction
          (force-push is forbidden, i.e. the rules are harder to bypass).

        The ``branch`` field carries the restriction *pattern*, which may be a
        glob. This is read-only — it only GETs policy metadata.
        """
        results: list[dict] = []
        for full_name in self._reachable_repos(max_pages=max_pages):
            # pattern -> aggregated restriction kinds/values
            by_pattern: dict[str, dict] = {}
            for resp in self._get_paginated(
                f"/2.0/repositories/{full_name}/branch-restrictions",
                params={"pagelen": 100},
                max_pages=max_pages,
                next_request=_bitbucket_next,
            ):
                for item in resp.json().get("values", []):
                    pattern = item.get("pattern")
                    if not pattern:
                        continue
                    agg = by_pattern.setdefault(
                        pattern,
                        {
                            "required_reviews": False,
                            "required_review_count": 0,
                            "dismiss_stale_reviews": False,
                            "enforce_admins": False,
                        },
                    )
                    kind = item.get("kind")
                    if kind == "require_approvals_to_merge":
                        agg["required_reviews"] = True
                        agg["required_review_count"] = int(item.get("value") or 0)
                    elif kind == "reset_pullrequest_approvals_on_change":
                        agg["dismiss_stale_reviews"] = True
                    elif kind == "force":
                        agg["enforce_admins"] = True
            for pattern, agg in by_pattern.items():
                results.append(
                    {
                        "repo": full_name,
                        "branch": pattern,
                        "required_reviews": agg["required_reviews"],
                        "required_review_count": agg["required_review_count"],
                        "dismiss_stale_reviews": agg["dismiss_stale_reviews"],
                        # Bitbucket Cloud has no signed-commit restriction kind.
                        "require_signed_commits": False,
                        "enforce_admins": agg["enforce_admins"],
                    }
                )
        return results

    def _reachable_repos(self, max_pages: int = DEFAULT_MAX_PAGES) -> list[str]:
        """Return the ``workspace/repo`` full names this token is a member of.

        Walks ``GET /2.0/repositories?role=member`` with the shared
        ``next``-envelope paginator. Used by :meth:`enumerate_deploy_keys` to
        know which repos' deploy keys to inspect.
        """
        names: list[str] = []
        for resp in self._get_paginated(
            "/2.0/repositories",
            params={"role": "member", "pagelen": 100},
            max_pages=max_pages,
            next_request=_bitbucket_next,
        ):
            for item in resp.json().get("values", []):
                full_name = item.get("full_name")
                if full_name:
                    names.append(full_name)
        return names

    def enumerate_webhooks(self, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        """List the workspace-level webhooks this token can reach (exfil/SSRF).

        Bitbucket's analogue of a GitHub org webhook is the *workspace hook*;
        ``GET /2.0/workspaces/{slug}/hooks`` lists the webhooks configured on a
        workspace. We discover the workspaces the token can reach (via
        :meth:`enumerate_orgs`) and walk each one's hooks with the shared
        ``next``-envelope paginator, returning the same normalized
        ``{"scope", "owner", "id", "url", "events", "active"}`` shape as the
        other SCMs' :meth:`enumerate_webhooks`. ``scope`` is ``"workspace"`` and
        ``owner`` is the workspace slug. Bitbucket returns the subscribed event
        keys as an ``events`` array directly. The destination ``url`` is the
        recon signal and is surfaced verbatim; the hook *secret* is never
        requested or echoed.
        """
        results: list[dict] = []
        for workspace in self.enumerate_orgs(max_pages=max_pages):
            owner = workspace.get("name")
            if not owner:
                continue
            for resp in self._get_paginated(
                f"/2.0/workspaces/{owner}/hooks",
                params={"pagelen": 100},
                max_pages=max_pages,
                next_request=_bitbucket_next,
            ):
                for item in resp.json().get("values", []):
                    hook_uuid = item.get("uuid")
                    if not hook_uuid:
                        continue
                    results.append(
                        {
                            "scope": "workspace",
                            "owner": owner,
                            "id": hook_uuid,
                            "url": item.get("url"),
                            "events": item.get("events") or [],
                            "active": bool(item.get("active", False)),
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
