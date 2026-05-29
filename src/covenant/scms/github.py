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

    def enumerate_gists(self, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        """List the gists owned by this token's account (leaked-credential surface).

        Walks ``GET /gists`` (the authenticated user's own gists — both public
        and secret) with the shared paginator, returning a normalized list of
        ``{"id", "description", "visibility", "url", "files"}`` dicts. Gists are
        a notorious credential-leak vector: developers paste config snippets,
        ``.env`` excerpts and ad-hoc scripts into "secret" gists that are in fact
        readable by anyone with the URL. This enumeration is the recon analogue
        of :meth:`enumerate_keys`: it maps the blast radius of a captured token
        by surfacing every gist the identity owns, including the FILENAMES (a
        ``credentials.json`` or ``.env`` filename is itself a strong signal)
        WITHOUT dumping file CONTENT — covenant reports the attack surface, it
        does not exfiltrate the contents.
        """
        results: list[dict] = []
        for resp in self._get_paginated(
            "/gists",
            params={"per_page": 100},
            max_pages=max_pages,
            next_request=_next_link,
        ):
            body = resp.json()
            if not isinstance(body, list):
                continue
            for item in body:
                gist_id = item.get("id")
                if not gist_id:
                    continue
                # files is an object keyed by filename; we expose only the
                # filenames (the leak signal), never the raw_url/content.
                files = sorted((item.get("files") or {}).keys())
                results.append(
                    {
                        "id": gist_id,
                        "description": item.get("description"),
                        "visibility": "public"
                        if item.get("public")
                        else "secret",
                        "url": item.get("html_url"),
                        "files": files,
                    }
                )
        return results

    def enumerate_deploy_keys(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """List the deploy keys on the repos this token can reach (persistence).

        A *deploy key* is an SSH key bolted onto a single repository rather than
        a user account: it grants Git access (often **write** access) to that one
        repo, independent of any human's credentials, and survives a user's
        password reset or off-boarding. That makes it a prime persistence and
        supply-chain foothold — a writable deploy key lets an attacker push to
        the repo as the repo itself. This enumeration is the repo-scoped
        complement to :meth:`enumerate_keys` (which covers the *account's* SSH/GPG
        keys): it walks the repositories the token can reach (``GET /user/repos``)
        and, for each, lists ``GET /repos/{owner}/{repo}/keys``, returning a
        normalized list of ``{"repo", "id", "title", "read_only", "fingerprint"}``
        dicts. ``read_only`` is the decisive signal — ``False`` means the key can
        push. Only PUBLIC key metadata is returned; covenant never reads private
        key material (the API does not expose it).
        """
        results: list[dict] = []
        for repo in self._reachable_repos(max_pages=max_pages):
            full_name = repo
            for resp in self._get_paginated(
                f"/repos/{full_name}/keys",
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
                            "repo": full_name,
                            "id": key_id,
                            "title": item.get("title"),
                            "read_only": bool(item.get("read_only", True)),
                            "fingerprint": item.get("key"),
                        }
                    )
        return results

    def audit_branch_protection(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """Audit the branch-protection posture of the repos this token can reach.

        Where the enumeration methods map a captured token's *offensive* reach
        (keys it owns, repos it can push to), branch protection is the *defensive*
        counterpart: it tells the operator whether a writable foothold — a
        compromised deploy key, a permissive PAT, a malicious PR — would actually
        be stopped before landing on an important branch. A protected branch that
        does NOT require pull-request review, does NOT require signed commits,
        and/or does NOT enforce its rules on admins is a supply-chain weak point:
        code can reach the branch with little or no scrutiny.

        This walks the repositories the token can reach (``GET /user/repos``) and,
        for each, lists its *protected* branches
        (``GET /repos/{owner}/{repo}/branches?protected=true``) then fetches each
        one's protection detail
        (``GET /repos/{owner}/{repo}/branches/{branch}/protection``), returning a
        normalized list of
        ``{"repo", "branch", "required_reviews", "required_review_count",
        "dismiss_stale_reviews", "require_signed_commits", "enforce_admins"}``
        dicts. ``required_reviews=False`` (or a zero
        ``required_review_count``) on a reachable repo is the high-signal finding:
        an attacker who can push can do so unreviewed. This is read-only — it only
        GETs policy metadata and never alters protection.
        """
        results: list[dict] = []
        for full_name in self._reachable_repos(max_pages=max_pages):
            for resp in self._get_paginated(
                f"/repos/{full_name}/branches",
                params={"protected": "true", "per_page": 100},
                max_pages=max_pages,
                next_request=_next_link,
            ):
                body = resp.json()
                if not isinstance(body, list):
                    continue
                for branch in body:
                    branch_name = branch.get("name")
                    if not branch_name:
                        continue
                    results.append(
                        self._branch_protection_detail(full_name, branch_name)
                    )
        return results

    def _branch_protection_detail(self, full_name: str, branch: str) -> dict:
        """Fetch and normalize one branch's protection policy.

        A protected branch is listed by the branches endpoint, but the detailed
        policy (required reviews, signed commits, admin enforcement) lives behind
        ``GET /repos/{owner}/{repo}/branches/{branch}/protection``. We GET that
        and map GitHub's nested shape into covenant's flat normalized record.
        """
        detail = self._get(
            f"/repos/{full_name}/branches/{branch}/protection"
        ).json()
        reviews = detail.get("required_pull_request_reviews") or {}
        return {
            "repo": full_name,
            "branch": branch,
            "required_reviews": bool(reviews),
            "required_review_count": reviews.get(
                "required_approving_review_count", 0
            ),
            "dismiss_stale_reviews": bool(reviews.get("dismiss_stale_reviews", False)),
            "require_signed_commits": bool(
                (detail.get("required_signatures") or {}).get("enabled", False)
            ),
            "enforce_admins": bool(
                (detail.get("enforce_admins") or {}).get("enabled", False)
            ),
        }

    def _reachable_repos(self, max_pages: int = DEFAULT_MAX_PAGES) -> list[str]:
        """Return the ``owner/name`` full names of repos this token can reach.

        Walks ``GET /user/repos`` (the repositories the authenticated user has
        access to) with the shared paginator. Used by
        :meth:`enumerate_deploy_keys` to know which repos to inspect.
        """
        names: list[str] = []
        for resp in self._get_paginated(
            "/user/repos",
            params={"per_page": 100},
            max_pages=max_pages,
            next_request=_next_link,
        ):
            body = resp.json()
            if not isinstance(body, list):
                continue
            for item in body:
                full_name = item.get("full_name")
                if full_name:
                    names.append(full_name)
        return names

    def enumerate_webhooks(self, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        """List the org-level webhooks this token can reach (exfil/SSRF surface).

        Webhooks are the next blast-radius axis after SSH/GPG keys and gists:
        an org webhook POSTs every matching event (pushes, PRs, member changes)
        to an attacker-influenceable URL, which is both a *data-exfiltration*
        channel (the payloads carry repo content and metadata) and an *SSRF*
        primitive (an in-scope org webhook can be pointed at internal infra). A
        captured token that can read or, worse, edit org webhooks can quietly
        redirect or clone the event stream.

        This walks the organizations the token belongs to (via
        :meth:`enumerate_orgs`) and, for each, lists ``GET /orgs/{org}/hooks``
        with the shared paginator, returning a normalized list of
        ``{"scope", "owner", "id", "url", "events", "active"}`` dicts. ``scope``
        is always ``"org"`` for GitHub here (org-level hooks are the
        account-reachable surface; per-repo hooks require naming a repo and are
        out of this flag's scope). The destination ``url`` (the ``config.url``)
        is the actionable signal — it is the place events are sent — and is
        surfaced verbatim because it is the whole point of the recon; the hook
        *secret* (``config.secret``) is never returned by the API and covenant
        never requests or echoes it.
        """
        results: list[dict] = []
        for org in self.enumerate_orgs(max_pages=max_pages):
            owner = org.get("name")
            if not owner:
                continue
            for resp in self._get_paginated(
                f"/orgs/{owner}/hooks",
                params={"per_page": 100},
                max_pages=max_pages,
                next_request=_next_link,
            ):
                body = resp.json()
                if not isinstance(body, list):
                    continue
                for item in body:
                    hook_id = item.get("id")
                    if hook_id is None:
                        continue
                    config = item.get("config") or {}
                    results.append(
                        {
                            "scope": "org",
                            "owner": owner,
                            "id": hook_id,
                            "url": config.get("url"),
                            "events": item.get("events") or [],
                            "active": bool(item.get("active", False)),
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
