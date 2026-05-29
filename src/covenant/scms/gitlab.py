"""GitLab SCM client (cloud + self-hosted via --target-url)."""

from __future__ import annotations

from urllib.parse import quote

import httpx

from ..tokens import classify_token
from .base import (
    DEFAULT_MAX_PAGES,
    PACKAGE_MANIFESTS,
    BaseSCMClient,
    SCMError,
    codeowners_candidate_paths,
    parse_codeowners,
    parse_manifest,
)

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


def _gitlab_access_role(access_level: int) -> str:
    """Map a GitLab numeric ``access_level`` to covenant's role vocabulary.

    GitLab grades access numerically (50 Owner, 40 Maintainer, 30 Developer,
    20 Reporter, 10 Guest); we collapse it to the same labels the GitHub
    collaborator audit uses so the cross-SCM output is uniform: >=50 ``admin``,
    40 ``maintain``, 30 ``write``, 20 ``triage``, anything lower ``read``.
    """
    if access_level >= 50:
        return "admin"
    if access_level >= 40:
        return "maintain"
    if access_level >= 30:
        return "write"
    if access_level >= 20:
        return "triage"
    return "read"


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

    def audit_branch_protection(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """Audit the branch-protection posture of the projects this token reaches.

        Branch protection is the defensive counterpart to the offensive
        enumeration methods: it tells the operator whether a writable foothold
        would actually be stopped before code lands on a protected branch. We walk
        the projects the token is a member of
        (``GET /api/v4/projects?membership=true``) and, for each, list its
        protected branches (``GET /api/v4/projects/{id}/protected_branches``),
        returning the same normalized
        ``{"repo", "branch", "required_reviews", "required_review_count",
        "dismiss_stale_reviews", "require_signed_commits", "enforce_admins"}``
        shape as the other SCMs.

        GitLab models protection differently from GitHub, so the fields are mapped
        to the nearest equivalent signal and the per-project policy is fetched
        once and reused for every branch on that project:

        * ``required_reviews`` / ``required_review_count`` come from the project's
          ``approvals_before_merge`` (``GET /api/v4/projects/{id}/approvals``):
          ``required_reviews`` is ``True`` when at least one approval is required.
        * ``dismiss_stale_reviews`` maps to ``reset_approvals_on_push``.
        * ``require_signed_commits`` maps to the project push rule
          ``reject_unsigned_commits`` (``GET /api/v4/projects/{id}/push_rule``).
        * ``enforce_admins`` maps to the protected branch *disallowing* force
          push (``not allow_force_push``) — the nearest "rules are not bypassable"
          signal GitLab exposes per branch.

        This is read-only — it only GETs policy metadata and never alters
        protection. Endpoints that a low-privilege token can't read (approvals /
        push rules often require Maintainer) fail soft to the safe defaults so the
        audit still reports the protected branches it can see.
        """
        results: list[dict] = []
        for project in self._reachable_projects(max_pages=max_pages):
            project_id = project["id"]
            repo = project["repo"]
            policy = self._project_protection_policy(project_id)
            bp_path = f"/api/v4/projects/{project_id}/protected_branches"
            bp_params = {"per_page": _PER_PAGE, "page": 1}
            for resp in self._get_paginated(
                bp_path,
                params=bp_params,
                max_pages=max_pages,
                next_request=_gitlab_next(bp_path, bp_params),
            ):
                body = resp.json()
                if not isinstance(body, list):
                    continue
                for item in body:
                    branch = item.get("name")
                    if not branch:
                        continue
                    results.append(
                        {
                            "repo": repo,
                            "branch": branch,
                            "required_reviews": policy["required_review_count"] > 0,
                            "required_review_count": policy["required_review_count"],
                            "dismiss_stale_reviews": policy["dismiss_stale_reviews"],
                            "require_signed_commits": policy[
                                "require_signed_commits"
                            ],
                            "enforce_admins": not bool(
                                item.get("allow_force_push", False)
                            ),
                        }
                    )
        return results

    def _project_protection_policy(self, project_id) -> dict:
        """Fetch the project-level approval and push-rule policy once per project.

        GitLab keeps the review-count and signed-commit requirements at the
        *project* level (not per branch), so we resolve them a single time and
        reuse the result for every protected branch. Both endpoints may be denied
        to a low-privilege token; on any error we fall back to the safe,
        unprotected-looking defaults so the audit degrades gracefully rather than
        aborting.
        """
        required_review_count = 0
        dismiss_stale_reviews = False
        require_signed_commits = False
        try:
            approvals = self._get(
                f"/api/v4/projects/{project_id}/approvals"
            ).json()
            required_review_count = int(
                approvals.get("approvals_before_merge", 0) or 0
            )
            dismiss_stale_reviews = bool(
                approvals.get("reset_approvals_on_push", False)
            )
        except (SCMError, ValueError, TypeError):
            pass
        try:
            push_rule = self._get(
                f"/api/v4/projects/{project_id}/push_rule"
            ).json()
            if isinstance(push_rule, dict):
                require_signed_commits = bool(
                    push_rule.get("reject_unsigned_commits", False)
                )
        except (SCMError, ValueError, TypeError):
            pass
        return {
            "required_review_count": required_review_count,
            "dismiss_stale_reviews": dismiss_stale_reviews,
            "require_signed_commits": require_signed_commits,
        }

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
                        "default_branch": item.get("default_branch") or "main",
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

    def enumerate_actions_secrets(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """List the GitLab CI/CD variable NAMES this token can reach.

        GitLab's analogue of a GitHub Actions secret is the *CI/CD variable*:
        the credentials, tokens and config the ``.gitlab-ci.yml`` pipeline runs
        with. They live at both the *group* level
        (``GET /api/v4/groups/{id}/variables``) and the *project* level
        (``GET /api/v4/projects/{id}/variables``). A project or group carrying a
        long list of variables is a high-value, high-blast-radius target: an
        attacker who can read or exfiltrate them via a malicious pipeline gains
        the pipeline's lateral-movement and supply-chain reach.

        We walk the groups from :meth:`enumerate_orgs` (``scope="org"``) and the
        projects from :meth:`_reachable_projects` (``scope="repo"``), returning
        the same normalized ``{"scope", "owner", "name", "protected"}`` shape as
        the other SCMs. The GitLab API returns each variable's ``key`` (name),
        ``value`` and a ``protected`` flag; covenant surfaces ONLY the ``key`` as
        ``name`` (the excessive-exposure signal) and the ``protected`` flag — the
        secret ``value`` is never read into the output. Endpoints a low-privilege
        token can't read (variables typically require Maintainer) fail soft to an
        empty result so the audit still reports what it can see. Read-only.
        """
        results: list[dict] = []
        for group in self.enumerate_orgs(max_pages=max_pages):
            owner = group.get("name")
            if not owner:
                continue
            path = f"/api/v4/groups/{_group_id(owner)}/variables"
            params = {"per_page": _PER_PAGE, "page": 1}
            try:
                pages = list(
                    self._get_paginated(
                        path,
                        params=params,
                        max_pages=max_pages,
                        next_request=_gitlab_next(path, params),
                    )
                )
            except SCMError:
                continue
            for resp in pages:
                body = resp.json()
                if not isinstance(body, list):
                    continue
                for item in body:
                    key = item.get("key")
                    if not key:
                        continue
                    results.append(
                        {
                            "scope": "org",
                            "owner": owner,
                            "name": key,
                            "protected": bool(item.get("protected", False)),
                        }
                    )
        for project in self._reachable_projects(max_pages=max_pages):
            project_id = project["id"]
            repo = project["repo"]
            path = f"/api/v4/projects/{project_id}/variables"
            params = {"per_page": _PER_PAGE, "page": 1}
            try:
                pages = list(
                    self._get_paginated(
                        path,
                        params=params,
                        max_pages=max_pages,
                        next_request=_gitlab_next(path, params),
                    )
                )
            except SCMError:
                continue
            for resp in pages:
                body = resp.json()
                if not isinstance(body, list):
                    continue
                for item in body:
                    key = item.get("key")
                    if not key:
                        continue
                    results.append(
                        {
                            "scope": "repo",
                            "owner": repo,
                            "name": key,
                            "protected": bool(item.get("protected", False)),
                        }
                    )
        return results

    def audit_actions_environments(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """Audit the deployment-environment gate posture of reachable projects.

        GitLab's analogue of a GitHub Actions deployment environment is the
        project *environment*; the gate that protects it is the *protected
        environment* (``GET /api/v4/projects/{id}/protected_environments``),
        which carries a ``required_approval_count`` (how many approvers must sign
        off before a deployment proceeds). An environment that is NOT protected,
        or is protected with a zero approval count, lets a pipeline deploy — and
        read the environment-scoped CI/CD variables — without human review, the
        environment-scoped, secret-exfiltration counterpart to
        :meth:`audit_branch_protection`.

        We walk the projects the token is a member of
        (``GET /api/v4/projects?membership=true``), fetch each project's
        protected-environment set once (failing soft to "none protected" for a
        low-privilege token), then list ``GET /api/v4/projects/{id}/environments``
        and map each into the same normalized
        ``{"repo", "environment", "required_reviewers",
        "required_reviewer_count", "wait_timer", "branch_policy"}`` shape as the
        other SCMs. ``required_reviewers`` is ``True`` when the environment is
        protected with at least one required approval; ``required_reviewer_count``
        is that approval count. GitLab has no per-environment deploy *wait timer*
        in the GitHub sense, so ``wait_timer`` is always ``0``. ``branch_policy``
        is ``"protected"`` when the environment is in the protected set (deploys
        are gated to authorized branches/users) and ``"all"`` otherwise (any
        pipeline may deploy). Read-only — only GETs policy metadata.
        """
        results: list[dict] = []
        for project in self._reachable_projects(max_pages=max_pages):
            project_id = project["id"]
            repo = project["repo"]
            protected = self._protected_environments(
                project_id, max_pages=max_pages
            )
            env_path = f"/api/v4/projects/{project_id}/environments"
            env_params = {"per_page": _PER_PAGE, "page": 1}
            for resp in self._get_paginated(
                env_path,
                params=env_params,
                max_pages=max_pages,
                next_request=_gitlab_next(env_path, env_params),
            ):
                body = resp.json()
                if not isinstance(body, list):
                    continue
                for item in body:
                    name = item.get("name")
                    if not name:
                        continue
                    approvals = protected.get(name, 0)
                    is_protected = name in protected
                    results.append(
                        {
                            "repo": repo,
                            "environment": name,
                            "required_reviewers": approvals > 0,
                            "required_reviewer_count": approvals,
                            "wait_timer": 0,
                            "branch_policy": "protected"
                            if is_protected
                            else "all",
                        }
                    )
        return results

    def _protected_environments(
        self, project_id, max_pages: int = DEFAULT_MAX_PAGES
    ) -> dict[str, int]:
        """Map protected-environment name -> required approval count for a project.

        ``GET /api/v4/projects/{id}/protected_environments`` lists the
        environments whose deployments are gated, each with a
        ``required_approval_count``. The endpoint requires Maintainer on the
        project, so a low-privilege token gets a 403; we fail soft to an empty
        map (everything reads as unprotected) rather than aborting the audit.
        """
        out: dict[str, int] = {}
        path = f"/api/v4/projects/{project_id}/protected_environments"
        params = {"per_page": _PER_PAGE, "page": 1}
        try:
            pages = list(
                self._get_paginated(
                    path,
                    params=params,
                    max_pages=max_pages,
                    next_request=_gitlab_next(path, params),
                )
            )
        except SCMError:
            return out
        for resp in pages:
            body = resp.json()
            if not isinstance(body, list):
                continue
            for item in body:
                name = item.get("name")
                if not name:
                    continue
                try:
                    out[name] = int(item.get("required_approval_count", 0) or 0)
                except (ValueError, TypeError):
                    out[name] = 0
        return out

    def audit_repo_visibility(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """Audit the visibility posture of the projects this token can reach.

        The GitLab analogue of GitHub's repo-visibility audit. Where the
        ``--enumerate-*`` flags map a token's offensive reach, this reports the
        *exposure* posture: which reachable projects are externally readable. A
        ``public`` project is world-readable; an ``internal`` project is
        readable by any authenticated user of the instance (a broader-than-it-
        looks exposure on a shared/self-managed GitLab) — both are part of the
        attack surface a ``private`` project is not.

        Walks ``GET /api/v4/projects?membership=true`` with the shared offset
        paginator and returns ``{"repo", "visibility", "public"}`` dicts.
        GitLab reports a ``visibility`` string of ``public``/``internal``/
        ``private``; covenant surfaces it verbatim and sets ``public`` true for
        anything other than ``private`` (so ``internal``'s instance-wide
        readability is flagged as exposure, not hidden as private). Only project
        metadata is read.
        """
        path = "/api/v4/projects"
        params = {"membership": "true", "per_page": _PER_PAGE, "page": 1}
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
                repo = (
                    item.get("path_with_namespace")
                    or item.get("name")
                    or (str(item["id"]) if item.get("id") is not None else None)
                )
                if not repo:
                    continue
                visibility = item.get("visibility") or "private"
                results.append(
                    {
                        "repo": repo,
                        "visibility": visibility,
                        "public": visibility != "private",
                    }
                )
        return results

    def audit_codeowners(self, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        """Audit the CODEOWNERS coverage of the projects this token can reach.

        CODEOWNERS routes mandatory review to a named owner per path and is the
        partner control to branch protection: GitLab honors it via *code-owner
        approval* on a protected branch — but only for paths a rule matches. A
        project with NO CODEOWNERS file (``present=false``) cannot gate review by
        owner at all, and one whose CODEOWNERS has rules but no catch-all ``*``
        leaves every unmatched path with no required owner, a gap that the
        branch-protection audit alone does not reveal.

        Walks the projects the token is a member of
        (``GET /api/v4/projects?membership=true``) and, for each, probes the
        standard CODEOWNERS locations (``.gitlab/CODEOWNERS``, ``CODEOWNERS``,
        ``docs/CODEOWNERS``) via the repository-files API
        (``GET /api/v4/projects/{id}/repository/files/{path}?ref={branch}``,
        which returns base64 ``content``), reporting the first one found on the
        project's default branch. Returns the same normalized
        ``{"repo", "present", "path", "rule_count", "has_global_owner"}`` shape as
        the other SCMs. Only the rule COUNT and the presence of a ``*`` catch-all
        are surfaced — the owner handles are not echoed and no other content is
        read. Read-only.
        """
        results: list[dict] = []
        for project in self._reachable_projects(max_pages=max_pages):
            project_id = project["id"]
            repo = project["repo"]
            ref = project.get("default_branch") or "main"
            record = {
                "repo": repo,
                "present": False,
                "path": None,
                "rule_count": 0,
                "has_global_owner": False,
            }
            for path in codeowners_candidate_paths(".gitlab"):
                encoded_path = quote(path, safe="")
                api_path = (
                    f"/api/v4/projects/{project_id}/repository/files/"
                    f"{encoded_path}"
                )
                text = self._fetch_file_content(api_path, ref)
                if text is None:
                    continue
                summary = parse_codeowners(text)
                record.update(
                    {
                        "present": True,
                        "path": path,
                        "rule_count": summary["rule_count"],
                        "has_global_owner": summary["has_global_owner"],
                    }
                )
                break
            results.append(record)
        return results

    def audit_packages(self, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        """Inventory the declared package dependencies of reachable projects.

        Where ``--audit-dependabot-alerts`` reports KNOWN-vulnerable dependencies
        (GitLab dependency-scanning findings), this reports the FULL declared
        dependency surface: every package a reachable project's manifest files
        pull in, named with its declared version and ecosystem. It is the
        software-supply-chain complement to covenant's security-configuration
        audits — the inventory needed before triaging which dependency is
        vulnerable, typosquatted, or abandoned.

        Walks the projects the token is a member of
        (``GET /api/v4/projects?membership=true``) and, for each, probes the repo
        root for the supported manifest files (``package.json``,
        ``requirements.txt``, ``pyproject.toml``, ``Pipfile``, ``go.mod``,
        ``Gemfile``, ``pom.xml``) via the repository-files API
        (``GET /api/v4/projects/{id}/repository/files/{path}?ref={branch}``) on
        the project's default branch. Each declared package becomes one normalized
        ``{"repo", "manifest", "ecosystem", "package", "version"}`` dict, the same
        cross-provider shape as the other SCMs. ``version`` is the spec the
        manifest declares (never resolved) and is ``null`` when unpinned. A project
        with no recognized manifest contributes no rows. Read-only — only the named
        manifest files are read and only package names + declared versions are
        surfaced.
        """
        results: list[dict] = []
        for project in self._reachable_projects(max_pages=max_pages):
            project_id = project["id"]
            repo = project["repo"]
            ref = project.get("default_branch") or "main"
            for manifest, ecosystem in PACKAGE_MANIFESTS:
                encoded_path = quote(manifest, safe="")
                api_path = (
                    f"/api/v4/projects/{project_id}/repository/files/"
                    f"{encoded_path}"
                )
                text = self._fetch_file_content(api_path, ref)
                if text is None:
                    continue
                for pkg in parse_manifest(manifest, text):
                    results.append(
                        {
                            "repo": repo,
                            "manifest": manifest,
                            "ecosystem": ecosystem,
                            "package": pkg["package"],
                            "version": pkg["version"],
                        }
                    )
        return results

    def _fetch_file_content(self, api_path: str, ref: str) -> str | None:
        """GET a project file's decoded text, or ``None`` if it does not exist.

        Uses GitLab's repository-files API, which returns a JSON object with a
        base64-encoded ``content`` field. A 404 (file absent on the ref) returns
        ``None`` so the caller can probe several candidate paths cheaply.
        """
        url = f"{self.base_url}{api_path}"
        resp = self._request_with_retry(url, {"ref": ref}, self._headers())
        if resp.status_code == 404:
            return None
        if resp.status_code == 401:
            raise SCMError("authentication failed (401) — check the token")
        if resp.status_code >= 400:
            raise SCMError(
                f"{self.base_url} returned HTTP {resp.status_code} for {api_path}"
            )
        body = resp.json()
        if not isinstance(body, dict):
            return None
        encoded = body.get("content")
        if not isinstance(encoded, str):
            return ""
        import base64  # noqa: PLC0415

        try:
            return base64.b64decode(encoded).decode("utf-8", errors="replace")
        except (ValueError, TypeError):
            return ""

    def audit_dependabot_alerts(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """Audit the OPEN dependency-scanning vulnerabilities on reachable projects.

        GitLab has no "Dependabot" — its analogue is the Vulnerability Report fed
        by *dependency scanning*: each finding is a known CVE in a dependency the
        project ships, with a severity and an external identifier. This is the
        same known-vulnerability attack-surface signal as GitHub's Dependabot
        alerts, so covenant surfaces it under the identical flag and normalized
        shape for a uniform cross-provider audit.

        Walks the projects the token is a member of
        (``GET /api/v4/projects?membership=true``) and, for each, lists its
        DETECTED vulnerabilities
        (``GET /api/v4/projects/{id}/vulnerabilities?state=detected``), returning
        a normalized list of
        ``{"repo", "package", "ecosystem", "severity", "state", "identifier"}``
        dicts. ``severity`` is lower-cased to match the other SCMs
        (``critical``/``high``/...), ``package`` is the affected dependency name
        and ``ecosystem`` its scanner/report type, and ``identifier`` is the
        advisory handle (CVE/GHSA), never a credential. Only OPEN (``detected``)
        findings are requested. A project without the security feature (or a token
        lacking access) answers 403/404 for that project; covenant skips it rather
        than failing the whole audit. Read-only — it only GETs finding metadata
        and never confirms, dismisses, or resolves a vulnerability.
        """
        results: list[dict] = []
        for project in self._reachable_projects(max_pages=max_pages):
            project_id = project["id"]
            repo = project["repo"]
            path = f"/api/v4/projects/{project_id}/vulnerabilities"
            params = {"state": "detected", "per_page": _PER_PAGE, "page": 1}
            url = f"{self.base_url}{path}"
            probe = self._request_with_retry(url, params, self._headers())
            # No security feature / no access for this project — skip it, do not
            # abort the whole audit.
            if probe.status_code in (403, 404):
                continue
            if probe.status_code == 401:
                raise SCMError("authentication failed (401) — check the token")
            if probe.status_code >= 400:
                raise SCMError(
                    f"{self.base_url} returned HTTP {probe.status_code} "
                    f"for {repo} vulnerabilities"
                )
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
                    severity = (item.get("severity") or "").lower() or None
                    finding = item.get("finding") or {}
                    identifier = item.get("cve") or finding.get("identifier")
                    results.append(
                        {
                            "repo": repo,
                            "package": item.get("title")
                            or finding.get("name"),
                            "ecosystem": item.get("report_type"),
                            "severity": severity,
                            "state": item.get("state", "detected"),
                            "identifier": identifier,
                        }
                    )
        return results

    def audit_secret_scanning(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """Audit the OPEN secret-detection findings on reachable projects.

        GitLab has no "secret-scanning alerts" endpoint of its own; its analogue
        is the Vulnerability Report fed by *secret detection* — the same report
        that ``--audit-dependabot-alerts`` reads for dependency findings, here
        filtered to ``report_type=secret_detection``. Each such finding is a
        credential GitLab's scanner detected committed in the project, the same
        already-confirmed-leak signal as GitHub's secret-scanning alerts, so
        covenant surfaces it under the identical flag and normalized shape for a
        uniform cross-provider audit.

        Walks the projects the token is a member of
        (``GET /api/v4/projects?membership=true``) and, for each, lists its
        DETECTED secret-detection vulnerabilities
        (``GET /api/v4/projects/{id}/vulnerabilities?report_type=secret_detection&state=detected``),
        returning a normalized list of
        ``{"repo", "secret_type", "state", "validity", "html_url"}`` dicts.
        ``secret_type`` is the finding's classifier (its title, e.g. "AWS Access
        Key") — the KIND of secret, never its value. ``validity`` is ``"unknown"``
        (GitLab does not expose a credential-freshness signal, so the field is
        carried for cross-provider shape parity rather than populated with a
        guess). ``html_url`` is the finding's web link, not the secret.

        **The decisive invariant**: the raw leaked secret is NEVER surfaced.
        GitLab's vulnerability object can carry the matched credential in its
        ``finding``/``raw_metadata`` payload; covenant reads neither — only the
        classifier, state, and the finding URL. Only OPEN (``detected``) findings
        are requested. A project without the security feature (or a token lacking
        access) answers 403/404 for that project; covenant skips it rather than
        failing the whole audit. Read-only — it only GETs finding metadata and
        never confirms, dismisses, or resolves a vulnerability.
        """
        results: list[dict] = []
        for project in self._reachable_projects(max_pages=max_pages):
            project_id = project["id"]
            repo = project["repo"]
            path = f"/api/v4/projects/{project_id}/vulnerabilities"
            params = {
                "report_type": "secret_detection",
                "state": "detected",
                "per_page": _PER_PAGE,
                "page": 1,
            }
            url = f"{self.base_url}{path}"
            probe = self._request_with_retry(url, params, self._headers())
            # No security feature / no access for this project — skip it, do not
            # abort the whole audit.
            if probe.status_code in (403, 404):
                continue
            if probe.status_code == 401:
                raise SCMError("authentication failed (401) — check the token")
            if probe.status_code >= 400:
                raise SCMError(
                    f"{self.base_url} returned HTTP {probe.status_code} "
                    f"for {repo} secret-detection findings"
                )
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
                    finding = item.get("finding") or {}
                    # NEVER read finding["raw_metadata"] / any matched-credential
                    # field — only the classifier (title/name), state, and URL.
                    results.append(
                        {
                            "repo": repo,
                            "secret_type": item.get("title")
                            or finding.get("name"),
                            "state": item.get("state", "detected"),
                            "validity": "unknown",
                            "html_url": item.get("web_url")
                            or finding.get("web_url"),
                        }
                    )
        return results

    def audit_code_scanning_alerts(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """Audit the OPEN static-analysis (SAST) findings on reachable projects.

        GitLab has no "code-scanning alerts" endpoint of its own; its analogue is
        the Vulnerability Report fed by *SAST* — the same report that
        ``--audit-dependabot-alerts`` reads for dependency findings, here filtered
        to ``report_type=sast``. Each such finding is a vulnerability GitLab's
        static analyzer detected in the project's OWN first-party source (an
        injection sink, a crypto misuse, a path-traversal), the same code-flaw
        signal as GitHub's code-scanning alerts, so covenant surfaces it under the
        identical flag and normalized shape for a uniform cross-provider audit.

        Walks the projects the token is a member of
        (``GET /api/v4/projects?membership=true``) and, for each, lists its
        DETECTED SAST vulnerabilities
        (``GET /api/v4/projects/{id}/vulnerabilities?report_type=sast&state=detected``),
        returning a normalized list of
        ``{"repo", "rule_id", "rule_name", "severity", "state", "html_url"}``
        dicts. ``rule_id`` is the finding's analyzer identifier (its
        ``finding.identifier`` where present, else the title), ``rule_name`` its
        human title, and ``severity`` is lower-cased to match the other SCMs
        (``critical``/``high``/...). ``html_url`` is the finding's web link, not a
        credential. Only OPEN (``detected``) findings are requested. A project
        without the security feature (or a token lacking access) answers 403/404
        for that project; covenant skips it rather than failing the whole audit.
        Read-only — it only GETs finding metadata and never confirms, dismisses,
        or resolves a vulnerability.
        """
        results: list[dict] = []
        for project in self._reachable_projects(max_pages=max_pages):
            project_id = project["id"]
            repo = project["repo"]
            path = f"/api/v4/projects/{project_id}/vulnerabilities"
            params = {
                "report_type": "sast",
                "state": "detected",
                "per_page": _PER_PAGE,
                "page": 1,
            }
            url = f"{self.base_url}{path}"
            probe = self._request_with_retry(url, params, self._headers())
            # No security feature / no access for this project — skip it, do not
            # abort the whole audit.
            if probe.status_code in (403, 404):
                continue
            if probe.status_code == 401:
                raise SCMError("authentication failed (401) — check the token")
            if probe.status_code >= 400:
                raise SCMError(
                    f"{self.base_url} returned HTTP {probe.status_code} "
                    f"for {repo} SAST findings"
                )
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
                    finding = item.get("finding") or {}
                    severity = (item.get("severity") or "").lower() or None
                    results.append(
                        {
                            "repo": repo,
                            "rule_id": finding.get("identifier")
                            or item.get("title"),
                            "rule_name": item.get("title")
                            or finding.get("name"),
                            "severity": severity,
                            "state": item.get("state", "detected"),
                            "html_url": item.get("web_url")
                            or finding.get("web_url"),
                        }
                    )
        return results

    def audit_advisory_alerts(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """No-op on GitLab, which has no maintainer-authored repository advisory API.

        The GitHub flag enumerates the repository security advisories a project's
        own maintainers PUBLISHED against their own product — each a GHSA the org
        wrote up itself. GitLab has no equivalent per-project, token-readable
        surface: GitLab's advisory data is the global GitLab Advisory Database
        (an instance-wide feed of third-party CVEs, already covered as a
        DEPENDENCY signal by ``--audit-dependabot-alerts``), not a per-repo
        endpoint where a project publishes advisories about its OWN code, so
        there is nothing for covenant to enumerate here under this flag.

        To keep the cross-provider audit uniform, the method exists and returns
        an empty list (the same normalized shape the other SCMs would yield, just
        with no entries) and records a single non-fatal ``warnings`` note so the
        operator understands the empty result reflects a platform-model
        difference, not a clean bill of health. Read-only — it makes no request.
        """
        self.warnings.append(
            "advisory-alerts audit is unsupported on GitLab "
            "(no per-project maintainer-authored repository advisory API; the "
            "GitLab Advisory Database is an instance-wide third-party feed); "
            "result is empty by design, not a clean bill of health"
        )
        return []

    def audit_actions_permissions(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """No-op on GitLab, which has no per-repo Actions-permission API.

        The GitHub flag audits the policy that governs what a workflow run may
        do — whether Actions is enabled and, decisively, the default
        read/write permission of the automatic ``GITHUB_TOKEN`` granted to every
        run. GitLab CI has no single token-readable equivalent: the analogous
        controls (the CI/CD job-token scope, protected-branch CI rules, the
        instance-level pipeline settings) are spread across distinct,
        differently-shaped settings rather than one ``actions/permissions``
        endpoint, so there is no uniform per-repo record for covenant to surface
        under this flag.

        To keep the cross-provider audit uniform, the method exists and returns
        an empty list (the same normalized shape the other SCMs would yield, just
        with no entries) and records a single non-fatal ``warnings`` note so the
        operator understands the empty result reflects a platform-model
        difference, not a clean bill of health. Read-only — it makes no request.
        """
        self.warnings.append(
            "actions-permissions audit is unsupported on GitLab "
            "(no single per-project Actions-permission API; CI job-token scope "
            "and pipeline settings are governed separately); result is empty by "
            "design, not a clean bill of health"
        )
        return []

    def enumerate_members(self, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        """List the other members of the groups this token can reach (lateral moves).

        The GitLab analogue of GitHub org-member enumeration. Where the rest of
        the ``--enumerate-*`` family maps what *this* token reaches, member
        enumeration maps the *people* who share that reach: the accounts with
        access to each group the token belongs to, and at what access level. That
        is the lateral-movement surface (other identities an operator could
        target to widen a foothold) and, for the Owners specifically, the set of
        accounts whose compromise grants administrative control of the group.

        Walks the groups the token belongs to (via :meth:`enumerate_orgs`) and,
        for each, lists ``GET /api/v4/groups/{id}/members/all`` (effective
        membership, including members inherited from ancestor groups) with the
        shared offset paginator. GitLab reports each member's numeric
        ``access_level`` (50 = Owner, 40 = Maintainer, 30 = Developer, ...); we
        normalize the Owner level (>= 50) to ``role="admin"`` and everything else
        to ``role="member"`` so the shape matches the other SCMs. Returns
        ``{"scope", "owner", "username", "role"}`` dicts (``scope`` is
        ``"group"``). Only membership identity is surfaced — no token, no key, no
        email — a read-only directory query.
        """
        results: list[dict] = []
        for group in self.enumerate_orgs(max_pages=max_pages):
            owner = group.get("name")
            if not owner:
                continue
            path = f"/api/v4/groups/{_group_id(owner)}/members/all"
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
                    username = item.get("username")
                    if not username:
                        continue
                    try:
                        access_level = int(item.get("access_level", 0) or 0)
                    except (TypeError, ValueError):
                        access_level = 0
                    results.append(
                        {
                            "scope": "group",
                            "owner": owner,
                            "username": username,
                            "role": "admin" if access_level >= 50 else "member",
                        }
                    )
        return results

    def enumerate_collaborators(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """List the direct members of the projects this token can reach (ghost accounts).

        The GitLab analogue of GitHub outside-collaborator enumeration. Where
        :meth:`enumerate_members` maps the people who share a *group's* reach,
        this is project-scoped and surfaces the higher-signal blast radius: the
        accounts granted access DIRECTLY on a specific project rather than
        inherited from an ancestor group. A direct project member is GitLab's
        outside-collaborator equivalent — a personal account bolted onto one repo
        (often a contractor or ex-employee) that an org/group-member audit misses
        and that survives long after the person leaves. A project with a
        write-or-above direct member is a supply-chain and persistence risk.

        Walks the projects the token is a member of
        (``GET /api/v4/projects?membership=true``) and, for each, lists its
        DIRECT members (``GET /api/v4/projects/{id}/members`` — the non-``/all``
        endpoint, which returns members granted on the project itself, excluding
        those inherited from a group). GitLab reports each member's numeric
        ``access_level`` (50 = Owner, 40 = Maintainer, 30 = Developer, 20 =
        Reporter, 10 = Guest); we map it to the same role vocabulary as the
        GitHub collaborator audit (>=50 ``admin``, 40 ``maintain``, 30 ``write``,
        20 ``triage``, else ``read``). Every returned account is a direct
        (outside-style) grant, so ``outside`` is ``True``. Returns a normalized
        list of ``{"repo", "username", "role", "outside"}`` dicts. Only
        membership identity and the access level are surfaced — never an email,
        key, or credential. Read-only.
        """
        results: list[dict] = []
        for project in self._reachable_projects(max_pages=max_pages):
            project_id = project["id"]
            repo = project["repo"]
            path = f"/api/v4/projects/{project_id}/members"
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
                    username = item.get("username")
                    if not username:
                        continue
                    try:
                        access_level = int(item.get("access_level", 0) or 0)
                    except (TypeError, ValueError):
                        access_level = 0
                    results.append(
                        {
                            "repo": repo,
                            "username": username,
                            "role": _gitlab_access_role(access_level),
                            "outside": True,
                        }
                    )
        return results

    def scan_commits(self, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        """Collect commit metadata + messages from the projects this token reaches.

        The GitLab analogue of GitHub commit-history scanning. Commit *messages*
        are a notorious secret-leak vector: a credential scrubbed from a tracked
        file routinely survives verbatim in the commit subject/body, in a
        revert/merge message quoting a diff, or in an automated bump commit. Where
        ``--scan-secrets`` only sees the *current* blob content the search API
        returns, this maps the leak surface in *history*: it walks the recent
        commits the token can read and surfaces each commit's message for the
        caller to scan with the same :func:`covenant.secrets.scan_fragments`
        machinery.

        Walks the projects the token is a member of
        (``GET /api/v4/projects?membership=true``) and, for each, lists
        ``GET /api/v4/projects/{id}/repository/commits`` (newest first), returning
        one normalized ``{"repo", "sha", "author", "message"}`` record per commit.
        ``author`` is the commit's ``author_name`` (identity only — the
        ``author_email`` is deliberately never read) and ``message`` is the raw
        commit message; the commit *diff* is never fetched. Read-only.
        """
        results: list[dict] = []
        for project in self._reachable_projects(max_pages=max_pages):
            project_id = project["id"]
            repo = project["repo"]
            path = f"/api/v4/projects/{project_id}/repository/commits"
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
                    sha = item.get("id")
                    if not sha:
                        continue
                    results.append(
                        {
                            "repo": repo,
                            "sha": sha,
                            "author": item.get("author_name"),
                            "message": item.get("message")
                            or item.get("title", ""),
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
