"""Bitbucket Cloud SCM client (Bitbucket Server is EOL'd, out of scope)."""

from __future__ import annotations

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


def _bitbucket_runner_labels(labels) -> list[str]:
    """Normalize a Bitbucket runner's ``labels`` field to a list of bare names.

    Bitbucket Cloud returns labels either as a flat list of strings
    (``["self.hosted","linux"]``) or, in some payloads, as a set-style list of
    label dicts; we accept either and emit a stable list of strings. Defensive
    against missing/malformed entries.
    """
    out: list[str] = []
    if not labels:
        return out
    for label in labels:
        if isinstance(label, str) and label:
            out.append(label)
        elif isinstance(label, dict):
            name = label.get("name")
            if isinstance(name, str) and name:
                out.append(name)
    return out


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

    def audit_webhook(self, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        """No-op on Bitbucket Cloud — workspace-hooks expose no posture record.

        The GitHub flag audits three posture fields on each org webhook: HMAC
        secret presence, TLS verification (``insecure_ssl``), and active
        wildcard-event scope. Bitbucket Cloud's workspace-hook API
        (``GET /2.0/workspaces/{slug}/hooks``) surfaces the destination URL,
        the subscribed event keys, and an ``active`` flag (already mapped by
        :meth:`enumerate_webhooks`) but does NOT expose a per-hook secret-
        presence boolean or a TLS-verification flag — workspace webhooks
        rely on the Bitbucket-provided IP allow-list of POST origins rather
        than a per-hook HMAC the receiver verifies, and TLS verification at
        the receiver is not a configurable per-hook posture. There is no
        uniform per-webhook posture record for covenant to surface under
        this flag on Bitbucket Cloud.

        To keep the cross-provider audit uniform, the method exists and
        returns an empty list (the same normalized shape the GitHub client
        would yield, just with no entries) and records a single non-fatal
        ``warnings`` note so the operator understands the empty result
        reflects a platform-model difference, not a clean bill of health.
        Read-only — it makes no request at all.
        """
        self.warnings.append(
            "webhook-configuration audit is unsupported on Bitbucket Cloud "
            "(the workspace-hook API does not expose per-hook secret "
            "presence or TLS-verification posture; Bitbucket gates "
            "delivery on a provider IP allow-list instead); result is "
            "empty by design, not a clean bill of health"
        )
        return []

    def enumerate_actions_secrets(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """List the Bitbucket Pipelines variable NAMES this token can reach.

        Bitbucket Cloud's analogue of a GitHub Actions secret is the *Pipelines
        variable*: the credentials and config a ``bitbucket-pipelines.yml`` build
        runs with. They live at both the *workspace* level
        (``GET /2.0/workspaces/{slug}/pipelines-config/variables``) and the
        *repository* level
        (``GET /2.0/repositories/{full_name}/pipelines-config/variables``). A repo
        or workspace carrying a long list of variables is a high-value,
        high-blast-radius target: an attacker who can read or exfiltrate them via
        a malicious pipeline gains the pipeline's lateral-movement and
        supply-chain reach.

        We walk the workspaces from :meth:`enumerate_orgs` (``scope="org"``) and
        the repos from :meth:`_reachable_repos` (``scope="repo"``), returning the
        same normalized ``{"scope", "owner", "name", "protected"}`` shape as the
        other SCMs. Bitbucket returns each variable's ``key`` (name) and a
        ``secured`` flag; for a *secured* variable the API omits the ``value``
        entirely. covenant surfaces ONLY the ``key`` as ``name`` (the
        excessive-exposure signal) and maps ``secured`` to ``protected`` — the
        variable ``value`` is never read into the output. Endpoints a token can't
        read fail soft to an empty result. Read-only.
        """
        results: list[dict] = []
        for workspace in self.enumerate_orgs(max_pages=max_pages):
            owner = workspace.get("name")
            if not owner:
                continue
            try:
                pages = list(
                    self._get_paginated(
                        f"/2.0/workspaces/{owner}/pipelines-config/variables",
                        params={"pagelen": 100},
                        max_pages=max_pages,
                        next_request=_bitbucket_next,
                    )
                )
            except SCMError:
                continue
            for resp in pages:
                for item in resp.json().get("values", []):
                    key = item.get("key")
                    if not key:
                        continue
                    results.append(
                        {
                            "scope": "org",
                            "owner": owner,
                            "name": key,
                            "protected": bool(item.get("secured", False)),
                        }
                    )
        for full_name in self._reachable_repos(max_pages=max_pages):
            try:
                pages = list(
                    self._get_paginated(
                        f"/2.0/repositories/{full_name}/pipelines-config/variables",
                        params={"pagelen": 100},
                        max_pages=max_pages,
                        next_request=_bitbucket_next,
                    )
                )
            except SCMError:
                continue
            for resp in pages:
                for item in resp.json().get("values", []):
                    key = item.get("key")
                    if not key:
                        continue
                    results.append(
                        {
                            "scope": "repo",
                            "owner": full_name,
                            "name": key,
                            "protected": bool(item.get("secured", False)),
                        }
                    )
        return results

    def enumerate_runners(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """List the self-hosted Bitbucket Pipelines runners this token can reach.

        Bitbucket Cloud's analogue of a GitHub Actions self-hosted runner is a
        *Pipelines runner* attached to a workspace or repository (``GET
        /2.0/workspaces/{slug}/pipelines-config/runners`` and ``GET
        /2.0/repositories/{full_name}/pipelines-config/runners``). Every job
        that targets the runner executes on its host: the runner sees the job's
        Pipelines variables, the checked-out source and the build artifacts, so
        a compromised or planted self-hosted runner is a persistence and
        lateral-movement foothold. A runner registered at *workspace* scope is
        the broadest, because any repo in the workspace can dispatch to it.

        Walks the workspaces from :meth:`enumerate_orgs` (``scope="org"``) and
        the repos from :meth:`_reachable_repos` (``scope="repo"``), returning
        the same normalized
        ``{"scope", "owner", "id", "name", "labels", "self_hosted"}`` shape as
        the other SCMs. Bitbucket Pipelines runners are self-hosted by
        definition (the platform-managed compute is not surfaced here), so
        ``self_hosted`` is always ``True`` for Bitbucket entries. ``id`` is the
        runner UUID; ``labels`` is the Bitbucket label list (e.g.
        ``["self.hosted","linux"]``). Endpoints a token can't read fail soft to
        an empty result. Read-only; the runner *OAuth client secret* is never
        echoed.
        """
        results: list[dict] = []
        for workspace in self.enumerate_orgs(max_pages=max_pages):
            owner = workspace.get("name")
            if not owner:
                continue
            try:
                pages = list(
                    self._get_paginated(
                        f"/2.0/workspaces/{owner}/pipelines-config/runners",
                        params={"pagelen": 100},
                        max_pages=max_pages,
                        next_request=_bitbucket_next,
                    )
                )
            except SCMError:
                continue
            for resp in pages:
                for item in resp.json().get("values", []):
                    runner_uuid = item.get("uuid")
                    name = item.get("name")
                    if not runner_uuid or not name:
                        continue
                    results.append(
                        {
                            "scope": "org",
                            "owner": owner,
                            "id": runner_uuid,
                            "name": name,
                            "labels": _bitbucket_runner_labels(
                                item.get("labels", [])
                            ),
                            "self_hosted": True,
                        }
                    )
        for full_name in self._reachable_repos(max_pages=max_pages):
            try:
                pages = list(
                    self._get_paginated(
                        f"/2.0/repositories/{full_name}/pipelines-config/runners",
                        params={"pagelen": 100},
                        max_pages=max_pages,
                        next_request=_bitbucket_next,
                    )
                )
            except SCMError:
                continue
            for resp in pages:
                for item in resp.json().get("values", []):
                    runner_uuid = item.get("uuid")
                    name = item.get("name")
                    if not runner_uuid or not name:
                        continue
                    results.append(
                        {
                            "scope": "repo",
                            "owner": full_name,
                            "id": runner_uuid,
                            "name": name,
                            "labels": _bitbucket_runner_labels(
                                item.get("labels", [])
                            ),
                            "self_hosted": True,
                        }
                    )
        return results

    def audit_actions_environments(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """Audit the deployment-environment gate posture of reachable repos.

        Bitbucket Cloud's analogue of a GitHub Actions deployment environment is
        the Pipelines *deployment environment* (``GET
        /2.0/repositories/{full_name}/environments``), where the
        environment-scoped Pipelines variables surfaced by
        :meth:`enumerate_actions_secrets` live. The gate that protects a
        deployment is the environment's *restrictions* (the ``admin_only`` lock
        on the deployment gate): when set, only an admin may approve a deployment
        to that environment; when unset, any pipeline run may deploy and read the
        environment's secured variables unreviewed. This is the
        environment-scoped, secret-exfiltration counterpart to
        :meth:`audit_branch_protection`.

        We walk the repositories the token is a member of
        (``GET /2.0/repositories?role=member``) and, for each, list its
        environments, mapping each into the same normalized
        ``{"repo", "environment", "required_reviewers",
        "required_reviewer_count", "wait_timer", "branch_policy"}`` shape as the
        other SCMs. ``required_reviewers`` is ``True`` when the environment's
        deployment gate is admin-restricted (the ``restrictions.admin_only``
        flag), the nearest human-gate signal Bitbucket Cloud exposes.
        Bitbucket Cloud has no per-environment reviewer *count*, deploy *wait
        timer*, or deployment *branch policy*, so ``required_reviewer_count`` and
        ``wait_timer`` are always ``0`` and ``branch_policy`` is always ``"all"``
        — the fields are kept for cross-provider shape parity. Read-only — only
        GETs policy metadata.
        """
        results: list[dict] = []
        for full_name in self._reachable_repos(max_pages=max_pages):
            for resp in self._get_paginated(
                f"/2.0/repositories/{full_name}/environments",
                params={"pagelen": 100},
                max_pages=max_pages,
                next_request=_bitbucket_next,
            ):
                for item in resp.json().get("values", []):
                    name = item.get("name")
                    if not name:
                        continue
                    restrictions = item.get("restrictions") or {}
                    admin_only = bool(restrictions.get("admin_only", False))
                    results.append(
                        {
                            "repo": full_name,
                            "environment": name,
                            "required_reviewers": admin_only,
                            "required_reviewer_count": 0,
                            "wait_timer": 0,
                            "branch_policy": "all",
                        }
                    )
        return results

    def audit_deployment_protection(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """No-op on Bitbucket Cloud — no custom deployment-protection-rule API.

        The GitHub flag lists the custom third-party GitHub Apps an
        environment delegates its deploy gate to (each app returns
        approve/reject and the deployment lands or is held). Bitbucket
        Pipelines has no token-readable equivalent: the analogous gating is
        the built-in ``restrictions.admin_only`` deploy gate on a deployment
        environment (already surfaced by :meth:`audit_actions_environments`),
        and Bitbucket Cloud has no per-environment listing of installed
        third-party apps that gate a deploy. There is no uniform
        per-environment custom-rule record for covenant to surface under this
        flag on Bitbucket Cloud.

        To keep the cross-provider audit uniform, the method exists and
        returns an empty list (the same normalized shape the other SCMs would
        yield, just with no entries) and records a single non-fatal
        ``warnings`` note so the operator understands the empty result
        reflects a platform-model difference, not a clean bill of health.
        Read-only — it makes no request at all.
        """
        self.warnings.append(
            "deployment-protection audit is unsupported on Bitbucket Cloud "
            "(no per-environment custom-rule app API; the admin_only deploy "
            "gate is surfaced by --audit-actions-environments); result is "
            "empty by design, not a clean bill of health"
        )
        return []

    def audit_repo_visibility(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """Audit the visibility posture of the repos this token can reach.

        Bitbucket Cloud's analogue of GitHub's repo-visibility audit. Where the
        ``--enumerate-*`` flags map a token's offensive reach, this reports the
        *exposure* posture: which reachable repos are PUBLIC. A public Bitbucket
        repo is world-readable source/history/issues — the external attack
        surface a private repo is not — and is where covenant's own secret
        scanning has the most to find.

        Walks ``GET /2.0/repositories?role=member`` with the shared
        ``next``-envelope paginator and returns
        ``{"repo", "visibility", "public"}`` dicts. Bitbucket reports a boolean
        ``is_private``; covenant derives ``public`` from it and surfaces a
        human-readable ``visibility`` label (``private``/``public``). Only repo
        metadata is read.
        """
        results: list[dict] = []
        for resp in self._get_paginated(
            "/2.0/repositories",
            params={"role": "member", "pagelen": 100},
            max_pages=max_pages,
            next_request=_bitbucket_next,
        ):
            for item in resp.json().get("values", []):
                full_name = item.get("full_name")
                if not full_name:
                    continue
                is_private = bool(item.get("is_private", True))
                results.append(
                    {
                        "repo": full_name,
                        "visibility": "private" if is_private else "public",
                        "public": not is_private,
                    }
                )
        return results

    def audit_codeowners(self, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        """Audit the CODEOWNERS coverage of the repos this token can reach.

        CODEOWNERS routes mandatory review to a named owner per path and is the
        partner control to branch protection: Bitbucket honors it via the
        *Code owners approval* merge check — but only for paths a rule matches. A
        repo with NO CODEOWNERS file (``present=false``) cannot gate review by
        owner at all, and one whose CODEOWNERS has rules but no catch-all ``*``
        leaves every unmatched path with no required owner, a gap that the
        branch-protection audit alone does not reveal.

        Walks the repositories the token can reach
        (``GET /2.0/repositories?role=member``) and, for each, probes the
        standard CODEOWNERS locations (``CODEOWNERS``, ``docs/CODEOWNERS`` — and,
        for parity, the provider directory, though Bitbucket reads it from the
        root) via the source API
        (``GET /2.0/repositories/{full_name}/src/HEAD/{path}``, which returns the
        file's RAW text on the main branch's tip), reporting the first one found.
        Returns the same normalized
        ``{"repo", "present", "path", "rule_count", "has_global_owner"}`` shape as
        the other SCMs. Only the rule COUNT and the presence of a ``*`` catch-all
        are surfaced — the owner handles are not echoed and no other content is
        read. Read-only.
        """
        results: list[dict] = []
        for full_name in self._reachable_repos(max_pages=max_pages):
            record = {
                "repo": full_name,
                "present": False,
                "path": None,
                "rule_count": 0,
                "has_global_owner": False,
            }
            # Bitbucket resolves CODEOWNERS from the repo root (and docs/); it has
            # no provider directory, so an empty provider arg drops that probe.
            for path in codeowners_candidate_paths(""):
                text = self._fetch_file_content(
                    f"/2.0/repositories/{full_name}/src/HEAD/{path}"
                )
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
        """Inventory the declared package dependencies of reachable repos.

        Where ``--audit-dependabot-alerts`` is a no-op on Bitbucket Cloud (it has
        no first-party dependency-alert API), this audit DOES work there: it reads
        the dependency surface straight from the manifest files in the repo, so a
        Bitbucket-only engagement still gets a full declared-dependency inventory —
        the software-supply-chain map an operator needs before triaging which
        package is vulnerable, typosquatted, or abandoned.

        Walks the repositories the token can reach
        (``GET /2.0/repositories?role=member``) and, for each, probes the repo
        root for the supported manifest files (``package.json``,
        ``requirements.txt``, ``pyproject.toml``, ``Pipfile``, ``go.mod``,
        ``Gemfile``, ``pom.xml``) via the source API
        (``GET /2.0/repositories/{full_name}/src/HEAD/{manifest}``, which returns
        the file's RAW text on the main branch's tip). Each declared package
        becomes one normalized
        ``{"repo", "manifest", "ecosystem", "package", "version"}`` dict, the same
        cross-provider shape as the other SCMs. ``version`` is the spec the manifest
        declares (never resolved) and is ``null`` when unpinned. A repo with no
        recognized manifest contributes no rows. Read-only — only the named manifest
        files are read and only package names + declared versions are surfaced.
        """
        results: list[dict] = []
        for full_name in self._reachable_repos(max_pages=max_pages):
            for manifest, ecosystem in PACKAGE_MANIFESTS:
                text = self._fetch_file_content(
                    f"/2.0/repositories/{full_name}/src/HEAD/{manifest}"
                )
                if text is None:
                    continue
                for pkg in parse_manifest(manifest, text):
                    results.append(
                        {
                            "repo": full_name,
                            "manifest": manifest,
                            "ecosystem": ecosystem,
                            "package": pkg["package"],
                            "version": pkg["version"],
                        }
                    )
        return results

    def _fetch_file_content(self, path: str) -> str | None:
        """GET a repo file's RAW text, or ``None`` if it does not exist.

        Bitbucket's source API returns the file body verbatim (not a JSON
        envelope), so we read ``resp.text`` directly. A 404 (file absent on the
        ref) returns ``None`` so the caller can probe several candidate paths
        cheaply.
        """
        url = f"{self.base_url}{path}"
        resp = self._request_with_retry(url, None, self._headers())
        if resp.status_code == 404:
            return None
        if resp.status_code == 401:
            raise SCMError("authentication failed (401) — check the token")
        if resp.status_code >= 400:
            raise SCMError(
                f"{self.base_url} returned HTTP {resp.status_code} for {path}"
            )
        return resp.text

    def audit_dependabot_alerts(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """No-op on Bitbucket Cloud, which has no dependency-alert API.

        GitHub's Dependabot alerts and GitLab's dependency-scanning
        vulnerabilities both expose a known-vulnerability attack surface over a
        read-only REST endpoint. Bitbucket Cloud has no equivalent surface: its
        dependency security is delivered through third-party Pipelines
        integrations (e.g. Snyk) rather than a first-party, token-readable
        ``alerts`` endpoint, so there is nothing for covenant to enumerate here.

        To keep the cross-provider audit uniform, the method exists and returns an
        empty list (the same normalized shape as the other SCMs would yield, just
        with no entries) and records a single non-fatal ``warnings`` note so the
        operator understands the empty result reflects a platform limitation, not
        a clean bill of health. Read-only — it makes no request at all.
        """
        self.warnings.append(
            "dependabot-alerts audit is unsupported on Bitbucket Cloud "
            "(no first-party dependency-alert API); result is empty by design, "
            "not a clean bill of health"
        )
        return []

    def audit_secret_scanning(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """No-op on Bitbucket Cloud, which has no secret-scanning-alert API.

        GitHub's secret-scanning alerts and GitLab's secret-detection findings
        both expose, over a read-only REST endpoint, the credentials the
        platform's own scanner has already detected committed in a repo.
        Bitbucket Cloud has no equivalent first-party surface: secret detection
        on Bitbucket is delivered through third-party Pipelines integrations
        rather than a token-readable ``alerts`` endpoint, so there is nothing for
        covenant to enumerate here.

        To keep the cross-provider audit uniform, the method exists and returns
        an empty list (the same normalized shape as the other SCMs would yield,
        just with no entries) and records a single non-fatal ``warnings`` note so
        the operator understands the empty result reflects a platform limitation,
        not a clean bill of health. Read-only — it makes no request at all.
        """
        self.warnings.append(
            "secret-scanning audit is unsupported on Bitbucket Cloud "
            "(no first-party secret-scanning-alert API); result is empty by "
            "design, not a clean bill of health"
        )
        return []

    def audit_code_scanning_alerts(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """No-op on Bitbucket Cloud, which has no code-scanning-alert API.

        GitHub's code-scanning alerts and GitLab's SAST findings both expose, over
        a read-only REST endpoint, the vulnerabilities the platform's own static
        analyzer found in a repo's first-party source. Bitbucket Cloud has no
        equivalent first-party surface: static analysis on Bitbucket is delivered
        through third-party Pipelines integrations (e.g. SonarQube, Snyk Code)
        rather than a token-readable ``alerts`` endpoint, so there is nothing for
        covenant to enumerate here.

        To keep the cross-provider audit uniform, the method exists and returns an
        empty list (the same normalized shape as the other SCMs would yield, just
        with no entries) and records a single non-fatal ``warnings`` note so the
        operator understands the empty result reflects a platform limitation, not
        a clean bill of health. Read-only — it makes no request at all.
        """
        self.warnings.append(
            "code-scanning-alerts audit is unsupported on Bitbucket Cloud "
            "(no first-party static-analysis-alert API); result is empty by "
            "design, not a clean bill of health"
        )
        return []

    def audit_advisory_alerts(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """No-op on Bitbucket Cloud, which has no repository advisory API.

        The GitHub flag enumerates the repository security advisories a repo's own
        maintainers published against their own product. Bitbucket Cloud has no
        equivalent first-party surface: it offers no token-readable endpoint where
        a repository publishes maintainer-authored advisories about its own code,
        so there is nothing for covenant to enumerate here.

        To keep the cross-provider audit uniform, the method exists and returns an
        empty list (the same normalized shape the other SCMs would yield, just
        with no entries) and records a single non-fatal ``warnings`` note so the
        empty result is not misread as a clean bill of health. Read-only — it
        makes no request at all.
        """
        self.warnings.append(
            "advisory-alerts audit is unsupported on Bitbucket Cloud "
            "(no maintainer-authored repository advisory API); result is empty "
            "by design, not a clean bill of health"
        )
        return []

    def audit_actions_permissions(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """No-op on Bitbucket Cloud, which has no Actions-permission API.

        The GitHub flag audits the policy that governs what a workflow run may
        do — whether Actions is enabled and the default read/write permission of
        the automatic ``GITHUB_TOKEN`` it grants. Bitbucket Pipelines has no
        token-readable equivalent: a pipeline's effective permissions derive from
        the (write-only, non-enumerable) repository/workspace variables and the
        runner configuration rather than a per-repo ``permissions`` endpoint, so
        there is nothing for covenant to enumerate here.

        To keep the cross-provider audit uniform, the method exists and returns
        an empty list (the same normalized shape the other SCMs would yield, just
        with no entries) and records a single non-fatal ``warnings`` note so the
        empty result is not misread as a clean bill of health. Read-only — it
        makes no request at all.
        """
        self.warnings.append(
            "actions-permissions audit is unsupported on Bitbucket Cloud "
            "(no per-repo Pipelines-permission API); result is empty by "
            "design, not a clean bill of health"
        )
        return []

    def audit_workflow_runs(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """Audit recent Bitbucket Pipelines runs across reachable repos.

        Bitbucket Cloud's analogue of GitHub's workflow-run audit. The decisive
        signal is anomalous pipeline activity: a streak of
        ``conclusion="FAILED"`` runs (active attack attempts, broken CI gates,
        runners under load), a ``conclusion="STOPPED"`` run (operator/defender
        intervention killing a job in flight), or an unexpected ``event``
        (trigger) distribution — e.g. a sudden burst of ``MANUAL`` triggers or
        off-hours ``SCHEDULE`` runs (a planted scheduled pipeline) is a
        CI-misuse signal a posture audit alone does not catch.

        Walks the repositories the token can reach
        (``GET /2.0/repositories?role=member``) and, for each, lists
        ``GET /2.0/repositories/{full_name}/pipelines/`` (sorted newest first
        via ``sort=-created_on``), normalizing each pipeline to
        ``{"repo", "run_id", "name", "event", "status", "conclusion",
        "created_at"}`` for cross-SCM parity. ``run_id`` is the pipeline's
        ``uuid``; ``name`` is the target ``ref_name`` (the branch/tag the
        pipeline ran on) so an operator can see *which* branch a suspicious
        run targeted; ``event`` is the trigger name (``PUSH``/``MANUAL``/
        ``SCHEDULE``/...); ``status`` is the lifecycle state
        (``PENDING``/``IN_PROGRESS``/``COMPLETED``); and ``conclusion`` is the
        terminal outcome (``SUCCESSFUL``/``FAILED``/``STOPPED``/``ERROR``/...) —
        ``None`` while still running.

        Only pipeline *metadata* is surfaced — step logs, artifact URLs, and
        any Pipelines variable values the run saw are never fetched. A repo
        with Pipelines disabled or out of the token's scope answers 403/404;
        covenant skips it (returning nothing for that repo) rather than
        aborting the whole audit. Read-only — it never re-runs, stops, or
        triggers a pipeline.
        """
        results: list[dict] = []
        for full_name in self._reachable_repos(max_pages=max_pages):
            try:
                pages = list(
                    self._get_paginated(
                        f"/2.0/repositories/{full_name}/pipelines/",
                        params={"pagelen": 100, "sort": "-created_on"},
                        max_pages=max_pages,
                        next_request=_bitbucket_next,
                    )
                )
            except SCMError:
                continue
            for resp in pages:
                for item in resp.json().get("values", []):
                    uuid = item.get("uuid")
                    if not uuid:
                        continue
                    state = item.get("state") or {}
                    state_name = state.get("name")
                    result = state.get("result") or {}
                    conclusion = result.get("name")
                    trigger = item.get("trigger") or {}
                    target = item.get("target") or {}
                    results.append(
                        {
                            "repo": full_name,
                            "run_id": uuid,
                            "name": target.get("ref_name"),
                            "event": trigger.get("name"),
                            "status": state_name,
                            "conclusion": conclusion,
                            "created_at": item.get("created_on"),
                        }
                    )
        return results

    def audit_branch_ruleset(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """No-op on Bitbucket Cloud, which has no branch-ruleset API.

        Bitbucket Cloud's policy model for gating code landing on a branch is
        delivered exclusively through ``branch-restrictions`` (already covered
        by :meth:`audit_branch_protection`); it has no separate named
        rule-collection object with an enforcement mode and a bypass-actor
        list, the way GitHub branch rulesets do (and that GitLab push rules
        approximate). There is therefore nothing for covenant to enumerate
        here.

        To keep the cross-provider audit uniform, the method exists and
        returns an empty list (the same normalized shape as the other SCMs
        would yield, just with no entries) and records a single non-fatal
        ``warnings`` note so the operator understands the empty result
        reflects a platform limitation, not a clean bill of health — and a
        pointer to ``--audit-branch-protection`` which DOES cover Bitbucket
        Cloud's equivalent surface. Read-only — it makes no request at all.
        """
        self.warnings.append(
            "branch-ruleset audit is unsupported on Bitbucket Cloud "
            "(no named-ruleset API; branch policy lives in "
            "branch-restrictions, covered by --audit-branch-protection); "
            "result is empty by design, not a clean bill of health"
        )
        return []

    def enumerate_members(self, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        """List the other members of the workspaces this token can reach.

        Bitbucket Cloud's analogue of GitHub org-member enumeration. Where the
        rest of the ``--enumerate-*`` family maps what *this* token reaches,
        member enumeration maps the *people* who share that reach: the accounts
        with membership in each workspace the token can access, and at what
        permission level. That is the lateral-movement surface (other identities
        an operator could target to widen a foothold) and, for the workspace
        owners specifically, the accounts whose compromise grants administrative
        control of the workspace.

        Walks the workspaces the token can reach (via :meth:`enumerate_orgs`)
        and, for each, lists ``GET /2.0/workspaces/{slug}/members`` with the
        shared ``next``-envelope paginator. Each membership carries a
        ``user`` object (we surface its ``nickname``/``display_name`` as the
        ``username``) and a ``permission`` level; we normalize ``owner`` to
        ``role="admin"`` and everything else to ``role="member"`` so the shape
        matches the other SCMs. Returns ``{"scope", "owner", "username", "role"}``
        dicts (``scope`` is ``"workspace"``). Only membership identity is
        surfaced — no token, no key, no email — a read-only directory query.
        """
        results: list[dict] = []
        for workspace in self.enumerate_orgs(max_pages=max_pages):
            owner = workspace.get("name")
            if not owner:
                continue
            for resp in self._get_paginated(
                f"/2.0/workspaces/{owner}/members",
                params={"pagelen": 100},
                max_pages=max_pages,
                next_request=_bitbucket_next,
            ):
                for item in resp.json().get("values", []):
                    user = item.get("user") or {}
                    username = (
                        user.get("nickname")
                        or user.get("display_name")
                        or user.get("username")
                    )
                    if not username:
                        continue
                    permission = item.get("permission")
                    results.append(
                        {
                            "scope": "workspace",
                            "owner": owner,
                            "username": username,
                            "role": "admin"
                            if permission == "owner"
                            else "member",
                        }
                    )
        return results

    def enumerate_collaborators(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """List the per-repo user grants on the repos this token can reach.

        Bitbucket Cloud's analogue of GitHub outside-collaborator enumeration.
        Where :meth:`enumerate_members` maps the people who share a *workspace's*
        reach, this is repo-scoped and surfaces the higher-signal blast radius:
        the individual user accounts granted access DIRECTLY on a specific
        repository via its explicit user-permission config, rather than via
        workspace membership. A direct repo grant is Bitbucket's outside-
        collaborator equivalent — a personal account bolted onto one repo (often
        a contractor or ex-employee) that a workspace-member audit misses and
        that survives long after the person leaves. A repo with a write-or-above
        direct grant is a supply-chain and persistence risk.

        Walks the repositories the token can reach
        (``GET /2.0/repositories?role=member``) and, for each, lists its explicit
        user permissions (``GET /2.0/repositories/{workspace}/{repo}/
        permissions-config/users``). Each entry carries a ``user`` object (we
        surface its ``nickname``/``display_name`` as ``username``) and a
        ``permission`` level (``admin``/``write``/``read``); we surface the
        permission verbatim as ``role`` (it already matches the cross-SCM
        vocabulary). Every returned account is a direct (outside-style) grant, so
        ``outside`` is ``True``. The endpoint requires repo-admin and a low-
        privilege token gets a 403, so it fails soft (that repo contributes
        nothing) rather than aborting the audit. Returns a normalized list of
        ``{"repo", "username", "role", "outside"}`` dicts. Only membership
        identity and the permission level are surfaced — never an email, key, or
        credential. Read-only.
        """
        results: list[dict] = []
        for full_name in self._reachable_repos(max_pages=max_pages):
            try:
                pages = list(
                    self._get_paginated(
                        f"/2.0/repositories/{full_name}/permissions-config/users",
                        params={"pagelen": 100},
                        max_pages=max_pages,
                        next_request=_bitbucket_next,
                    )
                )
            except SCMError:
                # Repo-admin is required to read the explicit-permission config;
                # a low-privilege token gets a 403. Fail soft so the audit still
                # reports the repos it can see.
                continue
            for resp in pages:
                for item in resp.json().get("values", []):
                    user = item.get("user") or {}
                    username = (
                        user.get("nickname")
                        or user.get("display_name")
                        or user.get("username")
                    )
                    if not username:
                        continue
                    results.append(
                        {
                            "repo": full_name,
                            "username": username,
                            "role": item.get("permission") or "read",
                            "outside": True,
                        }
                    )
        return results

    def scan_commits(self, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        """Collect commit metadata + messages from the repos this token reaches.

        The Bitbucket Cloud analogue of GitHub commit-history scanning. Commit
        *messages* are a notorious secret-leak vector: a credential scrubbed from
        a tracked file routinely survives verbatim in the commit message, in a
        revert/merge body quoting a diff, or in an automated bump commit. Where
        ``--scan-secrets`` only sees the *current* file content the code-search
        API returns, this maps the leak surface in *history*: it walks the recent
        commits the token can read and surfaces each commit's message for the
        caller to scan with the same :func:`covenant.secrets.scan_fragments`
        machinery.

        Walks the repositories the token is a member of
        (``GET /2.0/repositories?role=member``) and, for each, lists
        ``GET /2.0/repositories/{full_name}/commits`` (newest first), returning
        one normalized ``{"repo", "sha", "author", "message"}`` record per commit.
        ``author`` is the author's display name/nickname (identity only — the raw
        ``raw`` author string carrying an email is deliberately parsed down to the
        display name) and ``message`` is the raw commit message; the commit
        *diff* is never fetched. Read-only.
        """
        results: list[dict] = []
        for full_name in self._reachable_repos(max_pages=max_pages):
            for resp in self._get_paginated(
                f"/2.0/repositories/{full_name}/commits",
                params={"pagelen": 100},
                max_pages=max_pages,
                next_request=_bitbucket_next,
            ):
                for item in resp.json().get("values", []):
                    sha = item.get("hash")
                    if not sha:
                        continue
                    author = item.get("author") or {}
                    user = author.get("user") or {}
                    # Surface only the display identity; never the `raw`
                    # "Name <email>" string (which carries the author email).
                    author_name = (
                        user.get("nickname")
                        or user.get("display_name")
                    )
                    results.append(
                        {
                            "repo": full_name,
                            "sha": sha,
                            "author": author_name,
                            "message": item.get("message", ""),
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
