"""GitHub SCM client (cloud GitHub for v0.1; GHE deferred to v0.2)."""

from __future__ import annotations

import httpx

import base64

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

# GitHub's text-match Accept header requests snippet fragments alongside code
# search results so we can scan them for secrets without a separate fetch.
_TEXT_MATCH_ACCEPT = "application/vnd.github.text-match+json"


def _github_branch_policy(policy: dict | None) -> str:
    """Map GitHub's ``deployment_branch_policy`` object to a flat label.

    GitHub reports the branch restriction for a deployment environment as a
    ``{"protected_branches": bool, "custom_branch_policies": bool}`` object, or
    ``null`` when no policy is configured. ``null`` (or both flags false) means
    *any* branch may deploy — the weakest posture — which we report as
    ``"all"``. ``protected_branches`` restricts deployment to the repo's
    protected branches (``"protected"``); ``custom_branch_policies`` allows a
    custom allow-list of branch-name patterns (``"custom"``). When both are set
    we report ``"custom"`` (the more permissive of the two — a custom allow-list
    can include unprotected patterns).
    """
    if not isinstance(policy, dict):
        return "all"
    if policy.get("custom_branch_policies"):
        return "custom"
    if policy.get("protected_branches"):
        return "protected"
    return "all"


def _github_collaborator_role(collaborator: dict) -> str:
    """Reduce a GitHub collaborator object to its highest-privilege role label.

    GitHub reports a collaborator's access both as a ``role_name`` string and a
    ``permissions`` boolean map (``admin``/``maintain``/``push``/``triage``/
    ``pull``). We collapse this to the single most-privileged label so the
    blast-radius signal is unambiguous, checking the map from highest to lowest
    privilege and falling back to ``role_name`` (normalizing ``push`` -> ``write``
    and ``pull`` -> ``read``) when the map is absent. An unrecognized shape
    reports ``"read"`` (the least-privilege, safe default).
    """
    perms = collaborator.get("permissions")
    if isinstance(perms, dict):
        for label in ("admin", "maintain", "push", "triage", "pull"):
            if perms.get(label):
                return {"push": "write", "pull": "read"}.get(label, label)
    role_name = collaborator.get("role_name")
    if role_name:
        return {"push": "write", "pull": "read"}.get(role_name, role_name)
    return "read"


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

    def enumerate_actions_secrets(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """List the GitHub Actions secret NAMES this token can reach.

        Where the SSH/GPG/deploy-key enumerations map *key* material and the
        webhook enumeration maps the exfiltration surface, CI/CD secrets are the
        credential surface that powers the build pipeline: cloud keys, registry
        passwords, signing tokens and deploy credentials all live here, and an
        attacker who can read or, worse, exfiltrate them via a malicious workflow
        gains exactly the lateral-movement and supply-chain reach the pipeline
        had. A repo or org carrying a long list of Actions secrets is a
        high-value, high-blast-radius target.

        This walks both axes the token can reach:

        * **org-level** secrets — ``GET /orgs/{org}/actions/secrets`` for each
          org from :meth:`enumerate_orgs` (``scope="org"``);
        * **repo-level** secrets — ``GET /repos/{owner}/{repo}/actions/secrets``
          for each repo from :meth:`_reachable_repos` (``scope="repo"``).

        It returns a normalized list of ``{"scope", "owner", "name", "protected"}``
        dicts. Critically, the GitHub API returns only the secret *name* and
        metadata — never the value — and covenant surfaces ONLY the name (the
        excessive-exposure signal). The ``protected`` field is ``True`` for an
        org secret whose ``visibility`` is restricted to selected repositories
        (a tighter blast radius); repo secrets have no such field and report
        ``False``. The audit is read-only and never reads or echoes a value.
        """
        results: list[dict] = []
        for org in self.enumerate_orgs(max_pages=max_pages):
            owner = org.get("name")
            if not owner:
                continue
            for resp in self._get_paginated(
                f"/orgs/{owner}/actions/secrets",
                params={"per_page": 100},
                max_pages=max_pages,
                next_request=_next_link,
            ):
                body = resp.json()
                if not isinstance(body, dict):
                    continue
                for item in body.get("secrets", []):
                    name = item.get("name")
                    if not name:
                        continue
                    results.append(
                        {
                            "scope": "org",
                            "owner": owner,
                            "name": name,
                            "protected": item.get("visibility", "all")
                            == "selected",
                        }
                    )
        for full_name in self._reachable_repos(max_pages=max_pages):
            for resp in self._get_paginated(
                f"/repos/{full_name}/actions/secrets",
                params={"per_page": 100},
                max_pages=max_pages,
                next_request=_next_link,
            ):
                body = resp.json()
                if not isinstance(body, dict):
                    continue
                for item in body.get("secrets", []):
                    name = item.get("name")
                    if not name:
                        continue
                    results.append(
                        {
                            "scope": "repo",
                            "owner": full_name,
                            "name": name,
                            "protected": False,
                        }
                    )
        return results

    def audit_actions_environments(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """Audit the deployment-environment gate posture of reachable repos.

        A *deployment environment* (GitHub Actions "Environments") is where the
        most sensitive CI/CD secrets live — the production cloud keys, registry
        passwords and deploy tokens that :meth:`enumerate_actions_secrets` finds
        scoped per-environment. The environment's *protection rules* are the gate
        that decides whether a workflow may deploy to it (and thereby read those
        secrets): a *required-reviewers* rule forces a human to approve the
        deployment, a *wait timer* delays it, and a *deployment branch policy*
        restricts which branches may deploy at all.

        The high-signal finding is an environment that protects valuable secrets
        but gates them weakly: ``required_reviewers=False`` **and** a permissive
        ``branch_policy`` of ``"all"`` means any branch — including an attacker's
        feature branch carrying a malicious workflow — can deploy to that
        environment and exfiltrate its secrets unreviewed. This is the
        environment-scoped, secret-exfiltration counterpart to
        :meth:`audit_branch_protection` (which gates code landing on a branch);
        here we gate *deployments* reaching the secrets.

        Walks the repositories the token can reach (``GET /user/repos``) and, for
        each, lists ``GET /repos/{owner}/{repo}/environments`` then maps each
        environment's ``protection_rules`` and ``deployment_branch_policy`` into
        the normalized
        ``{"repo", "environment", "required_reviewers",
        "required_reviewer_count", "wait_timer", "branch_policy"}`` shape.
        ``branch_policy`` is ``"protected"`` (only protected branches may
        deploy), ``"custom"`` (a custom allow-list of branch name patterns), or
        ``"all"`` (no branch restriction — any branch may deploy, the weakest
        posture). This is read-only — it only GETs policy metadata and never
        creates, edits, or triggers a deployment.
        """
        results: list[dict] = []
        for full_name in self._reachable_repos(max_pages=max_pages):
            for resp in self._get_paginated(
                f"/repos/{full_name}/environments",
                params={"per_page": 100},
                max_pages=max_pages,
                next_request=_next_link,
            ):
                body = resp.json()
                # GitHub wraps environments in {"total_count", "environments"}.
                if not isinstance(body, dict):
                    continue
                for env in body.get("environments", []):
                    name = env.get("name")
                    if not name:
                        continue
                    required_reviewers = False
                    required_reviewer_count = 0
                    wait_timer = 0
                    for rule in env.get("protection_rules", []):
                        rule_type = rule.get("type")
                        if rule_type == "required_reviewers":
                            required_reviewers = True
                            required_reviewer_count = len(
                                rule.get("reviewers", [])
                            )
                        elif rule_type == "wait_timer":
                            wait_timer = int(rule.get("wait_timer", 0) or 0)
                    results.append(
                        {
                            "repo": full_name,
                            "environment": name,
                            "required_reviewers": required_reviewers,
                            "required_reviewer_count": required_reviewer_count,
                            "wait_timer": wait_timer,
                            "branch_policy": _github_branch_policy(
                                env.get("deployment_branch_policy")
                            ),
                        }
                    )
        return results

    def audit_repo_visibility(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """Audit the visibility posture of the repos this token can reach.

        Where the ``--enumerate-*`` flags map a captured token's *offensive*
        reach (keys it owns, repos it can push to, secrets it can read), the
        visibility audit reports the *exposure* posture: which reachable repos
        are PUBLIC. A public repo is the org's external attack surface — its
        full source, history, issues and (often) leaked secrets are world-
        readable. An unexpectedly public repo (a repo that should be private
        given its name or its private siblings) is a direct leak/supply-chain
        risk, and a public repo is also where covenant's own ``recon-code``
        secret scanning has the most to find. Flagging the public set lets an
        operator triage the externally-reachable surface first.

        Walks ``GET /user/repos`` with the shared paginator and returns a
        normalized list of ``{"repo", "visibility", "public"}`` dicts. GitHub
        repos report a boolean ``private`` (and, on newer API versions, a
        ``visibility`` string of ``public``/``private``/``internal``); covenant
        derives ``public`` from ``private`` and surfaces the human-readable
        ``visibility`` label. Only repo metadata is read — no code, no secrets.
        """
        results: list[dict] = []
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
                if not full_name:
                    continue
                is_private = bool(item.get("private", True))
                visibility = item.get("visibility") or (
                    "private" if is_private else "public"
                )
                results.append(
                    {
                        "repo": full_name,
                        "visibility": visibility,
                        "public": not is_private,
                    }
                )
        return results

    def audit_codeowners(self, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        """Audit the CODEOWNERS coverage of the repos this token can reach.

        CODEOWNERS is the file that routes mandatory review to a named owner per
        path. It is the partner control to branch protection: a protected branch
        with ``require_code_owner_reviews`` enforces that the right owner signs
        off — but ONLY for paths a CODEOWNERS rule matches. A repo with NO
        CODEOWNERS file (``present=false``) cannot gate review by owner at all,
        and a repo whose CODEOWNERS has rules but no catch-all ``*`` leaves every
        unmatched path — including a newly added file an attacker introduces —
        with no required owner, a silent gap that ``--audit-branch-protection``
        alone does not reveal. This audit surfaces that posture so an operator can
        triage which reachable repos lack an owner-review safety net.

        Walks the repositories the token can reach (``GET /user/repos``) and, for
        each, probes the standard CODEOWNERS locations
        (``.github/CODEOWNERS``, ``CODEOWNERS``, ``docs/CODEOWNERS``) via
        ``GET /repos/{owner}/{repo}/contents/{path}`` (which defaults to the
        repo's default branch), reporting the first one found. Returns a
        normalized list of
        ``{"repo", "present", "path", "rule_count", "has_global_owner"}`` dicts.
        Only the rule COUNT and the presence of a ``*`` catch-all are surfaced —
        the owner handles themselves are not echoed, and no other repository
        content is read. Read-only.
        """
        results: list[dict] = []
        for full_name in self._reachable_repos(max_pages=max_pages):
            results.append(self._codeowners_for_repo(full_name))
        return results

    def _codeowners_for_repo(self, full_name: str) -> dict:
        """Probe one repo's CODEOWNERS locations and normalize the result."""
        record = {
            "repo": full_name,
            "present": False,
            "path": None,
            "rule_count": 0,
            "has_global_owner": False,
        }
        for path in codeowners_candidate_paths(".github"):
            text = self._fetch_file_content(f"/repos/{full_name}/contents/{path}")
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
        return record

    def _fetch_file_content(self, path: str) -> str | None:
        """GET a repo file's decoded text, or ``None`` if it does not exist.

        Uses ``GET /repos/{owner}/{repo}/contents/{path}`` which returns a JSON
        object carrying base64-encoded ``content``. A 404 (file absent) returns
        ``None`` rather than raising so the caller can probe several candidate
        paths cheaply. Only the requested file is read.
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
        body = resp.json()
        if not isinstance(body, dict):
            return None
        encoded = body.get("content")
        if not isinstance(encoded, str):
            return ""
        if body.get("encoding") == "base64" or "\n" in encoded or encoded.strip():
            try:
                return base64.b64decode(encoded).decode("utf-8", errors="replace")
            except (ValueError, TypeError):
                return ""
        return ""

    def audit_packages(self, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        """Inventory the declared package dependencies of reachable repos.

        Where ``--audit-dependabot-alerts`` reports KNOWN-vulnerable dependencies
        (those a provider scanner has already flagged), this reports the FULL
        declared dependency surface: every package a reachable repo's manifest
        files pull in, named with its declared version and ecosystem. It is the
        software-supply-chain complement to covenant's security-configuration
        audits — the inventory an operator needs before asking "which of these is
        vulnerable / typosquatted / abandoned?", and the surface a Dependabot
        audit can only annotate, not enumerate.

        Walks the repositories the token can reach (``GET /user/repos``) and, for
        each, probes the repo root for the supported manifest files
        (``package.json``, ``requirements.txt``, ``pyproject.toml``, ``Pipfile``,
        ``go.mod``, ``Gemfile``, ``pom.xml``) via
        ``GET /repos/{owner}/{repo}/contents/{manifest}`` (which defaults to the
        repo's default branch). Each declared package becomes one normalized
        ``{"repo", "manifest", "ecosystem", "package", "version"}`` dict.
        ``version`` is the spec the manifest *declares* (covenant inventories the
        declaration, it never resolves or installs anything) and is ``null`` when
        no version is pinned. A repo with no recognized manifest contributes no
        rows. Read-only — only the named manifest files are read (never lockfile
        graphs, never source), and only package names + declared versions are
        surfaced.
        """
        results: list[dict] = []
        for full_name in self._reachable_repos(max_pages=max_pages):
            for manifest, ecosystem in PACKAGE_MANIFESTS:
                text = self._fetch_file_content(
                    f"/repos/{full_name}/contents/{manifest}"
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

    def audit_dependabot_alerts(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """Audit the OPEN Dependabot vulnerability alerts on reachable repos.

        Where ``--audit-branch-protection`` / ``--audit-codeowners`` report
        *process* gaps (would a bad push be stopped?), Dependabot alerts report a
        *known-vulnerability* attack surface: every open alert is a
        publicly-documented CVE/GHSA in a dependency the repo actually ships, with
        a known severity and (often) a known exploit. For an authorized engagement
        this is a high-signal triage axis — a reachable repo carrying open
        ``critical`` alerts in an internet-facing ecosystem is where a real
        intrusion is most likely to start, and the alert names the exact package
        and advisory so the operator can map it to an exploit without further
        probing.

        Walks the repositories the token can reach (``GET /user/repos``) and, for
        each, lists its OPEN Dependabot alerts
        (``GET /repos/{owner}/{repo}/dependabot/alerts?state=open``), returning a
        normalized list of
        ``{"repo", "package", "ecosystem", "severity", "state", "identifier"}``
        dicts. ``severity`` is the advisory's CVSS band
        (``critical``/``high``/``medium``/``low``) and ``identifier`` is the
        GHSA/CVE id (the advisory handle, NOT a credential). Only OPEN alerts are
        requested — a dismissed/fixed alert is not live surface. A repo with
        Dependabot disabled (or a token lacking the ``security_events`` scope)
        returns HTTP 403/404 for that repo; covenant skips it rather than failing
        the whole audit, so a partial-permission token still reports what it can
        see. Read-only — it only GETs alert metadata and never dismisses, fixes,
        or creates an alert.
        """
        results: list[dict] = []
        for full_name in self._reachable_repos(max_pages=max_pages):
            for record in self._dependabot_alerts_for_repo(
                full_name, max_pages=max_pages
            ):
                results.append(record)
        return results

    def _dependabot_alerts_for_repo(
        self, full_name: str, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """List one repo's open Dependabot alerts, skipping repos we can't read.

        Dependabot alerts are only readable when the feature is enabled on the
        repo AND the token carries the ``security_events`` (or, for public repos,
        ``public_repo``) scope; otherwise GitHub answers 403/404. We swallow those
        two statuses for a single repo and return no alerts for it rather than
        aborting the whole audit, so a token with mixed permissions still reports
        every repo it CAN read.
        """
        records: list[dict] = []
        url = f"{self.base_url}/repos/{full_name}/dependabot/alerts"
        probe = self._request_with_retry(
            url, {"state": "open", "per_page": 100}, self._headers()
        )
        # A repo with Dependabot disabled, or a token without the
        # security_events scope, yields 403/404 — skip it, do not fail the run.
        if probe.status_code in (403, 404):
            return records
        if probe.status_code == 401:
            raise SCMError("authentication failed (401) — check the token")
        if probe.status_code >= 400:
            raise SCMError(
                f"{self.base_url} returned HTTP {probe.status_code} "
                f"for {full_name} dependabot alerts"
            )
        for resp in self._get_paginated(
            f"/repos/{full_name}/dependabot/alerts",
            params={"state": "open", "per_page": 100},
            max_pages=max_pages,
            next_request=_next_link,
        ):
            body = resp.json()
            if not isinstance(body, list):
                continue
            for item in body:
                advisory = item.get("security_advisory") or {}
                vuln = item.get("security_vulnerability") or {}
                pkg = vuln.get("package") or {}
                # Prefer the GHSA id, falling back to the first CVE identifier.
                identifier = advisory.get("ghsa_id")
                if not identifier:
                    for ref in advisory.get("identifiers", []):
                        if ref.get("value"):
                            identifier = ref.get("value")
                            break
                records.append(
                    {
                        "repo": full_name,
                        "package": pkg.get("name"),
                        "ecosystem": pkg.get("ecosystem"),
                        "severity": vuln.get("severity")
                        or advisory.get("severity"),
                        "state": item.get("state", "open"),
                        "identifier": identifier,
                    }
                )
        return records

    def audit_secret_scanning(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """Audit the OPEN secret-scanning alerts on the reachable repos.

        Where ``--audit-dependabot-alerts`` reports a KNOWN-VULNERABILITY surface
        (a documented CVE in a dependency the repo ships), secret-scanning alerts
        report the highest-signal surface of all: a credential the provider's own
        scanner has ALREADY detected committed in the repo. An OPEN alert is a
        live leak the org has not yet remediated — the exact thing covenant's
        ``--scan-secrets``/``--scan-commits`` go looking for, except here the
        platform has already found and confirmed it. For an authorized engagement
        this is the first place to look: a reachable repo with open secret-scanning
        alerts is sitting on credentials that may still authenticate.

        Walks the repositories the token can reach (``GET /user/repos``) and, for
        each, lists its OPEN secret-scanning alerts
        (``GET /repos/{owner}/{repo}/secret-scanning/alerts?state=open``),
        returning a normalized list of
        ``{"repo", "secret_type", "state", "validity", "html_url"}`` dicts.
        ``secret_type`` is the provider's classifier for the leaked credential
        (e.g. ``aws_access_key_id``, ``github_personal_access_token``) — the KIND
        of secret, never its value. ``validity`` is GitHub's freshness signal
        (``active``/``inactive``/``unknown``) telling the operator whether the
        leaked credential is believed to still authenticate, the single most
        useful triage field. ``html_url`` points at the alert in the GitHub UI,
        not at the secret.

        **The decisive invariant**: the raw leaked secret is NEVER surfaced. The
        secret-scanning API returns the matched credential in a ``secret`` field
        (and a ``secret_type_display_name``); covenant reads neither — it reports
        only the classifier, state, validity, and the alert URL. Echoing the
        secret would make covenant's own report a new copy of the leak, the exact
        anti-pattern ``--scan-secrets`` redaction exists to prevent.

        Only OPEN alerts are requested — a resolved/dismissed alert is not a live
        leak. A repo with secret scanning disabled (or a token lacking the
        ``security_events`` scope, or a non-GHAS repo) answers HTTP 403/404 for
        that repo; covenant skips it rather than failing the whole audit, so a
        partial-permission token still reports what it can see. Read-only — it
        only GETs alert metadata and never resolves, dismisses, or reopens an
        alert.
        """
        results: list[dict] = []
        for full_name in self._reachable_repos(max_pages=max_pages):
            for record in self._secret_scanning_alerts_for_repo(
                full_name, max_pages=max_pages
            ):
                results.append(record)
        return results

    def _secret_scanning_alerts_for_repo(
        self, full_name: str, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """List one repo's open secret-scanning alerts, skipping repos we can't read.

        Secret-scanning alerts are only readable when the feature is enabled on
        the repo AND the token carries the ``security_events`` (or, for public
        repos, ``public_repo``) scope; otherwise GitHub answers 403/404. We
        swallow those two statuses for a single repo and return no alerts for it
        rather than aborting the whole audit, so a token with mixed permissions
        still reports every repo it CAN read.
        """
        records: list[dict] = []
        url = f"{self.base_url}/repos/{full_name}/secret-scanning/alerts"
        probe = self._request_with_retry(
            url, {"state": "open", "per_page": 100}, self._headers()
        )
        # A repo with secret scanning disabled, or a token without the
        # security_events scope, yields 403/404 — skip it, do not fail the run.
        if probe.status_code in (403, 404):
            return records
        if probe.status_code == 401:
            raise SCMError("authentication failed (401) — check the token")
        if probe.status_code >= 400:
            raise SCMError(
                f"{self.base_url} returned HTTP {probe.status_code} "
                f"for {full_name} secret-scanning alerts"
            )
        for resp in self._get_paginated(
            f"/repos/{full_name}/secret-scanning/alerts",
            params={"state": "open", "per_page": 100},
            max_pages=max_pages,
            next_request=_next_link,
        ):
            body = resp.json()
            if not isinstance(body, list):
                continue
            for item in body:
                # NEVER read item["secret"] or item["secret_type_display_name"]
                # — the raw credential and its decorated name must not leak into
                # covenant's report. Only the classifier, state, validity, and
                # the alert URL are surfaced.
                records.append(
                    {
                        "repo": full_name,
                        "secret_type": item.get("secret_type"),
                        "state": item.get("state", "open"),
                        "validity": item.get("validity") or "unknown",
                        "html_url": item.get("html_url"),
                    }
                )
        return records

    def audit_code_scanning_alerts(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """Audit the OPEN code-scanning alerts on the reachable repos.

        Where ``--audit-dependabot-alerts`` reports a KNOWN-VULNERABILITY surface
        in a repo's *third-party dependencies* and ``--audit-secret-scanning``
        reports already-detected leaked credentials, code-scanning alerts report
        the vulnerabilities the provider's static analyzer (GitHub Advanced
        Security / CodeQL, or a third-party SAST tool uploading SARIF) found in
        the repo's *own first-party source*: an injection sink, a hard-coded
        crypto misuse, a path-traversal, a deserialization flaw. For an authorized
        engagement this is a high-signal triage axis the dependency and
        credential audits do not cover — an open ``error``/``critical`` code-
        scanning alert in a reachable repo names the exact rule and source
        location where a real exploit is most likely to live, and (unlike a
        dependency CVE) it is a bug in code the org itself controls.

        Walks the repositories the token can reach (``GET /user/repos``) and, for
        each, lists its OPEN code-scanning alerts
        (``GET /repos/{owner}/{repo}/code-scanning/alerts?state=open``), returning
        a normalized list of
        ``{"repo", "rule_id", "rule_name", "severity", "state", "html_url"}``
        dicts. ``rule_id`` is the analyzer's rule identifier (e.g.
        ``py/sql-injection``), ``rule_name`` its human description, and
        ``severity`` the rule's security-severity band, preferring the
        ``security_severity_level`` (``critical``/``high``/``medium``/``low``)
        and falling back to the alert's generic ``severity``
        (``error``/``warning``/``note``) when the security band is absent — the
        decisive triage field. ``html_url`` points at the alert in the GitHub UI,
        at the finding's source location — never at a credential.

        Only OPEN alerts are requested — a dismissed/fixed alert is not live
        surface. A repo with code scanning disabled (or a token lacking the
        ``security_events`` scope, or a non-GHAS repo with no uploaded SARIF)
        answers HTTP 403/404 for that repo; covenant skips it rather than failing
        the whole audit, so a partial-permission token still reports what it can
        see. Read-only — it only GETs alert metadata and never dismisses, fixes,
        or creates an alert.
        """
        results: list[dict] = []
        for full_name in self._reachable_repos(max_pages=max_pages):
            for record in self._code_scanning_alerts_for_repo(
                full_name, max_pages=max_pages
            ):
                results.append(record)
        return results

    def _code_scanning_alerts_for_repo(
        self, full_name: str, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """List one repo's open code-scanning alerts, skipping repos we can't read.

        Code-scanning alerts are only readable when the feature is enabled on the
        repo AND the token carries the ``security_events`` (or, for public repos,
        ``public_repo``) scope; otherwise GitHub answers 403/404. A repo on which
        code scanning has simply never run answers 404 with a ``"no analysis
        found"`` message. We swallow those two statuses for a single repo and
        return no alerts for it rather than aborting the whole audit, so a token
        with mixed permissions still reports every repo it CAN read.
        """
        records: list[dict] = []
        url = f"{self.base_url}/repos/{full_name}/code-scanning/alerts"
        probe = self._request_with_retry(
            url, {"state": "open", "per_page": 100}, self._headers()
        )
        # A repo with code scanning disabled, never-run, or a token without the
        # security_events scope yields 403/404 — skip it, do not fail the run.
        if probe.status_code in (403, 404):
            return records
        if probe.status_code == 401:
            raise SCMError("authentication failed (401) — check the token")
        if probe.status_code >= 400:
            raise SCMError(
                f"{self.base_url} returned HTTP {probe.status_code} "
                f"for {full_name} code-scanning alerts"
            )
        for resp in self._get_paginated(
            f"/repos/{full_name}/code-scanning/alerts",
            params={"state": "open", "per_page": 100},
            max_pages=max_pages,
            next_request=_next_link,
        ):
            body = resp.json()
            if not isinstance(body, list):
                continue
            for item in body:
                rule = item.get("rule") or {}
                # Prefer the security-severity band (critical/high/medium/low);
                # fall back to the alert's generic severity (error/warning/note).
                severity = (
                    rule.get("security_severity_level")
                    or rule.get("severity")
                    or item.get("severity")
                )
                records.append(
                    {
                        "repo": full_name,
                        "rule_id": rule.get("id"),
                        "rule_name": rule.get("name")
                        or rule.get("description"),
                        "severity": severity,
                        "state": item.get("state", "open"),
                        "html_url": item.get("html_url"),
                    }
                )
        return records

    def enumerate_members(self, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        """List the other members of the orgs this token can reach (lateral moves).

        Where the rest of the ``--enumerate-*`` family maps what *this* token
        reaches (its keys, its repos, the secrets it can read), member
        enumeration maps the *people* who share that reach: the other accounts
        with access to each org the token belongs to. That is the
        lateral-movement surface — the set of additional identities an operator
        could target to widen a foothold (phishing, credential reuse, a weaker
        teammate token) — and, for the org owners specifically, the set of
        accounts whose compromise grants administrative control of the whole org.

        Walks the organizations the token belongs to (via :meth:`enumerate_orgs`)
        and, for each, lists its members with their organization role:
        ``GET /orgs/{org}/members?role=admin`` returns the owners and
        ``GET /orgs/{org}/members?role=member`` returns the rest, so the
        normalized ``role`` is ``"admin"`` (org owner) or ``"member"``. Returns a
        list of ``{"scope", "owner", "username", "role"}`` dicts (``scope`` is
        always ``"org"`` here). Only public membership identity is surfaced — no
        email, no keys, no secrets — and the API never exposes a credential, so
        this is a read-only directory query, not a data dump.
        """
        results: list[dict] = []
        for org in self.enumerate_orgs(max_pages=max_pages):
            owner = org.get("name")
            if not owner:
                continue
            # The members endpoint does not return per-user role, so we query
            # the two role-filtered views and tag each accordingly. admins
            # (org owners) are the highest-value lateral target.
            for role in ("admin", "member"):
                for resp in self._get_paginated(
                    f"/orgs/{owner}/members",
                    params={"role": role, "per_page": 100},
                    max_pages=max_pages,
                    next_request=_next_link,
                ):
                    body = resp.json()
                    if not isinstance(body, list):
                        continue
                    for item in body:
                        username = item.get("login")
                        if not username:
                            continue
                        results.append(
                            {
                                "scope": "org",
                                "owner": owner,
                                "username": username,
                                "role": role,
                            }
                        )
        return results

    def enumerate_collaborators(
        self, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """List the collaborators on the repos this token can reach (ghost accounts).

        Where :meth:`enumerate_members` maps the people who share an *org's*
        reach, collaborator enumeration is repo-scoped and surfaces the
        higher-signal blast radius: the accounts granted access to a SPECIFIC
        repository, and in particular the *outside* collaborators — individuals
        who are NOT members of the owning org yet still hold repo access. Outside
        collaborators are the classic ghost-account / ex-employee / leftover-
        contractor vector: a personal account with standing push access to a
        critical repo, invisible to an org-member audit, that survives long after
        the person leaves. A repo with write/admin outside collaborators is a
        direct supply-chain and persistence risk.

        Walks the repositories the token can reach (``GET /user/repos``) and, for
        each, lists ``GET /repos/{owner}/{repo}/collaborators``. The collaborator
        object carries a ``permissions`` map (``admin``/``push``/``pull``/...);
        covenant reduces it to the single highest-privilege ``role``
        (``admin`` > ``maintain`` > ``write`` > ``triage`` > ``read``) — the
        decisive blast-radius signal — and flags ``outside`` from GitHub's
        ``role_name``/affiliation. To find the outside set without a second
        pass, the listing is fetched with ``affiliation=outside`` so every
        returned account is an outside collaborator (``outside=True``); a repo
        with none yields nothing. Returns a normalized list of
        ``{"repo", "username", "role", "outside"}`` dicts. Only public identity
        and the permission level are surfaced — never an email, key, or
        credential. The audit is read-only and never grants or revokes access.
        """
        results: list[dict] = []
        for full_name in self._reachable_repos(max_pages=max_pages):
            for resp in self._get_paginated(
                f"/repos/{full_name}/collaborators",
                params={"affiliation": "outside", "per_page": 100},
                max_pages=max_pages,
                next_request=_next_link,
            ):
                body = resp.json()
                if not isinstance(body, list):
                    continue
                for item in body:
                    username = item.get("login")
                    if not username:
                        continue
                    results.append(
                        {
                            "repo": full_name,
                            "username": username,
                            "role": _github_collaborator_role(item),
                            "outside": True,
                        }
                    )
        return results

    def scan_commits(self, max_pages: int = DEFAULT_MAX_PAGES) -> list[dict]:
        """Collect commit metadata + messages from the repos this token reaches.

        Commit *messages* are a notorious, much-overlooked secret-leak vector —
        the credential that was scrubbed from a tracked file routinely survives
        verbatim in the ``git commit -m "fix: rotate to AKIA..."`` line, in a
        merge/revert body that quotes a diff, or in an automated bump commit that
        echoes a token. covenant's ``--scan-secrets`` only ever sees the *current*
        file content the code-search API returns; this is the recon analogue for
        the *history*: it walks the recent commits the token can read and surfaces
        each commit's message text so the caller can scan it for credentials with
        the same :func:`covenant.secrets.scan_fragments` machinery.

        Walks the repositories the token can reach (``GET /user/repos``) and, for
        each, lists ``GET /repos/{owner}/{repo}/commits`` (newest first), returning
        one normalized ``{"repo", "sha", "author", "message"}`` record per commit.
        ``author`` is the commit author's login/name (identity only — never an
        email) and ``message`` is the raw commit message the CLI feeds to the
        secret scanner; the commit *diff/patch* is never fetched, so covenant maps
        the leak surface in history without dumping repository content. Read-only.
        """
        results: list[dict] = []
        for full_name in self._reachable_repos(max_pages=max_pages):
            for resp in self._get_paginated(
                f"/repos/{full_name}/commits",
                params={"per_page": 100},
                max_pages=max_pages,
                next_request=_next_link,
            ):
                body = resp.json()
                if not isinstance(body, list):
                    continue
                for item in body:
                    sha = item.get("sha")
                    if not sha:
                        continue
                    commit = item.get("commit") or {}
                    author_obj = commit.get("author") or {}
                    # Prefer the GitHub account login (identity), falling back to
                    # the git author name; the email is deliberately never read.
                    login = (item.get("author") or {}).get("login")
                    results.append(
                        {
                            "repo": full_name,
                            "sha": sha,
                            "author": login or author_obj.get("name"),
                            "message": commit.get("message", ""),
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
