"""In-process mock SCM API servers for covenant's end-to-end smoke tests.

Each mock emulates the minimal surface of a real SCM API that covenant's recon
and token-validation modules touch. Servers bind to an **ephemeral port** chosen
via ``socket.bind(('', 0))`` at startup (criterion 3) so tests never collide on a
fixed port and never touch the reserved 8888 voice port.

[Worker decision: mock servers speak raw HTTP via http.server rather than
mocking the PyGithub / python-gitlab / atlassian SDK objects. covenant's SCM
clients therefore talk plain httpx to a configurable base URL, which keeps the
recon path identical between live and mock runs and lets one mock harness cover
all three SCMs with the same ephemeral-port pattern.]
"""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


# Queries beginning with this prefix make every mock server emit a multi-page
# response (TOTAL_PAGES pages, one distinct item per page) so the pagination
# tests can prove covenant walks past page one.
MULTIPAGE_PREFIX = "multipage"
TOTAL_PAGES = 3

# Rate-limit simulation (POST_V01.md Item 6). A query beginning with
# RATELIMIT_PREFIX makes the server return HTTP 429 with a ``Retry-After: 0``
# header for the first RATELIMIT_FAILS attempts, then succeed — proving covenant
# retries with backoff and ultimately gets results. A query beginning with
# RATELIMIT_FOREVER_PREFIX returns 429 on every attempt, so covenant exhausts
# its retry budget and must surface a non-fatal ``warnings`` entry. Retry-After
# is 0 in the mock so the backoff sleep is a no-op and tests stay fast.
RATELIMIT_PREFIX = "ratelimit"
RATELIMIT_FOREVER_PREFIX = "ratelimitforever"
#: How many 429s the recoverable ``ratelimit`` scenario emits before succeeding.
RATELIMIT_FAILS = 2


def _rate_limit_response(handler, query: str) -> bool:
    """If ``query`` requests the rate-limit scenario, emit a 429 and return True.

    Recoverable (``ratelimit`` but not ``ratelimitforever``): the first
    RATELIMIT_FAILS calls for that query key get a 429 with ``Retry-After: 0``;
    afterwards this returns False so the handler serves a normal 200.

    Unrecoverable (``ratelimitforever``): every call gets a 429 with a reset
    header, so covenant exhausts its retry budget. We exercise the
    ``X-RateLimit-Reset`` epoch-header path here (instead of ``Retry-After``) to
    cover that branch of ``_parse_retry_after`` too; the reset is set to "now"
    so the computed sleep clamps to ~0 and the test stays fast.

    Per-query call counts live on the server instance so state persists across
    the stateless per-request handler objects.
    """
    if not query.startswith(RATELIMIT_PREFIX):
        return False

    counts = getattr(handler.server, "_rl_counts", None)
    if counts is None:
        counts = {}
        handler.server._rl_counts = counts
    counts[query] = counts.get(query, 0) + 1
    seen = counts[query]

    forever = query.startswith(RATELIMIT_FOREVER_PREFIX)
    if forever:
        import time as _time

        handler._json(
            429,
            {"message": "rate limited"},
            headers={"X-RateLimit-Reset": str(int(_time.time()))},
        )
        return True
    if seen <= RATELIMIT_FAILS:
        handler._json(429, {"message": "rate limited"}, headers={"Retry-After": "0"})
        return True
    return False


def _record_query(handler, value: str) -> None:
    """Stash the most-recent raw search-query string on the server instance.

    Lets the Item-7 ``--exclude`` tests assert that the negative ``NOT <term>``
    qualifiers actually reached the wire (the handlers otherwise only read the
    first token of the query). Per-server state survives across the stateless
    per-request handler objects.
    """
    queries = getattr(handler.server, "received_queries", None)
    if queries is None:
        queries = []
        handler.server.received_queries = queries
    queries.append(value)


def _record_group(handler, group_id: str) -> None:
    """Stash the group ``:id`` segment from a group-scoped GitLab request.

    Lets the ``--org`` tests assert recon actually hit the group-scoped
    endpoint (``/api/v4/groups/:id/...``) rather than the host-wide one, and
    that the group path was URL-encoded onto the wire (``acme%2Fplatform``).
    """
    groups = getattr(handler.server, "received_groups", None)
    if groups is None:
        groups = []
        handler.server.received_groups = groups
    groups.append(group_id)


def _github_search_repos(query: str, page: int = 1) -> dict:
    return {
        "total_count": 1,
        "incomplete_results": False,
        "items": [
            {
                "name": f"{query}-book-{page}",
                "full_name": f"acme/{query}-book-{page}",
                "private": False,
                "visibility": "public",
                "html_url": f"https://github.com/acme/{query}-book-{page}",
                "description": "A repository of spells",
            }
        ],
    }


def _github_search_code(query: str, text_match: bool = False, page: int = 1) -> dict:
    item: dict = {
        "name": f"{query}-{page}.py",
        "path": f"src/{query}-{page}.py",
        "repository": {
            "name": f"{query}-book",
            "private": False,
            "html_url": f"https://github.com/acme/{query}-book",
        },
        "html_url": f"https://github.com/acme/{query}-book/blob/main/src/{query}-{page}.py",
    }
    if text_match:
        # Simulate a GitHub text-match fragment containing a fake AWS key so
        # the --scan-secrets tests have something to detect.
        item["text_matches"] = [
            {
                "object_type": "FileContent",
                "object_url": item["html_url"],
                "property": "content",
                "fragment": f"# {query}\nAWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE\n",
                "matches": [{"text": "AKIAIOSFODNN7EXAMPLE", "indices": [28, 48]}],
            }
        ]
    return {
        "total_count": 1,
        "incomplete_results": False,
        "items": [item],
    }


class _GitHubHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # noqa: D401 - silence test noise
        return

    def _json(self, code: int, payload, headers: dict | None = None):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _link_header(self, path: str, params: dict, page: int) -> dict | None:
        """Emit an RFC-5988 ``Link: <url>; rel="next"`` header for multi-page
        queries (q starts with MULTIPAGE_PREFIX) until TOTAL_PAGES is reached.
        """
        query = params.get("q", ["spell"])[0]
        if not query.startswith(MULTIPAGE_PREFIX) or page >= TOTAL_PAGES:
            return None
        from urllib.parse import urlencode

        next_params = {k: v[0] for k, v in params.items()}
        next_params["page"] = page + 1
        next_url = f"http://127.0.0.1:{self.server.server_address[1]}{path}?{urlencode(next_params)}"
        return {"Link": f'<{next_url}>; rel="next"'}

    def do_GET(self):  # noqa: N802 - http.server API
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        auth = self.headers.get("Authorization", "")

        if not auth.lower().startswith(("token ", "bearer ")):
            self._json(401, {"message": "Requires authentication"})
            return

        page = int(params.get("page", ["1"])[0])

        if parsed.path == "/search/repositories":
            query = params.get("q", ["spell"])[0].split()[0]
            if _rate_limit_response(self, query):
                return
            headers = self._link_header(parsed.path, params, page)
            self._json(200, _github_search_repos(query, page=page), headers=headers)
        elif parsed.path == "/search/code":
            _record_query(self, params.get("q", ["spell"])[0])
            query = params.get("q", ["spell"])[0].split()[0]
            accept = self.headers.get("Accept", "")
            text_match = "text-match" in accept
            headers = self._link_header(parsed.path, params, page)
            self._json(
                200,
                _github_search_code(query, text_match=text_match, page=page),
                headers=headers,
            )
        elif parsed.path == "/user":
            self._json(
                200,
                {"login": "spellcaster", "id": 4242, "site_admin": True},
                headers={"X-OAuth-Scopes": "repo, read:org, admin:org"},
            )
        elif parsed.path == "/user/keys":
            # SSH-key enumeration (--enumerate-keys). Public metadata only.
            self._json(
                200,
                [
                    {
                        "id": 1,
                        "title": "laptop",
                        "key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA laptop",
                    },
                    {
                        "id": 2,
                        "title": "ci-runner",
                        "key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB ci-runner",
                    },
                ],
            )
        elif parsed.path == "/user/gpg_keys":
            # GPG signing-key enumeration (--enumerate-keys).
            self._json(
                200,
                [
                    {
                        "id": 7,
                        "key_id": "ABCDEF0123456789",
                        "name": "release-signing",
                    },
                ],
            )
        elif parsed.path == "/gists":
            # Gist enumeration (--enumerate-gists). Public metadata + filenames
            # only; the raw_url/content of each file is deliberately omitted.
            self._json(
                200,
                [
                    {
                        "id": "gist1",
                        "description": "deploy helper",
                        "public": True,
                        "html_url": "https://gist.github.com/spellcaster/gist1",
                        "files": {
                            "deploy.sh": {"filename": "deploy.sh"},
                        },
                    },
                    {
                        "id": "gist2",
                        "description": "scratch env",
                        "public": False,
                        "html_url": "https://gist.github.com/spellcaster/gist2",
                        "files": {
                            ".env": {"filename": ".env"},
                            "notes.md": {"filename": "notes.md"},
                        },
                    },
                ],
            )
        elif parsed.path.startswith("/orgs/") and parsed.path.endswith("/hooks"):
            # Org-webhook enumeration (--enumerate-webhooks). The config.url is
            # the exfil/SSRF destination; config.secret is intentionally NOT
            # included (the real API never returns it and covenant must not echo
            # it). Each reachable org returns one hook.
            owner = parsed.path.split("/")[2]
            self._json(
                200,
                [
                    {
                        "id": 100,
                        "active": True,
                        "events": ["push", "pull_request"],
                        "config": {
                            "url": f"https://hooks.example.com/{owner}",
                            "content_type": "json",
                            "secret": "********",
                        },
                    },
                ],
            )
        elif parsed.path == "/user/repos":
            # Repo listing used by deploy-key enumeration
            # (--enumerate-deploy-keys). Two reachable repos.
            self._json(
                200,
                [
                    {"full_name": "acme-corp/spellbook", "private": True},
                    {"full_name": "acme-corp/grimoire", "private": False},
                ],
            )
        elif parsed.path.startswith("/repos/") and parsed.path.endswith(
            "/protection"
        ):
            # Per-branch protection detail (--audit-branch-protection). The
            # spellbook 'main' branch is WEAK: no required reviews, no signed
            # commits, admins not enforced (the high-signal supply-chain gap).
            # The grimoire 'main' branch is STRONG.
            # path: /repos/{owner}/{repo}/branches/{branch}/protection
            segs = parsed.path.split("/")
            repo = "/".join(segs[2:4])
            weak = repo.endswith("/spellbook")
            if weak:
                self._json(
                    200,
                    {
                        "required_pull_request_reviews": None,
                        "required_signatures": {"enabled": False},
                        "enforce_admins": {"enabled": False},
                    },
                )
            else:
                self._json(
                    200,
                    {
                        "required_pull_request_reviews": {
                            "required_approving_review_count": 2,
                            "dismiss_stale_reviews": True,
                        },
                        "required_signatures": {"enabled": True},
                        "enforce_admins": {"enabled": True},
                    },
                )
        elif parsed.path.startswith("/repos/") and parsed.path.endswith(
            "/branches"
        ):
            # Protected-branch listing (--audit-branch-protection). Each repo has
            # one protected branch, 'main'.
            self._json(200, [{"name": "main", "protected": True}])
        elif parsed.path.startswith("/repos/") and parsed.path.endswith("/keys"):
            # Per-repo deploy-key enumeration (--enumerate-deploy-keys). The
            # `key` is the PUBLIC SSH key; no private material is ever returned.
            # spellbook has a WRITABLE deploy key (read_only false — the
            # high-signal case); grimoire has a read-only one.
            repo = "/".join(parsed.path.split("/")[2:4])
            writable = repo.endswith("/spellbook")
            self._json(
                200,
                [
                    {
                        "id": 300,
                        "title": "ci-deploy" if writable else "readonly-deploy",
                        "key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA deploy",
                        "read_only": not writable,
                    },
                ],
            )
        elif parsed.path.startswith("/orgs/") and parsed.path.endswith(
            "/actions/secrets"
        ):
            # Org-level Actions secret-NAME enumeration
            # (--enumerate-actions-secrets). The API returns names + metadata
            # only — never the value. One org secret is restricted to selected
            # repos (visibility=selected -> protected=true). GitHub wraps the
            # list in a {"total_count", "secrets": [...]} envelope.
            owner = parsed.path.split("/")[2]
            self._json(
                200,
                {
                    "total_count": 2,
                    "secrets": [
                        {"name": "ORG_AWS_KEY", "visibility": "all"},
                        {
                            "name": "ORG_NPM_TOKEN",
                            "visibility": "selected",
                            "selected_repositories_url": (
                                f"https://api.github.com/orgs/{owner}"
                                "/actions/secrets/ORG_NPM_TOKEN/repositories"
                            ),
                        },
                    ],
                },
            )
        elif parsed.path.startswith("/repos/") and parsed.path.endswith(
            "/actions/permissions/workflow"
        ):
            # Actions workflow-token policy (--audit-actions-permissions). The
            # spellbook repo grants every workflow a read/WRITE GITHUB_TOKEN and
            # lets workflows self-approve PRs — the high-signal posture; the
            # grimoire repo uses the locked-down 'read' default with no
            # self-approval. Read-only policy metadata; never a credential.
            repo = "/".join(parsed.path.split("/")[2:4])
            if repo.endswith("/spellbook"):
                self._json(
                    200,
                    {
                        "default_workflow_permissions": "write",
                        "can_approve_pull_request_reviews": True,
                    },
                )
            else:
                self._json(
                    200,
                    {
                        "default_workflow_permissions": "read",
                        "can_approve_pull_request_reviews": False,
                    },
                )
        elif parsed.path.startswith("/repos/") and parsed.path.endswith(
            "/actions/permissions"
        ):
            # Actions execution-permission posture (--audit-actions-permissions).
            # The spellbook repo has Actions ENABLED with allowed_actions='all';
            # the grimoire repo has Actions DISABLED (so there is no
            # workflow-token policy to read — covenant reports
            # default_workflow_permissions=null for it). Read-only metadata.
            repo = "/".join(parsed.path.split("/")[2:4])
            if repo.endswith("/spellbook"):
                self._json(
                    200,
                    {"enabled": True, "allowed_actions": "all"},
                )
            else:
                self._json(
                    200,
                    {"enabled": False},
                )
        elif parsed.path.startswith("/repos/") and parsed.path.endswith(
            "/actions/secrets"
        ):
            # Repo-level Actions secret-NAME enumeration
            # (--enumerate-actions-secrets). Names + metadata only; no value.
            self._json(
                200,
                {
                    "total_count": 1,
                    "secrets": [
                        {"name": "DEPLOY_TOKEN"},
                    ],
                },
            )
        elif parsed.path.startswith("/orgs/") and parsed.path.endswith(
            "/actions/runners"
        ):
            # Org-level self-hosted runner enumeration
            # (--enumerate-runners). GitHub wraps runners in
            # {"total_count", "runners": [...]}. The API by definition lists
            # only self-hosted runners. The "shouldnotappear" placeholder
            # would never appear here in real responses (no secret-bearing
            # field), but we plant a no-credential-leak invariant elsewhere.
            self._json(
                200,
                {
                    "total_count": 2,
                    "runners": [
                        {
                            "id": 700,
                            "name": "acme-org-runner-1",
                            "os": "linux",
                            "status": "online",
                            "labels": [
                                {"id": 1, "name": "self-hosted", "type": "read-only"},
                                {"id": 2, "name": "linux", "type": "read-only"},
                                {"id": 3, "name": "production", "type": "custom"},
                            ],
                        },
                        {
                            "id": 701,
                            "name": "acme-org-runner-2",
                            "os": "linux",
                            "status": "offline",
                            "labels": [
                                {"id": 1, "name": "self-hosted", "type": "read-only"},
                                {"id": 2, "name": "linux", "type": "read-only"},
                            ],
                        },
                    ],
                },
            )
        elif parsed.path.startswith("/repos/") and parsed.path.endswith(
            "/actions/runners"
        ):
            # Repo-level self-hosted runner enumeration
            # (--enumerate-runners). Repo-attached runners. Names + metadata
            # only; no registration token.
            repo = "/".join(parsed.path.split("/")[2:4])
            if repo.endswith("/spellbook"):
                self._json(
                    200,
                    {
                        "total_count": 1,
                        "runners": [
                            {
                                "id": 710,
                                "name": "spellbook-repo-runner",
                                "os": "linux",
                                "status": "online",
                                "labels": [
                                    {"id": 1, "name": "self-hosted", "type": "read-only"},
                                ],
                            },
                        ],
                    },
                )
            else:
                self._json(200, {"total_count": 0, "runners": []})
        elif parsed.path.startswith("/repos/") and parsed.path.endswith(
            "/environments"
        ):
            # Deployment-environment audit (--audit-actions-environments).
            # GitHub wraps environments in {"total_count", "environments"}. The
            # spellbook 'production' env is WEAK: no protection rules and no
            # deployment_branch_policy (any branch can deploy and read its
            # secrets unreviewed — the high-signal gap). The grimoire 'production'
            # env is STRONG: required reviewers, a wait timer, and a
            # protected-branch deployment policy.
            repo = "/".join(parsed.path.split("/")[2:4])
            weak = repo.endswith("/spellbook")
            if weak:
                self._json(
                    200,
                    {
                        "total_count": 1,
                        "environments": [
                            {
                                "id": 500,
                                "name": "production",
                                "protection_rules": [],
                                "deployment_branch_policy": None,
                            },
                        ],
                    },
                )
            else:
                self._json(
                    200,
                    {
                        "total_count": 1,
                        "environments": [
                            {
                                "id": 501,
                                "name": "production",
                                "protection_rules": [
                                    {
                                        "id": 1,
                                        "type": "required_reviewers",
                                        "reviewers": [
                                            {"type": "User"},
                                            {"type": "Team"},
                                        ],
                                    },
                                    {
                                        "id": 2,
                                        "type": "wait_timer",
                                        "wait_timer": 30,
                                    },
                                ],
                                "deployment_branch_policy": {
                                    "protected_branches": True,
                                    "custom_branch_policies": False,
                                },
                            },
                        ],
                    },
                )
        elif parsed.path.startswith("/repos/") and parsed.path.endswith(
            "/collaborators"
        ):
            # Per-repo collaborator enumeration (--enumerate-collaborators).
            # covenant requests affiliation=outside, so every returned account
            # is an OUTSIDE collaborator (ghost-account / ex-employee vector).
            # The spellbook outside collaborator has WRITE (push) access — the
            # high-signal case; grimoire's has read-only (pull). Only public
            # identity + the permissions map is returned, never an email/key.
            repo = "/".join(parsed.path.split("/")[2:4])
            writable = repo.endswith("/spellbook")
            if writable:
                self._json(
                    200,
                    [
                        {
                            "login": "ex-contractor",
                            "role_name": "write",
                            "permissions": {
                                "admin": False,
                                "maintain": False,
                                "push": True,
                                "triage": True,
                                "pull": True,
                            },
                        },
                    ],
                )
            else:
                self._json(
                    200,
                    [
                        {
                            "login": "auditor",
                            "role_name": "read",
                            "permissions": {
                                "admin": False,
                                "maintain": False,
                                "push": False,
                                "triage": False,
                                "pull": True,
                            },
                        },
                    ],
                )
        elif parsed.path.startswith("/orgs/") and parsed.path.endswith(
            "/members"
        ):
            # Org-member enumeration (--enumerate-members). The endpoint is
            # role-filtered (?role=admin|member); covenant queries both and tags
            # each. Admins are the org owners (the high-value lateral target).
            # Only public membership identity is returned — no email or keys.
            owner = parsed.path.split("/")[2]
            role = params.get("role", ["all"])[0]
            if role == "admin":
                self._json(200, [{"login": f"{owner}-owner"}])
            else:
                self._json(
                    200,
                    [
                        {"login": "spellcaster"},
                        {"login": "apprentice"},
                    ],
                )
        elif parsed.path.startswith("/repos/") and parsed.path.endswith(
            "/commits"
        ):
            # Commit-history scanning (--scan-commits). The spellbook repo has a
            # commit whose MESSAGE leaks a fake AWS key (the high-signal,
            # message-leak case); grimoire's commit message is clean. Only the
            # commit metadata + message are returned — the diff/patch is never
            # fetched, and the author EMAIL is deliberately omitted.
            repo = "/".join(parsed.path.split("/")[2:4])
            leaky = repo.endswith("/spellbook")
            if leaky:
                self._json(
                    200,
                    [
                        {
                            "sha": "a1b2c3d",
                            "author": {"login": "ex-contractor"},
                            "commit": {
                                "author": {"name": "Ex Contractor"},
                                "message": (
                                    "fix: rotate to "
                                    "AKIAIOSFODNN7EXAMPLE temporarily"
                                ),
                            },
                        },
                    ],
                )
            else:
                self._json(
                    200,
                    [
                        {
                            "sha": "deadbeef",
                            "author": {"login": "spellcaster"},
                            "commit": {
                                "author": {"name": "Spell Caster"},
                                "message": "docs: update the README",
                            },
                        },
                    ],
                )
        elif parsed.path.startswith("/repos/") and parsed.path.endswith(
            "/dependabot/alerts"
        ):
            # Dependabot-alert audit (--audit-dependabot-alerts). The spellbook
            # repo has an OPEN CRITICAL alert (the high-signal known-vulnerability
            # case); the grimoire repo has Dependabot DISABLED, which GitHub
            # answers with 403/404 — covenant must SKIP that repo, not fail the
            # whole audit. The API returns the security_advisory / vulnerability /
            # package metadata; only the advisory IDENTIFIER (GHSA/CVE) is a
            # handle, never a credential.
            repo = "/".join(parsed.path.split("/")[2:4])
            if repo.endswith("/spellbook"):
                self._json(
                    200,
                    [
                        {
                            "number": 1,
                            "state": "open",
                            "security_advisory": {
                                "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
                                "severity": "critical",
                                "identifiers": [
                                    {"type": "GHSA", "value": "GHSA-xxxx-yyyy-zzzz"},
                                    {"type": "CVE", "value": "CVE-2025-0001"},
                                ],
                            },
                            "security_vulnerability": {
                                "severity": "critical",
                                "package": {
                                    "ecosystem": "pip",
                                    "name": "requests",
                                },
                            },
                        },
                    ],
                )
            else:
                # grimoire: Dependabot disabled / token lacks security_events.
                self._json(403, {"message": "Dependabot alerts are disabled"})
        elif parsed.path.startswith("/repos/") and parsed.path.endswith(
            "/secret-scanning/alerts"
        ):
            # Secret-scanning audit (--audit-secret-scanning). The spellbook repo
            # has one OPEN alert for a leaked AWS key whose validity is ACTIVE
            # (the high-signal still-live-credential case); the grimoire repo has
            # secret scanning DISABLED, which GitHub answers with 403 — covenant
            # must SKIP that repo, not fail the whole audit. The API response
            # carries the raw matched credential in `secret` and a decorated name
            # in `secret_type_display_name`; covenant must read NEITHER — only the
            # secret_type classifier, state, validity, and html_url.
            repo = "/".join(parsed.path.split("/")[2:4])
            if repo.endswith("/spellbook"):
                self._json(
                    200,
                    [
                        {
                            "number": 7,
                            "state": "open",
                            "secret_type": "aws_access_key_id",
                            "secret_type_display_name": "Amazon AWS Access Key ID",
                            # The raw leaked credential — covenant must NEVER echo it.
                            "secret": "AKIAIOSFODNN7EXAMPLE",
                            "validity": "active",
                            "html_url": (
                                "https://github.com/acme-corp/spellbook/"
                                "security/secret-scanning/7"
                            ),
                        },
                    ],
                )
            else:
                # grimoire: secret scanning disabled / token lacks security_events.
                self._json(403, {"message": "Secret scanning is disabled"})
        elif parsed.path.startswith("/repos/") and parsed.path.endswith(
            "/code-scanning/alerts"
        ):
            # Code-scanning audit (--audit-code-scanning-alerts). The spellbook
            # repo has one OPEN CRITICAL CodeQL alert in its own source (the
            # high-signal first-party-code-flaw case); the grimoire repo has code
            # scanning DISABLED / never-run, which GitHub answers with 404 —
            # covenant must SKIP that repo, not fail the whole audit. The API
            # returns the rule's id/name/severity and the alert html_url; only
            # that metadata is surfaced, never a credential.
            repo = "/".join(parsed.path.split("/")[2:4])
            if repo.endswith("/spellbook"):
                self._json(
                    200,
                    [
                        {
                            "number": 42,
                            "state": "open",
                            "rule": {
                                "id": "py/sql-injection",
                                "name": "SQL query built from user-controlled "
                                "sources",
                                "severity": "error",
                                "security_severity_level": "critical",
                                "description": "SQL injection",
                            },
                            "html_url": (
                                "https://github.com/acme-corp/spellbook/"
                                "security/code-scanning/42"
                            ),
                        },
                    ],
                )
            else:
                # grimoire: code scanning disabled / never run / token lacks scope.
                self._json(404, {"message": "no analysis found"})
        elif parsed.path.startswith("/repos/") and parsed.path.endswith(
            "/security-advisories"
        ):
            # Repository-advisory audit (--audit-advisory-alerts). The spellbook
            # repo has one PUBLISHED CRITICAL advisory the org's own maintainers
            # wrote up against their OWN product (the high-signal publisher case);
            # the grimoire repo has the advisory feature unavailable / token
            # lacks scope, which GitHub answers with 404 — covenant must SKIP that
            # repo, not fail the whole audit. The API returns the advisory's
            # GHSA/CVE handle, summary, severity, state, and html_url; only that
            # metadata is surfaced, never a credential.
            repo = "/".join(parsed.path.split("/")[2:4])
            if repo.endswith("/spellbook"):
                self._json(
                    200,
                    [
                        {
                            "ghsa_id": "GHSA-spel-lboo-k123",
                            "cve_id": "CVE-2024-13337",
                            "summary": "Authentication bypass in spellbook "
                            "session handling",
                            "severity": "critical",
                            "state": "published",
                            "html_url": (
                                "https://github.com/acme-corp/spellbook/"
                                "security/advisories/GHSA-spel-lboo-k123"
                            ),
                        },
                    ],
                )
            else:
                # grimoire: advisory feature unavailable / token lacks scope.
                self._json(404, {"message": "Not Found"})
        elif parsed.path.startswith("/repos/") and "/contents/" in parsed.path:
            # CODEOWNERS-coverage audit (--audit-codeowners). GitHub serves file
            # content as a JSON object with base64-encoded `content`. covenant
            # probes .github/CODEOWNERS, CODEOWNERS, then docs/CODEOWNERS and
            # reports the first hit. The spellbook repo has a PARTIAL CODEOWNERS
            # (rules but no catch-all '*' — the high-signal coverage gap) at
            # .github/CODEOWNERS; the grimoire repo has a COMPLETE one (with a '*'
            # global owner) at the repo root. Any other path 404s (absent).
            import base64 as _b64

            segs = parsed.path.split("/")
            repo = "/".join(segs[2:4])
            file_path = parsed.path.split("/contents/", 1)[1]
            # spellbook: rules but NO catch-all '*' (the partial-coverage gap).
            spellbook_body = (
                "# spellbook ownership\n"
                "src/ @org/backend\n"
                "docs/ @org/docs-team\n"
            )
            grimoire_body = (
                "# grimoire ownership\n"
                "* @org/maintainers\n"
                "src/ @org/backend\n"
            )
            # Package-dependency inventory (--audit-packages). The spellbook repo
            # ships a package.json (npm) and a requirements.txt (pip); the
            # grimoire repo has no recognized manifest. covenant probes each
            # manifest filename in PACKAGE_MANIFESTS order and parses every hit.
            spellbook_package_json = json.dumps(
                {
                    "name": "spellbook",
                    "dependencies": {"left-pad": "^1.3.0", "lodash": "4.17.21"},
                    "devDependencies": {"jest": "^29.0.0"},
                }
            )
            spellbook_requirements = "requests==2.31.0\nflask>=2.0\n# a comment\n"
            content = None
            if repo.endswith("/spellbook") and file_path == ".github/CODEOWNERS":
                content = spellbook_body
            elif repo.endswith("/grimoire") and file_path == "CODEOWNERS":
                content = grimoire_body
            elif repo.endswith("/spellbook") and file_path == "package.json":
                content = spellbook_package_json
            elif repo.endswith("/spellbook") and file_path == "requirements.txt":
                content = spellbook_requirements
            if content is None:
                self._json(404, {"message": "Not Found"})
            else:
                self._json(
                    200,
                    {
                        "name": file_path.rsplit("/", 1)[-1],
                        "path": file_path,
                        "encoding": "base64",
                        "content": _b64.b64encode(content.encode()).decode(),
                    },
                )
        elif parsed.path == "/user/orgs":
            # Org/blast-radius enumeration (--enumerate-orgs). Supports the
            # MULTIPAGE_PREFIX is not relevant here (no query); serve a single
            # page of two orgs so the test can assert the normalized shape.
            self._json(
                200,
                [
                    {
                        "login": "acme-corp",
                        "id": 1,
                        "url": "https://api.github.com/orgs/acme-corp",
                    },
                    {
                        "login": "wizards-inc",
                        "id": 2,
                        "url": "https://api.github.com/orgs/wizards-inc",
                    },
                ],
            )
        else:
            self._json(404, {"message": "Not Found"})


class _GitLabHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def _json(self, code: int, payload, headers: dict | None = None):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _page_headers(self, search: str, page: int) -> dict:
        """Emit GitLab offset-pagination headers. For MULTIPAGE_PREFIX queries
        advertise a next page until TOTAL_PAGES; otherwise no next page.
        """
        if search.startswith(MULTIPAGE_PREFIX) and page < TOTAL_PAGES:
            return {
                "X-Page": str(page),
                "X-Next-Page": str(page + 1),
                "X-Total-Pages": str(TOTAL_PAGES),
            }
        return {"X-Page": str(page), "X-Next-Page": "", "X-Total-Pages": str(page)}

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        token = self.headers.get("PRIVATE-TOKEN", "") or self.headers.get(
            "Authorization", ""
        )
        if not token:
            self._json(401, {"message": "401 Unauthorized"})
            return

        page = int(params.get("page", ["1"])[0])

        # Group-scoped --org narrowing uses /api/v4/groups/:id/{projects,search}.
        # We record the group id so a test can assert the request was group-
        # scoped, then fall through to the same response bodies the host-wide
        # endpoints produce.
        group_projects = (
            parsed.path.startswith("/api/v4/groups/")
            and parsed.path.endswith("/projects")
        )
        group_search = (
            parsed.path.startswith("/api/v4/groups/")
            and parsed.path.endswith("/search")
        )
        if group_projects or group_search:
            _record_group(self, parsed.path.split("/")[4])

        if parsed.path == "/api/v4/projects" or group_projects:
            search = params.get("search", ["spell"])[0]
            if _rate_limit_response(self, search):
                return
            self._json(
                200,
                [
                    {
                        "id": 99,
                        "name": f"{search}-book-{page}",
                        "path_with_namespace": f"acme/{search}-book-{page}",
                        "default_branch": "main",
                        "visibility": "private",
                        "web_url": f"https://gitlab.com/acme/{search}-book-{page}",
                        "description": "A repository of spells",
                    }
                ],
                headers=self._page_headers(search, page),
            )
        elif parsed.path == "/api/v4/search" or group_search:
            scope = params.get("scope", ["blobs"])[0]
            _record_query(self, params.get("search", ["spell"])[0])
            search = params.get("search", ["spell"])[0]
            if scope == "blobs":
                self._json(
                    200,
                    [
                        {
                            "basename": f"{search}",
                            "data": f"# {search}\nAWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE\n",
                            "filename": f"{search}-{page}.py",
                            "id": None,
                            "path": f"src/{search}-{page}.py",
                            "project_id": 99,
                            "ref": "main",
                            "startline": 1,
                            "web_url": f"https://gitlab.com/acme/{search}-book/-/blob/main/src/{search}-{page}.py",
                        }
                    ],
                    headers=self._page_headers(search, page),
                )
            else:
                self._json(200, [])
        elif parsed.path == "/api/v4/user":
            self._json(200, {"username": "spellcaster", "id": 4242, "is_admin": False})
        elif parsed.path == "/api/v4/personal_access_tokens/self":
            self._json(
                200,
                {"name": "covenant", "scopes": ["read_api", "read_repository"]},
            )
        elif parsed.path == "/api/v4/user/keys":
            # SSH-key enumeration (--enumerate-keys).
            self._json(
                200,
                [
                    {
                        "id": 1,
                        "title": "laptop",
                        "key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA laptop",
                        "fingerprint": "SHA256:abc123laptop",
                    },
                    {
                        "id": 2,
                        "title": "ci-runner",
                        "key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB ci",
                        "fingerprint": "SHA256:def456ci",
                    },
                ],
                headers={"X-Page": "1", "X-Next-Page": "", "X-Total-Pages": "1"},
            )
        elif parsed.path == "/api/v4/user/gpg_keys":
            # GPG signing-key enumeration (--enumerate-keys). GitLab returns
            # only the armored public key body.
            self._json(
                200,
                [
                    {
                        "id": 9,
                        "key": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQ ...armor... \n-----END PGP PUBLIC KEY BLOCK-----",
                    },
                ],
                headers={"X-Page": "1", "X-Next-Page": "", "X-Total-Pages": "1"},
            )
        elif parsed.path == "/api/v4/snippets":
            # Snippet enumeration (--enumerate-gists). Exercises both the newer
            # `files` array shape and the legacy single `file_name` shape.
            self._json(
                200,
                [
                    {
                        "id": 51,
                        "title": "deploy helper",
                        "description": None,
                        "visibility": "public",
                        "web_url": "https://gitlab.com/-/snippets/51",
                        "files": [
                            {"path": "deploy.sh", "raw_url": "https://x/raw"},
                        ],
                    },
                    {
                        "id": 52,
                        "title": "scratch env",
                        "description": "private creds",
                        "visibility": "private",
                        "web_url": "https://gitlab.com/-/snippets/52",
                        "file_name": ".env",
                    },
                ],
                headers={"X-Page": "1", "X-Next-Page": "", "X-Total-Pages": "1"},
            )
        elif parsed.path.startswith("/api/v4/groups/") and parsed.path.endswith(
            "/hooks"
        ):
            # Group-webhook enumeration (--enumerate-webhooks). GitLab encodes
            # subscribed events as per-event boolean flags; the hook `token`
            # (the secret) is intentionally NOT included.
            from urllib.parse import unquote

            owner = unquote(parsed.path.split("/")[4])
            self._json(
                200,
                [
                    {
                        "id": 200,
                        "url": f"https://hooks.example.com/{owner}",
                        "push_events": True,
                        "merge_requests_events": True,
                        "issues_events": False,
                    },
                ],
                headers={"X-Page": "1", "X-Next-Page": "", "X-Total-Pages": "1"},
            )
        elif parsed.path.startswith("/api/v4/projects/") and parsed.path.endswith(
            "/protected_branches"
        ):
            # Protected-branch listing (--audit-branch-protection). One protected
            # branch, 'main', which DISALLOWS force push (enforce_admins true).
            self._json(
                200,
                [
                    {
                        "id": 1,
                        "name": "main",
                        "allow_force_push": False,
                    },
                ],
                headers={"X-Page": "1", "X-Next-Page": "", "X-Total-Pages": "1"},
            )
        elif parsed.path.startswith("/api/v4/projects/") and parsed.path.endswith(
            "/approvals"
        ):
            # Project approval policy (--audit-branch-protection). Two approvals
            # required, approvals reset on push (dismiss_stale_reviews true).
            self._json(
                200,
                {
                    "approvals_before_merge": 2,
                    "reset_approvals_on_push": True,
                },
            )
        elif parsed.path.startswith("/api/v4/projects/") and parsed.path.endswith(
            "/push_rule"
        ):
            # Project push rule (--audit-branch-protection). Unsigned commits are
            # rejected (require_signed_commits true).
            self._json(200, {"id": 1, "reject_unsigned_commits": True})
        elif parsed.path.startswith("/api/v4/projects/") and parsed.path.endswith(
            "/deploy_keys"
        ):
            # Per-project deploy-key enumeration (--enumerate-deploy-keys).
            # GitLab encodes write access as `can_push`; covenant inverts it to
            # `read_only`. This key is WRITABLE (can_push true) — the high-signal
            # case. The `key` is the PUBLIC SSH key; no private material.
            self._json(
                200,
                [
                    {
                        "id": 301,
                        "title": "ci-deploy",
                        "key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA deploy",
                        "fingerprint": "SHA256:deploykey301",
                        "can_push": True,
                    },
                ],
                headers={"X-Page": "1", "X-Next-Page": "", "X-Total-Pages": "1"},
            )
        elif parsed.path.startswith("/api/v4/groups/") and parsed.path.endswith(
            "/variables"
        ):
            # Group-level CI/CD variable-NAME enumeration
            # (--enumerate-actions-secrets). GitLab returns each variable's
            # `key` (name), `value` and `protected` flag; covenant emits the
            # name + protected only, never the value. One group variable is
            # protected.
            self._json(
                200,
                [
                    {
                        "key": "GROUP_AWS_KEY",
                        "value": "shouldnotappear",
                        "protected": False,
                    },
                    {
                        "key": "GROUP_NPM_TOKEN",
                        "value": "shouldnotappear",
                        "protected": True,
                    },
                ],
                headers={"X-Page": "1", "X-Next-Page": "", "X-Total-Pages": "1"},
            )
        elif parsed.path.startswith("/api/v4/projects/") and parsed.path.endswith(
            "/variables"
        ):
            # Project-level CI/CD variable-NAME enumeration
            # (--enumerate-actions-secrets). Name + protected only; no value.
            self._json(
                200,
                [
                    {
                        "key": "DEPLOY_TOKEN",
                        "value": "shouldnotappear",
                        "protected": False,
                    },
                ],
                headers={"X-Page": "1", "X-Next-Page": "", "X-Total-Pages": "1"},
            )
        elif parsed.path.startswith("/api/v4/groups/") and parsed.path.endswith(
            "/runners"
        ):
            # Group-level self-hosted runner enumeration (--enumerate-runners).
            # GitLab returns a flat list of runners with runner_type,
            # is_shared, and tag_list. One runner is the platform-managed SaaS
            # shared runner (is_shared true -> self_hosted false); one is a
            # group-attached self-hosted runner.
            self._json(
                200,
                [
                    {
                        "id": 800,
                        "description": "acme-group-runner",
                        "runner_type": "group_type",
                        "status": "online",
                        "is_shared": False,
                        "tag_list": ["self-hosted", "linux"],
                    },
                    {
                        "id": 801,
                        "description": "shared-saas-runner",
                        "runner_type": "instance_type",
                        "status": "online",
                        "is_shared": True,
                        "tag_list": ["saas-linux-small"],
                    },
                ],
                headers={"X-Page": "1", "X-Next-Page": "", "X-Total-Pages": "1"},
            )
        elif parsed.path.startswith("/api/v4/projects/") and parsed.path.endswith(
            "/runners"
        ):
            # Project-level self-hosted runner enumeration
            # (--enumerate-runners). One project-attached runner.
            self._json(
                200,
                [
                    {
                        "id": 810,
                        "description": "spellbook-project-runner",
                        "runner_type": "project_type",
                        "status": "online",
                        "is_shared": False,
                        "tag_list": ["self-hosted", "deploy"],
                    },
                ],
                headers={"X-Page": "1", "X-Next-Page": "", "X-Total-Pages": "1"},
            )
        elif parsed.path.startswith("/api/v4/projects/") and parsed.path.endswith(
            "/protected_environments"
        ):
            # Protected-environment listing (--audit-actions-environments).
            # 'production' is protected with 2 required approvals; 'staging' is
            # NOT in this list (so it reads as unprotected — branch_policy 'all').
            self._json(
                200,
                [
                    {
                        "name": "production",
                        "required_approval_count": 2,
                    },
                ],
                headers={"X-Page": "1", "X-Next-Page": "", "X-Total-Pages": "1"},
            )
        elif parsed.path.startswith("/api/v4/projects/") and parsed.path.endswith(
            "/environments"
        ):
            # Project-environment listing (--audit-actions-environments).
            self._json(
                200,
                [
                    {"id": 1, "name": "production"},
                    {"id": 2, "name": "staging"},
                ],
                headers={"X-Page": "1", "X-Next-Page": "", "X-Total-Pages": "1"},
            )
        elif parsed.path.startswith("/api/v4/projects/") and parsed.path.endswith(
            "/members"
        ):
            # Per-project DIRECT member enumeration (--enumerate-collaborators).
            # The non-/all endpoint returns members granted on the project
            # itself (GitLab's outside-collaborator analogue). access_level 30
            # (Developer) -> write; covenant flags every entry outside=true.
            # Only membership identity + access level — no token/key/email.
            self._json(
                200,
                [
                    {"username": "ex-contractor", "access_level": 30},
                    {"username": "auditor", "access_level": 10},
                ],
                headers={"X-Page": "1", "X-Next-Page": "", "X-Total-Pages": "1"},
            )
        elif parsed.path.startswith("/api/v4/groups/") and parsed.path.endswith(
            "/members/all"
        ):
            # Group-member enumeration (--enumerate-members). GitLab returns the
            # effective membership with a numeric access_level (50 = Owner);
            # covenant maps >=50 to role=admin, else member. Only membership
            # identity is returned — no token, key, or email.
            self._json(
                200,
                [
                    {"username": "spellcaster", "access_level": 50},
                    {"username": "apprentice", "access_level": 30},
                ],
                headers={"X-Page": "1", "X-Next-Page": "", "X-Total-Pages": "1"},
            )
        elif parsed.path.startswith("/api/v4/projects/") and parsed.path.endswith(
            "/repository/commits"
        ):
            # Commit-history scanning (--scan-commits). GitLab returns each
            # commit's id (sha), author_name (identity) and message. One commit
            # MESSAGE leaks a fake AWS key (the high-signal case). The author
            # EMAIL is deliberately omitted; the diff is never fetched.
            self._json(
                200,
                [
                    {
                        "id": "a1b2c3d",
                        "author_name": "Ex Contractor",
                        "title": "fix: rotate creds",
                        "message": (
                            "fix: rotate to AKIAIOSFODNN7EXAMPLE temporarily\n"
                        ),
                    },
                    {
                        "id": "deadbeef",
                        "author_name": "Spell Caster",
                        "title": "docs: update README",
                        "message": "docs: update README\n",
                    },
                ],
                headers={"X-Page": "1", "X-Next-Page": "", "X-Total-Pages": "1"},
            )
        elif parsed.path.startswith("/api/v4/projects/") and parsed.path.endswith(
            "/vulnerabilities"
        ):
            # The vulnerabilities endpoint backs three audits, distinguished by
            # the report_type query param:
            #   * no/dependency_scanning filter -> --audit-dependabot-alerts
            #   * report_type=secret_detection   -> --audit-secret-scanning
            #   * report_type=sast               -> --audit-code-scanning-alerts
            report_type = params.get("report_type", [None])[0]
            if report_type == "sast":
                # Code-scanning audit (--audit-code-scanning-alerts). GitLab's
                # analogue of a GitHub code-scanning/CodeQL alert is a detected
                # SAST vulnerability — a flaw the static analyzer found in the
                # project's OWN source. The mock project has one OPEN (detected)
                # CRITICAL finding. covenant lower-cases severity to match the
                # cross-provider shape and surfaces the rule id/name + web_url,
                # never a credential.
                self._json(
                    200,
                    [
                        {
                            "id": 9200,
                            "title": "SQL Injection",
                            "severity": "Critical",
                            "state": "detected",
                            "report_type": "sast",
                            "web_url": (
                                "https://gitlab.com/acme/spell-book-1/-/"
                                "security/vulnerabilities/9200"
                            ),
                            "finding": {
                                "name": "SQL Injection",
                                "identifier": "rules.sql_injection",
                            },
                        },
                    ],
                    headers={
                        "X-Page": "1",
                        "X-Next-Page": "",
                        "X-Total-Pages": "1",
                    },
                )
                return
            if report_type == "secret_detection":
                # Secret-detection audit (--audit-secret-scanning). GitLab's
                # analogue of a GitHub secret-scanning alert is a detected
                # secret_detection vulnerability. The mock project has one OPEN
                # (detected) finding for a leaked AWS key. The finding object can
                # carry the raw matched credential in raw_metadata; covenant must
                # read NEITHER it nor any secret value — only the title
                # classifier, state, and web_url.
                self._json(
                    200,
                    [
                        {
                            "id": 9100,
                            "title": "AWS Access Key",
                            "severity": "Critical",
                            "state": "detected",
                            "report_type": "secret_detection",
                            "web_url": (
                                "https://gitlab.com/acme/spell-book-1/-/"
                                "security/vulnerabilities/9100"
                            ),
                            "finding": {
                                "name": "AWS Access Key",
                                # Raw matched credential — covenant must NEVER echo it.
                                "raw_metadata": "AKIAIOSFODNN7EXAMPLE",
                            },
                        },
                    ],
                    headers={
                        "X-Page": "1",
                        "X-Next-Page": "",
                        "X-Total-Pages": "1",
                    },
                )
                return
            # Dependency-vulnerability audit (--audit-dependabot-alerts).
            # GitLab's analogue of a Dependabot alert is a detected
            # vulnerability from dependency scanning. The mock project has one
            # OPEN (detected) CRITICAL finding. covenant lower-cases severity to
            # match the cross-provider shape and surfaces only the advisory
            # identifier (CVE), never a credential.
            self._json(
                200,
                [
                    {
                        "id": 9001,
                        "title": "lodash",
                        "severity": "Critical",
                        "state": "detected",
                        "report_type": "dependency_scanning",
                        "cve": "CVE-2025-0002",
                        "finding": {
                            "name": "lodash",
                            "identifier": "CVE-2025-0002",
                        },
                    },
                ],
                headers={"X-Page": "1", "X-Next-Page": "", "X-Total-Pages": "1"},
            )
        elif parsed.path.startswith("/api/v4/projects/") and (
            "/repository/files/" in parsed.path
        ):
            # CODEOWNERS-coverage audit (--audit-codeowners). GitLab serves file
            # content as a JSON object with base64-encoded `content`, addressed by
            # URL-encoded path + `ref`. covenant probes .gitlab/CODEOWNERS,
            # CODEOWNERS, then docs/CODEOWNERS. The mock's single project has a
            # PARTIAL CODEOWNERS (rules but no catch-all '*' — the high-signal
            # coverage gap) at .gitlab/CODEOWNERS; other paths 404 (absent).
            import base64 as _b64
            from urllib.parse import unquote

            encoded = parsed.path.split("/repository/files/", 1)[1]
            file_path = unquote(encoded)
            body = (
                "# ownership\n"
                "src/ @backend\n"
                "docs/ @docs-team\n"
            )  # no '*' rule on purpose
            # Package-dependency inventory (--audit-packages). The mock project
            # ships a go.mod (go) manifest at the repo root; other manifest probes
            # 404. covenant parses the module + version rows.
            go_mod_body = (
                "module example.com/spell-book\n\n"
                "go 1.22\n\n"
                "require (\n"
                "\tgithub.com/pkg/errors v0.9.1\n"
                "\tgolang.org/x/sync v0.7.0 // indirect\n"
                ")\n"
            )
            served = None
            if file_path == ".gitlab/CODEOWNERS":
                served = body
            elif file_path == "go.mod":
                served = go_mod_body
            if served is not None:
                self._json(
                    200,
                    {
                        "file_path": file_path,
                        "ref": params.get("ref", ["main"])[0],
                        "encoding": "base64",
                        "content": _b64.b64encode(served.encode()).decode(),
                    },
                    headers={"X-Page": "1", "X-Next-Page": "", "X-Total-Pages": "1"},
                )
            else:
                self._json(404, {"message": "404 File Not Found"})
        elif parsed.path == "/api/v4/groups":
            # Group/blast-radius enumeration (--enumerate-orgs).
            self._json(
                200,
                [
                    {
                        "id": 10,
                        "name": "Acme Corp",
                        "path": "acme-corp",
                        "full_path": "acme-corp",
                        "web_url": "https://gitlab.com/groups/acme-corp",
                    },
                    {
                        "id": 11,
                        "name": "Wizards",
                        "path": "wizards",
                        "full_path": "acme-corp/wizards",
                        "web_url": "https://gitlab.com/groups/acme-corp/wizards",
                    },
                ],
                headers={"X-Page": "1", "X-Next-Page": "", "X-Total-Pages": "1"},
            )
        else:
            self._json(404, {"message": "404 Not Found"})


def _bitbucket_search_code(query: str, page: int = 1) -> dict:
    """Simulate a Bitbucket Cloud /2.0/workspaces/{ws}/search/code response.

    Injects a fake AWS key inside ``content_matches`` so ``--scan-secrets``
    tests have a real fragment to detect.
    """
    return {
        "values": [
            {
                "type": "code_search_result",
                "file": {
                    "path": f"src/{query}-{page}.py",
                    "commit": {
                        "repository": {
                            "full_name": f"acme/{query}-book",
                        }
                    },
                },
                "path_matches": [],
                "content_matches": [
                    {
                        "lines": [
                            {
                                "line": 1,
                                "segments": [
                                    {"text": f"# {query}\n"},
                                ],
                            },
                            {
                                "line": 2,
                                "segments": [
                                    {"text": "AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE\n"},
                                ],
                            },
                        ]
                    }
                ],
            }
        ],
        "size": 1,
    }


class _BitbucketHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def _json(self, code: int, payload, headers: dict | None = None):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        auth = self.headers.get("Authorization", "")
        if not auth:
            self._json(401, {"type": "error", "error": {"message": "Unauthorized"}})
            return

        if parsed.path == "/2.0/repositories":
            query = params.get("q", ['name~"spell"'])[0]
            term = "spell"
            if 'name~"' in query:
                term = query.split('name~"', 1)[1].split('"', 1)[0]
            if _rate_limit_response(self, term):
                return
            page = int(params.get("page", ["1"])[0])
            envelope = {
                "values": [
                    {
                        "name": f"{term}-book-{page}",
                        "full_name": f"acme/{term}-book-{page}",
                        "is_private": True,
                        "links": {
                            "html": {
                                "href": f"https://bitbucket.org/acme/{term}-book-{page}"
                            }
                        },
                        "description": "A repository of spells",
                    }
                ],
                "size": 1,
            }
            # For multi-page queries, advertise a `next` URL until TOTAL_PAGES.
            if term.startswith(MULTIPAGE_PREFIX) and page < TOTAL_PAGES:
                from urllib.parse import urlencode

                next_params = {k: v[0] for k, v in params.items()}
                next_params["page"] = page + 1
                host = self.server.server_address[1]
                envelope["next"] = (
                    f"http://127.0.0.1:{host}/2.0/repositories?{urlencode(next_params)}"
                )
            self._json(200, envelope)
        elif parsed.path.endswith("/search/code") and "/workspaces/" in parsed.path:
            # Workspace-scoped code search:
            # /2.0/workspaces/{workspace}/search/code
            term = params.get("search_query", ["spell"])[0]
            page = int(params.get("page", ["1"])[0])
            envelope = _bitbucket_search_code(term, page=page)
            # Multi-page support for pagination tests.
            if term.startswith(MULTIPAGE_PREFIX) and page < TOTAL_PAGES:
                from urllib.parse import urlencode

                next_params = {k: v[0] for k, v in params.items()}
                next_params["page"] = page + 1
                host = self.server.server_address[1]
                envelope["next"] = (
                    f"http://127.0.0.1:{host}{parsed.path}?{urlencode(next_params)}"
                )
            self._json(200, envelope)
        elif parsed.path == "/2.0/user":
            self._json(200, {"username": "spellcaster", "uuid": "{abc-123}"})
        elif parsed.path == "/2.0/user/permissions/repositories":
            self._json(
                200,
                {"values": [{"permission": "admin"}]},
            )
        elif parsed.path.startswith("/2.0/users/") and parsed.path.endswith(
            "/ssh-keys"
        ):
            # User-scoped SSH-key enumeration (--enumerate-keys). Bitbucket
            # Cloud has no GPG-key API, so only SSH keys are returned.
            self._json(
                200,
                {
                    "values": [
                        {
                            "uuid": "{key-1}",
                            "label": "laptop",
                            "key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA laptop",
                        },
                        {
                            "uuid": "{key-2}",
                            "label": "ci-runner",
                            "key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB ci",
                        },
                    ],
                    "size": 2,
                },
            )
        elif parsed.path == "/2.0/snippets":
            # Snippet enumeration (--enumerate-gists). `files` is an object
            # keyed by filename; only the filenames are surfaced as the leak
            # signal (the file links/content are omitted from covenant output).
            self._json(
                200,
                {
                    "values": [
                        {
                            "id": "snip1",
                            "title": "deploy helper",
                            "is_private": False,
                            "links": {
                                "html": {
                                    "href": "https://bitbucket.org/snippets/spellcaster/snip1"
                                }
                            },
                            "files": {"deploy.sh": {"links": {}}},
                        },
                        {
                            "id": "snip2",
                            "title": "scratch env",
                            "is_private": True,
                            "links": {
                                "html": {
                                    "href": "https://bitbucket.org/snippets/spellcaster/snip2"
                                }
                            },
                            "files": {".env": {"links": {}}, "notes.md": {"links": {}}},
                        },
                    ],
                    "size": 2,
                },
            )
        elif parsed.path.startswith("/2.0/workspaces/") and parsed.path.endswith(
            "/hooks"
        ):
            # Workspace-webhook enumeration (--enumerate-webhooks). Bitbucket
            # returns the subscribed events as an array directly; the hook
            # secret is intentionally NOT included.
            owner = parsed.path.split("/")[3]
            self._json(
                200,
                {
                    "values": [
                        {
                            "uuid": f"{{hook-{owner}}}",
                            "url": f"https://hooks.example.com/{owner}",
                            "active": True,
                            "events": ["repo:push", "pullrequest:created"],
                        },
                    ],
                    "size": 1,
                },
            )
        elif parsed.path.startswith("/2.0/repositories/") and parsed.path.endswith(
            "/branch-restrictions"
        ):
            # Branch-restriction listing (--audit-branch-protection). Bitbucket
            # returns a flat list of restriction objects keyed by pattern + kind;
            # covenant aggregates them per pattern. The 'main' pattern requires 2
            # approvals, resets approvals on change, and forbids force push.
            self._json(
                200,
                {
                    "values": [
                        {
                            "id": 1,
                            "kind": "require_approvals_to_merge",
                            "pattern": "main",
                            "value": 2,
                        },
                        {
                            "id": 2,
                            "kind": "reset_pullrequest_approvals_on_change",
                            "pattern": "main",
                            "value": None,
                        },
                        {
                            "id": 3,
                            "kind": "force",
                            "pattern": "main",
                            "value": None,
                        },
                    ],
                    "size": 3,
                },
            )
        elif parsed.path.startswith("/2.0/repositories/") and parsed.path.endswith(
            "/deploy-keys"
        ):
            # Per-repo deploy-key (access-key) enumeration
            # (--enumerate-deploy-keys). Bitbucket Cloud access keys are
            # read-only by design (no per-key push toggle). The `key` is the
            # PUBLIC SSH key; no private material is returned.
            repo = "/".join(parsed.path.split("/")[3:5])
            self._json(
                200,
                {
                    "values": [
                        {
                            "id": 401,
                            "label": "ci-deploy",
                            "key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA deploy",
                            "comment": repo,
                        },
                    ],
                    "size": 1,
                },
            )
        elif parsed.path.startswith("/2.0/workspaces/") and parsed.path.endswith(
            "/pipelines-config/variables"
        ):
            # Workspace-level Pipelines variable-NAME enumeration
            # (--enumerate-actions-secrets). Bitbucket returns each variable's
            # `key` and a `secured` flag; for a secured variable the API omits
            # the `value` entirely. covenant emits name + protected only. One
            # variable is secured (protected=true).
            self._json(
                200,
                {
                    "values": [
                        {
                            "uuid": "{var-1}",
                            "key": "WS_AWS_KEY",
                            "value": "shouldnotappear",
                            "secured": False,
                        },
                        {
                            "uuid": "{var-2}",
                            "key": "WS_NPM_TOKEN",
                            "secured": True,
                        },
                    ],
                    "size": 2,
                },
            )
        elif parsed.path.startswith("/2.0/repositories/") and parsed.path.endswith(
            "/pipelines-config/variables"
        ):
            # Repo-level Pipelines variable-NAME enumeration
            # (--enumerate-actions-secrets). Name + protected only; no value.
            self._json(
                200,
                {
                    "values": [
                        {
                            "uuid": "{var-3}",
                            "key": "DEPLOY_TOKEN",
                            "value": "shouldnotappear",
                            "secured": False,
                        },
                    ],
                    "size": 1,
                },
            )
        elif parsed.path.startswith("/2.0/workspaces/") and parsed.path.endswith(
            "/pipelines-config/runners"
        ):
            # Workspace-level self-hosted runner enumeration
            # (--enumerate-runners). Bitbucket Pipelines runners are
            # self-hosted by design. The OAuth client secret is never echoed.
            self._json(
                200,
                {
                    "values": [
                        {
                            "uuid": "{runner-ws-1}",
                            "name": "acme-workspace-runner",
                            "labels": ["self.hosted", "linux"],
                            "state": {"status": "ONLINE"},
                        },
                        {
                            "uuid": "{runner-ws-2}",
                            "name": "acme-workspace-runner-2",
                            "labels": ["self.hosted", "macos"],
                            "state": {"status": "OFFLINE"},
                        },
                    ],
                    "size": 2,
                },
            )
        elif parsed.path.startswith("/2.0/repositories/") and parsed.path.endswith(
            "/pipelines-config/runners"
        ):
            # Repo-level self-hosted runner enumeration (--enumerate-runners).
            self._json(
                200,
                {
                    "values": [
                        {
                            "uuid": "{runner-repo-1}",
                            "name": "spellbook-repo-runner",
                            "labels": ["self.hosted", "linux", "deploy"],
                            "state": {"status": "ONLINE"},
                        },
                    ],
                    "size": 1,
                },
            )
        elif parsed.path.startswith("/2.0/repositories/") and parsed.path.endswith(
            "/environments"
        ):
            # Deployment-environment audit (--audit-actions-environments).
            # 'production' has an admin-only deploy restriction (required_reviewers
            # True); 'staging' has none (unreviewed deploys). Bitbucket Cloud has
            # no per-env reviewer count / wait timer / branch policy, so those
            # fields are constant (0/0/'all').
            self._json(
                200,
                {
                    "values": [
                        {
                            "uuid": "{env-prod}",
                            "name": "production",
                            "restrictions": {"admin_only": True},
                        },
                        {
                            "uuid": "{env-stage}",
                            "name": "staging",
                            "restrictions": {"admin_only": False},
                        },
                    ],
                    "size": 2,
                },
            )
        elif parsed.path.startswith("/2.0/repositories/") and parsed.path.endswith(
            "/permissions-config/users"
        ):
            # Per-repo explicit user-permission enumeration
            # (--enumerate-collaborators). Bitbucket grades access as
            # admin/write/read; covenant surfaces it verbatim as `role` and
            # flags every entry outside=true. This grant has WRITE access — the
            # high-signal ghost-account case. Only identity + permission — no
            # token/key/email.
            self._json(
                200,
                {
                    "values": [
                        {
                            "user": {"nickname": "ex-contractor"},
                            "permission": "write",
                        },
                    ],
                    "size": 1,
                },
            )
        elif parsed.path.startswith("/2.0/workspaces/") and parsed.path.endswith(
            "/members"
        ):
            # Workspace-member enumeration (--enumerate-members). Each membership
            # carries a `user` object and a `permission` level; covenant maps
            # 'owner' to role=admin, else member. Only membership identity is
            # returned — no token, key, or email.
            self._json(
                200,
                {
                    "values": [
                        {
                            "user": {"nickname": "spellcaster"},
                            "permission": "owner",
                        },
                        {
                            "user": {"nickname": "apprentice"},
                            "permission": "member",
                        },
                    ],
                    "size": 2,
                },
            )
        elif parsed.path.startswith("/2.0/repositories/") and parsed.path.endswith(
            "/commits"
        ):
            # Commit-history scanning (--scan-commits). Bitbucket returns each
            # commit's hash (sha), an author object, and message. One commit
            # MESSAGE leaks a fake AWS key (the high-signal case). covenant
            # surfaces only the author display nickname — never the `raw`
            # "Name <email>" string — and never fetches the diff.
            self._json(
                200,
                {
                    "values": [
                        {
                            "hash": "a1b2c3d",
                            "author": {
                                "raw": "Ex Contractor <ex@evil.example>",
                                "user": {"nickname": "ex-contractor"},
                            },
                            "message": (
                                "fix: rotate to AKIAIOSFODNN7EXAMPLE temporarily"
                            ),
                        },
                        {
                            "hash": "deadbeef",
                            "author": {
                                "raw": "Spell Caster <sc@acme.example>",
                                "user": {"nickname": "spellcaster"},
                            },
                            "message": "docs: update README",
                        },
                    ],
                    "size": 2,
                },
            )
        elif parsed.path.startswith("/2.0/repositories/") and (
            "/src/HEAD/" in parsed.path
        ):
            # CODEOWNERS-coverage audit (--audit-codeowners). Bitbucket's source
            # API returns the file's RAW text (not a JSON envelope). covenant
            # probes CODEOWNERS then docs/CODEOWNERS at the HEAD of the main
            # branch. The mock's single repo has a PARTIAL CODEOWNERS (rules but
            # no catch-all '*' — the high-signal coverage gap) at the root; other
            # paths 404 (absent).
            # Package-dependency inventory (--audit-packages). The mock repo ships
            # a Gemfile (rubygems) manifest at the root; other manifest probes
            # 404. covenant parses the gem + version rows. Bitbucket has no
            # dependency-alert API, so --audit-packages is the only dependency
            # surface that works there.
            file_path = parsed.path.split("/src/HEAD/", 1)[1]
            raw = None
            if file_path == "CODEOWNERS":
                raw = (
                    b"# ownership\n"
                    b"src/ @backend\n"
                    b"docs/ @docs-team\n"
                )  # no '*' rule on purpose
            elif file_path == "Gemfile":
                raw = (
                    b"source 'https://rubygems.org'\n"
                    b"gem 'rails', '~> 7.0'\n"
                    b"gem 'puma'\n"
                )
            if raw is not None:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            else:
                self._json(
                    404, {"type": "error", "error": {"message": "Not Found"}}
                )
        elif parsed.path == "/2.0/workspaces":
            # Workspace/blast-radius enumeration (--enumerate-orgs).
            self._json(
                200,
                {
                    "values": [
                        {
                            "slug": "acme",
                            "name": "Acme Corp",
                            "links": {
                                "html": {"href": "https://bitbucket.org/acme"}
                            },
                        },
                        {
                            "slug": "wizards",
                            "name": "Wizards Inc",
                            "links": {
                                "html": {"href": "https://bitbucket.org/wizards"}
                            },
                        },
                    ],
                    "size": 2,
                },
            )
        else:
            self._json(404, {"type": "error", "error": {"message": "Not Found"}})


_HANDLERS = {
    "github": _GitHubHandler,
    "gitlab": _GitLabHandler,
    "bitbucket": _BitbucketHandler,
}


class MockSCMServer:
    """A threaded mock SCM API server bound to an ephemeral port."""

    def __init__(self, scm: str):
        handler = _HANDLERS[scm]
        # Ephemeral port: bind to port 0 and let the OS assign a free one.
        # ThreadingHTTPServer does this internally when given port 0, but we
        # follow the explicit socket.bind(('', 0)) pattern from the criteria.
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("", 0))
        port = probe.getsockname()[1]
        probe.close()

        self._server = ThreadingHTTPServer(("127.0.0.1", port), handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> "MockSCMServer":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)
