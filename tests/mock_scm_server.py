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
            headers = self._link_header(parsed.path, params, page)
            self._json(200, _github_search_repos(query, page=page), headers=headers)
        elif parsed.path == "/search/code":
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

        if parsed.path == "/api/v4/projects":
            search = params.get("search", ["spell"])[0]
            self._json(
                200,
                [
                    {
                        "id": 99,
                        "name": f"{search}-book-{page}",
                        "path_with_namespace": f"acme/{search}-book-{page}",
                        "visibility": "private",
                        "web_url": f"https://gitlab.com/acme/{search}-book-{page}",
                        "description": "A repository of spells",
                    }
                ],
                headers=self._page_headers(search, page),
            )
        elif parsed.path == "/api/v4/search":
            scope = params.get("scope", ["blobs"])[0]
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

    def _json(self, code: int, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
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
