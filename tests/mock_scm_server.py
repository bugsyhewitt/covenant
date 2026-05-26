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


def _github_search_repos(query: str) -> dict:
    return {
        "total_count": 1,
        "incomplete_results": False,
        "items": [
            {
                "name": f"{query}-book",
                "full_name": f"acme/{query}-book",
                "private": False,
                "visibility": "public",
                "html_url": f"https://github.com/acme/{query}-book",
                "description": "A repository of spells",
            }
        ],
    }


def _github_search_code(query: str) -> dict:
    return {
        "total_count": 1,
        "incomplete_results": False,
        "items": [
            {
                "name": f"{query}.py",
                "path": f"src/{query}.py",
                "repository": {
                    "name": f"{query}-book",
                    "private": False,
                    "html_url": f"https://github.com/acme/{query}-book",
                },
                "html_url": f"https://github.com/acme/{query}-book/blob/main/src/{query}.py",
            }
        ],
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

    def do_GET(self):  # noqa: N802 - http.server API
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        auth = self.headers.get("Authorization", "")

        if not auth.lower().startswith(("token ", "bearer ")):
            self._json(401, {"message": "Requires authentication"})
            return

        if parsed.path == "/search/repositories":
            query = params.get("q", ["spell"])[0].split()[0]
            self._json(200, _github_search_repos(query))
        elif parsed.path == "/search/code":
            query = params.get("q", ["spell"])[0].split()[0]
            self._json(200, _github_search_code(query))
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
        token = self.headers.get("PRIVATE-TOKEN", "") or self.headers.get(
            "Authorization", ""
        )
        if not token:
            self._json(401, {"message": "401 Unauthorized"})
            return

        if parsed.path == "/api/v4/projects":
            search = params.get("search", ["spell"])[0]
            self._json(
                200,
                [
                    {
                        "id": 99,
                        "name": f"{search}-book",
                        "path_with_namespace": f"acme/{search}-book",
                        "visibility": "private",
                        "web_url": f"https://gitlab.com/acme/{search}-book",
                        "description": "A repository of spells",
                    }
                ],
            )
        elif parsed.path == "/api/v4/user":
            self._json(200, {"username": "spellcaster", "id": 4242, "is_admin": False})
        elif parsed.path == "/api/v4/personal_access_tokens/self":
            self._json(
                200,
                {"name": "covenant", "scopes": ["read_api", "read_repository"]},
            )
        else:
            self._json(404, {"message": "404 Not Found"})


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
            self._json(
                200,
                {
                    "values": [
                        {
                            "name": f"{term}-book",
                            "full_name": f"acme/{term}-book",
                            "is_private": True,
                            "links": {
                                "html": {
                                    "href": f"https://bitbucket.org/acme/{term}-book"
                                }
                            },
                            "description": "A repository of spells",
                        }
                    ],
                    "size": 1,
                },
            )
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
