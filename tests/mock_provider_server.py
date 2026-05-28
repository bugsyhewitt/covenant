"""In-process mock provider servers for covenant's secret-verification probes.

Emulates the minimal read-only auth surfaces covenant probes when
``--verify-secrets`` is set: AWS STS ``GetCallerIdentity`` and Stripe
``GET /v1/balance``. Each server binds an **ephemeral port** so tests never
collide on a fixed port and never touch the reserved 8888 voice port.

A server is configured with a set of *live* secret values; a probe carrying a
live secret in its ``Authorization`` header gets the configured "valid" status,
anything else gets 401. A server can also be told to always return 429 (to prove
covenant treats a rate-limited credential as still-live) or a 500 (to prove an
indeterminate verdict maps to ``None``).
"""

from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class _ProviderHandler(BaseHTTPRequestHandler):
    # These are injected onto the handler class per-server via a closure factory.
    live_secrets: frozenset[str] = frozenset()
    valid_status: int = 200
    force_status: int | None = None

    def log_message(self, *args):  # noqa: D401 - silence test noise
        return

    def _send(self, code: int, body: bytes = b"{}"):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 - http.server API
        if self.force_status is not None:
            self._send(self.force_status)
            return

        auth = self.headers.get("Authorization", "")
        # Extract the credential token from either an AWS4 Credential= clause or
        # a Bearer token — both are the shapes covenant's verifiers send.
        secret = ""
        if "Credential=" in auth:
            secret = auth.split("Credential=", 1)[1].split(",", 1)[0].split("/", 1)[0]
        elif auth.lower().startswith("bearer "):
            secret = auth[7:].strip()

        parsed = urlparse(self.path)
        # Sanity: AWS probes are read-only GetCallerIdentity; Stripe probes hit
        # /v1/balance. We don't enforce the action strictly, but 404 anything
        # that's clearly not a known read-only surface.
        params = parse_qs(parsed.query)
        action = params.get("Action", [""])[0]
        if parsed.path not in ("/", "/v1/balance") and action != "GetCallerIdentity":
            self._send(404)
            return

        if secret and secret in self.live_secrets:
            self._send(self.valid_status)
        else:
            self._send(401)


def _make_handler(
    live_secrets: frozenset[str],
    valid_status: int,
    force_status: int | None,
) -> type[_ProviderHandler]:
    return type(
        "_BoundProviderHandler",
        (_ProviderHandler,),
        {
            "live_secrets": live_secrets,
            "valid_status": valid_status,
            "force_status": force_status,
        },
    )


class MockProviderServer:
    """A threaded mock provider server bound to an ephemeral port.

    Parameters
    ----------
    live_secrets:
        Secrets the server will accept as valid.
    valid_status:
        Status returned for a live secret (200 normally; 429 to simulate a
        rate-limited-but-valid credential).
    force_status:
        If set, every request returns this status regardless of auth (used to
        simulate a 500 → indeterminate ``None`` verdict).
    """

    def __init__(
        self,
        live_secrets: list[str] | None = None,
        *,
        valid_status: int = 200,
        force_status: int | None = None,
    ):
        handler = _make_handler(
            frozenset(live_secrets or []), valid_status, force_status
        )
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

    def __enter__(self) -> "MockProviderServer":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)
