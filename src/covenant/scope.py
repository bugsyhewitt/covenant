"""Scope enforcement for covenant.

Every covenant module that touches a remote SCM must first confirm the target
host is listed in the operator's ``--scope-file``. This is the guardrail that
keeps the tool inside the bounds of an authorized engagement: covenant refuses
to talk to any host that was not explicitly authorized.

A scope file lists one authorized SCM URL / org / repo per line. We extract the
host from each entry (entries may be bare hosts like ``github.com`` or fuller
paths like ``github.com/acme/repo`` or ``https://gitlab.example/group``) and a
target is in scope iff its host matches a listed host.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


class ScopeError(Exception):
    """Raised when a target host is not in the authorized scope."""


def _host_of(entry: str) -> str | None:
    """Extract a bare hostname from a scope-file entry or a target URL."""
    entry = entry.strip()
    if not entry:
        return None
    if "://" not in entry:
        # Bare host or host/path form; give urlparse a scheme to work with.
        entry = "//" + entry
    parsed = urlparse(entry, scheme="https")
    host = parsed.hostname
    if host:
        return host.lower()
    # Fallback: first path segment (e.g. "github.com/acme" with no scheme).
    candidate = parsed.path.lstrip("/").split("/", 1)[0]
    return candidate.lower() or None


@dataclass
class Scope:
    """A set of authorized SCM hosts loaded from a scope file."""

    hosts: set[str]

    @classmethod
    def from_file(cls, path: str) -> "Scope":
        hosts: set[str] = set()
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                host = _host_of(line)
                if host:
                    hosts.add(host)
        if not hosts:
            raise ScopeError(f"scope file {path!r} lists no authorized hosts")
        return cls(hosts=hosts)

    def is_in_scope(self, target_url: str) -> bool:
        host = _host_of(target_url)
        return bool(host) and host in self.hosts

    def assert_in_scope(self, target_url: str) -> None:
        if not self.is_in_scope(target_url):
            host = _host_of(target_url) or target_url
            raise ScopeError(
                f"target {host!r} is out of scope; not listed in the scope file"
            )
