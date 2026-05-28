"""Scope enforcement for covenant.

Every covenant module that touches a remote SCM must first confirm the target
host is listed in the operator's ``--scope-file``. This is the guardrail that
keeps the tool inside the bounds of an authorized engagement: covenant refuses
to talk to any host that was not explicitly authorized.

A scope file lists one authorized SCM URL / org / repo per line. We extract the
host from each entry (entries may be bare hosts like ``github.com`` or fuller
paths like ``github.com/acme/repo`` or ``https://gitlab.example/group``) and a
target is in scope iff its host matches a listed host.

Scope entries may *also* carry an org/group/workspace path segment
(``github.com/acme-corp``, ``bitbucket.org/acme/some-repo``). When every entry
for a given host carries such a path, covenant treats that host as
**org-restricted**: a recon target on that host is only authorized if the org it
names is among the listed orgs. A host that appears as a bare entry anywhere
(``github.com`` with no path) stays **host-wide** — any org on it is in scope —
preserving the original v0.1 behaviour and keeping the loopback test hosts
permissive. This closes the gap where listing ``bitbucket.org/acme`` and then
running ``recon-code --workspace victim`` would happily search a workspace the
operator was never authorized for, because only the host was ever checked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse


class ScopeError(Exception):
    """Raised when a target host is not in the authorized scope."""


def _split_host_org(entry: str) -> tuple[str | None, str | None]:
    """Split a scope-file entry or target URL into ``(host, org)``.

    ``org`` is the first path segment after the host — the org / group /
    workspace slug — lower-cased, or ``None`` when the entry is a bare host.
    A target URL with only an API path (e.g. ``api.bitbucket.org`` or
    ``github.com`` with no org) yields ``(host, None)``.
    """
    entry = entry.strip()
    if not entry:
        return None, None
    if "://" not in entry:
        # Bare host or host/path form; give urlparse a scheme to work with.
        entry = "//" + entry
    parsed = urlparse(entry, scheme="https")
    host = parsed.hostname
    path = parsed.path
    if not host:
        # Fallback: first path segment is the host (e.g. "github.com/acme"
        # with no scheme parsed oddly); re-split on '/'.
        segs = parsed.path.lstrip("/").split("/")
        host = segs[0] or None
        org = segs[1] if len(segs) > 1 and segs[1] else None
        return (host.lower() if host else None, org.lower() if org else None)
    org_seg = path.lstrip("/").split("/", 1)[0]
    org = org_seg.lower() if org_seg else None
    return host.lower(), org


def _host_of(entry: str) -> str | None:
    """Extract a bare hostname from a scope-file entry or a target URL."""
    host, _ = _split_host_org(entry)
    return host


@dataclass
class Scope:
    """The authorized SCM targets loaded from a scope file.

    ``hosts`` is the set of authorized hostnames (host-level guardrail).
    ``orgs`` maps a host to the set of org/group/workspace slugs explicitly
    authorized on it. ``host_wide`` is the set of hosts that appeared as a bare
    entry at least once and are therefore authorized for *any* org.
    """

    hosts: set[str]
    orgs: dict[str, set[str]] = field(default_factory=dict)
    host_wide: set[str] = field(default_factory=set)

    @classmethod
    def from_file(cls, path: str) -> "Scope":
        hosts: set[str] = set()
        orgs: dict[str, set[str]] = {}
        host_wide: set[str] = set()
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                host, org = _split_host_org(line)
                if not host:
                    continue
                hosts.add(host)
                if org:
                    orgs.setdefault(host, set()).add(org)
                else:
                    # A bare host entry authorizes the whole host (any org).
                    host_wide.add(host)
        if not hosts:
            raise ScopeError(f"scope file {path!r} lists no authorized hosts")
        return cls(hosts=hosts, orgs=orgs, host_wide=host_wide)

    def is_in_scope(self, target_url: str) -> bool:
        host = _host_of(target_url)
        return bool(host) and host in self.hosts

    def assert_in_scope(self, target_url: str) -> None:
        if not self.is_in_scope(target_url):
            host = _host_of(target_url) or target_url
            raise ScopeError(
                f"target {host!r} is out of scope; not listed in the scope file"
            )

    def is_host_org_restricted(self, host: str) -> bool:
        """True if ``host`` is authorized only for specific orgs.

        A host is org-restricted when it has at least one explicit org entry and
        never appeared as a bare (host-wide) entry. Such a host refuses targets
        in orgs outside its authorized set.
        """
        host = host.lower()
        return host in self.orgs and host not in self.host_wide

    def is_org_in_scope(self, target_url: str, org: str | None) -> bool:
        """True if ``org`` on ``target_url``'s host is authorized.

        - If the host is not in scope at all → ``False``.
        - If the host is host-wide (a bare entry exists) → ``True`` for any org.
        - If the host is org-restricted and ``org`` is ``None`` → ``False``:
          the operator restricted the host to specific orgs, so an unscoped
          (host-wide) recon target is not authorized.
        - Otherwise → ``True`` iff ``org`` is among the authorized orgs.
        """
        host = _host_of(target_url)
        if not host or host not in self.hosts:
            return False
        if not self.is_host_org_restricted(host):
            return True
        if org is None:
            return False
        return org.lower() in self.orgs.get(host, set())

    def assert_org_in_scope(self, target_url: str, org: str | None) -> None:
        """Raise :class:`ScopeError` if ``org`` is not authorized on the host.

        This is the org-level companion to :meth:`assert_in_scope`. Callers
        that can name the org/group/workspace a recon target lands in (e.g. the
        Bitbucket ``--workspace`` slug) use this to refuse a sibling org on an
        otherwise in-scope host.
        """
        if self.is_org_in_scope(target_url, org):
            return
        host = _host_of(target_url) or target_url
        if org is None:
            authorized = sorted(self.orgs.get(host, set()))
            raise ScopeError(
                f"host {host!r} is authorized only for specific orgs "
                f"({', '.join(authorized)}); this target names no org and is "
                "therefore out of scope. Add a bare host entry to authorize "
                "the whole host, or name an authorized org."
            )
        authorized = sorted(self.orgs.get(host, set()))
        raise ScopeError(
            f"org {org!r} on {host!r} is out of scope; "
            f"authorized orgs for this host: {', '.join(authorized) or '(none)'}"
        )
