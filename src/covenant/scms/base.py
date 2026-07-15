"""Common HTTP plumbing for covenant's SCM clients.

[Worker decision: covenant performs its API calls through a thin shared httpx
layer rather than driving PyGithub / python-gitlab / atlassian-python-api object
models directly. Those SDKs are still declared (and version-pinned) dependencies
per the criteria because they define the idiomatic surface a v0.2 can grow into,
but the v0.1 read-only recon path needs only a handful of GET endpoints. Talking
plain httpx to a configurable base URL keeps the live and mock-server paths
byte-for-byte identical, which is what the ephemeral-port smoke tests exercise.]
"""

from __future__ import annotations

import json
import re
import time
import tomllib
from collections.abc import Callable

import httpx

#: Default page-walk ceiling exposed via the CLI ``--max-pages`` flag. Recon
#: callers may lower this; the hard ceiling is enforced in the CLI.
DEFAULT_MAX_PAGES = 10
#: Absolute upper bound on pages, chosen to respect GitHub's ~100-page search
#: cap. The CLI clamps ``--max-pages`` to this value.
HARD_MAX_PAGES = 100

#: Default number of retry attempts for a rate-limited (403/429) response
#: before covenant gives up on that request. The original attempt is not
#: counted, so a value of 3 means up to 4 total GETs for one logical request.
DEFAULT_MAX_RETRIES = 3
#: Hard cap on how long covenant will honor a server-supplied retry interval.
#: A hostile or misconfigured API can advertise an enormous ``Retry-After``;
#: we never sleep longer than this regardless of what the header claims.
MAX_BACKOFF_SECONDS = 60.0
#: Base interval for the exponential backoff used when the server gives no
#: explicit retry hint: attempt N sleeps ``BASE_BACKOFF_SECONDS * 2**N``.
BASE_BACKOFF_SECONDS = 1.0

#: HTTP status codes covenant treats as "rate-limited, retry after a wait"
#: rather than a hard failure. 429 is the standard; GitHub's search API also
#: signals secondary rate limits with 403 + a ``Retry-After`` header.
_RATE_LIMIT_STATUSES = frozenset({403, 429})


class SCMError(Exception):
    """Raised when an SCM API call fails or returns an unexpected shape."""


#: Standard repository-root-relative locations a CODEOWNERS file may live at,
#: in the precedence order the SCMs themselves honor (``.github/`` /
#: ``.gitlab/`` first, then the root, then ``docs/``). All three SCMs support
#: the same three locations, so covenant probes them in this order and reports
#: the first one found. The provider-specific directory (``.github`` vs
#: ``.gitlab``) is supplied by each client; the root and ``docs/`` fallbacks are
#: universal.
CODEOWNERS_FILENAME = "CODEOWNERS"


def codeowners_candidate_paths(provider_dir: str) -> tuple[str, ...]:
    """Return the CODEOWNERS lookup paths for a provider, in precedence order.

    The SCMs resolve CODEOWNERS from, in order, their provider directory
    (``.github`` on GitHub, ``.gitlab`` on GitLab, ``.bitbucket`` is not used —
    Bitbucket keeps it at the root), then the repository root, then ``docs/``.
    We probe in that same order and report the first hit so the audit mirrors
    where the provider would actually read the file from.
    """
    paths: list[str] = []
    if provider_dir:
        paths.append(f"{provider_dir}/{CODEOWNERS_FILENAME}")
    paths.append(CODEOWNERS_FILENAME)
    paths.append(f"docs/{CODEOWNERS_FILENAME}")
    return tuple(paths)


def parse_codeowners(text: str) -> dict:
    """Parse a CODEOWNERS file body into the normalized audit summary fields.

    A CODEOWNERS file is a list of ``<path-pattern> <owner...>`` rules; lines
    that are blank or begin with ``#`` are comments. covenant does NOT surface
    the owners themselves (they are account/team handles, not credentials, but
    they are also not the audit's signal) — it surfaces the *posture*: how many
    ownership rules exist and whether a catch-all ``*`` rule routes review for
    every otherwise-unmatched path. A file with rules but no ``*`` leaves paths
    that match none of the patterns with NO required owner review even when a
    branch-protection ``require_code_owner_reviews`` gate is on — the high-signal
    gap this audit complements ``--audit-branch-protection`` to find.

    Returns ``{"rule_count", "has_global_owner"}``. The function is pure (no
    network, no SCM state) so it is unit-testable in isolation.
    """
    rule_count = 0
    has_global_owner = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        rule_count += 1
        pattern = line.split()[0]
        if pattern == "*":
            has_global_owner = True
    return {"rule_count": rule_count, "has_global_owner": has_global_owner}


#: Repository-root-relative dependency-manifest filenames covenant inventories,
#: each mapped to the package ecosystem it declares. This is the read-only
#: dependency-audit surface (``--audit-packages``): covenant probes each repo's
#: root for these files, parses the package names + declared versions, and
#: reports them. It complements covenant's existing GitHub-security-configuration
#: audits by mapping the *software supply-chain* surface — the third-party code a
#: repo pulls in — which is where a known-vulnerable or typosquatted dependency
#: would enter. The audit reads ONLY these manifest files (never lockfiles' full
#: graphs, never source), and never resolves, installs, or modifies anything.
#:
#: Ordered so the parser is deterministic; the ecosystem label matches the value
#: GitHub/GitLab dependency tooling uses (``npm``/``pip``/``go``/``rubygems``/
#: ``maven``) so a ``--audit-packages`` inventory lines up with an
#: ``--audit-dependabot-alerts`` finding's ``ecosystem`` field.
PACKAGE_MANIFESTS: tuple[tuple[str, str], ...] = (
    ("package.json", "npm"),
    ("requirements.txt", "pip"),
    ("pyproject.toml", "pip"),
    ("Pipfile", "pip"),
    ("go.mod", "go"),
    ("Gemfile", "rubygems"),
    ("pom.xml", "maven"),
)


def _packages_from_package_json(text: str) -> list[dict]:
    """Extract {name, version} pairs from an npm ``package.json``.

    Reads the ``dependencies``, ``devDependencies``, ``peerDependencies`` and
    ``optionalDependencies`` maps (each ``{name: version-spec}``). The version
    string is the declared spec verbatim (e.g. ``^1.2.3``) — covenant inventories
    what the manifest *declares*, it does not resolve it. A malformed file yields
    no packages rather than raising, so one bad manifest never aborts the audit.
    """
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    out: list[dict] = []
    for section in (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            if isinstance(name, str) and name:
                out.append(
                    {"package": name, "version": spec if isinstance(spec, str) else None}
                )
    return out


#: A requirements.txt requirement specifier, captured as name + (optional)
#: version. Handles ``pkg==1.2.3``, ``pkg>=1.0``, ``pkg~=2.0``, bare ``pkg`` and
#: extras (``pkg[extra]==1.0``). Environment markers (``; python_version<'3'``)
#: and inline comments are stripped before matching.
_REQ_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*"
    r"(?P<op>==|>=|<=|~=|!=|>|<|===)?\s*(?P<version>[^\s;#]+)?"
)


def _packages_from_requirements_txt(text: str) -> list[dict]:
    """Extract {name, version} pairs from a pip ``requirements.txt``.

    Skips blank lines, comments, and the ``-r``/``-c``/``--option`` directives
    (which reference other files or flags, not packages). The version is the
    declared constraint value where an operator is present (the pin behind
    ``==``, the bound behind ``>=``/``~=``/etc.), else ``None`` for a bare
    requirement with no version. A line that does not parse as a requirement is
    silently skipped.
    """
    out: list[dict] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Drop an inline comment and any environment marker before matching.
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        match = _REQ_LINE.match(line)
        if not match:
            continue
        name = match.group("name")
        if not name:
            continue
        version = match.group("version") if match.group("op") else None
        out.append({"package": name, "version": version})
    return out


def _packages_from_pyproject_toml(text: str) -> list[dict]:
    """Extract {name, version} pairs from a ``pyproject.toml``.

    Reads PEP 621 ``[project].dependencies`` (a list of requirement strings) and,
    when present, Poetry's ``[tool.poetry.dependencies]`` table (a
    ``{name: spec}`` map). The ``python`` pseudo-dependency Poetry records is
    skipped (it is the interpreter constraint, not a package). A file that is not
    valid TOML yields no packages rather than raising.
    """
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError, TypeError):
        return []
    out: list[dict] = []
    project = data.get("project")
    if isinstance(project, dict):
        for req in project.get("dependencies", []) or []:
            if isinstance(req, str):
                out.extend(_packages_from_requirements_txt(req))
    poetry = (
        data.get("tool", {}).get("poetry", {})
        if isinstance(data.get("tool"), dict)
        else {}
    )
    deps = poetry.get("dependencies") if isinstance(poetry, dict) else None
    if isinstance(deps, dict):
        for name, spec in deps.items():
            if name == "python":
                continue
            if isinstance(spec, dict):
                spec = spec.get("version")
            out.append(
                {"package": name, "version": spec if isinstance(spec, str) else None}
            )
    return out


def _packages_from_pipfile(text: str) -> list[dict]:
    """Extract {name, version} pairs from a ``Pipfile`` (TOML).

    Reads the ``[packages]`` and ``[dev-packages]`` tables, each a
    ``{name: spec}`` map where the spec is either a version string (``"*"`` for
    "any") or a table (``{version = "==1.0"}``). A ``"*"`` spec is reported as
    ``None`` (no pinned version). Invalid TOML yields no packages.
    """
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError, TypeError):
        return []
    out: list[dict] = []
    for section in ("packages", "dev-packages"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            if isinstance(spec, dict):
                spec = spec.get("version")
            version = spec if isinstance(spec, str) and spec not in ("", "*") else None
            out.append({"package": name, "version": version})
    return out


#: A ``go.mod`` ``require`` entry: ``<module-path> <version>``. The version is a
#: semver tag or pseudo-version (``v1.2.3`` / ``v0.0.0-2024...-abcdef``).
_GOMOD_REQUIRE = re.compile(r"^\s*(?P<name>[^\s]+)\s+(?P<version>v[^\s]+)")


def _packages_from_go_mod(text: str) -> list[dict]:
    """Extract {name, version} pairs from a Go ``go.mod``.

    Handles both single-line ``require <path> <version>`` directives and the
    block form (``require ( ... )``). The ``// indirect`` marker is ignored for
    naming (the module is still a dependency the repo ships). The module path is
    the package name and the semver/pseudo-version is the version.
    """
    out: list[dict] = []
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if in_block:
            if stripped == ")":
                in_block = False
                continue
            match = _GOMOD_REQUIRE.match(line)
            if match:
                out.append(
                    {"package": match.group("name"), "version": match.group("version")}
                )
            continue
        if stripped.startswith("require"):
            rest = stripped[len("require"):].strip()
            if rest.startswith("("):
                in_block = True
                continue
            match = _GOMOD_REQUIRE.match(rest)
            if match:
                out.append(
                    {"package": match.group("name"), "version": match.group("version")}
                )
    return out


#: A Bundler ``gem "name", "version"`` line. Captures the gem name and, when
#: present, the first version constraint string. Comments and other DSL lines
#: (``source``, ``group do``, ``ruby``) are ignored.
_GEMFILE_GEM = re.compile(
    r"""^\s*gem\s+['"](?P<name>[^'"]+)['"]"""
    r"""(?:\s*,\s*['"](?P<version>[^'"]+)['"])?"""
)


def _packages_from_gemfile(text: str) -> list[dict]:
    """Extract {name, version} pairs from a Bundler ``Gemfile``.

    Matches ``gem "name"`` and ``gem "name", "~> 1.2"`` declarations; the version
    is the first constraint string when one is given, else ``None``. Non-gem DSL
    lines and comments are skipped. Only the gem NAME and declared constraint are
    surfaced.
    """
    out: list[dict] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0]
        match = _GEMFILE_GEM.match(line)
        if match:
            out.append(
                {"package": match.group("name"), "version": match.group("version")}
            )
    return out


#: A Maven ``pom.xml`` ``<dependency>`` block's groupId/artifactId/version. We
#: parse with regex rather than a full XML library to keep the audit dependency-
#: free and resilient to namespaces; the dependency block is well-structured
#: enough that a non-greedy scan is reliable for inventory purposes.
_POM_DEPENDENCY = re.compile(
    r"<dependency>(?P<body>.*?)</dependency>", re.DOTALL | re.IGNORECASE
)
_POM_GROUP = re.compile(r"<groupId>\s*(?P<v>[^<]+?)\s*</groupId>", re.IGNORECASE)
_POM_ARTIFACT = re.compile(r"<artifactId>\s*(?P<v>[^<]+?)\s*</artifactId>", re.IGNORECASE)
_POM_VERSION = re.compile(r"<version>\s*(?P<v>[^<]+?)\s*</version>", re.IGNORECASE)


def _packages_from_pom_xml(text: str) -> list[dict]:
    """Extract {name, version} pairs from a Maven ``pom.xml``.

    Each ``<dependency>`` block contributes one package named
    ``groupId:artifactId`` (the Maven coordinate convention) with its declared
    ``<version>`` (or ``None`` when the version is inherited / managed elsewhere).
    Blocks missing an artifactId are skipped. A malformed document yields only
    the blocks that do parse.
    """
    out: list[dict] = []
    for block in _POM_DEPENDENCY.finditer(text):
        body = block.group("body")
        artifact_match = _POM_ARTIFACT.search(body)
        if not artifact_match:
            continue
        artifact = artifact_match.group("v").strip()
        group_match = _POM_GROUP.search(body)
        group = group_match.group("v").strip() if group_match else None
        name = f"{group}:{artifact}" if group else artifact
        version_match = _POM_VERSION.search(body)
        version = version_match.group("v").strip() if version_match else None
        out.append({"package": name, "version": version})
    return out


#: Manifest filename -> the pure parser that turns its body into a list of
#: ``{"package", "version"}`` dicts. Used by :func:`parse_manifest`.
_MANIFEST_PARSERS = {
    "package.json": _packages_from_package_json,
    "requirements.txt": _packages_from_requirements_txt,
    "pyproject.toml": _packages_from_pyproject_toml,
    "Pipfile": _packages_from_pipfile,
    "go.mod": _packages_from_go_mod,
    "Gemfile": _packages_from_gemfile,
    "pom.xml": _packages_from_pom_xml,
}


def parse_manifest(filename: str, text: str) -> list[dict]:
    """Parse a dependency-manifest body into a list of ``{package, version}`` dicts.

    Dispatches on ``filename`` (one of :data:`PACKAGE_MANIFESTS`' keys) to the
    matching ecosystem parser. The ``version`` is the spec the manifest
    *declares* (``^1.2.3``, ``==1.0``, ``v1.4.0``, ...) — covenant inventories
    the declaration, it never resolves or installs it — and is ``None`` when the
    manifest pins no version for that package. An unknown filename or an
    unparseable body returns ``[]`` rather than raising, so one bad manifest can
    never abort an audit. The function is pure (no network, no SCM state) so it is
    unit-testable in isolation, and surfaces ONLY package names + declared
    versions — never file contents, source, or any credential a manifest might
    inadvisedly contain.
    """
    parser = _MANIFEST_PARSERS.get(filename)
    if parser is None:
        return []
    return parser(text)


def _parse_retry_after(resp: httpx.Response, attempt: int) -> float:
    """Return how many seconds to wait before retrying a rate-limited response.

    Honors, in priority order, the standard ``Retry-After`` header (an integer
    number of seconds), then the reset-epoch headers that GitHub
    (``X-RateLimit-Reset``) and GitLab (``RateLimit-Reset``) return, computing
    the delta from now. If none is present or parseable, falls back to a bounded
    exponential backoff keyed on the attempt number. The result is always
    clamped to ``[0, MAX_BACKOFF_SECONDS]`` so a malicious or buggy server can
    never make covenant sleep unboundedly.
    """
    headers = resp.headers
    raw_after = headers.get("Retry-After") or headers.get("retry-after")
    if raw_after:
        try:
            return min(max(float(raw_after.strip()), 0.0), MAX_BACKOFF_SECONDS)
        except ValueError:
            pass  # fall through to reset headers / backoff

    for key in ("X-RateLimit-Reset", "RateLimit-Reset", "ratelimit-reset"):
        raw_reset = headers.get(key)
        if raw_reset:
            try:
                reset_epoch = float(raw_reset.strip())
            except ValueError:
                continue
            delta = reset_epoch - time.time()
            return min(max(delta, 0.0), MAX_BACKOFF_SECONDS)

    backoff = BASE_BACKOFF_SECONDS * (2 ** max(attempt, 0))
    return min(backoff, MAX_BACKOFF_SECONDS)


class BaseSCMClient:
    #: Default API base URL for the live service; overridden by --target-url.
    default_base_url: str = ""

    def __init__(
        self,
        token: str,
        base_url: str | None = None,
        timeout: float = 15.0,
        *,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ):
        self.token = token
        self.base_url = (base_url or self.default_base_url).rstrip("/")
        self._timeout = timeout
        self._max_retries = max(int(max_retries), 0)
        #: Non-fatal warnings accumulated during a run (e.g. a retry budget was
        #: exhausted mid-walk, truncating recall). The CLI surfaces these in the
        #: payload's ``warnings`` array so the operator knows results may be
        #: partial rather than complete. Reset per logical operation by the CLI.
        self.warnings: list[str] = []

    def _headers(self) -> dict[str, str]:
        raise NotImplementedError

    def _sleep(self, seconds: float) -> None:
        """Indirection over :func:`time.sleep` so tests can run without real
        wall-clock delays while still asserting that a backoff occurred."""
        if seconds > 0:
            time.sleep(seconds)

    def _request_with_retry(
        self,
        url: str,
        params: dict | None,
        headers: dict,
    ) -> httpx.Response:
        """Issue a GET, retrying 403/429 rate-limit responses with backoff.

        On a rate-limited status covenant reads the server's retry hint (see
        :func:`_parse_retry_after`), sleeps the (clamped) interval, and retries
        up to ``self._max_retries`` times. If the budget is exhausted while the
        server is still rate-limiting, a non-fatal warning is appended to
        ``self.warnings`` and the last rate-limited response is returned so the
        caller's normal ``status >= 400`` handling raises a clear error — unless
        the caller is the paginator, which checks ``warnings`` to stop cleanly
        and keep the partial results gathered so far.
        """
        attempt = 0
        while True:
            try:
                resp = httpx.get(
                    url,
                    params=params,
                    headers=headers,
                    timeout=self._timeout,
                )
            except httpx.HTTPError as exc:  # network-level failure
                raise SCMError(f"request to {url} failed: {exc}") from exc

            if resp.status_code in _RATE_LIMIT_STATUSES and attempt < self._max_retries:
                wait = _parse_retry_after(resp, attempt)
                self._sleep(wait)
                attempt += 1
                continue

            if resp.status_code in _RATE_LIMIT_STATUSES and attempt >= self._max_retries:
                # Budget exhausted while still throttled — record it so the
                # operator learns recall may be truncated, then let the caller
                # decide (paginator stops cleanly; single GET raises).
                self.warnings.append(
                    f"rate limited (HTTP {resp.status_code}) at {url}: retry "
                    f"budget of {self._max_retries} exhausted; results may be "
                    "partial"
                )
            return resp

    def _get(
        self,
        path: str,
        params: dict | None = None,
        extra_headers: dict | None = None,
    ) -> httpx.Response:
        url = f"{self.base_url}{path}"
        headers = {**self._headers(), **(extra_headers or {})}
        resp = self._request_with_retry(url, params, headers)
        if resp.status_code == 401:
            raise SCMError("authentication failed (401) — check the token")
        if resp.status_code >= 400:
            raise SCMError(
                f"{self.base_url} returned HTTP {resp.status_code} for {path}"
            )
        return resp

    def _get_paginated(
        self,
        path: str,
        params: dict | None = None,
        *,
        max_pages: int = DEFAULT_MAX_PAGES,
        extra_headers: dict | None = None,
        next_request: Callable[[httpx.Response], tuple[str, dict | None] | None],
        skip_statuses: frozenset[int] = frozenset(),
    ):
        """Walk paginated GET responses, yielding one ``httpx.Response`` per page.

        The first page is fetched from ``path`` with ``params``. After each
        page, ``next_request`` is called with the just-received response; it
        returns either ``(next_path_or_url, next_params)`` to continue or
        ``None`` to stop. ``next_path_or_url`` may be an absolute URL (GitHub
        and Bitbucket hand back full ``next`` links) or a path/params pair
        (GitLab walks by incrementing ``page``).

        The loop is hard-bounded by ``max_pages`` regardless of what the server
        offers, so a misbehaving or hostile API can never make covenant walk
        forever. A ``max_pages`` of ``1`` fetches exactly one page — the
        pre-pagination behaviour.

        When ``skip_statuses`` is provided, a response whose status code is in
        that set causes the walk to stop cleanly (yielding nothing for that
        page) without raising an error. This avoids a probe-then-paginate
        pattern for endpoints that return 403/404 when a feature is disabled:
        callers pass ``skip_statuses=frozenset({403, 404})`` and the walk
        simply yields no pages rather than requiring a separate preflight GET.

        [Worker decision: pagination is a shared loop in base.py that delegates
        the SCM-specific "where's the next page?" parsing to a per-client
        ``next_request`` callback. This keeps the RFC-5988 Link-header walk
        (GitHub), the X-Next-Page walk (GitLab), and the ``next``-envelope walk
        (Bitbucket) in their respective clients while the bounding, HTTP
        plumbing, and error handling stay in one place. Yielding raw responses
        (not parsed items) lets each client keep its existing item-extraction
        code unchanged — it just loops over pages instead of reading one.]
        """
        if max_pages < 1:
            max_pages = 1
        if max_pages > HARD_MAX_PAGES:
            max_pages = HARD_MAX_PAGES

        next_path: str | None = path
        next_params = params
        pages = 0
        while next_path is not None and pages < max_pages:
            headers = {**self._headers(), **(extra_headers or {})}
            if next_path.startswith(("http://", "https://")):
                url = next_path
            else:
                url = f"{self.base_url}{next_path}"
            warnings_before = len(self.warnings)
            resp = self._request_with_retry(url, next_params, headers)
            if resp.status_code in skip_statuses:
                return
            if resp.status_code == 401:
                raise SCMError("authentication failed (401) — check the token")
            if resp.status_code in _RATE_LIMIT_STATUSES and len(self.warnings) > warnings_before:
                # Retry budget exhausted while the server is still throttling.
                # Stop the walk cleanly: the pages already yielded are kept and
                # the warning recorded by ``_request_with_retry`` tells the
                # operator recall is partial, not complete. This is the key
                # difference from a one-shot ``_get`` (which raises) — a recon
                # walk that dies on the first 429 would discard everything it
                # had already gathered.
                break
            if resp.status_code >= 400:
                raise SCMError(
                    f"{url} returned HTTP {resp.status_code}"
                )
            pages += 1
            yield resp
            advance = next_request(resp)
            if advance is None:
                break
            next_path, next_params = advance

    def _get_absolute(
        self,
        url: str,
        params: dict | None = None,
        extra_headers: dict | None = None,
    ) -> httpx.Response:
        """Like :meth:`_get` but ``url`` is already absolute.

        GitHub and Bitbucket return fully-qualified ``next`` URLs in their
        pagination metadata; we issue those verbatim rather than re-deriving a
        path against ``base_url``.
        """
        headers = {**self._headers(), **(extra_headers or {})}
        resp = self._request_with_retry(url, params, headers)
        if resp.status_code == 401:
            raise SCMError("authentication failed (401) — check the token")
        if resp.status_code >= 400:
            raise SCMError(f"{url} returned HTTP {resp.status_code}")
        return resp

    # ------------------------------------------------------------------
    # recon_code_with_fragments — override in subclasses that support it
    # ------------------------------------------------------------------

    def recon_code_with_fragments(
        self, query: str, max_pages: int = DEFAULT_MAX_PAGES
    ) -> list[dict]:
        """Like :meth:`recon_code` but each result also carries a
        ``"fragments"`` key (list of text snippets) that the caller can feed
        to :func:`covenant.secrets.scan_fragments`.

        Default implementation: call :meth:`recon_code` and attach an empty
        ``"fragments"`` list.  Subclasses that can cheaply retrieve snippet
        text from the same API response override this.
        """
        results = self.recon_code(query, max_pages=max_pages)
        for r in results:
            r.setdefault("fragments", [])
        return results
