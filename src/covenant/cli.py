"""covenant command-line interface.

Subcommands are organized per SCM (``github``, ``gitlab``, ``bitbucket``) and
each SCM exposes the same read-only modules: ``recon-repo``, ``recon-code`` and
``validate-token``.

Exit codes:
  0  success
  1  operational error (missing token, API failure, bad input)
  2  out-of-scope target (the scope guardrail tripped)
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .scms import CLIENTS
from .scms.base import DEFAULT_MAX_PAGES, HARD_MAX_PAGES, SCMError
from .scope import Scope, ScopeError

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_OUT_OF_SCOPE = 2

_MODULES = ("recon-repo", "recon-code", "validate-token")

#: SCMs whose search query language accepts a leading ``NOT <term>`` negative
#: qualifier. GitHub and GitLab both honor ``NOT`` in their search syntax;
#: Bitbucket Cloud's code search uses a different grammar, so ``--exclude`` is
#: a no-op there (the flag is accepted but the query is passed through
#: unchanged) rather than emitting a qualifier the API would misparse.
_NOT_QUALIFIER_SCMS = frozenset({"github", "gitlab"})

#: SCMs that accept an ``--org`` flag to narrow recon to a single
#: organization/group. Bitbucket's organizational unit is the *workspace* and
#: already has its own dedicated ``--workspace`` flag (which is mandatory for
#: code search), so ``--org`` is offered only for GitHub and GitLab — closing
#: the same authorization gap ``--workspace`` closes for Bitbucket: when the
#: scope file authorizes a host only for specific orgs, naming a sibling org
#: must be refused, and a recon run with no org named on an org-restricted host
#: must not silently search the whole host.
_ORG_FLAG_SCMS = frozenset({"github", "gitlab"})


def build_query(query: str, excludes: list[str] | None, scm: str) -> str:
    """Append provider-appropriate negative qualifiers to a search query.

    For ``--exclude TERM`` (repeatable), GitHub and GitLab support stripping
    matches with a ``NOT <term>`` qualifier, which is the recon-literature's
    recommended way to drop demo/test/localhost noise and stretch the per-query
    page budget. Each term is appended as ``NOT <term>`` in order; blank terms
    are ignored. For SCMs outside :data:`_NOT_QUALIFIER_SCMS` (i.e. Bitbucket)
    the query is returned unchanged. The function is pure so it is unit-testable
    independent of the CLI and the network.
    """
    if not excludes or scm not in _NOT_QUALIFIER_SCMS:
        return query
    parts = [query.strip()] if query.strip() else []
    for term in excludes:
        term = term.strip()
        if term:
            parts.append(f"NOT {term}")
    return " ".join(parts)


def apply_org(query: str, org: str | None, scm: str) -> str:
    """Narrow a search query to a single organization/group.

    When ``--org SLUG`` is supplied, the search is constrained to that org by
    appending a provider-appropriate qualifier to the query string:

    - **GitHub** code/repo search honors an ``org:<slug>`` qualifier, so we
      append ``org:<slug>``.
    - **GitLab**'s global search has no in-query ``org:`` qualifier; group
      narrowing is done with a separate group-scoped endpoint (handled in the
      client), so the query string itself is returned unchanged here and the
      slug is threaded to the client instead. ``apply_org`` therefore only
      augments the GitHub query.

    The function is pure (no network, no CLI state) so it is unit-testable in
    isolation. A blank/``None`` org returns the query unchanged. The org slug is
    appended *after* any ``--exclude`` ``NOT`` qualifiers, matching the order an
    operator would type by hand.
    """
    if not org or not org.strip():
        return query
    if scm != "github":
        return query
    slug = org.strip()
    base = query.strip()
    return f"{base} org:{slug}".strip() if base else f"org:{slug}"


def _add_org_arg(parser: argparse.ArgumentParser, scm: str) -> None:
    """Attach the ``--org`` narrowing flag to a GitHub/GitLab recon parser."""
    unit = "organization" if scm == "github" else "group"
    parser.add_argument(
        "--org",
        default=None,
        metavar="SLUG",
        dest="org",
        help=(
            f"narrow recon to a single {scm} {unit} (slug). The {unit} is "
            "verified against the scope file: if the host is authorized only "
            "for specific orgs, a different --org is refused (exit 2), and an "
            "org-restricted host requires --org. Sharpens recall and enforces "
            "org-level authorization, mirroring Bitbucket's --workspace."
        ),
    )

# Lazy import guard: secrets module requires the optional 'scan' extra.
def _get_scan_fragments():  # noqa: ANN201
    from .secrets import scan_fragments, SecretScanUnavailable  # noqa: PLC0415
    return scan_fragments, SecretScanUnavailable


def _get_verify_findings():  # noqa: ANN201
    from .verify import verify_findings  # noqa: PLC0415
    return verify_findings

# Default API base URLs used for scope-checking when --target-url is omitted.
_DEFAULT_URLS = {
    "github": "https://api.github.com",
    "gitlab": "https://gitlab.com",
    "bitbucket": "https://api.bitbucket.org",
}


def _add_common_args(parser: argparse.ArgumentParser, *, needs_query: bool) -> None:
    parser.add_argument(
        "--scope-file",
        required=True,
        help="path to the file listing authorized SCM hosts/orgs/repos",
    )
    parser.add_argument(
        "--token-env",
        default="COVENANT_TOKEN",
        help="environment variable holding the API token (default: COVENANT_TOKEN)",
    )
    parser.add_argument(
        "--target-url",
        default=None,
        help="override the SCM API base URL (e.g. self-hosted or a mock server)",
    )
    if needs_query:
        parser.add_argument(
            "--query",
            required=True,
            help="search term for the recon module",
        )
        parser.add_argument(
            "--max-pages",
            type=int,
            default=DEFAULT_MAX_PAGES,
            help=(
                f"maximum number of result pages to fetch "
                f"(default: {DEFAULT_MAX_PAGES}, hard ceiling: {HARD_MAX_PAGES}). "
                "Recon walks pages until exhausted or this limit; raising it "
                "increases recall at the cost of more API calls."
            ),
        )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="covenant",
        description=(
            "Recon + token-validation toolkit for AUTHORIZED SCM bug-bounty "
            "engagements only. Operates strictly within --scope-file."
        ),
    )
    scm_subs = parser.add_subparsers(dest="scm", metavar="{github,gitlab,bitbucket}")
    scm_subs.required = True

    for scm in ("github", "gitlab", "bitbucket"):
        scm_parser = scm_subs.add_parser(scm, help=f"{scm} recon modules")
        mod_subs = scm_parser.add_subparsers(dest="module", metavar="{" + ",".join(_MODULES) + "}")
        mod_subs.required = True

        repo = mod_subs.add_parser("recon-repo", help="search accessible repositories")
        _add_common_args(repo, needs_query=True)
        if scm in _ORG_FLAG_SCMS:
            _add_org_arg(repo, scm)

        code = mod_subs.add_parser("recon-code", help="search code across repositories")
        _add_common_args(code, needs_query=True)
        if scm in _ORG_FLAG_SCMS:
            _add_org_arg(code, scm)
        code.add_argument(
            "--scan-secrets",
            action="store_true",
            default=False,
            help=(
                "scan code-search result fragments for leaked credentials using "
                "necromancer-patterns (requires 'covenant[scan]' extra); "
                "adds 'secret_findings' to each result"
            ),
        )
        code.add_argument(
            "--show-secrets",
            action="store_true",
            default=False,
            help=(
                "emit the full raw secret value in findings instead of the "
                "default share-safe redacted fingerprint (implies "
                "--scan-secrets). Use with care: output may land in logs, "
                "scrollback, and shared artifacts."
            ),
        )
        code.add_argument(
            "--verify-secrets",
            action="store_true",
            default=False,
            help=(
                "live-verify each detected credential against its issuing "
                "provider with a single READ-ONLY auth probe (AWS "
                "sts:GetCallerIdentity, Stripe GET /v1/balance), deduped per "
                "unique secret; tags findings 'verified': true/false/null. "
                "Implies --scan-secrets. WARNING: this transmits the candidate "
                "secret OFF-BOX to the third-party provider — only use it when "
                "the target host is in scope and you have authorization."
            ),
        )
        code.add_argument(
            "--pattern-set",
            default=None,
            metavar="SET",
            help=(
                "secret-scan rule set to apply (e.g. minimal, aws, full); "
                "defaults to 'full'. Narrowing it (e.g. 'aws') drops the "
                "generic high-entropy rule and its false positives. Only "
                "meaningful with --scan-secrets/--show-secrets/--verify-secrets. "
                "Validated against the installed necromancer-patterns sets."
            ),
        )
        code.add_argument(
            "--exclude",
            action="append",
            default=None,
            metavar="TERM",
            dest="exclude",
            help=(
                "append a 'NOT <TERM>' negative qualifier to the search query "
                "to strip demo/test/localhost noise (repeatable). GitHub and "
                "GitLab only; ignored for Bitbucket. Sharpens precision and "
                "stretches the per-query page budget."
            ),
        )
        if scm == "bitbucket":
            code.add_argument(
                "--workspace",
                default=None,
                metavar="WORKSPACE",
                help=(
                    "Bitbucket workspace slug (required for recon-code; "
                    "e.g. the slug from bitbucket.org/<workspace>/...)"
                ),
            )

        token = mod_subs.add_parser(
            "validate-token", help="enumerate what the token can access"
        )
        _add_common_args(token, needs_query=False)
        token.add_argument(
            "--enumerate-orgs",
            action="store_true",
            default=False,
            dest="enumerate_orgs",
            help=(
                "additionally list the organizations/groups/workspaces this "
                "token can reach (GitHub orgs, GitLab groups, Bitbucket "
                "workspaces) via a read-only membership query; adds an "
                "'orgs' array to the output. Bitbucket workspace slugs feed "
                "the recon-code --workspace flag."
            ),
        )
        token.add_argument(
            "--enumerate-keys",
            action="store_true",
            default=False,
            dest="enumerate_keys",
            help=(
                "additionally list the SSH and GPG public keys attached to "
                "this token's account via read-only key queries; adds a "
                "'keys' array of {type, id, title, fingerprint} entries. "
                "Reveals which machines can push as this identity (SSH) and "
                "which keys can sign 'Verified' commits in its name (GPG). "
                "Only PUBLIC key metadata is shown; private keys are never "
                "read. Bitbucket exposes SSH keys only (no GPG-key API)."
            ),
        )
        token.add_argument(
            "--enumerate-gists",
            action="store_true",
            default=False,
            dest="enumerate_gists",
            help=(
                "additionally list the gists/snippets owned by this token's "
                "account (GitHub gists, GitLab snippets, Bitbucket snippets) "
                "via a read-only query; adds a 'gists' array of "
                "{id, description, visibility, url, files} entries. Gists and "
                "snippets are a notorious leaked-credential vector; the FILE "
                "NAMES are surfaced as a leak signal (e.g. '.env', "
                "'credentials.json') but file CONTENT is never read or echoed."
            ),
        )
        token.add_argument(
            "--enumerate-webhooks",
            action="store_true",
            default=False,
            dest="enumerate_webhooks",
            help=(
                "additionally list the org/group/workspace webhooks this token "
                "can reach (GitHub org hooks, GitLab group hooks, Bitbucket "
                "workspace hooks) via a read-only query; adds a 'webhooks' "
                "array of {scope, owner, id, url, events, active} entries. "
                "Webhooks are an EXFILTRATION and SSRF surface: the destination "
                "URL is where event payloads (repo content/metadata) are POSTed "
                "and can be an internal-network target. The destination URL is "
                "surfaced; the hook SECRET is never requested or echoed."
            ),
        )
        token.add_argument(
            "--enumerate-deploy-keys",
            action="store_true",
            default=False,
            dest="enumerate_deploy_keys",
            help=(
                "additionally list the deploy keys on the repos this token can "
                "reach (GitHub/GitLab/Bitbucket per-repo SSH keys) via a "
                "read-only query; adds a 'deploy_keys' array of "
                "{repo, id, title, read_only, fingerprint} entries. A deploy "
                "key grants Git access to a SINGLE repo independent of any "
                "human credential, so a writable one (read_only=false) is a "
                "persistence and supply-chain foothold. Only PUBLIC key "
                "metadata is shown; private keys are never read. (Bitbucket "
                "access keys are read-only by design, so read_only is always "
                "true there.)"
            ),
        )
        token.add_argument(
            "--audit-branch-protection",
            action="store_true",
            default=False,
            dest="audit_branch_protection",
            help=(
                "additionally audit the branch-protection posture of the repos "
                "this token can reach (GitHub branch protection, GitLab "
                "protected branches + approval/push rules, Bitbucket branch "
                "restrictions) via a read-only query; adds a "
                "'branch_protection' array of {repo, branch, required_reviews, "
                "required_review_count, dismiss_stale_reviews, "
                "require_signed_commits, enforce_admins} entries. This is the "
                "DEFENSIVE counterpart to the --enumerate-* flags: it reveals "
                "whether a writable foothold would be stopped before code lands "
                "on a protected branch. A protected branch with "
                "required_reviews=false is a supply-chain weak point. The audit "
                "never alters protection."
            ),
        )
        token.add_argument(
            "--max-pages",
            type=int,
            default=DEFAULT_MAX_PAGES,
            help=(
                f"maximum org/group/workspace/key/gist/webhook/deploy-key/"
                f"branch-protection pages to walk when an --enumerate-* or "
                f"--audit-* flag is set (default: {DEFAULT_MAX_PAGES}, hard "
                f"ceiling: {HARD_MAX_PAGES})."
            ),
        )

    return parser


def _resolve_token(env_var: str) -> str:
    token = os.environ.get(env_var, "").strip()
    if not token:
        raise SCMError(
            f"no token found in environment variable {env_var!r}; "
            f"set it before running (e.g. export {env_var}=...)"
        )
    return token


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    target_url = args.target_url or _DEFAULT_URLS[args.scm]

    # 1. Scope guardrail — refuse before any token is even read.
    try:
        scope = Scope.from_file(args.scope_file)
        scope.assert_in_scope(target_url)
        # Org-level narrowing: when the operator can name the org/workspace a
        # recon target lands in (Bitbucket code search is workspace-scoped) and
        # the host was authorized only for specific orgs, refuse a sibling org
        # on the same host. Without this an entry like "bitbucket.org/acme"
        # would still let "--workspace victim" through, because only the host
        # was ever checked. Modules that don't name an org are unaffected unless
        # the host itself is org-restricted.
        if args.scm == "bitbucket" and args.module == "recon-code":
            scope.assert_org_in_scope(target_url, getattr(args, "workspace", None))
        # GitHub/GitLab org narrowing (--org) carries the same authorization
        # obligation as Bitbucket's --workspace: a recon target that names an
        # org must be verified against the org-restricted scope, and a target
        # on an org-restricted host that names NO org must be refused (it would
        # otherwise search the whole host the operator only partly authorized).
        elif args.scm in _ORG_FLAG_SCMS and args.module in (
            "recon-repo",
            "recon-code",
        ):
            target_org = getattr(args, "org", None)
            if target_org is not None or scope.is_url_org_restricted(target_url):
                scope.assert_org_in_scope(target_url, target_org)
    except ScopeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_OUT_OF_SCOPE
    except OSError as exc:
        print(f"error: cannot read scope file: {exc}", file=sys.stderr)
        return EXIT_ERROR

    # 2. Token + client.
    try:
        token = _resolve_token(args.token_env)
        client = CLIENTS[args.scm](token=token, base_url=target_url)
    except SCMError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    # Clamp --max-pages to [1, HARD_MAX_PAGES]; recon modules only.
    max_pages = getattr(args, "max_pages", DEFAULT_MAX_PAGES)
    if max_pages < 1:
        max_pages = 1
    elif max_pages > HARD_MAX_PAGES:
        max_pages = HARD_MAX_PAGES

    # --org narrows GitHub/GitLab recon to a single org/group (already scope-
    # verified above). GitHub takes an in-query ``org:<slug>`` qualifier;
    # GitLab uses a group-scoped endpoint, so the slug is passed to the client.
    org = getattr(args, "org", None)

    # 3. Dispatch the module.
    try:
        if args.module == "recon-repo":
            repo_query = apply_org(args.query, org, args.scm)
            repo_kwargs: dict = {"max_pages": max_pages}
            if args.scm == "gitlab" and org:
                repo_kwargs["group"] = org
            payload = {
                "scm": args.scm,
                "query": args.query,
                "results": client.recon_repo(repo_query, **repo_kwargs),
            }
            if client.warnings:
                payload["warnings"] = list(client.warnings)
        elif args.module == "recon-code":
            # --show-secrets opts into the full raw value and implies scanning.
            # --verify-secrets implies scanning too, and needs the raw secret to
            # probe even when the operator did NOT pass --show-secrets, so we
            # scan with reveal=True internally and re-redact the output below.
            reveal_secrets = getattr(args, "show_secrets", False)
            verify_secrets = getattr(args, "verify_secrets", False)
            scan_secrets = (
                getattr(args, "scan_secrets", False)
                or reveal_secrets
                or verify_secrets
            )
            # --exclude appends provider-appropriate NOT qualifiers (Item 7);
            # --org appends/threads a single-org narrowing. The augmented query
            # is what we actually send to the SCM API.
            effective_query = build_query(
                args.query, getattr(args, "exclude", None), args.scm
            )
            effective_query = apply_org(effective_query, org, args.scm)
            # Bitbucket code search is workspace-scoped; surface the workspace
            # kwarg only when talking to Bitbucket so other clients are unchanged.
            code_kwargs: dict = {"max_pages": max_pages}
            if args.scm == "bitbucket":
                code_kwargs["workspace"] = getattr(args, "workspace", None)
            elif args.scm == "gitlab" and org:
                code_kwargs["group"] = org
            if scan_secrets:
                scan_fragments, SecretScanUnavailable = _get_scan_fragments()
                # Resolve and validate the requested pattern set against the
                # installed library (Item 7). A default of None means "full".
                requested_set = getattr(args, "pattern_set", None)
                try:
                    from .secrets import (  # noqa: PLC0415
                        DEFAULT_PATTERN_SET,
                        available_pattern_sets,
                    )

                    valid_sets = available_pattern_sets()
                except SecretScanUnavailable as exc:
                    print(f"error: {exc}", file=sys.stderr)
                    return EXIT_ERROR
                pattern_set = requested_set or DEFAULT_PATTERN_SET
                if pattern_set not in valid_sets:
                    print(
                        f"error: unknown --pattern-set {pattern_set!r}; "
                        f"available sets: {', '.join(valid_sets)}",
                        file=sys.stderr,
                    )
                    return EXIT_ERROR
                results = client.recon_code_with_fragments(
                    effective_query, **code_kwargs
                )
                # When verifying we must scan raw (to probe), then redact the
                # emitted value afterwards unless --show-secrets was given.
                scan_reveal = reveal_secrets or verify_secrets
                for result in results:
                    fragments = result.pop("fragments", [])
                    try:
                        findings = scan_fragments(
                            fragments,
                            reveal=scan_reveal,
                            pattern_set=pattern_set,
                        )
                    except SecretScanUnavailable as exc:
                        print(f"error: {exc}", file=sys.stderr)
                        return EXIT_ERROR
                    if verify_secrets:
                        verify_findings = _get_verify_findings()
                        verify_findings(findings)
                        if not reveal_secrets:
                            from .secrets import redact  # noqa: PLC0415

                            for f in findings:
                                f["secret"] = redact(f.get("secret", ""))
                    result["secret_findings"] = findings
            else:
                results = client.recon_code(effective_query, **code_kwargs)
            payload = {"scm": args.scm, "query": args.query, "results": results}
            if client.warnings:
                payload["warnings"] = list(client.warnings)
        elif args.module == "validate-token":
            payload = client.validate_token()
            # Optional org/group/workspace blast-radius enumeration. Read-only,
            # additive: the v0.1 validate-token fields are untouched and the
            # 'orgs' array only appears when --enumerate-orgs is requested.
            if getattr(args, "enumerate_orgs", False):
                payload["orgs"] = client.enumerate_orgs(max_pages=max_pages)
            # Optional SSH/GPG key blast-radius enumeration. Read-only,
            # additive: the v0.1 validate-token fields are untouched and the
            # 'keys' array only appears when --enumerate-keys is requested.
            if getattr(args, "enumerate_keys", False):
                payload["keys"] = client.enumerate_keys(max_pages=max_pages)
            # Optional gist/snippet enumeration. Read-only, additive: the v0.1
            # validate-token fields are untouched and the 'gists' array only
            # appears when --enumerate-gists is requested. Only filenames are
            # surfaced (the leak signal); file content is never read.
            if getattr(args, "enumerate_gists", False):
                payload["gists"] = client.enumerate_gists(max_pages=max_pages)
            # Optional webhook enumeration. Read-only, additive: the v0.1
            # validate-token fields are untouched and the 'webhooks' array only
            # appears when --enumerate-webhooks is requested. Maps the
            # exfiltration/SSRF surface (where org/group/workspace events are
            # POSTed); the hook secret is never requested or echoed.
            if getattr(args, "enumerate_webhooks", False):
                payload["webhooks"] = client.enumerate_webhooks(
                    max_pages=max_pages
                )
            # Optional deploy-key enumeration. Read-only, additive: the v0.1
            # validate-token fields are untouched and the 'deploy_keys' array
            # only appears when --enumerate-deploy-keys is requested. Maps the
            # repo-scoped persistence/supply-chain surface (per-repo SSH keys);
            # private key material is never read.
            if getattr(args, "enumerate_deploy_keys", False):
                payload["deploy_keys"] = client.enumerate_deploy_keys(
                    max_pages=max_pages
                )
            # Optional branch-protection audit. Read-only, additive: the v0.1
            # validate-token fields are untouched and the 'branch_protection'
            # array only appears when --audit-branch-protection is requested.
            # This is the DEFENSIVE counterpart to the --enumerate-* flags —
            # it reports whether reachable repos would stop an unreviewed or
            # unsigned push, never altering protection.
            if getattr(args, "audit_branch_protection", False):
                payload["branch_protection"] = client.audit_branch_protection(
                    max_pages=max_pages
                )
            if (
                getattr(args, "enumerate_orgs", False)
                or getattr(args, "enumerate_keys", False)
                or getattr(args, "enumerate_gists", False)
                or getattr(args, "enumerate_webhooks", False)
                or getattr(args, "enumerate_deploy_keys", False)
                or getattr(args, "audit_branch_protection", False)
            ) and client.warnings:
                payload["warnings"] = list(client.warnings)
        else:  # pragma: no cover - argparse guarantees a valid module
            parser.error(f"unknown module {args.module!r}")
            return EXIT_ERROR
    except SCMError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    json.dump(payload, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
