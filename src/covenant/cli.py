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

        code = mod_subs.add_parser("recon-code", help="search code across repositories")
        _add_common_args(code, needs_query=True)
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

    # 3. Dispatch the module.
    try:
        if args.module == "recon-repo":
            payload = {
                "scm": args.scm,
                "query": args.query,
                "results": client.recon_repo(args.query, max_pages=max_pages),
            }
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
            # Bitbucket code search is workspace-scoped; surface the workspace
            # kwarg only when talking to Bitbucket so other clients are unchanged.
            code_kwargs: dict = {"max_pages": max_pages}
            if args.scm == "bitbucket":
                code_kwargs["workspace"] = getattr(args, "workspace", None)
            if scan_secrets:
                scan_fragments, SecretScanUnavailable = _get_scan_fragments()
                results = client.recon_code_with_fragments(
                    args.query, **code_kwargs
                )
                # When verifying we must scan raw (to probe), then redact the
                # emitted value afterwards unless --show-secrets was given.
                scan_reveal = reveal_secrets or verify_secrets
                for result in results:
                    fragments = result.pop("fragments", [])
                    try:
                        findings = scan_fragments(fragments, reveal=scan_reveal)
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
                results = client.recon_code(args.query, **code_kwargs)
            payload = {"scm": args.scm, "query": args.query, "results": results}
        elif args.module == "validate-token":
            payload = client.validate_token()
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
