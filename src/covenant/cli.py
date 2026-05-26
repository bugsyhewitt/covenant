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
from .scms.base import SCMError
from .scope import Scope, ScopeError

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_OUT_OF_SCOPE = 2

_MODULES = ("recon-repo", "recon-code", "validate-token")

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

    # 3. Dispatch the module.
    try:
        if args.module == "recon-repo":
            payload = {"scm": args.scm, "query": args.query, "results": client.recon_repo(args.query)}
        elif args.module == "recon-code":
            payload = {"scm": args.scm, "query": args.query, "results": client.recon_code(args.query)}
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
