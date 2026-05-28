"""Offline token-type fingerprinting for covenant's validate-token module.

:func:`classify_token` inspects the *shape* of a credential string — its
documented prefix taxonomy and, for legacy GitHub PATs, its bare 40-hex form —
and returns a ``token_type`` label, a human-readable ``note``, and a
``confidence`` band. It is a **pure, offline** function: no network call, no
new dependency, no rate-limit risk.

The token class is decisive for blast-radius reasoning. A fine-grained PAT's
scope list means something completely different from a classic PAT's, and a
GitHub App installation token (``ghs_``) implies GitHub App reach rather than a
single user's access. The credential's class sits right there in its prefix;
this module surfaces it so the operator does not have to over-read the raw
``scopes`` array.

[Worker decision (POST_V01 Item 4): classification lives in its own module of
pure string predicates rather than inside each SCM client, so the prefix
taxonomy is unit-testable in isolation with zero mock servers. Each client's
``validate_token()`` calls :func:`classify_token` and merges ``token_type`` (and
a GitLab-specific scopes-AND-roles caveat) into its existing payload — the v0.1
fields are untouched, the new field is purely additive.]

Sources for the taxonomy: GitHub token-prefix changelog (fine-grained PATs GA,
March 2025), GitLab token docs (``glpat-``/``gloas-``/``glptt-``), and the
Atlassian Bitbucket app-password deprecation timeline (creation ended
2025-09-09, full cutover 2026-06-09).
"""

from __future__ import annotations

#: Length of a legacy bare-hex GitHub personal access token.
_GITHUB_LEGACY_HEX_LEN = 40

#: Stable note explaining that GitLab effective access is bounded by scopes AND
#: the user's role — a permissive scope list does not by itself grant access.
_GITLAB_ROLE_CAVEAT = (
    "GitLab effective access is bounded by scopes AND the user's role; a "
    "permissive scopes list does not by itself guarantee access."
)


def _result(token_type: str, note: str, confidence: str) -> dict[str, str]:
    """Build a classification result with a stable key set.

    Never embeds the raw token in any field — the output is safe to print
    alongside redacted findings.
    """
    return {"token_type": token_type, "note": note, "confidence": confidence}


def _unknown(scm: str) -> dict[str, str]:
    return _result(
        "unknown",
        f"could not fingerprint this {scm} credential from its shape; "
        "treat the token class as undetermined",
        "low",
    )


def _is_hex(value: str) -> bool:
    if not value:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _classify_github(token: str) -> dict[str, str]:
    # Documented GitHub token-class prefixes (case-sensitive).
    prefixes = {
        "ghp_": (
            "github-pat-classic",
            "classic personal access token; scopes apply org-wide to every "
            "resource the user can reach",
        ),
        "gho_": (
            "github-oauth",
            "OAuth access token issued to an OAuth App on the user's behalf",
        ),
        "ghu_": (
            "github-app-user",
            "GitHub App user-to-server token; access is bounded by the App's "
            "grant and the user's permissions",
        ),
        "ghs_": (
            "github-app-installation",
            "GitHub App installation (server-to-server) token; implies App "
            "reach across the installation, not a single user's access",
        ),
        "ghr_": (
            "github-refresh",
            "GitHub App refresh token; used to mint new user-to-server tokens",
        ),
    }
    for prefix, (label, note) in prefixes.items():
        if token.startswith(prefix):
            return _result(label, note, "high")
    if token.startswith("github_pat_"):
        return _result(
            "github-pat-fine-grained",
            "fine-grained personal access token (GA March 2025); permissions "
            "are per-repository and per-resource, so its scope list reads very "
            "differently from a classic PAT",
            "high",
        )
    if len(token) == _GITHUB_LEGACY_HEX_LEN and _is_hex(token):
        return _result(
            "github-pat-legacy",
            "legacy 40-hex personal access token (pre-prefix era); classic-PAT "
            "blast radius applies",
            "medium",
        )
    return _unknown("github")


def _classify_gitlab(token: str) -> dict[str, str]:
    prefixes = {
        "glpat-": ("gitlab-pat", "personal access token"),
        "gloas-": ("gitlab-oauth", "OAuth access token"),
        "glptt-": ("gitlab-pipeline-trigger", "pipeline trigger token"),
    }
    for prefix, (label, kind) in prefixes.items():
        if token.startswith(prefix):
            return _result(label, f"GitLab {kind}. {_GITLAB_ROLE_CAVEAT}", "high")
    return _unknown("gitlab")


def _classify_bitbucket(token: str) -> dict[str, str]:
    # Bitbucket Cloud API tokens carry an ``ATCTT`` prefix; the legacy
    # app-password form (being retired — creation ended 2025-09-09, full
    # cutover 2026-06-09) carries the older ``ATBB`` prefix.
    if token.startswith("ATCTT"):
        return _result(
            "bitbucket-api-token",
            "Bitbucket Cloud API token (the supported credential form)",
            "high",
        )
    if token.startswith("ATBB"):
        return _result(
            "bitbucket-app-password",
            "Bitbucket app password — DEPRECATED: creation ended 2025-09-09 "
            "and full cutover to API tokens completes 2026-06-09; migrate to "
            "an API token",
            "high",
        )
    return _unknown("bitbucket")


_CLASSIFIERS = {
    "github": _classify_github,
    "gitlab": _classify_gitlab,
    "bitbucket": _classify_bitbucket,
}


def classify_token(token: str, scm: str) -> dict[str, str]:
    """Fingerprint a credential's *type* from its shape, offline.

    Returns a dict with three stable keys:

    * ``token_type`` — a label such as ``"github-pat-classic"``,
      ``"gitlab-oauth"``, ``"bitbucket-app-password"``, or ``"unknown"``.
    * ``note`` — a human-readable blast-radius / caveat note.
    * ``confidence`` — ``"high"`` for a matched documented prefix, ``"medium"``
      for the legacy hex heuristic, ``"low"`` when the shape is unrecognized.

    The function makes no network call and never echoes the raw token into any
    returned field, so its output is safe to print. An unrecognized ``scm`` or
    an empty/whitespace token classifies as ``"unknown"`` rather than raising.
    """
    token = (token or "").strip()
    classifier = _CLASSIFIERS.get(scm)
    if classifier is None or not token:
        return _unknown(scm)
    return classifier(token)
