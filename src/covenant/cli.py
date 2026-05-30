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
            "--enumerate-actions-secrets",
            action="store_true",
            default=False,
            dest="enumerate_actions_secrets",
            help=(
                "additionally list the CI/CD secret NAMES this token can reach "
                "(GitHub Actions org/repo secrets, GitLab group/project CI/CD "
                "variables, Bitbucket workspace/repo Pipelines variables) via a "
                "read-only query; adds an 'actions_secrets' array of "
                "{scope, owner, name, protected} entries. CI/CD secrets are the "
                "credential surface that powers the build pipeline (cloud keys, "
                "registry passwords, signing/deploy tokens), so a long list is a "
                "high-blast-radius lateral-movement and supply-chain target. "
                "Only the secret NAME and metadata are surfaced — the secret "
                "VALUE is never read or echoed (the APIs do not return secured "
                "values, and covenant emits names only). 'protected' flags an "
                "org secret restricted to selected repos (GitHub) or a "
                "protected/secured variable (GitLab/Bitbucket). Read-only."
            ),
        )
        token.add_argument(
            "--enumerate-runners",
            action="store_true",
            default=False,
            dest="enumerate_runners",
            help=(
                "additionally list the SELF-HOSTED pipeline runners this token "
                "can reach (GitHub Actions org/repo self-hosted runners, GitLab "
                "group/project runners, Bitbucket workspace/repo Pipelines "
                "runners) via a read-only query; adds a 'runners' array of "
                "{scope, owner, id, name, labels, self_hosted} entries. A "
                "self-hosted runner is a distinct, high-signal blast-radius "
                "surface: every job that targets it executes on its host and "
                "sees that run's GITHUB_TOKEN / CI variables / checked-out "
                "source — so a compromised or planted self-hosted runner is a "
                "persistence and lateral-movement foothold, and a runner "
                "registered at ORG/group/workspace scope is the broadest "
                "(every repo in the org can dispatch to it). GitHub Actions and "
                "Bitbucket Pipelines list only self-hosted runners by design, so "
                "'self_hosted' is True there; for GitLab it is False on the "
                "platform-managed shared SaaS runners (is_shared=true) and True "
                "on attached runners running on infrastructure the org operates. "
                "Endpoints a low-privilege token can't read fail soft to an "
                "empty result rather than failing the whole audit. Only runner "
                "identity and labels are surfaced — never a registration token, "
                "OAuth client secret, or any credential."
            ),
        )
        token.add_argument(
            "--audit-actions-environments",
            action="store_true",
            default=False,
            dest="audit_actions_environments",
            help=(
                "additionally audit the deployment-environment gate posture of "
                "the repos this token can reach (GitHub Actions Environments, "
                "GitLab project environments + protected environments, Bitbucket "
                "Pipelines deployment environments) via a read-only query; adds "
                "an 'actions_environments' array of {repo, environment, "
                "required_reviewers, required_reviewer_count, wait_timer, "
                "branch_policy} entries. A deployment environment is where the "
                "most sensitive CI/CD secrets are scoped (production cloud keys, "
                "deploy tokens); its protection rules are the gate that decides "
                "whether a workflow may deploy to it and thereby READ those "
                "secrets. An environment with required_reviewers=false and "
                "branch_policy='all' lets ANY branch — including an attacker's "
                "feature branch carrying a malicious workflow — deploy and "
                "exfiltrate its secrets unreviewed: the environment-scoped, "
                "secret-exfiltration counterpart to --audit-branch-protection. "
                "Read-only; never creates, edits, or triggers a deployment."
            ),
        )
        token.add_argument(
            "--audit-deployment-protection",
            action="store_true",
            default=False,
            dest="audit_deployment_protection",
            help=(
                "additionally audit the CUSTOM deployment-protection-rule apps "
                "installed on the deployment environments of the repos this "
                "token can reach (GitHub Actions custom deployment protection "
                "rules) via a read-only query; adds a 'deployment_protection' "
                "array of {repo, environment, rule_id, app_slug, app_id, "
                "enabled} entries — one per installed custom rule. Where "
                "--audit-actions-environments reports the BUILT-IN environment "
                "gate (required reviewers, wait timer, branch policy), this "
                "lists the THIRD-PARTY GitHub Apps an environment delegates its "
                "deploy gate to: each app returns approve/reject and a deploy "
                "lands or is held on its verdict, so the app IS the gate. That "
                "delegation is a supply-chain trust bond — a compromise of the "
                "third-party app's infrastructure or review logic means deploys "
                "to that environment pass automatically; an 'enabled=false' rule "
                "is a gate the operator thinks they have but does not. Only "
                "rule metadata and the gating app's identity (slug + id) are "
                "surfaced, never an installation token, webhook secret, or any "
                "credential. GitLab and Bitbucket Cloud have no per-environment "
                "custom-rule-app API, so the result is empty there with an "
                "explanatory warning. Read-only; never installs, removes, "
                "enables, or disables a protection rule."
            ),
        )
        token.add_argument(
            "--audit-webhook",
            action="store_true",
            default=False,
            dest="audit_webhook",
            help=(
                "additionally audit the SECURITY POSTURE of the org/group/"
                "workspace webhook configurations this token can reach "
                "(GitHub org webhooks) via a read-only query; adds a "
                "'webhook_configuration' array of {scope, owner, id, url, "
                "has_secret, insecure_ssl, active, events, wildcard_events} "
                "entries. Where --enumerate-webhooks maps the destination "
                "URLs (the exfil/SSRF surface — where event payloads land), "
                "this audits whether each hook was wired with the controls "
                "that decide whether a captured hook is actually trustable: "
                "has_secret=false (no HMAC, so the receiver cannot verify "
                "the POST came from the SCM and an attacker who learns the "
                "URL can forge events), insecure_ssl=true (TLS verification "
                "disabled, so an attacker-in-the-middle can intercept or "
                "modify the payload and a rogue cert silently authenticates), "
                "and an active hook with wildcard_events=true (events=['*'] "
                "— the broadest event subscription, the widest exfil channel). "
                "GitHub does not return the secret value itself (only a "
                "'********' placeholder when one is set); covenant surfaces "
                "ONLY the boolean PRESENCE, never the placeholder, the URL's "
                "query string, or any header. GitLab (group-hook API does "
                "not expose a uniform per-hook posture record to a recon-"
                "grade token) and Bitbucket Cloud (workspace-hooks expose "
                "neither a per-hook secret-presence boolean nor a TLS-"
                "verification flag) have no equivalent, so the result is "
                "empty there with an explanatory warning. Read-only; never "
                "creates, edits, deletes, pings, or otherwise modifies a "
                "webhook."
            ),
        )
        token.add_argument(
            "--audit-repo-visibility",
            action="store_true",
            default=False,
            dest="audit_repo_visibility",
            help=(
                "additionally audit the visibility posture of the repos this "
                "token can reach (GitHub/Bitbucket private flag, GitLab "
                "visibility string) via a read-only query; adds a "
                "'repo_visibility' array of {repo, visibility, public} entries. "
                "A PUBLIC repo is the org's external attack surface — its "
                "source, history and any leaked secrets are world-readable — so "
                "an unexpectedly public repo is a direct leak/supply-chain risk "
                "and the place covenant's recon-code scanning finds the most. "
                "GitLab 'internal' projects (readable by any authenticated user "
                "of the instance) are flagged as public=true exposure. Only "
                "repo metadata is read; no code or secrets are fetched."
            ),
        )
        token.add_argument(
            "--audit-codeowners",
            action="store_true",
            default=False,
            dest="audit_codeowners",
            help=(
                "additionally audit the CODEOWNERS coverage of the repos this "
                "token can reach (GitHub/GitLab/Bitbucket repository CODEOWNERS "
                "file) via a read-only file fetch; adds a 'codeowners' array of "
                "{repo, present, path, rule_count, has_global_owner} entries. "
                "CODEOWNERS is the control that routes MANDATORY review to a "
                "named owner per path, so it is the partner to "
                "--audit-branch-protection: a protected branch's "
                "require-code-owner-review gate only bites for paths a "
                "CODEOWNERS rule matches. A reachable repo with present=false has "
                "NO owner-review gate at all, and one with rules but "
                "has_global_owner=false leaves every unmatched path — including a "
                "file an attacker newly adds — with no required owner: the "
                "owner-coverage gap a branch-protection audit alone misses. Only "
                "the rule COUNT and whether a catch-all '*' rule exists are "
                "surfaced — the owner handles themselves are never echoed and no "
                "other repository content is read. Read-only; never edits "
                "CODEOWNERS or any review setting."
            ),
        )
        token.add_argument(
            "--audit-dependabot-alerts",
            action="store_true",
            default=False,
            dest="audit_dependabot_alerts",
            help=(
                "additionally audit the OPEN dependency-vulnerability alerts on "
                "the repos this token can reach (GitHub Dependabot alerts, GitLab "
                "dependency-scanning vulnerabilities) via a read-only query; adds "
                "a 'dependabot_alerts' array of {repo, package, ecosystem, "
                "severity, state, identifier} entries. Where "
                "--audit-branch-protection and --audit-codeowners report PROCESS "
                "gaps, this reports a KNOWN-VULNERABILITY attack surface: each "
                "alert is a documented CVE/GHSA in a dependency the repo actually "
                "ships, named by package and advisory so it maps straight to an "
                "exploit. Only OPEN alerts are requested; a repo with the feature "
                "disabled or a token without the security-events scope is skipped "
                "(403/404) rather than failing the whole audit. The advisory "
                "IDENTIFIER is surfaced — never a credential. Bitbucket Cloud has "
                "no first-party dependency-alert API, so the result is empty there "
                "with an explanatory warning. Read-only; never dismisses, fixes, "
                "or creates an alert."
            ),
        )
        token.add_argument(
            "--audit-packages",
            action="store_true",
            default=False,
            dest="audit_packages",
            help=(
                "additionally inventory the declared package dependencies of the "
                "repos this token can reach by reading their manifest files "
                "(package.json, requirements.txt, pyproject.toml, Pipfile, "
                "go.mod, Gemfile, pom.xml) via a read-only file fetch; adds a "
                "'packages' array of {repo, manifest, ecosystem, package, version} "
                "entries. Where --audit-dependabot-alerts reports the KNOWN-"
                "VULNERABLE dependencies a provider scanner has already flagged, "
                "this reports the FULL declared dependency surface — the software-"
                "supply-chain inventory an operator needs before asking which of "
                "those packages is vulnerable, typosquatted, or abandoned, and the "
                "surface a Dependabot audit can only annotate, not enumerate. "
                "'version' is the spec the manifest DECLARES (e.g. ^1.2.3) — "
                "covenant inventories the declaration, it never resolves or "
                "installs anything — and is null when unpinned. Unlike "
                "--audit-dependabot-alerts (a no-op on Bitbucket Cloud), this "
                "works on all three SCMs because it reads manifests directly. "
                "Only the named manifest files are read (never lockfile graphs, "
                "never source) and only package names + declared versions are "
                "surfaced. Read-only; never resolves, installs, or modifies a "
                "dependency."
            ),
        )
        token.add_argument(
            "--audit-secret-scanning",
            action="store_true",
            default=False,
            dest="audit_secret_scanning",
            help=(
                "additionally audit the OPEN secret-scanning alerts on the repos "
                "this token can reach (GitHub secret-scanning alerts, GitLab "
                "secret-detection findings) via a read-only query; adds a "
                "'secret_scanning' array of {repo, secret_type, state, validity, "
                "html_url} entries. The highest-signal surface of all: each alert "
                "is a credential the PROVIDER'S OWN scanner has ALREADY detected "
                "committed in the repo — a live leak the org has not yet "
                "remediated, exactly what --scan-secrets/--scan-commits hunt for "
                "except already found and confirmed. 'validity' (active/inactive/"
                "unknown) flags whether the leaked credential is believed to still "
                "authenticate. CRITICAL: the raw secret VALUE is never surfaced — "
                "only the secret_type classifier, state, validity, and the alert "
                "URL — so the report is not itself a new copy of the leak. Only "
                "OPEN alerts are requested; a repo with the feature disabled or a "
                "token without the security-events scope is skipped (403/404) "
                "rather than failing the whole audit. Bitbucket Cloud has no "
                "first-party secret-scanning-alert API, so the result is empty "
                "there with an explanatory warning. Read-only; never resolves, "
                "dismisses, or reopens an alert."
            ),
        )
        token.add_argument(
            "--audit-code-scanning-alerts",
            action="store_true",
            default=False,
            dest="audit_code_scanning_alerts",
            help=(
                "additionally audit the OPEN code-scanning alerts on the repos "
                "this token can reach (GitHub code-scanning/CodeQL alerts, GitLab "
                "SAST findings) via a read-only query; adds a "
                "'code_scanning_alerts' array of {repo, rule_id, rule_name, "
                "severity, state, html_url} entries. Where "
                "--audit-dependabot-alerts reports a KNOWN-VULNERABILITY surface "
                "in a repo's third-party DEPENDENCIES, this reports the static-"
                "analyzer findings in the repo's OWN first-party source (injection "
                "sinks, crypto misuse, path-traversal) — a bug in code the org "
                "itself controls, named by rule and source location so it maps "
                "straight to an exploit. 'severity' prefers the security-severity "
                "band (critical/high/medium/low). Only OPEN alerts are requested; "
                "a repo with the feature disabled, never analyzed, or out of the "
                "token's scope is skipped (403/404) rather than failing the whole "
                "audit. The html_url points at the finding, never a credential. "
                "Bitbucket Cloud has no first-party static-analysis-alert API, so "
                "the result is empty there with an explanatory warning. Read-only; "
                "never dismisses, fixes, or creates an alert."
            ),
        )
        token.add_argument(
            "--audit-advisory-alerts",
            action="store_true",
            default=False,
            dest="audit_advisory_alerts",
            help=(
                "additionally audit the PUBLISHED repository advisory alerts on "
                "the repos this token can reach (GitHub repository security "
                "advisories) via a read-only query; adds an 'advisory_alerts' "
                "array of {repo, ghsa_id, cve_id, summary, severity, state, "
                "html_url} entries. Distinct from the other security flags: "
                "where --audit-dependabot-alerts reports a repo CONSUMING the "
                "global advisory database (a known CVE in a third-party "
                "DEPENDENCY) and --audit-code-scanning-alerts reports static-"
                "analyzer findings in the repo's own source, this reports the "
                "repo as a PUBLISHER of advisories — the GHSAs the org's own "
                "maintainers wrote up against their OWN product, each naming a "
                "real (often already-patched) vulnerability in code the org "
                "ships to others; on an unpatched or partially-deployed fleet "
                "the GHSA/CVE handle and summary point straight at where a "
                "working exploit still lives. Only PUBLISHED advisories are "
                "requested; a repo with none, the feature unavailable, or out of "
                "the token's scope is skipped (403/404) rather than failing the "
                "whole audit. ghsa_id/cve_id are advisory handles, never a "
                "credential. GitLab (its advisory data is an instance-wide "
                "third-party feed) and Bitbucket Cloud have no per-repo "
                "maintainer-authored advisory API, so the result is empty there "
                "with an explanatory warning. Read-only; never creates, edits, "
                "or publishes an advisory."
            ),
        )
        token.add_argument(
            "--audit-actions-permissions",
            action="store_true",
            default=False,
            dest="audit_actions_permissions",
            help=(
                "additionally audit the GitHub Actions execution-permission "
                "posture of the repos this token can reach via a read-only "
                "query; adds an 'actions_permissions' array of {repo, "
                "actions_enabled, allowed_actions, default_workflow_permissions, "
                "can_approve_pull_request_reviews} entries. Where "
                "--audit-actions-environments gates which DEPLOYMENTS reach an "
                "environment's secrets, this audits what a workflow run may DO "
                "once it executes: the decisive field is "
                "default_workflow_permissions='write', which grants every "
                "workflow (including one introduced by a malicious PR on a repo "
                "that runs untrusted PR workflows) a read/write GITHUB_TOKEN "
                "over the repo's contents/releases/packages — a far wider blast "
                "radius than the locked-down 'read' default — and "
                "can_approve_pull_request_reviews=true lets a workflow "
                "self-approve PRs and so satisfy a review gate without a human: "
                "the execution-side counterpart to --audit-branch-protection. A "
                "repo with Actions disabled reports "
                "default_workflow_permissions=null; a repo the token cannot "
                "administer is skipped (403/404) rather than failing the whole "
                "audit. GitLab and Bitbucket Cloud have no single per-repo "
                "Actions-permission API, so the result is empty there with an "
                "explanatory warning. Read-only; never enables, disables, or "
                "rewrites a permission."
            ),
        )
        token.add_argument(
            "--audit-workflow-runs",
            action="store_true",
            default=False,
            dest="audit_workflow_runs",
            help=(
                "additionally audit recent CI/CD pipeline runs on the repos "
                "this token can reach (GitHub Actions workflow runs, GitLab "
                "project pipelines, Bitbucket Pipelines runs) via a read-only "
                "query; adds a 'workflow_runs' array of {repo, run_id, name, "
                "event, status, conclusion, created_at} entries. Where the "
                "other --audit-actions-* flags report POLICY posture (what a "
                "run is allowed to do), this reports observed ACTIVITY (what "
                "the pipeline actually ran): a streak of conclusion='failure' "
                "runs is an active attack/broken-CI signal, a 'cancelled' run "
                "is operator/defender intervention, and an unexpected 'event' "
                "distribution (a burst of manual/workflow_dispatch triggers, "
                "off-hours schedule runs) is a CI-misuse signal a posture "
                "audit alone does not catch. Only run METADATA is surfaced — "
                "logs, artifact URLs, and any CI variable values the run saw "
                "are never fetched. A repo with Actions/Pipelines disabled or "
                "out of the token's scope is skipped (403/404) rather than "
                "failing the whole audit. Read-only; never re-runs, cancels, "
                "or dispatches a workflow."
            ),
        )
        token.add_argument(
            "--audit-branch-ruleset",
            action="store_true",
            default=False,
            dest="audit_branch_ruleset",
            help=(
                "additionally audit the named branch-ruleset / push-rule "
                "posture of the repos this token can reach (GitHub branch "
                "rulesets, GitLab push rules) via a read-only query; adds a "
                "'branch_rulesets' array of {repo, ruleset_id, name, "
                "enforcement, target, rule_types, bypass_actor_count} "
                "entries. The newer/complementary rule-model counterpart to "
                "--audit-branch-protection: where that one walks each "
                "protected branch's CLASSIC settings, this surfaces the "
                "POSTURE of the NEWER named-rule-collection model the two "
                "coexist with — the high-signal findings are "
                "enforcement='disabled'/'evaluate' (a configured ruleset "
                "that does not actively block), bypass_actor_count > 0 "
                "(somebody can route around the rule), and a rule_types "
                "list missing core gates ('pull_request' / "
                "'required_signatures' / 'non_fast_forward'). Only ruleset "
                "POSTURE is surfaced — bypass-actor identities are NEVER "
                "echoed (only the count is the signal), no rule parameter "
                "values (regex patterns, exact reviewer counts) are read, "
                "and no repository content is touched. A repo whose "
                "rulesets endpoint answers 403/404 is skipped (not fatal). "
                "Bitbucket Cloud has no named-ruleset API (its policy lives "
                "in branch-restrictions, covered by "
                "--audit-branch-protection); result is empty there with an "
                "explanatory warning. Read-only; never creates, edits, or "
                "deletes a ruleset."
            ),
        )
        token.add_argument(
            "--enumerate-members",
            action="store_true",
            default=False,
            dest="enumerate_members",
            help=(
                "additionally list the OTHER members of the org/group/workspace "
                "this token can reach (GitHub org members, GitLab group members, "
                "Bitbucket workspace members) via a read-only directory query; "
                "adds a 'members' array of {scope, owner, username, role} "
                "entries. Where the other --enumerate-* flags map what THIS "
                "token reaches, this maps the PEOPLE who share that reach — the "
                "lateral-movement surface (other identities to target to widen a "
                "foothold) and, for role=admin (org owners), the accounts whose "
                "compromise grants administrative control of the org. Only "
                "membership identity + role is surfaced — never an email, key, "
                "or credential."
            ),
        )
        token.add_argument(
            "--enumerate-collaborators",
            action="store_true",
            default=False,
            dest="enumerate_collaborators",
            help=(
                "additionally list the per-repo collaborator grants on the repos "
                "this token can reach (GitHub outside collaborators, GitLab "
                "direct project members, Bitbucket explicit repo user grants) via "
                "a read-only query; adds a 'collaborators' array of "
                "{repo, username, role, outside} entries. Where --enumerate-members "
                "maps people who share an ORG/group/workspace's reach, this is "
                "REPO-scoped and surfaces the higher-signal ghost-account / "
                "ex-employee / leftover-contractor vector: personal accounts "
                "granted access DIRECTLY on a specific repo (outside=true) that an "
                "org-member audit misses and that survive long after the person "
                "leaves. A write-or-above direct grant is a supply-chain and "
                "persistence risk. 'role' is the highest-privilege level "
                "(admin/maintain/write/triage/read). Only identity + permission "
                "level are surfaced — never an email, key, or credential. The "
                "audit never grants or revokes access."
            ),
        )
        token.add_argument(
            "--scan-commits",
            action="store_true",
            default=False,
            dest="scan_commits",
            help=(
                "additionally scan the COMMIT-MESSAGE history of the repos this "
                "token can reach for leaked credentials using necromancer-patterns "
                "(requires the 'covenant[scan]' extra); adds a 'commit_findings' "
                "array of {repo, sha, author, secret_findings} entries, one per "
                "commit whose message matched. Commit messages are a notorious, "
                "overlooked leak vector: a credential scrubbed from a tracked file "
                "routinely survives verbatim in a 'git commit -m \"rotate to "
                "AKIA...\"' subject or a revert/merge body. Where --scan-secrets "
                "(recon-code) only sees CURRENT file content, this maps the leak "
                "surface in HISTORY. Findings are share-safe REDACTED by default "
                "(see --show-commit-secrets); the commit DIFF is never fetched and "
                "no author email is surfaced. Read-only. Honors --pattern-set."
            ),
        )
        token.add_argument(
            "--show-commit-secrets",
            action="store_true",
            default=False,
            dest="show_commit_secrets",
            help=(
                "emit the full raw secret value in --scan-commits findings instead "
                "of the default share-safe redacted fingerprint (implies "
                "--scan-commits). Use with care: output may land in logs, "
                "scrollback, and shared artifacts."
            ),
        )
        token.add_argument(
            "--pattern-set",
            default=None,
            metavar="SET",
            dest="pattern_set",
            help=(
                "secret-scan rule set to apply to --scan-commits (e.g. minimal, "
                "aws, full); defaults to 'full'. Narrowing it (e.g. 'aws') drops "
                "the generic high-entropy rule and its false positives. Only "
                "meaningful with --scan-commits. Validated against the installed "
                "necromancer-patterns sets."
            ),
        )
        token.add_argument(
            "--max-pages",
            type=int,
            default=DEFAULT_MAX_PAGES,
            help=(
                f"maximum org/group/workspace/key/gist/webhook/deploy-key/"
                f"branch-protection/actions-secret/repo-visibility/codeowners/"
                f"dependabot-alert/package/secret-scanning/member/collaborator/"
                f"commit/workflow-run/deployment-protection pages to walk when "
                f"an --enumerate-*, "
                f"--audit-*, or --scan-commits flag is set (default: "
                f"{DEFAULT_MAX_PAGES}, hard ceiling: {HARD_MAX_PAGES})."
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
            # Optional CI/CD secret-name enumeration. Read-only, additive: the
            # v0.1 validate-token fields are untouched and the 'actions_secrets'
            # array only appears when --enumerate-actions-secrets is requested.
            # Maps the build-pipeline credential surface (org/repo Actions
            # secrets, group/project CI/CD variables, workspace/repo Pipelines
            # variables); only secret NAMES are surfaced, never the VALUES.
            if getattr(args, "enumerate_actions_secrets", False):
                payload["actions_secrets"] = client.enumerate_actions_secrets(
                    max_pages=max_pages
                )
            # Optional self-hosted runner enumeration. Read-only, additive: the
            # v0.1 validate-token fields are untouched and the 'runners' array
            # only appears when --enumerate-runners is requested. Maps the
            # pipeline-execution-host blast radius (org/group/workspace and
            # repo/project self-hosted runners) — every job dispatched to a
            # runner runs on its host and sees the run's secrets, so a
            # compromised runner is a persistence/lateral-movement foothold.
            # Only runner identity + labels are surfaced, never a registration
            # token or OAuth client secret.
            if getattr(args, "enumerate_runners", False):
                payload["runners"] = client.enumerate_runners(
                    max_pages=max_pages
                )
            # Optional deployment-environment audit. Read-only, additive: the
            # v0.1 validate-token fields are untouched and the
            # 'actions_environments' array only appears when
            # --audit-actions-environments is requested. Reports whether the
            # reachable repos' deployment environments gate deploys (and thus
            # access to their environment-scoped secrets) behind required
            # reviewers / a branch policy; never alters or triggers a deployment.
            if getattr(args, "audit_actions_environments", False):
                payload["actions_environments"] = (
                    client.audit_actions_environments(max_pages=max_pages)
                )
            # Optional deployment-protection audit. Read-only, additive: the
            # v0.1 validate-token fields are untouched and the
            # 'deployment_protection' array only appears when
            # --audit-deployment-protection is requested. Lists the CUSTOM
            # third-party deployment-protection-rule apps an environment
            # delegates its deploy gate to — the supply-chain trust bond
            # the built-in --audit-actions-environments posture does not
            # cover. Only rule metadata + the gating app's identity are
            # surfaced, never a credential.
            if getattr(args, "audit_deployment_protection", False):
                payload["deployment_protection"] = (
                    client.audit_deployment_protection(max_pages=max_pages)
                )
            # Optional webhook-configuration posture audit. Read-only,
            # additive: the v0.1 validate-token fields are untouched and the
            # 'webhook_configuration' array only appears when --audit-webhook
            # is requested. Where --enumerate-webhooks maps the destination
            # URLs, this audits whether each hook is wired with the controls
            # that make a captured-URL hook actually trustable: HMAC secret
            # presence, TLS verification, and the event-subscription scope.
            # Only the boolean presence of the secret is surfaced, never the
            # API's '********' placeholder.
            if getattr(args, "audit_webhook", False):
                payload["webhook_configuration"] = client.audit_webhook(
                    max_pages=max_pages
                )
            # Optional repo-visibility audit. Read-only, additive: the v0.1
            # validate-token fields are untouched and the 'repo_visibility'
            # array only appears when --audit-repo-visibility is requested.
            # Reports the EXPOSURE posture (which reachable repos are public),
            # the complement to the offensive --enumerate-* family; only repo
            # metadata is read, never code or secrets.
            if getattr(args, "audit_repo_visibility", False):
                payload["repo_visibility"] = client.audit_repo_visibility(
                    max_pages=max_pages
                )
            # Optional CODEOWNERS-coverage audit. Read-only, additive: the v0.1
            # validate-token fields are untouched and the 'codeowners' array
            # only appears when --audit-codeowners is requested. The partner to
            # --audit-branch-protection: reports whether each reachable repo has
            # an owner-review gate (a CODEOWNERS file) and whether a catch-all
            # '*' rule covers otherwise-unmatched paths; only the rule count and
            # the '*' flag are surfaced, never the owner handles or other content.
            if getattr(args, "audit_codeowners", False):
                payload["codeowners"] = client.audit_codeowners(
                    max_pages=max_pages
                )
            # Optional Dependabot / dependency-vulnerability audit. Read-only,
            # additive: the v0.1 validate-token fields are untouched and the
            # 'dependabot_alerts' array only appears when
            # --audit-dependabot-alerts is requested. Reports the
            # KNOWN-VULNERABILITY attack surface (open CVE/GHSA alerts in the
            # dependencies reachable repos ship) — the offensive triage axis the
            # PROCESS audits (branch protection, codeowners) do not cover. A repo
            # with the feature disabled or out of the token's scope is skipped,
            # never echoing a credential (only the advisory identifier).
            if getattr(args, "audit_dependabot_alerts", False):
                payload["dependabot_alerts"] = client.audit_dependabot_alerts(
                    max_pages=max_pages
                )
            # Optional package-dependency inventory. Read-only, additive: the
            # v0.1 validate-token fields are untouched and the 'packages' array
            # only appears when --audit-packages is requested. Reads each
            # reachable repo's manifest files and reports the FULL declared
            # dependency surface (the software-supply-chain inventory), the
            # complement to --audit-dependabot-alerts (which only annotates the
            # KNOWN-vulnerable subset). Only package names + declared versions are
            # surfaced — never lockfile graphs, source, or any credential.
            if getattr(args, "audit_packages", False):
                payload["packages"] = client.audit_packages(
                    max_pages=max_pages
                )
            # Optional secret-scanning audit. Read-only, additive: the v0.1
            # validate-token fields are untouched and the 'secret_scanning' array
            # only appears when --audit-secret-scanning is requested. Reports the
            # highest-signal surface: credentials the PROVIDER'S OWN scanner has
            # already detected committed in the reachable repos (live, confirmed
            # leaks). A repo with the feature disabled or out of the token's scope
            # is skipped. CRITICAL: only the secret_type classifier, state,
            # validity, and alert URL are surfaced — never the raw secret value,
            # so the report is not itself a copy of the leak.
            if getattr(args, "audit_secret_scanning", False):
                payload["secret_scanning"] = client.audit_secret_scanning(
                    max_pages=max_pages
                )
            # Optional code-scanning-alert audit. Read-only, additive: the v0.1
            # validate-token fields are untouched and the 'code_scanning_alerts'
            # array only appears when --audit-code-scanning-alerts is requested.
            # Reports the static-analyzer findings in the repo's OWN first-party
            # source (GitHub code-scanning/CodeQL alerts, GitLab SAST findings) —
            # the code-flaw triage axis the dependency and credential audits do
            # not cover. A repo with the feature disabled, never analyzed, or out
            # of the token's scope is skipped; only rule metadata + the alert URL
            # are surfaced, never a credential.
            if getattr(args, "audit_code_scanning_alerts", False):
                payload["code_scanning_alerts"] = (
                    client.audit_code_scanning_alerts(max_pages=max_pages)
                )
            # Optional repository-advisory audit. Read-only, additive: the v0.1
            # validate-token fields are untouched and the 'advisory_alerts' array
            # only appears when --audit-advisory-alerts is requested. Reports the
            # PUBLISHED advisories the org's own maintainers wrote up against
            # their OWN product (GitHub repository security advisories) — the
            # publisher-side triage axis the dependency and code-flaw audits do
            # not cover. A repo with no advisories or out of the token's scope is
            # skipped; only advisory metadata (GHSA/CVE handle + summary + URL)
            # is surfaced, never a credential.
            if getattr(args, "audit_advisory_alerts", False):
                payload["advisory_alerts"] = (
                    client.audit_advisory_alerts(max_pages=max_pages)
                )
            # Optional Actions-permission audit. Read-only, additive: the v0.1
            # validate-token fields are untouched and the 'actions_permissions'
            # array only appears when --audit-actions-permissions is requested.
            # Reports the execution-side posture each workflow run inherits — the
            # default GITHUB_TOKEN read/write permission and PR self-approval
            # flag — the supply-chain gap a branch-protection or environment
            # audit alone does not cover. A repo the token cannot administer is
            # skipped; only policy metadata is surfaced, never a credential.
            if getattr(args, "audit_actions_permissions", False):
                payload["actions_permissions"] = (
                    client.audit_actions_permissions(max_pages=max_pages)
                )
            # Optional workflow-run activity audit. Read-only, additive: the
            # v0.1 validate-token fields are untouched and the 'workflow_runs'
            # array only appears when --audit-workflow-runs is requested.
            # Reports observed CI activity (which workflows ran, what triggered
            # them, how they concluded) — the activity counterpart to the
            # policy audits; anomalous failure/cancellation streaks and
            # unexpected trigger distributions are CI-misuse signals a posture
            # audit alone does not catch. Only run metadata is surfaced, never
            # logs, artifacts, or CI variable values.
            if getattr(args, "audit_workflow_runs", False):
                payload["workflow_runs"] = client.audit_workflow_runs(
                    max_pages=max_pages
                )
            # Optional branch-ruleset / push-rule posture audit. Read-only,
            # additive: the v0.1 validate-token fields are untouched and the
            # 'branch_rulesets' array only appears when --audit-branch-ruleset
            # is requested. Reports the posture of the NEWER named-rule-
            # collection model that coexists with classic branch protection:
            # enforcement mode (disabled/evaluate is a paper tiger),
            # bypass-actor count (every actor is a route around the rule),
            # and the SET of rule types present (a list missing pull_request
            # / required_signatures / non_fast_forward is a coverage gap).
            # Only ruleset POSTURE is surfaced — bypass-actor identities
            # and rule parameter values (regex patterns, reviewer counts)
            # are never echoed. Bitbucket Cloud has no named-ruleset API
            # (returns empty + warning); a repo with rulesets unavailable
            # is skipped.
            if getattr(args, "audit_branch_ruleset", False):
                payload["branch_rulesets"] = client.audit_branch_ruleset(
                    max_pages=max_pages
                )
            # Optional org/group/workspace member enumeration. Read-only,
            # additive: the v0.1 validate-token fields are untouched and the
            # 'members' array only appears when --enumerate-members is
            # requested. Maps the lateral-movement surface (the OTHER identities
            # sharing the token's reach); only membership identity + role is
            # surfaced, never an email, key, or credential.
            if getattr(args, "enumerate_members", False):
                payload["members"] = client.enumerate_members(
                    max_pages=max_pages
                )
            # Optional per-repo collaborator enumeration. Read-only, additive:
            # the v0.1 validate-token fields are untouched and the
            # 'collaborators' array only appears when --enumerate-collaborators
            # is requested. Repo-scoped complement to --enumerate-members: it
            # maps the ghost-account / ex-employee surface — personal accounts
            # granted access DIRECTLY on a repo (outside=true) that an
            # org-member audit misses; only identity + permission level are
            # surfaced, never an email, key, or credential.
            if getattr(args, "enumerate_collaborators", False):
                payload["collaborators"] = client.enumerate_collaborators(
                    max_pages=max_pages
                )
            # Optional commit-message secret scanning. Read-only, additive: the
            # v0.1 validate-token fields are untouched and the 'commit_findings'
            # array only appears when --scan-commits is requested. Maps the
            # leak surface in HISTORY (commit messages) that --scan-secrets,
            # which only sees current file content, misses; reuses the same
            # necromancer-patterns scan machinery. The commit diff is never
            # fetched and only commits with a matched message are surfaced.
            if getattr(args, "scan_commits", False) or getattr(
                args, "show_commit_secrets", False
            ):
                reveal_commit = getattr(args, "show_commit_secrets", False)
                scan_fragments, SecretScanUnavailable = _get_scan_fragments()
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
                commit_findings: list[dict] = []
                for commit in client.scan_commits(max_pages=max_pages):
                    findings = scan_fragments(
                        [commit.get("message", "")],
                        reveal=reveal_commit,
                        pattern_set=pattern_set,
                    )
                    if not findings:
                        continue
                    commit_findings.append(
                        {
                            "repo": commit.get("repo"),
                            "sha": commit.get("sha"),
                            "author": commit.get("author"),
                            "secret_findings": findings,
                        }
                    )
                payload["commit_findings"] = commit_findings
            if (
                getattr(args, "enumerate_orgs", False)
                or getattr(args, "enumerate_keys", False)
                or getattr(args, "enumerate_gists", False)
                or getattr(args, "enumerate_webhooks", False)
                or getattr(args, "enumerate_deploy_keys", False)
                or getattr(args, "audit_branch_protection", False)
                or getattr(args, "enumerate_actions_secrets", False)
                or getattr(args, "enumerate_runners", False)
                or getattr(args, "audit_actions_environments", False)
                or getattr(args, "audit_deployment_protection", False)
                or getattr(args, "audit_webhook", False)
                or getattr(args, "audit_repo_visibility", False)
                or getattr(args, "audit_codeowners", False)
                or getattr(args, "audit_dependabot_alerts", False)
                or getattr(args, "audit_packages", False)
                or getattr(args, "audit_secret_scanning", False)
                or getattr(args, "audit_code_scanning_alerts", False)
                or getattr(args, "audit_advisory_alerts", False)
                or getattr(args, "audit_actions_permissions", False)
                or getattr(args, "audit_workflow_runs", False)
                or getattr(args, "audit_branch_ruleset", False)
                or getattr(args, "enumerate_members", False)
                or getattr(args, "enumerate_collaborators", False)
                or getattr(args, "scan_commits", False)
                or getattr(args, "show_commit_secrets", False)
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
