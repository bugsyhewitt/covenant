# Changelog

All notable changes to covenant are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-06-20

covenant's first production-ready release. The tool ships a read-only SCM recon
+ token-validation surface for AUTHORIZED bug-bounty engagements only, gated
behind a mandatory scope guardrail. The CLI exposes three SCM modules
(`github`, `gitlab`, `bitbucket`) each with `recon-repo`, `recon-code`,
`validate-token`, plus a growing inventory of audit and enumeration
subcommands.

### Added

- **Scope guardrail** — `covenant` refuses to operate against any target
  not declared in `--scope-file`. Scope is enforced at every API call, not
  just at startup, so a token that escalates permissions mid-run cannot
  pull data outside the declared scope (see `src/covenant/scope.py`).
- **Three SCM backends** with a unified interface — `github` (REST API v3
  + GraphQL v4), `gitlab` (REST API v4), `bitbucket` (REST API v2.0 +
  Bitbucket Cloud app-password auth). Each backend implements `recon-repo`,
  `recon-code`, and `validate-token` against the provider's documented
  search and token-introspection endpoints.
- **Pagination** — `--max-pages` (default 10, hard ceiling 100) walks
  paginated GET responses for both `recon-repo` and `recon-code`. Each
  client supplies a `next_request` callback for its own pagination
  convention (Link-header for GitHub, `x-next-page` for GitLab, cursor
  tokens for Bitbucket).
- **`--scan-secrets`** opt-in flag on `recon-code` runs the shared
  `necromancer-patterns` ruleset client-side over code-search result
  fragments and adds `secret_findings` to each result. Requires the
  `covenant[scan]` extra.
- **Secret redaction by default** — `recon-code` redacts matches in its
  output unless `--show-secrets` is passed.
- **Token-type fingerprinting** in `validate-token`: classifies the token
  by its prefix (ghp_, gho_, ghu_, ghs_, ghr_, glpat-, ATATT, etc.) and
  reports the inferred provider, kind, and audit posture for the
  corresponding scopes.
- **Optional live credential verification** via `--verify-secrets`: rounds
  up the lowest-entropy matches against the relevant API (AWS
  `sts:GetCallerIdentity`, Stripe `GET /v1/balance`, GitHub `/user`, etc.)
  to confirm a leaked secret is still active. Opt-in to keep the
  read-only-by-default contract.
- **Rate-limit + transient-failure retry with backoff** — every paginated
  request honors `Retry-After` and `X-RateLimit-Reset`, with exponential
  backoff for transient 5xx and connection errors.
- **Pattern-set selection + query noise filtering** in `recon-code`:
  `--pattern-set {creds,infra,web,all}` and `--query-filter "<glob>"`
  narrow the result set on `full_name`, `description`, `language`, or
  `topics` before applying the patterns.
- **Org/workspace-level scope narrowing** — `--org <name>` restricts all
  recon + audit operations to a single org/workspace; the scope guardrail
  enforces the narrowing at every API call.
- **`--audit-branch-protection`** — per-repo branch-protection posture
  audit: required status checks, required reviews, dismiss-stale-reviewers,
  enforce-admins, required-linear-history, required-signatures,
  required-conversation-resolution.
- **`--audit-branch-ruleset`** — named rule-collection posture audit
  (parallel to `--audit-branch-protection` but for the newer
  ruleset-level API).
- **`--audit-code-scanning-alerts`** — read-only inventory of open + closed
  Code Scanning alerts per repo: rule ID, severity, state, created_at,
  fixed_at, HTML URL. Annotated with the rule's CWE class when available.
- **`--audit-dependabot-alerts`** — read-only inventory of open + closed
  Dependabot security advisories per repo: package ecosystem, package
  name, vulnerable version range, patched version, severity, GHSA ID.
- **`--audit-codeowners`** — CODEOWNERS-coverage audit: per protected
  branch, which paths have an owner and which do not.
- **`--audit-actions-permissions`** — per-org + per-repo GitHub Actions
  permission posture audit (read/write/all scopes on GITHUB_TOKEN;
  allowed-actions allowlists; workflow permissions at org vs repo level).
- **`--audit-org-mfa`** — org/group MFA enforcement posture audit:
  organization_members_can_create_repos, members_two_factor_requirement,
  outside_collaborators_two_factor_requirement, organization_two_factor_requirement.
- **`--audit-ip-allowlist`** — org-level IP perimeter posture audit:
  IP allow list enabled, installed IP ranges, IP allow list for
  installed GitHub Apps.
- **`--audit-advisory-alerts`** — read-only inventory of global GHSA
  security advisories applicable to the org's declared dependencies.
- **`--audit-packages`** — declared dependency surface audit: walks the
  manifest files (package.json, go.mod, Gemfile, pom.xml, requirements.txt,
  Pipfile, pyproject.toml, etc.) via a read-only file fetch; emits a
  `packages` array of `{repo, manifest, ecosystem, package, version}`
  entries. Where `--audit-dependabot-alerts` reports the KNOWN-VULNERABLE
  dependencies a provider scanner has already flagged, this reports the
  FULL declared dependency surface — the software-supply-chain inventory
  a Dependabot audit can only annotate, not enumerate.
- **`--audit-actions-environments`** — deployment-environment audit
  (reviewers, wait-timer, protection rules).
- **`--audit-deployment-protection`** — custom deployment-protection rule
  audit per environment.
- **`--audit-webhook`** — webhook posture audit (URL, content-type,
  secret-presence, ssl-verification, active-state).
- **`--audit-workflow-runs`** — recent CI/CD pipeline-run activity audit
  (read-only; status, conclusion, duration, head-branch, event).
- **`--audit-repo-visibility`** — per-repo public/private/visibility audit
  (including internal-visibility repos visible to the token's org).
- **`--scan-commits`** — commit-message secret scanning via the
  `necromancer-patterns` ruleset over a paginated `commits` traversal.
- **`--enumerate-orgs`** — org/group/workspace enumeration (name, slug,
  description, plan, created_at).
- **`--enumerate-members`** — per-org member enumeration (login, role,
  two-factor enabled state).
- **`--enumerate-collaborators`** — per-repo outside-collaborator
  enumeration (login, permissions, invitation_state).
- **`--enumerate-teams`** — org/group team and subgroup inventory (name,
  slug, description, parent, privacy, members_count).
- **`--enumerate-deploy-keys`** — per-repo deploy-key inventory (id, title,
  fingerprint, read/write, created_at, last_used).
- **`--enumerate-gists`** — per-user gist inventory (id, description,
  public, files, created_at, updated_at).
- **`--enumerate-keys`** — per-user SSH + GPG signing-key inventory.
- **`--enumerate-webhooks`** — per-repo + per-org webhook inventory.
- **`--enumerate-runners`** — self-hosted CI runner inventory (name,
  OS, status, busy, labels).
- **`--enumerate-actions-secrets`** — per-repo + per-org Actions secrets
  inventory (name, created_at, visibility, selected_repos_url when
  applicable). Names only; never values.
- **`--query-filter`** — filter results by a glob on the repo's
  `full_name`, `description`, `language`, or `topics`.

### Fixed

- **Top-level `--version` flag** (PR #38) — `covenant --version` now
  exits 0 and prints `covenant 1.0.0` without requiring an SCM subcommand.
  Previously the top-level parser's `add_subparsers` required
  `{github,gitlab,bitbucket}` as the first positional, which made
  `covenant --version` fail with "the following arguments are required".
- **Real Bitbucket code search** (POST_V01 Item 2) — replaces the
  alias-to-repo-search shortcut with the documented
  `/2.0/workspaces/{workspace}/search/code` endpoint.
- **Canonicalize SCM API hosts to web hosts in the scope guardrail**
  so `api.github.com` and `github.com` (and the GitLab/Bitbucket
  equivalents) compare as the same target.

### Changed

- **Version constant** bumped from `0.1.0` to `1.0.0`. The CLI's
  `--version` output, the `covenant.__version__` Python attribute, and
  the wheel distribution name (`covenant-1.0.0-py3-none-any.whl`) all
  reflect the new version.
- **Wheel distribution contract** — `pip install covenant==1.0.0` from a
  fresh venv installs a working `covenant` console script. The
  ship-gate test suite (`tests/test_wheel_ship_gate.py`,
  `@pytest.mark.ship_gate`, 11 tests including `test_top_level_version_flag_works`
  and `test_changelog_exists_with_v1_0_0_entry`) runs end-to-end against
  the built wheel.

### Security

- All HTTP requests are read-only (GET, HEAD). covenant never POSTs,
  PUTs, PATCHes, or DELETEs against the SCM API.
- Token values are loaded from environment variables or `--token-file`
  and are never written to disk, logged, or echoed in error messages.
- The scope guardrail is the last line of defense, not the first —
  every recon and audit function checks scope at call time.
- Live-credential verification (`--verify-secrets`) is opt-in; the
  default read-only path never makes a mutating call.

[0.1.0]: https://github.com/bugsyhewitt/covenant/releases/tag/v0.1.0
