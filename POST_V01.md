# covenant — Post-v0.1 Improvement Roadmap

**Generated:** 2026-05-26 by Worker (Rotation 2, research lap)
**Baseline:** covenant ships three read-only SCM modules (`recon-repo`, `recon-code`,
`validate-token`) for GitHub/GitLab/Bitbucket behind a mandatory scope guardrail, with an
opt-in `--scan-secrets` flag on `recon-code` that runs the shared `necromancer-patterns`
ruleset client-side over code-search fragments — but it fetches only the first API page,
prints secrets in the clear, has no live-credential verification, and fakes Bitbucket code
search by aliasing repo search.

## Methodology

I read the full source tree (`cli.py`, `scope.py`, `secrets.py`, all three `scms/*` clients,
`base.py`), the test suite, `pyproject.toml`, and the shared `necromancer-patterns` library,
then researched the 2025/2026 SCM-recon and token-abuse landscape: how TruffleHog/GitHound
differentiate (live secret *verification*, breadth-first code search), the documented
GitHub code-search pagination caps, GitHub's token-prefix taxonomy, GitLab's
scopes-AND-roles blast-radius model, and Bitbucket's app-password→API-token cutover. Items
are ranked by **signal-to-noise gain × inverse implementation complexity** — I favor changes
that materially raise recall or precision (or remove an active operational hazard) and that
fit one focused Phase-2 lap. Each item is a single shippable deliverable with tests; none
breaks the v0.1 read-only contract or the scope guardrail.

---

## Item 1 — Paginate recon-repo and recon-code results (Priority: CRITICAL) — ✅ IMPLEMENTED (Phase 2, Rotation 3)

> **Status: shipped.** A shared `BaseSCMClient._get_paginated()` helper now walks
> paginated GET responses, bounded by a `--max-pages` CLI flag (default 10, hard
> ceiling 100). Each client supplies a `next_request` callback for its own
> pagination contract: GitHub follows the RFC-5988 `Link: ...; rel="next"` header,
> GitLab honors `X-Next-Page` (offset pagination with `per_page=100&page=N`), and
> Bitbucket follows the `next` URL key in the `{"values": [...], "next": ...}`
> envelope. `recon_repo`, `recon_code`, and `recon_code_with_fragments` across all
> three clients now thread `max_pages` through and accumulate results across pages.
> The JSON output shape is unchanged — the flat `results` array is simply longer.
> Mock servers emit multi-page fixtures for any query prefixed `multipage`; tests
> in `tests/test_pagination.py` prove (a) GitHub Link-header walking, (b) GitLab
> `X-Next-Page` walking, (c) Bitbucket `next`-key walking, (d) `--max-pages 1`/`2`
> capping, (e) single-page responses stopping after one page, and ceiling clamping.
> Full suite: 37 tests passing (25 baseline + 12 new), zero regressions.



### What
Every recon module currently issues exactly one `_get(...)` and returns only that first
page — roughly 30 GitHub items, one GitLab page, one Bitbucket page. In real recon the
interesting result is rarely on page one. covenant silently caps recall at a single page,
which is the single largest correctness gap in the tool: an operator can run a query, get
"3 results", and conclude a target is clean when there are 300 matches. The 2025 GitHub-recon
literature is explicit that GitHub itself caps code search at ~100 pages (5 pages in the new
UI), so the *only* way to approach full recall is to walk pages up to that ceiling — which
covenant doesn't do at all today.

### How
Add page-walking inside each client, bounded by a `--max-pages` CLI flag (default e.g. 10,
hard ceiling 100 to respect GitHub's cap):
- **GitHub**: follow the RFC-5988 `Link: ...; rel="next"` response header (already returned
  by `/search/*`); loop until no `next` link or `--max-pages` reached.
- **GitLab**: honor `X-Next-Page` / `X-Total-Pages` headers (or pass `per_page=100` + `page=N`).
- **Bitbucket**: follow the `next` URL key in the paged `{"values": [...], "next": "..."}`
  envelope.
Thread `max_pages` through `recon_repo`, `recon_code`, and `recon_code_with_fragments`. Keep
the JSON output shape identical (a flat `results` array); just longer.

### Effort estimate
60–90K tokens. Touches all three clients + `base.py` (a shared `_get_paginated` helper) + CLI
arg + mock-server multi-page fixtures + tests asserting >1 page is consumed.

### Rationale
Highest signal-to-noise win in the backlog: it directly multiplies the tool's recall, which
is the entire point of a recon engine. Complexity is low-to-medium because the pagination
contracts are header/key-driven and well documented. Nothing else in this list matters if the
tool only ever sees page one.

---

## Item 2 — Real Bitbucket code search (Priority: HIGH) — ✅ IMPLEMENTED (Phase 2, Rotation 9)

> **Status: shipped.** `BitbucketClient.recon_code` /
> `recon_code_with_fragments` now hit the workspace-scoped
> `GET /2.0/workspaces/{workspace}/search/code` endpoint instead of aliasing
> repo search. The workspace is supplied via a `--workspace <slug>` flag
> (required for Bitbucket `recon-code`; absent → clear `SCMError`, never a
> silent fallback). Response `values[].file.path` maps to covenant's standard
> code-result shape, and `content_matches[].lines[].segments[].text` is exposed
> as `fragments` so `--scan-secrets` works on Bitbucket exactly as on
> GitHub/GitLab. Mirrored parity tests cover the success path, the
> no-workspace error, and the secret-scan finding shape.

### What
`BitbucketClient.recon_code` is a stub: it calls `recon_repo` and returns repositories, not
code matches (`return self.recon_repo(query)`). A user running `covenant bitbucket recon-code`
gets repo names dressed up as code results, and `--scan-secrets` on Bitbucket scans nothing
(the base `recon_code_with_fragments` attaches empty `fragments`). This is a silent
correctness bug: the module claims a capability it does not have.

### How
Implement against Bitbucket Cloud's code search endpoint
`GET /2.0/workspaces/{workspace}/search/code?search_query=...`. Because the endpoint is
workspace-scoped, derive the workspace from the scope file entries (the scope file already
lists `bitbucket.org/<workspace>` lines — surface the workspace via a `Scope.workspaces()`
accessor or a `--workspace` flag). Map response `values[].file.path` / `path_matches` /
`content_matches` into covenant's standard code-result shape, and override
`recon_code_with_fragments` to expose `content_matches[].lines[].segments[].text` as
`fragments` so `--scan-secrets` works on Bitbucket exactly as it does on GitHub/GitLab. If no
workspace is resolvable, emit a clear error rather than silently falling back to repo search.

### Effort estimate
70–110K tokens. New endpoint client method, scope/workspace plumbing, a Bitbucket
code-search mock handler with a planted credential fragment, and parity tests mirroring the
existing GitHub/GitLab `--scan-secrets` tests.

### Rationale
Removes a correctness lie. Bitbucket is one of three first-class SCMs and right now one third
of the `recon-code` surface is fake. High signal because it closes a capability gap users
reasonably assume already works; medium complexity because the endpoint exists and the result
mapping mirrors patterns already in the codebase.

---

## Item 3 — Redact secrets in output by default with opt-in `--show-secrets` (Priority: HIGH) — ✅ IMPLEMENTED (Phase 2, Rotation 5)

> **Status: shipped.** `secrets.py` now exposes a pure `redact(secret)` helper
> that returns a share-safe fingerprint — a 4-char type-revealing prefix, the
> length, and a 4-hex truncated SHA-256, e.g. `"AKIA…[20 chars, sha256:9f3a]"`.
> `scan_fragments` takes a `reveal: bool = False` keyword and redacts the
> `secret` field by default; `cli.py` adds a `--show-secrets` flag to
> `recon-code` (implying `--scan-secrets`) that opts back into the raw value.
> The finding shape is unchanged — only the `secret` value differs. Tests cover
> the `redact` helper (prefix preservation, length+hash, non-leakage,
> determinism, short-secret passthrough, distinct-secret distinction), the
> default-redacted vs `reveal=True` paths in `scan_fragments`, and end-to-end
> CLI assertions that the raw key never appears by default and is present under
> `--show-secrets`. Full suite: 54 tests passing (42 baseline + 12 new), zero
> regressions. README updated.

### What
`scan_fragments` returns the raw, full secret value, and `cli.py` dumps it verbatim into the
`"secret"` field of stdout JSON. Recon output routinely lands in engagement logs, terminal
scrollback, shell pipelines, and shared report artifacts — so covenant's *own* finding output
becomes a new place the live credential leaks to. TruffleHog and GitHub secret scanning treat
the discovered value as sensitive; covenant currently treats it as plaintext.

### How
By default, redact the `secret` field to a fingerprint that is safe to share but still lets an
operator correlate findings: keep a short prefix (e.g. first 4 chars, useful because the
prefix encodes the credential type — `AKIA`, `ghp_`, `sk_live`) plus a length and a truncated
SHA-256, e.g. `"AKIA…[20 chars, sha256:9f3a]"`. Add a `--show-secrets` flag to `recon-code`
that opts back into the full value for the rare case the operator needs it. Implement the
redaction in `secrets.py` (a `redact(finding, reveal: bool)` helper) so the policy lives in
one place and is unit-testable independent of the CLI.

### Effort estimate
25–40K tokens. One helper in `secrets.py`, one CLI flag, update the README example output,
and tests asserting default-redacted vs `--show-secrets`-revealed shapes.

### Rationale
Pure operational-safety win with near-zero complexity and no recall/precision tradeoff. The
prefix-preserving fingerprint actually *adds* signal (type is visible) while removing a
self-inflicted leakage hazard. High value because it changes a default that is quietly unsafe.

---

## Item 4 — Token-type fingerprinting in validate-token (Priority: HIGH) — ✅ IMPLEMENTED (Phase 2, Rotation 6)

> **Status: shipped.** A new pure, offline `covenant/tokens.py` exposes
> `classify_token(token, scm)` that fingerprints a credential's *type* from its
> prefix taxonomy — GitHub `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`/`github_pat_`/
> legacy-40-hex, GitLab `glpat-`/`gloas-`/`glptt-`, Bitbucket API token
> (`ATCTT`) vs the deprecated app-password form (`ATBB`) — and returns a
> `token_type` label, a blast-radius `note`, and a `confidence` band, never
> echoing the raw token. All three clients' `validate_token()` now merge
> `token_type`, `token_note`, and `token_type_confidence` into their payloads
> (v0.1 `scopes`/`user`/`admin` fields untouched, the new fields are purely
> additive). The GitLab note carries the scopes-AND-roles caveat so a permissive
> scope list isn't over-read. Tests: `tests/test_tokens.py` covers the full
> prefix table, the empty/whitespace/unknown-scm edges, confidence banding, and
> the no-raw-token-leak invariant; e2e tests assert the field appears end-to-end
> for all three SCMs. Full suite: 80 tests passing (54 baseline + 26 new), zero
> regressions. README updated.

### What
`validate-token` reports `scopes`, `user`, and `admin`, but never tells the operator *what
kind of token* they hold. GitHub encodes the token class in a case-sensitive prefix —
`ghp_` (classic PAT), `gho_` (OAuth), `ghu_`/`ghs_` (GitHub App user/installation), `ghr_`
(refresh), `github_pat_` (fine-grained, GA as of March 2025), and bare 40-hex for legacy PATs.
The token class is decisive for blast-radius reasoning: a fine-grained PAT's scope list means
something completely different from a classic PAT's, and an installation token (`ghs_`) implies
GitHub App reach. covenant has this information sitting in `self.token` and throws it away.

### How
Add a pure-string `classify_token(token, scm)` function (no network call) that returns a
`token_type` label and a confidence note. For GitHub, branch on the documented prefixes; for
GitLab, distinguish `glpat-` (PAT) vs `gloas-` (OAuth) vs job tokens; for Bitbucket, note
API-token vs the deprecating app-password form (app-password creation ends Sept 2025, full
cutover June 2026 — flag app-password-shaped credentials as deprecated). Add the resulting
`"token_type"` field to each client's `validate_token()` payload. Pair it with a
GitLab-specific note that effective access is bounded by **scopes AND the user's role**, so a
permissive scope list does not guarantee access — preventing the operator from over-reading
the `scopes` array.

### Effort estimate
30–50K tokens. One `classify_token` helper (entirely offline, trivially testable), wired into
three `validate_token` methods, plus unit tests over the prefix table.

### Rationale
High signal, very low complexity — it's offline string analysis over a published prefix
taxonomy, so it adds zero API calls, zero rate-limit risk, and zero new dependencies, yet
materially improves the operator's ability to reason about what a captured token can do. Pure
upside.

---

## Item 5 — Optional live secret verification `--verify-secrets` (Priority: MEDIUM)

### What
covenant's `--scan-secrets` reports *candidate* credentials by regex/entropy. The defining
2025/2026 differentiator between a noise-generator and a credible secret scanner (TruffleHog's
`--results=verified`) is **verification**: actually authenticating the found credential against
its issuing service to prove it is live, not expired or a placeholder. A verified AWS key is an
incident; an unverified one is a maybe. covenant produces only maybes today.

### How
Add a `--verify-secrets` flag (implies `--scan-secrets`) that, for credential types covenant
knows how to check, makes a single, **read-only, non-destructive** auth probe per unique
secret and tags each finding with `"verified": true|false|null` (null = unsupported type).
Start with the two provider rules already in `necromancer-patterns`:
- **AWS access key** → `sts:GetCallerIdentity` (the canonical zero-impact "who am I" call).
- **Stripe secret key** → `GET /v1/balance` (read-only).
Guardrails that keep this in covenant's lane: (a) each target's host must pass the existing
scope check before any probe; (b) dedupe by secret so 50 copies = 1 probe (the literature warns
verification can trip target rate-limits/anomaly detection); (c) treat both 200 and 429 as
"valid" (a rate-limited credential is still live); (d) document loudly in `--help` and README
that verification transmits the candidate secret to the issuing provider.

### Effort estimate
100–150K tokens. New `verify.py` with one verifier per rule type, dedupe layer, mock-provider
test servers, and a clear opt-in/consent path. This is the heaviest item.

### Rationale
The biggest *precision* gain available — it turns covenant from "here are strings that look
like keys" into "here are live keys" — but it carries real complexity (per-provider verifier
logic) and genuine scope/ethics considerations (transmitting secrets off-box, touching
third-party APIs). Ranked mid-pack rather than top because the cheaper recall/safety items
(1–4) should land first, and verification only pays off once recall (Item 1) is fixed so there
are more candidates worth verifying.

---

## Item 6 — Rate-limit and transient-failure handling with backoff (Priority: MEDIUM) — ✅ IMPLEMENTED (Phase 2, Rotation 8)

> **Status: shipped.** `base.py` now treats a `403`/`429` rate-limit response as
> "wait and retry" rather than a hard failure. A shared `_request_with_retry`
> helper backs every GET (`_get`, `_get_absolute`, and the paginator): on a
> rate-limit status it computes a wait via `_parse_retry_after` — honoring
> `Retry-After`, then GitHub's `X-RateLimit-Reset` / GitLab's `RateLimit-Reset`
> reset-epoch headers, then a bounded exponential backoff — sleeps the
> (clamped to `[0, 60s]`) interval, and retries up to `DEFAULT_MAX_RETRIES`
> (3). Sleeping is routed through an injectable `_sleep` so tests run instantly.
> When the budget is exhausted while the server is still throttling, covenant
> records a non-fatal entry on `client.warnings`; the paginator detects this
> and stops the walk **cleanly**, preserving the pages gathered so far instead
> of aborting the run. The CLI surfaces these as a `"warnings"` array in the
> `recon-repo`/`recon-code` payload (absent on a fully successful run, so its
> presence is the explicit "recall is partial" signal). Non-rate-limit 4xx
> (e.g. 404) and 401 are unchanged — they still raise immediately.
> Mock servers gain a `ratelimit`/`ratelimitforever` query prefix that emits
> `429`s (recoverable then 200, or forever). Tests: `tests/test_ratelimit.py`
> covers e2e recovery and budget-exhaustion-with-warnings across all three SCMs,
> the full `_parse_retry_after` header/clamp/backoff matrix, and
> `_request_with_retry` retry counting, `max_retries=0`, and the
> not-retried-404 case. Full suite: 119 tests passing (100 baseline + 19 new),
> zero regressions. README updated.

### What
`base._get` raises `SCMError` on any status ≥ 400, treating a 403/429 rate-limit response
identically to a hard failure. GitHub's search API has a low secondary-rate-limit ceiling
(~10 req/min unauthenticated-style budgets, and search is the most-throttled surface), and
pagination (Item 1) will hit it fast. Today a rate-limit mid-walk aborts the whole run and
loses partial results. A recon tool that dies on the first 429 is unreliable on exactly the
large targets where it's most valuable.

### How
In `base._get` (or a `_get_paginated` wrapper), special-case 403/429: read GitHub's
`Retry-After` / `X-RateLimit-Reset` headers (and GitLab's `RateLimit-Reset`), sleep the
indicated interval with a bounded exponential backoff and a small retry cap (e.g. 3), then
resume. Surface a non-fatal `"warnings"` array in the payload when results are partial because
a retry budget was exhausted, so the operator knows recall was truncated rather than complete.

### Effort estimate
40–60K tokens. Backoff logic in `base.py`, mock-server handlers that return 429 + reset
headers then 200, and tests asserting covenant retries and ultimately succeeds (with a clamped
sleep so tests stay fast).

### Rationale
Reliability multiplier that pairs directly with Item 1 — pagination without rate-limit
handling will fail in practice. Medium signal (it's robustness, not new capability), low-medium
complexity. Ordered after the capability items because it only matters once covenant is making
enough calls to get throttled.

---

## Item 7 — Pattern-set selection and query noise-filtering (Priority: MEDIUM)

### What
Two precision knobs are missing. (a) `secrets.scan_fragments` always calls
`necromancer_patterns.match()` with the default `"full"` pattern set; the library already ships
`minimal`/`aws`/`full` sets and `available_pattern_sets()`, but covenant gives the operator no
way to choose — so an AWS-only engagement still runs the generic high-entropy rule and eats its
false positives. (b) The recon literature is unanimous that the practical way to beat GitHub's
page cap and reduce noise is query refinement (`NOT example NOT test NOT localhost`,
`language:` filters). covenant passes the raw `--query` straight through.

### How
(a) Add `--pattern-set {minimal,aws,full}` to `recon-code`, plumb it into `scan_fragments`
(which forwards to `match(text, pattern_set=...)`), defaulting to `full` for backward
compatibility; validate against `available_pattern_sets()`. (b) Add an optional
`--exclude TERM` (repeatable) flag that appends provider-appropriate negative qualifiers to the
search query (`NOT <term>` for GitHub/GitLab) so operators can strip demo/test noise without
hand-crafting query strings. Both are CLI-and-mapping changes; no new detection logic.

### Effort estimate
35–55K tokens. Two CLI flags, a thread-through into `scan_fragments` and each client's query
builder, plus tests covering set selection and that excludes alter the outgoing query params.

### Rationale
Targeted precision tuning that leans entirely on capabilities already present in
`necromancer-patterns` and the SCM search APIs, so complexity is low. Medium signal: it sharpens
an existing feature rather than adding a new one, which is why it ranks last — valuable polish
once the recall, correctness, safety, and reliability items above are in place.

---

## Item 8 — Org/workspace-level scope narrowing (Priority: HIGH) — ✅ IMPLEMENTED (Phase 2, Rotation 10)

> **Status: shipped.** `Scope` now retains the org/group/workspace path from
> each scope entry instead of discarding everything after the host. A host that
> appears as a bare entry stays **host-wide** (v0.1 behavior preserved — loopback
> test hosts and `github.com`/`bitbucket.org` bare entries authorize any org); a
> host that appears *only* with org paths becomes **org-restricted** and refuses
> targets in a sibling org. New `Scope.is_org_in_scope` / `assert_org_in_scope`
> (and `is_host_org_restricted`) implement this, and the CLI wires the Bitbucket
> `--workspace` slug through `assert_org_in_scope` before any token is read,
> returning exit code 2 for an out-of-scope workspace. Tests: 7 unit tests in
> `tests/test_scope.py` (host-wide passthrough, org restriction, unnamed-org
> refusal, bare-entry override, case-insensitive match, multi-org, host-not-in-
> scope) plus 3 e2e CLI tests (workspace refused, workspace allowed, bare host
> authorizes any workspace). Full suite: 150 tests passing (140 baseline + 10
> new), zero regressions. README updated.

### What
covenant's central safety contract is "refuse any target you're not authorized
to test," but the scope guardrail matched **host-only**. The scope-file format
documents and encourages org-qualified entries (`github.com/acme-corp`,
`bitbucket.org/acme`), yet `scope.py` parsed the org segment and threw it away —
so listing `bitbucket.org/acme` authorized the *entire* `bitbucket.org` host.
Combined with Item 2's workspace-scoped Bitbucket code search, this was a
concrete authorization bypass: an operator scoped to `bitbucket.org/acme` could
run `recon-code --workspace victim` and covenant would search the victim
workspace, because only the host (`api.bitbucket.org`) was ever checked against
scope.

### How
Retain per-host org sets when loading the scope file. A host is "org-restricted"
iff it has explicit org entries and never appeared bare. Add
`is_org_in_scope(target_url, org)` / `assert_org_in_scope(...)` that pass any org
on a host-wide host (backward compatible) but refuse an unlisted org (and refuse
an unnamed org) on an org-restricted host. Wire the Bitbucket `--workspace` slug
through this check in the CLI's scope-guardrail block, before the token is read,
preserving the existing exit-code-2 semantics.

### Rationale
Highest-value remaining item: it hardens the tool's defining guarantee and
removes a real, demonstrable bypass, at low complexity (pure offline string
logic in one module plus one CLI call site) with zero new dependencies and full
backward compatibility for the common bare-host scope file.

---

## Research notes

**Sources consulted:**

- TruffleHog (trufflesecurity/trufflehog) — `--results=verified`, 800+ detectors with live
  non-destructive auth verification, and the documented nuance that 429 (rate-limited) still
  implies a *valid* credential. Primary basis for Item 5.
- 2025 GitHub-recon write-ups (Tillson Galloway's checklist, codelivly, GitHound) — code-search
  pagination caps (~100 pages / 5 pages in the new UI), breadth-first vs depth-first tooling,
  and `NOT`-operator query refinement. Basis for Items 1 and 7.
- GitHub token-prefix taxonomy (Microsoft Purview SIT definition, GitHub changelog "fine-grained
  PATs GA", Gato-X docs) — `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`/`github_pat_`/legacy-40-hex.
  Basis for Item 4.
- GitLab Search API docs + token docs — `blobs` scope shape, and the "scopes do not override
  roles" blast-radius rule. Informs Items 1, 4, 7.
- Atlassian Bitbucket Cloud docs — workspace-scoped `/2.0/.../search/code` endpoint, and the
  app-password deprecation timeline (creation ends 2025-09-09, full cutover 2026-06-09). Basis
  for Items 2 and 4.
- covenant source review — confirmed single-page fetch in all clients, the Bitbucket
  `recon_code` → `recon_repo` stub, plaintext `secret` output, and the unused `pattern_set`
  parameter in `necromancer_patterns.match`. Direct basis for Items 1, 2, 3, 7.

---

## New directions (post-exhaustion)

The original Items 1–8 plus the API-host follow-on are all shipped. Subsequent
laps extend the toolkit along its natural axis — turning a captured token into a
fuller blast-radius picture — rather than reopening closed items.

### SSH/GPG key enumeration in validate-token (`--enumerate-keys`) — ✅ IMPLEMENTED (Phase 2, Rotation 13)

> **Status: shipped.** A read-only `--enumerate-keys` flag on `validate-token`
> walks the account's PUBLIC SSH and GPG keys and adds a normalized `keys`
> array of `{type, id, title, fingerprint}` entries (`type` ∈ `ssh`/`gpg`).
> GitHub uses `GET /user/keys` + `GET /user/gpg_keys`; GitLab uses
> `GET /api/v4/user/keys` + `GET /api/v4/user/gpg_keys`; Bitbucket resolves the
> user UUID via `GET /2.0/user` then walks `GET /2.0/users/{uuid}/ssh-keys`
> (Bitbucket Cloud has no public GPG-key API, so SSH only). The signal: SSH
> keys reveal which machines can push as the identity (persistence); GPG keys
> reveal which keys can sign "Verified" commits in its name (trust/supply-chain).
> Only public metadata is emitted — private key material is never read, and
> GitLab's multi-line armored GPG body is collapsed to a bounded single-line
> share-safe fingerprint. The walk reuses the shared paginator, scope guardrail,
> and rate-limit backoff, is bounded by `--max-pages`, and composes with
> `--enumerate-orgs`. Purely additive: the v0.1 `scopes`/`user`/`admin` fields
> are untouched and the `keys` array appears only when the flag is set. Tests:
> `tests/test_enumerate_keys.py` covers each client's normalized shape, the
> GitLab GPG single-line-fingerprint reduction, the no-private-material
> invariant across all three SCMs, e2e presence-only-when-requested,
> composition with `--enumerate-orgs`, the scope-guardrail gate (exit 2), and
> `--help` documentation. Full suite: 179 passing (167 baseline + 12 new), zero
> regressions. README updated with an "SSH/GPG key enumeration" subsection.

### Webhook enumeration in validate-token (`--enumerate-webhooks`) — ✅ IMPLEMENTED (Phase 2, Rotation 15)

> **Status: shipped.** A read-only `--enumerate-webhooks` flag on
> `validate-token` walks the org/group/workspace webhooks a captured token can
> reach and adds a normalized `webhooks` array of
> `{scope, owner, id, url, events, active}` entries. It reuses
> `enumerate_orgs` to discover the reachable orgs (GitHub `GET /user/orgs`),
> groups (GitLab `GET /api/v4/groups`) and workspaces (Bitbucket
> `GET /2.0/workspaces`), then for each lists its hooks: GitHub
> `GET /orgs/{org}/hooks`, GitLab `GET /api/v4/groups/{id}/hooks` (per-event
> boolean flags normalized into the `events` list), Bitbucket
> `GET /2.0/workspaces/{slug}/hooks`. The signal: a webhook's destination URL
> is where event payloads (repo content/metadata) are POSTed — a data-exfil
> channel and, against internal infra, an SSRF target. The destination `url`
> is surfaced verbatim (the recon point); the hook **secret** is never
> requested or echoed. The walk reuses the shared paginator, scope guardrail
> and rate-limit backoff, is bounded by `--max-pages`, and composes with the
> other `--enumerate-*` flags. Purely additive: the v0.1
> `scopes`/`user`/`admin` fields are untouched and the `webhooks` array appears
> only when the flag is set. Tests: `tests/test_enumerate_webhooks.py` covers
> each client's normalized shape, the GitLab per-event-flag → `events`-list
> reduction, the no-hook-secret-leak invariant across all three SCMs, e2e
> presence-only-when-requested, composition with the other enumerations, the
> scope-guardrail gate (exit 2), and `--help` documentation. Full suite: 222
> passing (211 baseline + 11 new), zero regressions. README updated with a
> "Webhook enumeration" subsection.

### Deploy-key enumeration in validate-token (`--enumerate-deploy-keys`) — ✅ IMPLEMENTED (Phase 2, Rotation 16)

> **Status: shipped.** A read-only `--enumerate-deploy-keys` flag on
> `validate-token` walks the repositories a captured token can reach and, for
> each, lists its deploy keys, adding a normalized `deploy_keys` array of
> `{repo, id, title, read_only, fingerprint}` entries. Where `--enumerate-keys`
> covers the *account's* SSH/GPG keys, this covers the *repo-scoped* keys: a
> deploy key grants Git access to a single repo independent of any human
> credential and often carries write access, so a writable one
> (`read_only=false`) is a persistence and supply-chain foothold (push to the
> repo *as the repo*). GitHub walks `GET /user/repos` → `GET
> /repos/{owner}/{repo}/keys` (returns `read_only` directly); GitLab walks `GET
> /api/v4/projects?membership=true` → `GET /api/v4/projects/{id}/deploy_keys`
> (inverts `can_push` into `read_only`); Bitbucket walks `GET
> /2.0/repositories?role=member` → `GET
> /2.0/repositories/{full_name}/deploy-keys` (Cloud access keys are read-only by
> design, so `read_only` is always `true` there). Only PUBLIC key metadata is
> emitted — private key material is never read. The walk reuses the shared
> paginator, scope guardrail and rate-limit backoff, is bounded by
> `--max-pages`, and composes with the other `--enumerate-*` flags. Purely
> additive: the v0.1 `scopes`/`user`/`admin` fields are untouched and the
> `deploy_keys` array appears only when the flag is set. Tests:
> `tests/test_enumerate_deploy_keys.py` covers each client's normalized shape,
> the `read_only`/`can_push` write-semantics mapping across all three SCMs, the
> no-private-material invariant, e2e presence-only-when-requested, composition
> with the other enumerations, the scope-guardrail gate (exit 2), and `--help`
> documentation. Full suite: 233 passing (222 baseline + 11 new), zero
> regressions. README updated with a "Deploy-key enumeration" subsection.

### Branch-protection audit in validate-token (`--audit-branch-protection`) — ✅ IMPLEMENTED (Phase 2, Rotation 17)

> **Status: shipped.** A read-only `--audit-branch-protection` flag on
> `validate-token` is the DEFENSIVE counterpart to the `--enumerate-*` family:
> where those map a captured token's offensive reach (keys it owns, repos it
> can push to, webhooks it can redirect), this reports whether that reach would
> actually *land* — i.e. whether the reachable repos' protected branches would
> stop an unreviewed, unsigned, or admin-bypassing push. It walks the repos the
> token can reach and, for each, audits its protected branches, adding a
> normalized `branch_protection` array of `{repo, branch, required_reviews,
> required_review_count, dismiss_stale_reviews, require_signed_commits,
> enforce_admins}` entries. `required_reviews=false` (or a zero
> `required_review_count`) on a reachable repo is the high-signal supply-chain
> finding. GitHub walks `GET /user/repos` → `GET
> /repos/{owner}/{repo}/branches?protected=true` → `.../branches/{branch}/protection`
> (maps `required_pull_request_reviews`, `required_signatures.enabled`,
> `enforce_admins.enabled` directly); GitLab walks `GET
> /api/v4/projects?membership=true` → `GET
> /api/v4/projects/{id}/protected_branches`, resolving the project-level
> `approvals_before_merge` / `reset_approvals_on_push` (`GET .../approvals`) and
> `reject_unsigned_commits` (`GET .../push_rule`) once per project and mapping
> `enforce_admins` to the branch disallowing force push (approval/push-rule
> endpoints fail soft to safe defaults for low-privilege tokens); Bitbucket
> walks `GET /2.0/repositories?role=member` → `GET
> /2.0/repositories/{full_name}/branch-restrictions`, aggregating the flat
> restriction list per branch pattern (`require_approvals_to_merge`,
> `reset_pullrequest_approvals_on_change`, `force`) — Bitbucket Cloud has no
> signed-commit restriction so `require_signed_commits` is always `false` there.
> The audit is read-only (only GETs policy metadata, never alters protection),
> reuses the shared paginator, scope guardrail and rate-limit backoff, is bounded
> by `--max-pages`, and composes with the other `--enumerate-*` flags. Purely
> additive: the v0.1 `scopes`/`user`/`admin` fields are untouched and the
> `branch_protection` array appears only when the flag is set. Tests:
> `tests/test_audit_branch_protection.py` covers each client's normalized shape,
> the weak-vs-strong posture mapping across all three SCMs, the no-secret/no-key
> leak invariant, e2e presence-only-when-requested, composition with the other
> enumerations, the scope-guardrail gate (exit 2), and `--help` documentation.
> Full suite: 244 passing (233 baseline + 11 new), zero regressions. README
> updated with a "Branch-protection audit" subsection.

### CI/CD secret enumeration in validate-token (`--enumerate-actions-secrets`) — ✅ IMPLEMENTED (Phase 2, Rotation 18)

> **Status: shipped.** A read-only `--enumerate-actions-secrets` flag on
> `validate-token` maps the build-pipeline credential surface — the next
> blast-radius axis after SSH/GPG/deploy keys (key material) and webhooks
> (exfiltration). CI/CD secrets hold the cloud keys, registry passwords and
> signing/deploy tokens the pipeline runs with, so a repo or org carrying a long
> list is a high-value lateral-movement and supply-chain target: an attacker who
> can read or exfiltrate them via a malicious workflow inherits the pipeline's
> reach. It walks BOTH the org/group/workspace axis and the repo/project axis the
> token can reach and adds an `actions_secrets` array of
> `{scope, owner, name, protected}` entries. GitHub walks `GET
> /orgs/{org}/actions/secrets` (scope `org`, reusing `enumerate_orgs`) + `GET
> /repos/{owner}/{repo}/actions/secrets` (scope `repo`, reusing
> `_reachable_repos`), mapping `visibility=="selected"` to `protected`; GitLab
> walks `GET /api/v4/groups/{id}/variables` + `GET
> /api/v4/projects/{id}/variables`, mapping the variable `protected` flag;
> Bitbucket walks `GET /2.0/workspaces/{slug}/pipelines-config/variables` + `GET
> /2.0/repositories/{full_name}/pipelines-config/variables`, mapping the `secured`
> flag. **The decisive invariant is name-only disclosure**: covenant surfaces ONLY
> the secret NAME and metadata, never the VALUE — the provider APIs omit secured
> values and covenant emits names only. Variable-listing endpoints a low-privilege
> token can't read fail soft to an empty result (GitLab/Bitbucket) so the audit
> degrades gracefully. The walk reuses the shared paginator, scope guardrail and
> rate-limit backoff, is bounded by `--max-pages`, and composes with every other
> `--enumerate-*`/`--audit-*` flag. Purely additive: the v0.1
> `scopes`/`user`/`admin` fields are untouched and the `actions_secrets` array
> appears only when the flag is set. Tests:
> `tests/test_enumerate_actions_secrets.py` covers each client's normalized shape,
> the org-vs-repo `scope` split, the `protected` mapping across all three SCMs, the
> no-value-leak invariant (a planted `shouldnotappear` value never reaches output
> and no `value` field is present), e2e presence-only-when-requested, composition
> with the full `--enumerate-*` family, the scope-guardrail gate (exit 2), and
> `--help` documentation. Full suite: 255 passing (244 baseline + 11 new), zero
> regressions. README updated with a "CI/CD secret enumeration" subsection.

### Repository-visibility audit in validate-token (`--audit-repo-visibility`) — ✅ IMPLEMENTED (Phase 2, Rotation 19)

> **Status: shipped.** A read-only `--audit-repo-visibility` flag on
> `validate-token` reports the EXPOSURE posture of the repos a captured token
> can reach — the complement to the offensive `--enumerate-*` family. Where
> those map keys/secrets/push-reach, this flags which reachable repos are
> PUBLIC: a public repo is the org's external attack surface (world-readable
> source, history, issues and any leaked secrets) and the place covenant's own
> `recon-code` scanning finds the most, so an unexpectedly public repo beside
> private siblings is a direct leak/supply-chain risk. It walks the repos the
> token can reach and adds a normalized `repo_visibility` array of
> `{repo, visibility, public}` entries. GitHub walks `GET /user/repos` (derives
> `public` from the boolean `private`); GitLab walks `GET
> /api/v4/projects?membership=true` (maps the `visibility` string, flagging
> `internal` — readable by any authenticated instance user — as `public=true`
> exposure, not hidden as private); Bitbucket walks `GET
> /2.0/repositories?role=member` (derives `public` from `is_private`). Only repo
> metadata is read — no code, no secrets. The walk reuses the shared paginator,
> scope guardrail and rate-limit backoff, is bounded by `--max-pages`, and
> composes with every other `--enumerate-*`/`--audit-*` flag. Purely additive:
> the v0.1 `scopes`/`user`/`admin` fields are untouched and the
> `repo_visibility` array appears only when the flag is set. Tests:
> `tests/test_audit_repo_visibility.py` covers each client's normalized shape,
> the public/private derivation across all three SCMs (incl. the GitLab
> `internal`→`public=true` rule), the metadata-only invariant, e2e
> presence-only-when-requested, composition with the full
> `--enumerate-*`/`--audit-*` family, the scope-guardrail gate (exit 2), and
> `--help` documentation. Full suite: 267 passing (255 baseline + 12 new), zero
> regressions. README updated with a "Repository-visibility audit" subsection.

### Deployment-environment audit in validate-token (`--audit-actions-environments`) — ✅ IMPLEMENTED (Phase 2, Rotation 20)

> **Status: shipped.** A read-only `--audit-actions-environments` flag on
> `validate-token` is the environment-scoped, secret-exfiltration counterpart
> to `--audit-branch-protection`: where branch protection gates code landing on
> a branch, this gates *deployments* reaching the environment-scoped CI/CD
> secrets that `--enumerate-actions-secrets` finds. A deployment environment is
> where the most sensitive secrets live (production cloud keys, deploy tokens);
> its protection rules decide whether a workflow may deploy to it and READ those
> secrets. The high-signal finding is `required_reviewers=false` + a permissive
> `branch_policy="all"`, meaning any branch — including an attacker's feature
> branch carrying a malicious workflow — can deploy and exfiltrate the
> environment's secrets unreviewed. It walks the repos the token can reach and
> adds a normalized `actions_environments` array of `{repo, environment,
> required_reviewers, required_reviewer_count, wait_timer, branch_policy}`
> entries. GitHub walks `GET /repos/{owner}/{repo}/environments` (maps the
> `required_reviewers`/`wait_timer` protection rules and the
> `deployment_branch_policy` → `protected`/`custom`/`all`); GitLab walks `GET
> /api/v4/projects/{id}/environments` plus `.../protected_environments`
> (`required_approval_count` → reviewer count, `wait_timer` always 0, failing
> soft to "none protected" for a low-privilege token); Bitbucket walks `GET
> /2.0/repositories/{full_name}/environments` (the `restrictions.admin_only`
> deploy gate → `required_reviewers`, with `required_reviewer_count`/`wait_timer`
> 0 and `branch_policy` "all" for shape parity, as Bitbucket Cloud exposes no
> per-env count/timer/branch-policy). Only policy metadata is read — no
> deployment is ever created, edited, or triggered, and no secret VALUE is read.
> The walk reuses the shared paginator, scope guardrail and rate-limit backoff,
> is bounded by `--max-pages`, and composes with every other
> `--enumerate-*`/`--audit-*` flag. Purely additive: the v0.1
> `scopes`/`user`/`admin` fields are untouched and the `actions_environments`
> array appears only when the flag is set. Tests:
> `tests/test_audit_actions_environments.py` covers each client's normalized
> shape, the weak-vs-strong posture mapping across all three SCMs, the
> `_github_branch_policy` helper matrix (null/protected/custom/both), the
> no-secret-leak invariant, e2e presence-only-when-requested, composition with
> the other audits, the scope-guardrail gate (exit 2), and `--help`
> documentation. Full suite: 279 passing (267 baseline + 12 new), zero
> regressions. README updated with a "Deployment-environment audit" subsection.

### Member enumeration in validate-token (`--enumerate-members`) — ✅ IMPLEMENTED (Phase 2, Rotation 21)

> **Status: shipped.** A read-only `--enumerate-members` flag on `validate-token`
> maps the *lateral-movement* surface — the OTHER members of each
> org/group/workspace a captured token can reach, and at what role. Where the
> rest of the `--enumerate-*` family maps what *this* token reaches (keys,
> repos, secrets), this maps the PEOPLE who share that reach: additional
> identities an operator could target to widen a foothold (phishing, credential
> reuse, a weaker teammate token) and, for `role="admin"` (the org owners), the
> accounts whose compromise grants administrative control of the whole org. It
> reuses `enumerate_orgs` to discover the reachable orgs and, for each, lists its
> members: GitHub queries `GET /orgs/{org}/members?role=admin|member` (the
> endpoint carries no per-user role, so covenant queries both role-filtered views
> and tags each); GitLab walks `GET /api/v4/groups/{id}/members/all` (effective
> membership incl. inherited, mapping numeric `access_level >= 50` Owner →
> `admin`); Bitbucket walks `GET /2.0/workspaces/{slug}/members` (mapping the
> `permission` field `owner` → `admin`). **The decisive invariant is
> identity-and-role-only disclosure**: covenant surfaces the member's username
> and role and NEVER an email, SSH/GPG key, or any credential — a directory
> query, not a data dump. The walk reuses the shared paginator, scope guardrail
> and rate-limit backoff, is bounded by `--max-pages`, and composes with every
> other `--enumerate-*`/`--audit-*` flag. Purely additive: the v0.1
> `scopes`/`user`/`admin` fields are untouched and the `members` array appears
> only when the flag is set. Tests: `tests/test_enumerate_members.py` covers each
> client's normalized `{scope, owner, username, role}` shape, the admin/member
> role mapping across all three SCMs, the no-email/key/credential-leak invariant,
> e2e presence-only-when-requested, composition with the full
> `--enumerate-*`/`--audit-*` family, the scope-guardrail gate (exit 2), and
> `--help` documentation. Full suite: 290 passing (279 baseline + 11 new), zero
> regressions. README updated with a "Member enumeration" subsection.
>
> **Note on the pivot:** the prior "remaining candidate directions" list named
> OAuth-app / authorized-application enumeration as a top option, but a landscape
> check showed it lacks three-SCM parity — GitHub removed its authorized-OAuth-apps
> listing endpoint (only the GitHub-App `/user/installations` survives) and
> GitLab/Bitbucket have no clean token-reachable equivalent, which would force a
> lopsided, mostly-stubbed feature that breaks the toolkit's all-three-SCMs-in-parity
> discipline. Member enumeration, by contrast, has clean, documented, read-only
> endpoints on all three SCMs and the same high-signal blast-radius framing — so
> this lap took member enumeration instead.

### Collaborator enumeration in validate-token (`--enumerate-collaborators`) — ✅ IMPLEMENTED (Phase 2, Rotation 22)

> **Status: shipped.** A read-only `--enumerate-collaborators` flag on
> `validate-token` maps the *repo-scoped ghost-account* surface. Where
> `--enumerate-members` (Rotation 21) maps the people who share an
> org/group/workspace's reach, this is REPO-scoped and surfaces the higher-signal
> blast radius: the accounts granted access DIRECTLY on a specific repository
> rather than through org membership — the classic ghost-account / ex-employee /
> leftover-contractor vector (`outside=true`) that an org-member audit misses and
> that survives long after the person leaves. A write-or-above direct grant is a
> direct supply-chain and persistence risk. It walks the repos the token can reach
> and, for each, lists its per-repo grants: GitHub queries
> `GET /repos/{owner}/{repo}/collaborators?affiliation=outside` (so the result set
> *is* the outside collaborators) and reduces the `permissions` map to the single
> highest-privilege `role` (admin > maintain > write > triage > read); GitLab
> walks `GET /api/v4/projects/{id}/members` (the non-`/all` endpoint — grants made
> on the project itself, excluding group-inherited — mapping numeric
> `access_level` to the same role vocabulary); Bitbucket walks
> `GET /2.0/repositories/{workspace}/{repo}/permissions-config/users` (the explicit
> per-repo user-permission config, surfacing `admin`/`write`/`read` verbatim, and
> failing soft on the repo-admin-only 403). **The decisive invariant is
> identity-and-permission-only disclosure**: covenant surfaces the username and
> access level and NEVER an email, SSH/GPG key, or any credential, and never grants
> or revokes access. The walk reuses the shared paginator, scope guardrail and
> rate-limit backoff, is bounded by `--max-pages`, and composes with every other
> `--enumerate-*`/`--audit-*` flag. Purely additive: the v0.1 `scopes`/`user`/`admin`
> fields are untouched and the `collaborators` array appears only when the flag is
> set. Tests: `tests/test_enumerate_collaborators.py` covers each client's
> normalized `{repo, username, role, outside}` shape, the role mapping across all
> three SCMs, the `outside=true` flag, the no-email/key/credential-leak invariant,
> e2e presence-only-when-requested, composition with the full
> `--enumerate-*`/`--audit-*` family, the scope-guardrail gate (exit 2), and
> `--help` documentation. Full suite: 301 passing (290 baseline + 11 new), zero
> regressions. README updated with a "Collaborator enumeration" subsection.
>
> **Why this over OAuth-app enumeration:** the Rotation 21 note flagged OAuth-app /
> authorized-application enumeration as lacking three-SCM parity (GitHub removed
> its authorized-OAuth-apps listing; GitLab/Bitbucket have no clean token-reachable
> equivalent), which would force a lopsided, mostly-stubbed feature. Collaborator
> enumeration has clean, documented, read-only endpoints on all three SCMs and a
> distinct high-signal framing (per-repo ghost accounts, separate from the
> org-level people surfaced by `--enumerate-members`), so this lap took it.

### Commit-history secret scanning in validate-token (`--scan-commits`) — ✅ IMPLEMENTED (Phase 2, Rotation 23)

> **Status: shipped.** A read-only `--scan-commits` flag on `validate-token`
> scans the COMMIT-MESSAGE history of the repos a captured token can reach for
> leaked credentials, reusing the same `necromancer-patterns` engine that powers
> `--scan-secrets`. The distinct, high-signal framing: `--scan-secrets`
> (recon-code) only ever sees the CURRENT file content the code-search API
> returns, but a credential scrubbed from a tracked file routinely survives
> verbatim in the commit history — in a `git commit -m "rotate to AKIA..."`
> subject, a revert/merge body quoting a diff, or an automated bump commit.
> `--scan-commits` maps that history leak surface. It walks the reachable repos
> and lists each one's recent commits — GitHub `GET /repos/{owner}/{repo}/commits`,
> GitLab `GET /api/v4/projects/{id}/repository/commits`, Bitbucket
> `GET /2.0/repositories/{workspace}/{repo}/commits` — normalizing each commit to
> `{repo, sha, author, message}`, then feeds the message through
> `covenant.secrets.scan_fragments`. Only commits whose message actually matched
> are surfaced, as `{repo, sha, author, secret_findings}`. **The decisive
> invariants**: secrets are share-safe REDACTED by default (`--show-commit-secrets`
> opts into the raw value, mirroring recon-code's `--show-secrets`); the commit
> DIFF/patch is NEVER fetched (covenant maps the leak surface in history without
> dumping repository content); and the author EMAIL is never surfaced (only the
> account login / display name — Bitbucket's `raw` "Name <email>" string is
> deliberately parsed down). Honors `--pattern-set` (validated against the
> installed library) exactly as recon-code does. **Note on the "git log blob
> walking" framing from the prior remaining-candidates list:** covenant's defining
> architecture is purely read-only SCM API recon over httpx (no repo clones, no
> git operations), so blob-walking the full history would break that discipline
> and require a fundamentally different mechanism; the commit-MESSAGE surface is
> the API-native, three-SCM-parity slice of commit-history scanning that fits the
> architecture and is itself a notorious, distinct leak vector. The walk reuses
> the shared paginator, scope guardrail and rate-limit backoff, is bounded by
> `--max-pages`, and composes with every other `--enumerate-*`/`--audit-*` flag.
> Purely additive: the v0.1 `scopes`/`user`/`admin` fields are untouched and the
> `commit_findings` array appears only when the flag is set. Tests:
> `tests/test_scan_commits.py` covers each client's normalized
> `{repo, sha, author, message}` shape, the no-author-email-leak invariant, e2e
> detection of the planted AWS key, redaction-by-default vs raw-under-
> `--show-commit-secrets`, `--pattern-set` validation, composition with the
> `--enumerate-*` family, the scope-guardrail gate (exit 2), and `--help`
> documentation. Full suite: 315 passing (301 baseline + 14 new), zero
> regressions. README updated with a "Commit-history secret scanning" subsection.

**Remaining candidate directions (unimplemented, for future laps):** OAuth-app /
authorized-application enumeration (note its weak three-SCM parity, above), and
team/sub-group enumeration.

## Follow-on fixes

### API-host vs web-host scope mismatch (Priority: CRITICAL) — ✅ IMPLEMENTED (Phase 2, Rotation 11)

> **Status: shipped.** The scope guardrail compared the *API* host the client
> talks to (`api.github.com`, `api.bitbucket.org`) against the *web* host
> operators naturally list (`github.com`, `bitbucket.org`). Because they differ,
> a natural scope file refused every default GitHub and Bitbucket run with exit
> code 2 — two of three SCMs were unusable unless the operator listed the
> unnatural `api.*` host. (The e2e suite never caught this because it always
> overrides `--target-url` to a loopback mock that is in scope as `127.0.0.1`.)
> `scope.py` now canonicalizes the two known SCM API subdomains to their web
> host (`api.github.com → github.com`, `api.bitbucket.org → bitbucket.org`) at
> both load time and match time, so listing either form authorizes the default
> run. GitLab is unaffected (its API and web host are both `gitlab.com`).
> Canonicalization never widens scope to an unlisted host, and Item 8's
> org/workspace narrowing still holds against the canonical host (a
> `bitbucket.org/acme` entry still refuses `--workspace victim` even though the
> CLI checks `api.bitbucket.org`). Tests: 6 unit tests in `tests/test_scope.py`
> (web-host→API-host for GitHub and Bitbucket, symmetric API-form listing,
> GitLab untouched, unrelated `api.*` host still refused, org-restriction holds
> against the API host) plus 2 e2e tests asserting a default-URL GitHub/Bitbucket
> run no longer trips the scope guardrail (exit ≠ 2). README updated with a
> "Web hosts and API hosts are equivalent" subsection. Full suite: 158 passing
> (150 baseline + 8 new), zero regressions.
