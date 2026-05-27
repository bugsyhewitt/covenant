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

## Item 2 — Real Bitbucket code search (Priority: HIGH)

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

## Item 3 — Redact secrets in output by default with opt-in `--show-secrets` (Priority: HIGH)

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

## Item 4 — Token-type fingerprinting in validate-token (Priority: HIGH)

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

## Item 6 — Rate-limit and transient-failure handling with backoff (Priority: MEDIUM)

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
