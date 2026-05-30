# covenant

Linux-native Python recon + token-validation toolkit for **authorized** SCM
bug-bounty engagements. Targets GitHub (cloud), GitLab (cloud + self-hosted),
and Bitbucket Cloud.

covenant is a clean-room reimplementation of the read-only reconnaissance ideas
in IBM X-Force's [SCMKit](https://github.com/xforcered/SCMKit) (see `NOTICE`),
rebuilt for Linux and scoped down to the modules that are safe and useful inside
an authorized bug-bounty engagement.

---

## ⚠️ Authorized engagements only

**covenant is for authorized security testing only.** You must have explicit,
written authorization to test every SCM organization, repository, and account
you point it at. Every invocation requires a `--scope-file`; covenant refuses to
contact any host that is not listed in that file. Using this tool against
systems you are not authorized to test is illegal. You are solely responsible
for staying within the bounds of your engagement.

v0.1 ships **read-only** modules only. There are no persistence or
state-modifying modules.

---

## Install

Requires Python 3.13+.

```bash
git clone https://github.com/bugsyhewitt/covenant
cd covenant
python -m venv .venv && source .venv/bin/activate
pip install -e .
covenant --help
```

## Authentication

Tokens are read from an environment variable (never passed on the command line,
so they don't leak into shell history or process listings). The default
variable is `COVENANT_TOKEN`; override with `--token-env`.

```bash
export COVENANT_TOKEN="ghp_your_personal_access_token"
```

## Scope file format

A plain-text file listing the SCM hosts / orgs / repos you are authorized to
test, one per line. Blank lines and `#` comments are ignored. covenant extracts
the hostname from each entry and refuses any target whose host is not listed.

```
# scope.txt — authorized targets for ENGAGEMENT-1234
github.com/acme-corp
gitlab.com/acme-corp
bitbucket.org/acme-corp
```

#### Web hosts and API hosts are equivalent

List the **web-facing host** you reason about — `github.com`, `bitbucket.org` —
not the API subdomain. covenant talks to GitHub's and Bitbucket's REST APIs on
`api.github.com` / `api.bitbucket.org`, and it canonicalizes those to their web
host when matching scope, so a scope file listing `github.com` authorizes the
default GitHub recon run (and likewise for `bitbucket.org`). Listing the `api.*`
form works too — the two are treated as the same host. GitLab serves its API
from `gitlab.com` directly, so no aliasing is involved there. This is
canonicalization only: it never widens scope to a host you did not list, and the
org/workspace narrowing below still applies against the canonical host.

#### Org/workspace-level scope narrowing

A scope entry may be a **bare host** (`bitbucket.org`) or carry an
**org/group/workspace path** (`bitbucket.org/acme-corp`). The path is no longer
discarded:

- If a host appears as a bare entry anywhere, it stays **host-wide** — any org
  on it is authorized (this is the original v0.1 behavior, unchanged).
- If a host appears **only** with org paths, covenant treats it as
  **org-restricted**: a recon target that names a *different* org on that host
  is refused with exit code `2`, even though the host itself is listed.

This closes a real authorization gap. Bitbucket code search is workspace-scoped
(`recon-code --workspace <slug>`); previously, listing `bitbucket.org/acme` and
then running `--workspace victim` would happily search the `victim` workspace,
because only the *host* (`api.bitbucket.org`) was ever checked. Now the
`--workspace` slug is verified against the authorized orgs for the host. The
GitHub/GitLab `--org` flag (see "Single-org narrowing" below) is verified the
same way — and on an org-restricted host a recon run that names *no* org is
refused too, so the narrowing can't be silently bypassed.

```
# Org-restricted: only the acme workspace on bitbucket.org is authorized
bitbucket.org/acme

# --workspace acme   → allowed
# --workspace victim → refused (exit 2), even though bitbucket.org is "listed"
```

To authorize an entire host regardless of org, list it bare (`bitbucket.org`).

## Modules

Each SCM exposes the same read-only modules:

| Module           | What it does                                            |
|------------------|---------------------------------------------------------|
| `recon-repo`     | Search accessible repositories matching a query         |
| `recon-code`     | Search code across accessible repositories              |
| `validate-token` | Enumerate what the supplied token can access            |

All output is JSON on stdout. Exit codes: `0` success, `1` operational error,
`2` target out of scope.

### Client-side secret scanning (`--scan-secrets`)

Pass `--scan-secrets` to `recon-code` to scan the text fragments returned by
the SCM's code-search API for leaked credentials. Results gain a
`"secret_findings"` array; each finding has `rule_id`, `description`,
`secret`, `start`, `end`, and `fragment_index`.

**By default the `secret` field is redacted.** Recon output routinely lands in
engagement logs, terminal scrollback, shell pipelines, and shared report
artifacts — so emitting a live credential verbatim would make covenant's own
output a new place that secret leaks to. Instead, the `secret` field is a
share-safe fingerprint: a short type-revealing prefix, the length, and a
truncated SHA-256, e.g. `"AKIA…[20 chars, sha256:9f3a]"`. The prefix still
encodes the credential type (`AKIA`, `ghp_`, `sk_l`, …) and the hash lets you
correlate duplicate findings, but the live value never appears.

For the rare case where you genuinely need the raw value (e.g. immediate
verification), pass `--show-secrets` to opt back into the full credential.
`--show-secrets` implies `--scan-secrets`. Use it deliberately — its output is
unsafe to paste into shared artifacts.

```bash
# Default: redacted fingerprints
covenant github recon-code --scope-file scope.txt --query "api_key" --scan-secrets

# Opt in to full raw secrets (handle with care)
covenant github recon-code --scope-file scope.txt --query "api_key" --show-secrets
```

Powered by
[necromancer-patterns](https://github.com/bugsyhewitt/necromancer-patterns) —
the suite-wide shared credential-detection library. Rules currently cover:
AWS access keys, Stripe secret keys, and generic high-entropy secrets.

Requires the `scan` extra:

```bash
pip install -e ".[scan]"
```

Example (GitHub):

```bash
covenant github recon-code \
  --scope-file scope.txt \
  --query "api_key" \
  --scan-secrets
```

Example output with a finding (default redacted `secret`):

```json
{
  "scm": "github",
  "query": "api_key",
  "results": [
    {
      "name": "config.py",
      "path": "src/config.py",
      "visibility": "private",
      "url": "https://github.com/acme/infra/blob/main/src/config.py",
      "repository": "infra",
      "secret_findings": [
        {
          "rule_id": "aws-access-key-id",
          "description": "AWS access key ID",
          "secret": "AKIA…[20 chars, sha256:9f3a]",
          "start": 17,
          "end": 37,
          "fragment_index": 0
        }
      ]
    }
  ]
}
```

### Live secret verification (`--verify-secrets`)

`--scan-secrets` reports *candidate* credentials by pattern match — but a string
that *looks* like an AWS key may be expired, a placeholder, or example data. Pass
`--verify-secrets` (implies `--scan-secrets`) to actually authenticate each
detected credential against its issuing provider with a single **read-only,
non-destructive** probe, turning "here are strings that look like keys" into
"here are live keys."

Each finding gains a `"verified"` field:

| Value   | Meaning                                                          |
|---------|-----------------------------------------------------------------|
| `true`  | the credential authenticated (provider returned 200 — or 429: a rate-limited credential is still live) |
| `false` | the provider rejected the credential (401/403 — expired or invalid) |
| `null`  | covenant has no verifier for this credential type, or the probe could not complete |

Supported credential types and their probes:

| Credential type      | Probe (read-only)                          |
|----------------------|--------------------------------------------|
| AWS access key       | `sts:GetCallerIdentity` (the canonical zero-impact "who am I" call) |
| Stripe secret key    | `GET /v1/balance`                          |

Guardrails:

- **Dedupe by secret** — fifty copies of the same key trigger exactly one probe,
  so verification can't trip a target's rate-limits or anomaly detection by
  hammering the same credential.
- **Redaction still applies** — `--verify-secrets` probes the raw key internally
  but, unless you also pass `--show-secrets`, the emitted `secret` field stays a
  redacted fingerprint. The live value is verified without leaking into output.
- **Read-only only** — both probes are non-mutating "who am I / what's my
  balance" calls.

> ⚠️ **Verification transmits the candidate secret OFF-BOX to the third-party
> provider** (AWS / Stripe). Only use `--verify-secrets` when the target host is
> in scope and you are authorized to test it.

```bash
# Detect AND live-verify credentials (output stays redacted)
covenant github recon-code \
  --scope-file scope.txt \
  --query "api_key" \
  --verify-secrets
```

Example finding with verification:

```json
{
  "rule_id": "aws-access-key-id",
  "description": "AWS access key ID",
  "secret": "AKIA…[20 chars, sha256:9f3a]",
  "start": 17,
  "end": 37,
  "fragment_index": 0,
  "verified": true
}
```

### Result pagination (`--max-pages`)

`recon-repo` and `recon-code` walk **all** result pages, not just the first.
Each SCM's pagination contract is followed automatically — GitHub's RFC-5988
`Link` header, GitLab's `X-Next-Page` header, and Bitbucket's `next` envelope
key. Without page-walking an operator could query a target, see a handful of
hits on page one, and wrongly conclude the target is clean when hundreds of
matches exist on later pages.

The walk is bounded by `--max-pages` (default `10`, hard ceiling `100` to
respect GitHub's documented ~100-page search cap). Raise it for fuller recall
at the cost of more API calls; lower it (e.g. `--max-pages 1`) to fetch only
the first page:

```bash
# Walk up to 50 pages of code-search results
covenant github recon-code \
  --scope-file scope.txt \
  --query "internal_api" \
  --max-pages 50
```

The JSON output shape is unchanged — `results` is simply a longer flat array.

### Precision tuning (`--pattern-set`, `--exclude`)

`recon-code` exposes two knobs that sharpen signal-to-noise without changing
any detection logic.

**`--pattern-set {minimal,aws,full,…}`** picks which
[necromancer-patterns](https://github.com/bugsyhewitt/necromancer-patterns) rule
bundle `--scan-secrets` applies. The default is `full` (every rule, including
the generic high-entropy detector). On an AWS-only engagement, `--pattern-set
aws` drops the generic rule and the false positives it produces. The value is
validated against the rule sets the installed library actually ships — an
unknown set exits with the list of valid choices. It only takes effect together
with `--scan-secrets` / `--show-secrets` / `--verify-secrets`.

**`--exclude TERM`** (repeatable) appends a `NOT TERM` negative qualifier to the
search query before it hits the API, so you can strip demo/test/localhost noise
without hand-crafting query strings — and stretch the per-query page budget
against GitHub's search cap. Excludes apply to **GitHub and GitLab** (which
honor `NOT` in their search grammar); they are ignored for Bitbucket, whose
code-search syntax differs. The `query` field in the JSON output still echoes
the query you typed, not the augmented one.

```bash
# AWS-only scan, excluding obvious sample/test files
covenant github recon-code \
  --scope-file scope.txt \
  --query "AKIA" \
  --scan-secrets \
  --pattern-set aws \
  --exclude example \
  --exclude test
```

This sends `AKIA NOT example NOT test` to GitHub's code search and scans the
results with only the AWS rule set.

### Single-org narrowing (`--org`)

`recon-repo` and `recon-code` on **GitHub and GitLab** accept `--org SLUG` to
narrow a recon run to one organization (GitHub) or group (GitLab) instead of
searching every repository the token can reach. On GitHub the slug is appended
as an `org:<slug>` search qualifier; on GitLab covenant switches to the
group-scoped endpoints (`/groups/<slug>/projects`, `/groups/<slug>/search`), so
a GitLab slug may be a full group path like `acme/platform`. Bitbucket already
has its own mandatory `--workspace` flag for the same purpose, so `--org` is not
offered there.

`--org` is not just a precision knob — it is **scope-enforced**, closing the
same authorization gap `--workspace` already closes for Bitbucket. When the
scope file authorizes a host only for specific orgs (an org-path entry like
`github.com/acme-corp` with no bare-host entry), covenant now:

- **refuses `--org victim`** on that host with exit code `2` (out of scope),
  even though the host itself is listed; and
- **refuses a run with no `--org`** on that host with exit code `2` — an
  org-restricted host requires you to name an authorized org, because a no-org
  recon would otherwise search the *entire* host you only partially authorized.

A bare host entry (`github.com`) stays host-wide: any `--org`, or none, is
allowed (the original v0.1 behavior, unchanged). The `query` field in the JSON
output still echoes the query you typed, not the org-augmented one.

```bash
# GitHub: search only the acme-corp org for "api_key"
covenant github recon-code \
  --scope-file scope.txt \
  --query "api_key" \
  --org acme-corp

# GitLab: search only the acme/platform group (full group path)
covenant gitlab recon-code \
  --scope-file scope.txt \
  --query "api_key" \
  --org acme/platform
```

### Rate-limit handling (automatic retry with backoff)

SCM search APIs are aggressively throttled — GitHub's search surface in
particular has a low secondary-rate-limit ceiling, and page-walking
(`--max-pages`) hits it fast. covenant treats a `429` (or GitHub's secondary
`403`) as **"wait and retry,"** not a hard failure: it reads the server's retry
hint and resumes automatically. A recon tool that died on the first `429` would
be unreliable on exactly the large targets where it matters most.

How it works, with no flags to set:

- On a rate-limit response covenant honors, in priority order, the standard
  `Retry-After` header, then the reset-epoch headers GitHub (`X-RateLimit-Reset`)
  and GitLab (`RateLimit-Reset`) return; if none is present it falls back to a
  bounded exponential backoff.
- It retries up to **3 times** per request. Every wait is clamped (never longer
  than 60s) so a misbehaving or hostile API can't stall covenant indefinitely.
- If the retry budget is exhausted while the server is **still** throttling,
  covenant stops the page-walk **cleanly** — it keeps the results gathered so
  far instead of discarding the whole run — and adds a non-fatal `"warnings"`
  array to the output so you know recall was **truncated**, not complete.

```json
{
  "scm": "github",
  "query": "internal_api",
  "results": [ ... partial results ... ],
  "warnings": [
    "rate limited (HTTP 429) at https://api.github.com/search/code: retry budget of 3 exhausted; results may be partial"
  ]
}
```

When a run succeeds (even after retrying), no `warnings` key appears — its
presence is the explicit signal that the result set may be incomplete.

### Token-type fingerprinting (`validate-token`)

`validate-token` now reports **what kind of token** you hold, not just its
scopes. The token's class is encoded in its prefix, and the class is decisive
for blast-radius reasoning — a fine-grained PAT's scope list reads completely
differently from a classic PAT's, and a GitHub App installation token (`ghs_`)
implies App reach across an installation rather than a single user's access.
covenant derives this **offline** from the token's shape (no extra API call, no
rate-limit cost) and adds three fields to the output:

| Field                    | Meaning                                                |
|--------------------------|--------------------------------------------------------|
| `token_type`             | e.g. `github-pat-classic`, `gitlab-oauth`, `bitbucket-app-password`, or `unknown` |
| `token_note`             | human-readable blast-radius / caveat note              |
| `token_type_confidence`  | `high` (matched prefix), `medium` (legacy hex heuristic), `low` (unrecognized shape) |

Recognized classes include GitHub `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`/
`github_pat_`/legacy-40-hex, GitLab `glpat-`/`gloas-`/`glptt-`, and Bitbucket
API tokens (`ATCTT`) vs the **deprecated** app-password form (`ATBB`, with
creation ended 2025-09-09 and full cutover to API tokens completing 2026-06-09).
For GitLab, `token_note` also reminds you that effective access is bounded by
**scopes AND the user's role** — a permissive `scopes` list is not by itself a
grant.

The classifier reasons only about the token's shape and never echoes the raw
credential into its output, so `validate-token` results stay safe to share.

Example output:

```json
{
  "scopes": ["repo", "read:org"],
  "user": "spellcaster",
  "admin": false,
  "token_type": "github-pat-classic",
  "token_note": "classic personal access token; scopes apply org-wide to every resource the user can reach",
  "token_type_confidence": "high"
}
```

### Org/group/workspace enumeration (`--enumerate-orgs`)

Identity, scopes, and token class tell you *what a credential is*; the most
actionable next recon question is *what it can actually reach*. Pass
`--enumerate-orgs` to `validate-token` and covenant additionally walks the
token's organizational blast radius with a **read-only** membership query and
adds an `orgs` array to the output:

| SCM       | Organizational unit | Endpoint walked            |
|-----------|---------------------|----------------------------|
| GitHub    | organizations       | `GET /user/orgs`           |
| GitLab    | groups              | `GET /api/v4/groups`       |
| Bitbucket | workspaces          | `GET /2.0/workspaces`      |

Each entry is normalized to `{"name", "url"}`. GitLab groups use their
`full_path` so nested groups are unambiguous; Bitbucket entries use the
workspace **slug** — the exact value the `recon-code --workspace` flag wants, so
this is how you discover which workspaces are searchable. The walk is bounded by
the same `--max-pages` flag (default 10) and honors the scope guardrail and the
automatic rate-limit retry/backoff. The feature is purely additive: without the
flag the output is unchanged, and with it the v0.1 `scopes`/`user`/`admin`
fields are untouched — only the `orgs` array is added.

```bash
covenant github validate-token \
  --scope-file scope.txt \
  --enumerate-orgs \
  --token-env COVENANT_TOKEN
```

Example output:

```json
{
  "scopes": ["repo", "read:org"],
  "user": "spellcaster",
  "admin": false,
  "token_type": "github-pat-classic",
  "token_note": "...",
  "token_type_confidence": "high",
  "orgs": [
    { "name": "acme-corp", "url": "https://api.github.com/orgs/acme-corp" },
    { "name": "wizards-inc", "url": "https://api.github.com/orgs/wizards-inc" }
  ]
}
```

### SSH/GPG key enumeration (`--enumerate-keys`)

Organizational reach tells you *where* a credential can act; its registered keys
tell you *how it can persist and impersonate*. Pass `--enumerate-keys` to
`validate-token` and covenant additionally walks the account's **public** SSH
and GPG keys with **read-only** key queries and adds a `keys` array to the
output:

| SCM       | Endpoints walked                                            | Key types |
|-----------|-------------------------------------------------------------|-----------|
| GitHub    | `GET /user/keys`, `GET /user/gpg_keys`                      | SSH + GPG |
| GitLab    | `GET /api/v4/user/keys`, `GET /api/v4/user/gpg_keys`        | SSH + GPG |
| Bitbucket | `GET /2.0/users/{uuid}/ssh-keys`                            | SSH only  |

Why this matters for recon: an account's registered **SSH keys** reveal which
machines can push as that identity (a persistence foothold), and its **GPG keys**
reveal which keys can produce "Verified"-badged commits in its name (a supply-chain
/ trust signal). Bitbucket Cloud has no public GPG-key API, so only SSH keys are
returned there.

Each entry is normalized to `{"type", "id", "title", "fingerprint"}` where
`type` is `"ssh"` or `"gpg"`. **Only public key metadata is emitted** — covenant
never reads or echoes private key material, and the full public-key/armor body is
deliberately reduced to a bounded single-line fingerprint to keep findings compact
and share-safe. The walk is bounded by the same `--max-pages` flag and honors the
scope guardrail and the automatic rate-limit retry/backoff. Like `--enumerate-orgs`
the feature is purely additive (the two flags may be combined): without the flag
the output is unchanged, and with it the v0.1 `scopes`/`user`/`admin` fields are
untouched — only the `keys` array is added.

```bash
covenant github validate-token \
  --scope-file scope.txt \
  --enumerate-keys \
  --token-env COVENANT_TOKEN
```

Example output (combined with `--enumerate-orgs`):

```json
{
  "scopes": ["repo", "read:org"],
  "user": "spellcaster",
  "admin": false,
  "token_type": "github-pat-classic",
  "token_note": "...",
  "token_type_confidence": "high",
  "orgs": [
    { "name": "acme-corp", "url": "https://api.github.com/orgs/acme-corp" }
  ],
  "keys": [
    { "type": "ssh", "id": 1, "title": "laptop", "fingerprint": "ssh-ed25519 AAAA... laptop" },
    { "type": "gpg", "id": "ABCDEF0123456789", "title": "release-signing", "fingerprint": "ABCDEF0123456789" }
  ]
}
```

### Gist/snippet enumeration (`--enumerate-gists`)

Where keys tell you *how a credential can persist*, gists and snippets tell you
*what it has already leaked*. Pass `--enumerate-gists` to `validate-token` and
covenant additionally walks the gists (GitHub) / snippets (GitLab, Bitbucket)
**owned** by the account with a **read-only** query and adds a `gists` array to
the output:

| SCM       | Endpoint walked         | Unit     |
|-----------|-------------------------|----------|
| GitHub    | `GET /gists`            | gist     |
| GitLab    | `GET /api/v4/snippets`  | snippet  |
| Bitbucket | `GET /2.0/snippets`     | snippet  |

Why this matters for recon: gists and snippets are a notorious leaked-credential
vector — developers paste `.env` excerpts, config files and ad-hoc deploy scripts
into "secret" gists that are in fact readable by anyone who has the URL. Mapping
which gists an identity owns, and especially their **filenames**, is a high-signal
recon move: a gist named `credentials.json` or `.env` is itself a finding before
you ever read a byte of its content.

Each entry is normalized to `{"id", "description", "visibility", "url", "files"}`
where `files` is the list of **filenames** in the gist/snippet. **Only filenames
are emitted — covenant never reads or echoes the file CONTENT.** It maps the
attack surface; it does not exfiltrate it. GitHub's "secret" gists are reported
with `visibility: "secret"` (an honest label: a "secret" gist is unlisted, not
private). The walk is bounded by the same `--max-pages` flag and honors the scope
guardrail and the automatic rate-limit retry/backoff. Like the other `--enumerate-*`
flags the feature is purely additive (all three may be combined): without the flag
the output is unchanged, and with it the v0.1 `scopes`/`user`/`admin` fields are
untouched — only the `gists` array is added.

```bash
covenant github validate-token \
  --scope-file scope.txt \
  --enumerate-gists \
  --token-env COVENANT_TOKEN
```

Example `gists` array:

```json
{
  "gists": [
    { "id": "gist1", "description": "deploy helper", "visibility": "public", "url": "https://gist.github.com/spellcaster/gist1", "files": ["deploy.sh"] },
    { "id": "gist2", "description": "scratch env", "visibility": "secret", "url": "https://gist.github.com/spellcaster/gist2", "files": [".env", "notes.md"] }
  ]
}
```

### Webhook enumeration (`--enumerate-webhooks`)

Where keys tell you *how a credential persists* and gists tell you *what it has
leaked*, webhooks tell you *where its events flow* — and that is both an
**exfiltration** channel and an **SSRF** primitive. Pass `--enumerate-webhooks`
to `validate-token` and covenant walks the organizations/groups/workspaces the
token can reach (the same set surfaced by `--enumerate-orgs`) and, for each,
lists its webhooks with a **read-only** query, adding a `webhooks` array:

| SCM       | Endpoint walked                       | Scope       |
|-----------|---------------------------------------|-------------|
| GitHub    | `GET /orgs/{org}/hooks`               | `org`       |
| GitLab    | `GET /api/v4/groups/{id}/hooks`       | `group`     |
| Bitbucket | `GET /2.0/workspaces/{slug}/hooks`    | `workspace` |

Why this matters for recon: an org/group/workspace webhook POSTs every matching
event — pushes, pull/merge requests, membership changes — to a configured URL.
That URL is a **data-exfiltration** destination (the payloads carry repo content
and metadata) and, when it points at internal infrastructure, an **SSRF**
target. A captured token that can read or edit these hooks can quietly redirect
or clone the event stream, so the destination URL is exactly the blast-radius
signal an operator needs.

Each entry is normalized to `{"scope", "owner", "id", "url", "events",
"active"}`, where `url` is the hook's destination and `events` is the normalized
list of subscribed event types (GitLab's per-event boolean flags are collapsed
into this list). **The hook SECRET is never requested or echoed** — covenant
surfaces the destination, not the signing key. The walk is bounded by the same
`--max-pages` flag and honors the scope guardrail and the automatic rate-limit
retry/backoff. Like the other `--enumerate-*` flags the feature is purely
additive (all four may be combined): without the flag the output is unchanged,
and with it the v0.1 `scopes`/`user`/`admin` fields are untouched — only the
`webhooks` array is added.

```bash
covenant github validate-token \
  --scope-file scope.txt \
  --enumerate-webhooks \
  --token-env COVENANT_TOKEN
```

Example `webhooks` array:

```json
{
  "webhooks": [
    { "scope": "org", "owner": "acme-corp", "id": 100, "url": "https://hooks.example.com/acme-corp", "events": ["push", "pull_request"], "active": true }
  ]
}
```

### Deploy-key enumeration (`--enumerate-deploy-keys`)

Where `--enumerate-keys` covers the keys on the *account*, `--enumerate-deploy-keys`
covers the keys bolted onto individual *repositories*. A **deploy key** is an SSH
key scoped to a single repo, often with **write** access, that grants Git access
independent of any human credential — it survives a password reset or an
off-boarding, which makes a writable one a classic **persistence** and
**supply-chain** foothold (an attacker pushes to the repo *as the repo*). Pass
`--enumerate-deploy-keys` to `validate-token` and covenant walks the repositories
the token can reach and, for each, lists its deploy keys with a **read-only**
query, adding a `deploy_keys` array:

| SCM       | Repos walked                          | Keys endpoint                                  |
|-----------|---------------------------------------|------------------------------------------------|
| GitHub    | `GET /user/repos`                     | `GET /repos/{owner}/{repo}/keys`               |
| GitLab    | `GET /api/v4/projects?membership=true`| `GET /api/v4/projects/{id}/deploy_keys`        |
| Bitbucket | `GET /2.0/repositories?role=member`   | `GET /2.0/repositories/{full_name}/deploy-keys`|

Each entry is normalized to `{"repo", "id", "title", "read_only", "fingerprint"}`.
`read_only` is the decisive blast-radius signal — `false` means the key can
**push**. GitHub returns it directly; GitLab's `can_push` is inverted into it
(`read_only == not can_push`); Bitbucket Cloud access keys are read-only by
design, so `read_only` is always `true` there and the signal is the key's
existence and reach rather than a push flag. **Only PUBLIC key metadata is
shown** — covenant never reads private key material (the APIs do not expose it).
The walk is bounded by the same `--max-pages` flag and honors the scope guardrail
and the automatic rate-limit retry/backoff. Like the other `--enumerate-*` flags
the feature is purely additive (all may be combined): without the flag the output
is unchanged, and with it the v0.1 `scopes`/`user`/`admin` fields are untouched —
only the `deploy_keys` array is added.

```bash
covenant github validate-token \
  --scope-file scope.txt \
  --enumerate-deploy-keys \
  --token-env COVENANT_TOKEN
```

Example `deploy_keys` array:

```json
{
  "deploy_keys": [
    { "repo": "acme-corp/spellbook", "id": 300, "title": "ci-deploy", "read_only": false, "fingerprint": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA deploy" }
  ]
}
```

### Branch-protection audit (`--audit-branch-protection`)

Every other `validate-token` flag maps a captured token's **offensive** reach —
the keys it owns, the repos it can push to, the webhooks it can redirect.
`--audit-branch-protection` is the **defensive** counterpart: it reports whether
that reach would actually *land*. A writable deploy key or a permissive PAT is
only a supply-chain win if the target's protected branches let an unreviewed,
unsigned, or admin-bypassing push through. Pass `--audit-branch-protection` to
`validate-token` and covenant walks the repositories the token can reach and, for
each, audits its protected branches with a **read-only** query, adding a
`branch_protection` array:

| SCM       | Repos walked                          | Protection endpoint                                       |
|-----------|---------------------------------------|----------------------------------------------------------|
| GitHub    | `GET /user/repos`                     | `GET /repos/{owner}/{repo}/branches?protected=true` + `.../branches/{branch}/protection` |
| GitLab    | `GET /api/v4/projects?membership=true`| `GET /api/v4/projects/{id}/protected_branches` (+ `/approvals`, `/push_rule`) |
| Bitbucket | `GET /2.0/repositories?role=member`   | `GET /2.0/repositories/{full_name}/branch-restrictions`  |

Each entry is normalized to `{"repo", "branch", "required_reviews",
"required_review_count", "dismiss_stale_reviews", "require_signed_commits",
"enforce_admins"}`. **`required_reviews=false` (or a zero `required_review_count`)
on a reachable repo is the high-signal finding** — an attacker who can push can do
so unreviewed. The providers model protection differently, so the fields are
mapped to the nearest equivalent signal:

- **GitHub** maps directly: `required_pull_request_reviews`,
  `required_signatures.enabled`, and `enforce_admins.enabled`.
- **GitLab** keeps review/sign policy at the *project* level — `required_reviews`
  and `required_review_count` come from `approvals_before_merge`,
  `dismiss_stale_reviews` from `reset_approvals_on_push`, `require_signed_commits`
  from the `reject_unsigned_commits` push rule, and `enforce_admins` from the
  protected branch *disallowing* force push. Endpoints a low-privilege token can't
  read fail soft to the safe defaults so the audit still lists the branches it can
  see.
- **Bitbucket Cloud** models protection as a flat list of *restrictions* keyed by
  branch pattern; covenant aggregates them per pattern. `require_approvals_to_merge`
  drives the review fields, `reset_pullrequest_approvals_on_change` drives
  `dismiss_stale_reviews`, and a `force` restriction drives `enforce_admins`.
  Bitbucket Cloud has no signed-commit restriction, so `require_signed_commits` is
  always `false` there. The `branch` field carries the restriction *pattern*,
  which may be a glob (e.g. `release/*`).

The audit is **read-only** — it only GETs policy metadata and never alters
protection. The walk is bounded by the same `--max-pages` flag and honors the
scope guardrail and the automatic rate-limit retry/backoff. Like the
`--enumerate-*` flags the feature is purely additive (all may be combined):
without the flag the output is unchanged, and with it the v0.1
`scopes`/`user`/`admin` fields are untouched — only the `branch_protection` array
is added.

```bash
covenant github validate-token \
  --scope-file scope.txt \
  --audit-branch-protection \
  --token-env COVENANT_TOKEN
```

Example `branch_protection` array (a weak and a strong branch):

```json
{
  "branch_protection": [
    { "repo": "acme-corp/spellbook", "branch": "main", "required_reviews": false, "required_review_count": 0, "dismiss_stale_reviews": false, "require_signed_commits": false, "enforce_admins": false },
    { "repo": "acme-corp/grimoire", "branch": "main", "required_reviews": true, "required_review_count": 2, "dismiss_stale_reviews": true, "require_signed_commits": true, "enforce_admins": true }
  ]
}
```

### CI/CD secret enumeration (`--enumerate-actions-secrets`)

Where `--enumerate-deploy-keys` maps the *keys* a token can reach and
`--enumerate-webhooks` maps the exfiltration surface, **CI/CD secrets are the
credential surface that powers the build pipeline**: cloud keys, registry
passwords, signing tokens and deploy credentials all live here. An attacker who
can read or — via a malicious workflow — exfiltrate them inherits exactly the
lateral-movement and supply-chain reach the pipeline had, so a repo or org
carrying a long list of secrets is a high-value, high-blast-radius target. Pass
`--enumerate-actions-secrets` to `validate-token` and covenant walks both the
org/group/workspace axis and the repo/project axis the token can reach with a
**read-only** query, adding an `actions_secrets` array:

| SCM       | Org-level (scope `org`)                                    | Repo-level (scope `repo`)                                          |
|-----------|------------------------------------------------------------|--------------------------------------------------------------------|
| GitHub    | `GET /orgs/{org}/actions/secrets`                          | `GET /repos/{owner}/{repo}/actions/secrets`                        |
| GitLab    | `GET /api/v4/groups/{id}/variables`                        | `GET /api/v4/projects/{id}/variables`                              |
| Bitbucket | `GET /2.0/workspaces/{slug}/pipelines-config/variables`    | `GET /2.0/repositories/{full_name}/pipelines-config/variables`     |

Each entry is normalized to `{"scope", "owner", "name", "protected"}`.

> **Only the secret NAME and metadata are surfaced — the secret VALUE is never
> read or echoed.** The provider APIs deliberately omit the values of secured
> secrets, and covenant emits names only. The NAME is the excessive-exposure
> signal (e.g. an `AWS_*` or `NPM_TOKEN` name tells you the blast radius without
> ever touching the credential).

The `protected` field flags a tighter blast radius: for **GitHub** it is `true`
when an org secret's `visibility` is restricted to selected repositories; for
**GitLab** it maps the variable's `protected` flag; for **Bitbucket** it maps the
variable's `secured` flag. Endpoints a low-privilege token can't read (CI/CD
variables typically require Maintainer/admin) fail soft to an empty result so the
audit still reports what it can see. The walk is bounded by the same `--max-pages`
flag and honors the scope guardrail and automatic rate-limit retry/backoff. Like
the other `--enumerate-*` flags the feature is purely additive (all may be
combined): without the flag the output is unchanged, and with it the v0.1
`scopes`/`user`/`admin` fields are untouched — only the `actions_secrets` array is
added.

```bash
covenant github validate-token \
  --scope-file scope.txt \
  --enumerate-actions-secrets \
  --token-env COVENANT_TOKEN
```

Example `actions_secrets` array (org-wide and repo-scoped secrets, names only):

```json
{
  "actions_secrets": [
    { "scope": "org",  "owner": "acme-corp",          "name": "ORG_AWS_KEY",   "protected": false },
    { "scope": "org",  "owner": "acme-corp",          "name": "ORG_NPM_TOKEN", "protected": true  },
    { "scope": "repo", "owner": "acme-corp/spellbook", "name": "DEPLOY_TOKEN",  "protected": false }
  ]
}
```

### Repository-visibility audit (`--audit-repo-visibility`)

Where the `--enumerate-*` flags map a captured token's *offensive* reach (the
keys it owns, the repos it can push to, the CI/CD secrets it can read),
`--audit-repo-visibility` reports the *exposure* posture: **which reachable repos
are public**. A public repo is the org's external attack surface — its full
source, history, issues and any leaked secrets are world-readable — and is
exactly where covenant's own `recon-code` secret scanning has the most to find.
An unexpectedly public repo sitting alongside private siblings is a direct
leak/supply-chain risk worth triaging first. Pass `--audit-repo-visibility` to
`validate-token` and covenant walks the repos the token can reach with a
**read-only** query, adding a `repo_visibility` array:

| SCM       | Endpoint                                  | `public` derived from                                    |
|-----------|-------------------------------------------|----------------------------------------------------------|
| GitHub    | `GET /user/repos`                         | the boolean `private` flag                               |
| GitLab    | `GET /api/v4/projects?membership=true`    | the `visibility` string (`public`/`internal`/`private`)  |
| Bitbucket | `GET /2.0/repositories?role=member`       | the boolean `is_private` flag                            |

Each entry is normalized to `{"repo", "visibility", "public"}`.

> **GitLab `internal` projects are flagged `public: true`.** An `internal`
> project is readable by *any authenticated user of the instance* — a
> broader-than-it-looks exposure on a shared or self-managed GitLab — so the
> audit treats anything other than `private` as exposure rather than hiding it.

Only repo metadata (name + visibility) is read — no code, no secrets. The walk is
bounded by the same `--max-pages` flag and honors the scope guardrail and
automatic rate-limit retry/backoff. Like the other `--enumerate-*`/`--audit-*`
flags the feature is purely additive (all may be combined): without the flag the
output is unchanged, and with it the v0.1 `scopes`/`user`/`admin` fields are
untouched — only the `repo_visibility` array is added.

```bash
covenant github validate-token \
  --scope-file scope.txt \
  --audit-repo-visibility \
  --token-env COVENANT_TOKEN
```

Example `repo_visibility` array (a public repo flagged among private siblings):

```json
{
  "repo_visibility": [
    { "repo": "acme-corp/spellbook", "visibility": "private", "public": false },
    { "repo": "acme-corp/grimoire",  "visibility": "public",  "public": true  }
  ]
}
```

### CODEOWNERS-coverage audit (`--audit-codeowners`)

A **CODEOWNERS** file is the control that routes *mandatory* review to a named
owner per path: GitHub's "Require review from Code Owners", GitLab's code-owner
approval, and Bitbucket's "Code owners approval" merge check all read it. That
makes it the **partner control to branch protection** — a protected branch's
require-code-owner-review gate only bites for paths a CODEOWNERS rule matches, so
auditing branch protection without auditing CODEOWNERS leaves a blind spot:

- A reachable repo with **no CODEOWNERS file** (`present: false`) cannot gate
  review by owner *at all*, however strict its branch protection looks.
- A repo whose CODEOWNERS has rules but **no catch-all `*`**
  (`has_global_owner: false`) leaves every path matched by no rule — including a
  file an attacker newly adds in a PR — with no required owner. This is the
  silent owner-coverage gap that `--audit-branch-protection` alone does not
  reveal.

Pass `--audit-codeowners` to `validate-token` and covenant walks the repos the
token can reach, probing the standard CODEOWNERS locations (in precedence order:
the provider directory, then the repo root, then `docs/`) with a **read-only**
file fetch and reporting the first one found:

| SCM       | Endpoint                                                        | Locations probed                                      |
|-----------|----------------------------------------------------------------|-------------------------------------------------------|
| GitHub    | `GET /repos/{owner}/{repo}/contents/{path}`                    | `.github/CODEOWNERS`, `CODEOWNERS`, `docs/CODEOWNERS` |
| GitLab    | `GET /api/v4/projects/{id}/repository/files/{path}?ref={branch}` | `.gitlab/CODEOWNERS`, `CODEOWNERS`, `docs/CODEOWNERS` |
| Bitbucket | `GET /2.0/repositories/{full_name}/src/HEAD/{path}`            | `CODEOWNERS`, `docs/CODEOWNERS`                        |

Each entry is normalized to
`{"repo", "present", "path", "rule_count", "has_global_owner"}`.

> **Only the posture is surfaced — never the owners.** The owner account/team
> handles inside CODEOWNERS are *not* echoed (they are not the audit's signal),
> and no other repository content is read. covenant reports only how many
> ownership rules exist and whether a catch-all `*` rule covers otherwise-
> unmatched paths.

The walk is bounded by the same `--max-pages` flag and honors the scope guardrail
and automatic rate-limit retry/backoff. Like the other `--enumerate-*`/`--audit-*`
flags the feature is purely additive (all may be combined): without the flag the
output is unchanged, and with it the v0.1 `scopes`/`user`/`admin` fields are
untouched — only the `codeowners` array is added. It is **read-only** and never
edits CODEOWNERS or any review setting.

```bash
covenant github validate-token \
  --scope-file scope.txt \
  --audit-codeowners \
  --token-env COVENANT_TOKEN
```

Example `codeowners` array (a partial-coverage repo flagged alongside a covered
one):

```json
{
  "codeowners": [
    { "repo": "acme-corp/spellbook", "present": true, "path": ".github/CODEOWNERS", "rule_count": 2, "has_global_owner": false },
    { "repo": "acme-corp/grimoire",  "present": true, "path": "CODEOWNERS",         "rule_count": 2, "has_global_owner": true  }
  ]
}
```

### Dependency-vulnerability audit (`--audit-dependabot-alerts`)

Where `--audit-branch-protection` and `--audit-codeowners` report **process**
gaps (would a bad push be stopped before it lands?), this reports a
**known-vulnerability attack surface**: every open alert is a publicly-documented
CVE/GHSA in a dependency the repo *actually ships*, with a known severity and
(often) a known exploit. For an authorized engagement this is a high-signal
triage axis — a reachable repo carrying open `critical` alerts is where a real
intrusion is most likely to start, and the alert names the exact package and
advisory so the operator can map it to an exploit without further probing.

Pass `--audit-dependabot-alerts` to `validate-token` and covenant walks the repos
the token can reach, listing each one's **open** dependency alerts with a
**read-only** query:

| SCM       | Endpoint                                                              | Surface mapped                                          |
|-----------|----------------------------------------------------------------------|---------------------------------------------------------|
| GitHub    | `GET /repos/{owner}/{repo}/dependabot/alerts?state=open`             | Dependabot alerts (open)                                |
| GitLab    | `GET /api/v4/projects/{id}/vulnerabilities?state=detected`          | dependency-scanning vulnerabilities (detected)          |
| Bitbucket | *(none — no first-party dependency-alert API)*                       | empty result + an explanatory `warnings` entry          |

Each entry is normalized to
`{"repo", "package", "ecosystem", "severity", "state", "identifier"}`. `severity`
is the advisory's CVSS band (`critical`/`high`/`medium`/`low`, lower-cased for
cross-provider parity) and `identifier` is the GHSA/CVE advisory handle.

> **Only the advisory handle is surfaced — never a credential.** `identifier` is
> a public CVE/GHSA id, not a secret. A repo with the feature disabled or out of
> the token's scope answers `403`/`404`; covenant **skips that repo** rather than
> failing the whole audit, so a partial-permission token still reports every repo
> it can read. **Bitbucket Cloud** has no first-party dependency-alert API (its
> dependency security runs through third-party Pipelines integrations), so the
> result is empty there and a non-fatal `warnings` note explains that the empty
> result reflects a platform limitation, not a clean bill of health.

Only OPEN alerts are requested, and only alert metadata is read — covenant never
dismisses, fixes, or creates an alert. The walk is bounded by the same
`--max-pages` flag and honors the scope guardrail and automatic rate-limit
retry/backoff. Like the other `--enumerate-*`/`--audit-*` flags the feature is
purely additive (all may be combined): without the flag the output is unchanged,
and with it the v0.1 `scopes`/`user`/`admin` fields are untouched — only the
`dependabot_alerts` array is added.

```bash
covenant github validate-token \
  --scope-file scope.txt \
  --audit-dependabot-alerts \
  --token-env COVENANT_TOKEN
```

Example `dependabot_alerts` array (an open critical alert; a repo with the
feature disabled is silently skipped, not listed):

```json
{
  "dependabot_alerts": [
    { "repo": "acme-corp/spellbook", "package": "requests", "ecosystem": "pip", "severity": "critical", "state": "open", "identifier": "GHSA-xxxx-yyyy-zzzz" }
  ]
}
```

### Package-dependency inventory (`--audit-packages`)

Where `--audit-dependabot-alerts` reports the **known-vulnerable** subset a
provider scanner has *already flagged*, this reports the **full declared
dependency surface**: every package a reachable repo's manifest files pull in,
named with its declared version and ecosystem. It is the software-supply-chain
**inventory** an operator needs *before* asking "which of these is vulnerable,
typosquatted, or abandoned?" — the surface a Dependabot audit can only annotate,
not enumerate. And unlike `--audit-dependabot-alerts` (a no-op on Bitbucket
Cloud), this works on **all three SCMs**, because it reads the manifests
directly rather than relying on a first-party alert API.

Pass `--audit-packages` to `validate-token` and covenant walks the repos the
token can reach, probing each one's repository root for the supported manifest
files with a **read-only** file fetch and parsing the declared dependencies:

| SCM       | Endpoint                                                        | Body returned            |
|-----------|-----------------------------------------------------------------|--------------------------|
| GitHub    | `GET /repos/{owner}/{repo}/contents/{manifest}`                 | base64 JSON envelope     |
| GitLab    | `GET /api/v4/projects/{id}/repository/files/{manifest}?ref=…`   | base64 JSON envelope     |
| Bitbucket | `GET /2.0/repositories/{full_name}/src/HEAD/{manifest}`         | raw file text            |

The manifest files probed (and the ecosystem each declares):

| Manifest            | Ecosystem  | Source read                                           |
|---------------------|------------|-------------------------------------------------------|
| `package.json`      | `npm`      | `dependencies` + `devDependencies` + `peerDependencies` + `optionalDependencies` |
| `requirements.txt`  | `pip`      | requirement specifiers (`-r`/`-c`/`--option` directives skipped) |
| `pyproject.toml`    | `pip`      | PEP 621 `[project].dependencies` + Poetry `[tool.poetry.dependencies]` |
| `Pipfile`           | `pip`      | `[packages]` + `[dev-packages]`                       |
| `go.mod`            | `go`       | `require` directives (single-line and block form)     |
| `Gemfile`           | `rubygems` | `gem "name", "constraint"` declarations               |
| `pom.xml`           | `maven`    | each `<dependency>` block as `groupId:artifactId`     |

Each declared package is normalized to
`{"repo", "manifest", "ecosystem", "package", "version"}`. `version` is the spec
the manifest **declares** (`^1.2.3`, `==1.0`, `v1.4.0`, …) and is `null` when no
version is pinned for that package.

> **covenant inventories the declaration — it never resolves or installs it.**
> The `version` is exactly what the manifest says, not a resolved lockfile pin.
> Only the named manifest files are read (never lockfile graphs, never source),
> and only package names + declared versions are surfaced — never any credential
> a manifest might inadvisedly contain. A repo with no recognized manifest
> contributes no rows; a malformed manifest contributes no rows for that file
> rather than aborting the audit.

The walk is bounded by the same `--max-pages` flag and honors the scope
guardrail and automatic rate-limit retry/backoff. Like the other
`--enumerate-*`/`--audit-*` flags the feature is purely additive (all may be
combined): without the flag the output is unchanged, and with it the v0.1
`scopes`/`user`/`admin` fields are untouched — only the `packages` array is
added.

```bash
covenant github validate-token \
  --scope-file scope.txt \
  --audit-packages \
  --token-env COVENANT_TOKEN
```

Example `packages` array (npm + pip dependencies declared by one repo):

```json
{
  "packages": [
    { "repo": "acme-corp/spellbook", "manifest": "package.json", "ecosystem": "npm", "package": "left-pad", "version": "^1.3.0" },
    { "repo": "acme-corp/spellbook", "manifest": "requirements.txt", "ecosystem": "pip", "package": "requests", "version": "2.31.0" }
  ]
}
```

### Code-scanning-alert audit (`--audit-code-scanning-alerts`)

Where `--audit-dependabot-alerts` reports a known-vulnerability surface in a
repo's **third-party dependencies**, `--audit-code-scanning-alerts` reports the
static-analyzer findings in the repo's **own first-party source** — an injection
sink, a crypto misuse, a path-traversal, a deserialization flaw. These are bugs
in code the org itself controls, named by **rule** and **source location**, so a
finding maps straight to where a real exploit is likely to live. It is the
code-flaw triage axis the dependency and credential audits do not cover.

Pass `--audit-code-scanning-alerts` to `validate-token` and covenant walks the
repos the token can reach, listing each one's **open** code-scanning alerts with
a **read-only** query:

| SCM       | Endpoint                                                                                 | Surface read                       |
|-----------|------------------------------------------------------------------------------------------|------------------------------------|
| GitHub    | `GET /repos/{owner}/{repo}/code-scanning/alerts?state=open`                              | code-scanning / CodeQL alerts      |
| GitLab    | `GET /api/v4/projects/{id}/vulnerabilities?report_type=sast&state=detected`              | SAST findings (Vulnerability Report) |
| Bitbucket | *(unsupported — no first-party static-analysis-alert API; empty result + warning)*       | —                                  |

Each alert is normalized to
`{"repo", "rule_id", "rule_name", "severity", "state", "html_url"}`. `rule_id` is
the analyzer's rule identifier (e.g. `py/sql-injection`), `rule_name` its human
description, and `severity` prefers the security-severity band
(`critical`/`high`/`medium`/`low`), falling back to the alert's generic severity
(`error`/`warning`/`note`) when the band is absent — the decisive triage field.
`html_url` points at the alert in the provider UI, at the finding's source
location — never at a credential.

> **Only open alerts, only metadata.** A dismissed/fixed alert is not live
> surface, so only `state=open`/`detected` is requested. A repo with the feature
> disabled, **never analyzed**, or out of the token's scope answers HTTP 403/404
> for that repo; covenant **skips it** rather than failing the whole audit, so a
> partial-permission token still reports every repo it can read. The audit is
> read-only — it only GETs alert metadata and never dismisses, fixes, or creates
> an alert. Bitbucket Cloud has no first-party static-analysis-alert API (it is
> delivered through third-party Pipelines integrations), so the result is empty
> there with an explanatory warning rather than a misleading clean bill of health.

The walk is bounded by the same `--max-pages` flag and honors the scope guardrail
and automatic rate-limit retry/backoff. Like the other `--enumerate-*`/`--audit-*`
flags the feature is purely additive (all may be combined): without the flag the
output is unchanged, and with it the v0.1 `scopes`/`user`/`admin` fields are
untouched — only the `code_scanning_alerts` array is added.

```bash
covenant github validate-token \
  --scope-file scope.txt \
  --audit-code-scanning-alerts \
  --token-env COVENANT_TOKEN
```

Example `code_scanning_alerts` array (one open critical CodeQL finding):

```json
{
  "code_scanning_alerts": [
    {
      "repo": "acme-corp/spellbook",
      "rule_id": "py/sql-injection",
      "rule_name": "SQL query built from user-controlled sources",
      "severity": "critical",
      "state": "open",
      "html_url": "https://github.com/acme-corp/spellbook/security/code-scanning/42"
    }
  ]
}
```

### Repository-advisory audit (`--audit-advisory-alerts`)

This is the **publisher-side** counterpart to the two consumer-side flags above.
Where `--audit-dependabot-alerts` reports a repo **consuming** the global advisory
database (a known CVE in one of its third-party **dependencies**) and
`--audit-code-scanning-alerts` reports static-analyzer findings in the repo's
**own source**, `--audit-advisory-alerts` reports the repo as a **publisher** of
advisories — the **published** repository security advisories the org's own
maintainers wrote up against their **own product**. Each is a GHSA the org
authored itself, naming a real (often already-patched) vulnerability in code the
org **ships to others**; on an unpatched or partially-deployed fleet the GHSA/CVE
handle and summary point straight at where a working exploit still lives. It is
the triage axis the dependency and code-flaw audits do not cover.

Pass `--audit-advisory-alerts` to `validate-token` and covenant walks the repos
the token can reach, listing each one's **published** advisories with a
**read-only** query:

| SCM       | Endpoint                                                          | Surface read                          |
|-----------|-------------------------------------------------------------------|---------------------------------------|
| GitHub    | `GET /repos/{owner}/{repo}/security-advisories?state=published`   | maintainer-authored repo advisories   |
| GitLab    | *(unsupported — advisory data is an instance-wide third-party feed; empty result + warning)* | — |
| Bitbucket | *(unsupported — no maintainer-authored repository advisory API; empty result + warning)*     | — |

Each advisory is normalized to
`{"repo", "ghsa_id", "cve_id", "summary", "severity", "state", "html_url"}`.
`ghsa_id` is the advisory handle and `cve_id` its CVE mapping when assigned (both
advisory identifiers, never a credential), `severity` the advisory's CVSS band
(`critical`/`high`/`medium`/`low`), and `summary` the maintainer's one-line
description. `html_url` points at the advisory in the provider UI.

> **Only published advisories, only metadata.** A draft advisory is not yet a
> confirmed, public finding, so only `state=published` is requested. A repo with
> no advisories, the feature unavailable, or out of the token's scope answers
> HTTP 403/404 for that repo; covenant **skips it** rather than failing the whole
> audit, so a partial-permission token still reports every repo it can read. The
> audit is read-only — it only GETs advisory metadata and never creates, edits,
> or publishes an advisory. GitLab and Bitbucket Cloud have no per-repo
> maintainer-authored advisory surface, so the result is empty there with an
> explanatory warning rather than a misleading clean bill of health.

The walk is bounded by the same `--max-pages` flag and honors the scope guardrail
and automatic rate-limit retry/backoff. Like the other `--enumerate-*`/`--audit-*`
flags the feature is purely additive (all may be combined): without the flag the
output is unchanged, and with it the v0.1 `scopes`/`user`/`admin` fields are
untouched — only the `advisory_alerts` array is added.

```bash
covenant github validate-token \
  --scope-file scope.txt \
  --audit-advisory-alerts \
  --token-env COVENANT_TOKEN
```

Example `advisory_alerts` array (one published critical advisory):

```json
{
  "advisory_alerts": [
    {
      "repo": "acme-corp/spellbook",
      "ghsa_id": "GHSA-spel-lboo-k123",
      "cve_id": "CVE-2024-13337",
      "summary": "Authentication bypass in spellbook session handling",
      "severity": "critical",
      "state": "published",
      "html_url": "https://github.com/acme-corp/spellbook/security/advisories/GHSA-spel-lboo-k123"
    }
  ]
}
```

### Actions-permission audit (`--audit-actions-permissions`)

Where `--audit-actions-environments` gates which **deployments** may reach an
environment's secrets, `--audit-actions-permissions` audits what a workflow run
may **do once it executes**: whether Actions is enabled on the repo, the
`allowed_actions` policy, and — the decisive supply-chain field — the **default
permissions of the automatic `GITHUB_TOKEN`** granted to every run. It is the
execution-side counterpart to `--audit-branch-protection`: branch protection
gates code *landing*, this gates what automation may *do* once it runs.

The high-signal finding is a repo where `default_workflow_permissions` is
`write`: every workflow on that repo — including one introduced by a malicious
pull request, if the repo runs untrusted PR workflows — starts with a read/write
token over the repo's contents, releases and packages, a far wider blast radius
than the locked-down `read` default. A second amplifier is
`can_approve_pull_request_reviews=true`, which lets a workflow self-approve PRs
and so satisfy a branch-protection review gate **without a human**.

Pass `--audit-actions-permissions` to `validate-token` and covenant walks the
repos the token can reach, reading each one's Actions-permission posture with a
**read-only** query:

| SCM       | Endpoint                                                                                              | Surface read                          |
|-----------|-------------------------------------------------------------------------------------------------------|---------------------------------------|
| GitHub    | `GET /repos/{owner}/{repo}/actions/permissions` + `.../actions/permissions/workflow`                 | Actions on/off + workflow-token policy |
| GitLab    | *(unsupported — no single per-project Actions-permission API; empty result + warning)*               | —                                     |
| Bitbucket | *(unsupported — no per-repo Pipelines-permission API; empty result + warning)*                       | —                                     |

Each repo is normalized to
`{"repo", "actions_enabled", "allowed_actions", "default_workflow_permissions", "can_approve_pull_request_reviews"}`.
`allowed_actions` is the invocation policy (`all`/`local_only`/`selected`),
`default_workflow_permissions` is `read` or `write` (the decisive field), and
`can_approve_pull_request_reviews` is the PR self-approval flag.

> **Disabled repos and metadata only.** When Actions is **disabled** on a repo
> there is no workflow-token policy to read, so `default_workflow_permissions` is
> `null` and `can_approve_pull_request_reviews` is `false` (a disabled repo has
> no execution surface). A repo the token cannot **administer** answers HTTP
> 403/404; covenant **skips it** rather than failing the whole audit, so a
> partial-permission token still reports every repo it can read. The audit is
> read-only — it only GETs policy metadata and never enables, disables, or
> rewrites a permission. GitLab and Bitbucket Cloud have no single per-repo
> Actions-permission API, so the result is empty there with an explanatory
> warning rather than a misleading clean bill of health.

The walk is bounded by the same `--max-pages` flag and honors the scope guardrail
and automatic rate-limit retry/backoff. Like the other `--enumerate-*`/`--audit-*`
flags the feature is purely additive (all may be combined): without the flag the
output is unchanged, and with it the v0.1 `scopes`/`user`/`admin` fields are
untouched — only the `actions_permissions` array is added.

```bash
covenant github validate-token \
  --scope-file scope.txt \
  --audit-actions-permissions \
  --token-env COVENANT_TOKEN
```

Example `actions_permissions` array (a write-token repo and a disabled repo):

```json
{
  "actions_permissions": [
    {
      "repo": "acme-corp/spellbook",
      "actions_enabled": true,
      "allowed_actions": "all",
      "default_workflow_permissions": "write",
      "can_approve_pull_request_reviews": true
    },
    {
      "repo": "acme-corp/grimoire",
      "actions_enabled": false,
      "allowed_actions": null,
      "default_workflow_permissions": null,
      "can_approve_pull_request_reviews": false
    }
  ]
}
```

### Workflow-run activity audit (`--audit-workflow-runs`)

Where `--audit-actions-permissions` and `--audit-actions-environments` report
the **policy** posture a workflow run inherits (what it is *allowed* to do),
`--audit-workflow-runs` surfaces observed **activity** (what the pipeline
actually ran), so an operator can spot anomalous CI patterns before they
escalate. The decisive high-signal findings:

* a streak of `conclusion="failure"` runs (active attack attempts, broken CI
  gates, or a runner under load);
* a `conclusion="cancelled"` / `"STOPPED"` run (operator or defender
  intervention killing a job in flight); and
* an unexpected `event` (trigger) distribution — a sudden burst of
  `workflow_dispatch` / `MANUAL` (manual-trigger abuse) or off-hours
  `schedule` / `SCHEDULE` runs (a planted cron pipeline) is a CI-misuse signal
  a posture audit alone does not catch.

Pass `--audit-workflow-runs` to `validate-token` and covenant walks the repos
the token can reach and, for each, lists its recent pipeline runs — GitHub
`GET /repos/{owner}/{repo}/actions/runs`, GitLab
`GET /api/v4/projects/{id}/pipelines`, Bitbucket
`GET /2.0/repositories/{full_name}/pipelines/`. Each run is normalized to:

```json
{
  "repo": "acme-corp/spellbook",
  "run_id": 900,
  "name": "CI",
  "event": "push",
  "status": "completed",
  "conclusion": "failure",
  "created_at": "2026-05-28T10:00:00Z"
}
```

`name` is the workflow's human-readable name (GitHub) or the branch/ref the
pipeline ran on (GitLab/Bitbucket); `event` is the trigger
(`push`/`pull_request`/`workflow_dispatch`/`schedule`/...); `status` is the
lifecycle state and `conclusion` is the terminal outcome (`None` while the
run is still in progress). A repo with Actions/Pipelines disabled or out of
the token's scope answers 403/404 and is **skipped** (not fatal). Only run
**metadata** is surfaced — logs, artifact URLs, and any CI/CD variable values
the run saw are **never** fetched. Read-only; never re-runs, cancels, or
dispatches a workflow.

### Branch-ruleset posture audit (`--audit-branch-ruleset`)

Where `--audit-branch-protection` walks each protected branch's **classic**
settings, `--audit-branch-ruleset` surfaces the **newer named-rule-collection**
model the two coexist with — GitHub branch rulesets (2023+) and GitLab push
rules. A posture audit that only checks classic branch protection misses a
ruleset-only configuration; this audit complements the existing one so the
operator sees both rule models side by side. The decisive high-signal findings:

* `enforcement="disabled"` or `"evaluate"` — a configured ruleset that is not
  actively blocking is a paper tiger;
* `bypass_actor_count > 0` — every bypass actor is somebody who can route
  around the rule (a long list widens the bypass set); and
* the `rule_types` list missing core gates (`pull_request` for required
  review, `required_signatures` for signed commits,
  `non_fast_forward`/`deletion` for anti-force-push) — a ruleset named "main
  protection" whose rules don't include `pull_request` does not in fact
  require review.

Pass `--audit-branch-ruleset` to `validate-token` and covenant walks the repos
the token can reach and, for each, lists its rulesets — GitHub
`GET /repos/{owner}/{repo}/rulesets` (plus
`GET /repos/{owner}/{repo}/rulesets/{id}` for the rule and bypass-actor
detail), GitLab `GET /api/v4/projects/{id}/push_rule` (the per-project
push-rule object, the closest analogue). Each ruleset is normalized to:

```json
{
  "repo": "acme-corp/spellbook",
  "ruleset_id": 600,
  "name": "main-protection",
  "enforcement": "active",
  "target": "branch",
  "rule_types": ["deletion", "non_fast_forward", "pull_request", "required_signatures"],
  "bypass_actor_count": 0
}
```

`rule_types` is the sorted, de-duplicated list of rule-type strings (GitHub's
`pull_request` / `required_signatures` / `non_fast_forward` / `deletion` /
`creation` / ...; GitLab's `commit_message_regex` / `branch_name_regex` /
`prevent_secrets` / `reject_unsigned_commits` / `member_check` / ...) — the
**shape** of the rule set, not the parameter values inside any one rule.

Only ruleset **posture** is surfaced: bypass-actor **identities** are
deliberately never echoed (only the count is the high-signal blast-radius
value; a long list of names would be noise), no rule parameter values (regex
patterns, exact reviewer counts, named required status checks) are surfaced
beyond their presence in `rule_types`, and no repository content is read. A
repo whose rulesets endpoint answers 403/404 (rulesets unavailable on the
plan, or token lacks the admin scope) is **skipped** — the audit returns the
rulesets from the repos it CAN read rather than aborting on the first 404.
Bitbucket Cloud has no named-ruleset API (its policy lives in
branch-restrictions, already covered by `--audit-branch-protection`); the
result is empty there with an explanatory `warnings` entry so the empty list
is not misread as a clean bill of health. Read-only — covenant never creates,
edits, or deletes a ruleset.

### Self-hosted runner enumeration (`--enumerate-runners`)

Where `--enumerate-actions-secrets` maps the *credential* surface that powers a
build pipeline, `--enumerate-runners` maps the **execution-host** surface: the
self-hosted machines those pipelines actually run on. Every job dispatched to a
runner executes on the runner's host and sees that run's `GITHUB_TOKEN` (or
GitLab CI job token, or Bitbucket Pipelines variables), the checked-out source,
and the build artifacts. A compromised, planted, or unhardened self-hosted
runner is therefore a **persistence and lateral-movement foothold** — once an
attacker can place a job onto it, every subsequent job is also exposed — and a
runner registered at **org / group / workspace scope** is the broadest, because
any repo in the org can dispatch to it.

Pass `--enumerate-runners` to `validate-token` and covenant walks both axes the
token can reach with a **read-only** query, adding a `runners` array:

| SCM       | Org/group/workspace-level (scope `org`)                          | Repo/project-level (scope `repo`)                                |
|-----------|------------------------------------------------------------------|------------------------------------------------------------------|
| GitHub    | `GET /orgs/{org}/actions/runners`                                | `GET /repos/{owner}/{repo}/actions/runners`                      |
| GitLab    | `GET /api/v4/groups/{id}/runners`                                | `GET /api/v4/projects/{id}/runners`                              |
| Bitbucket | `GET /2.0/workspaces/{slug}/pipelines-config/runners`            | `GET /2.0/repositories/{full_name}/pipelines-config/runners`     |

Each entry is normalized to
`{"scope", "owner", "id", "name", "labels", "self_hosted"}`. `labels` is the
list of label names a workflow may target the runner with (GitHub's
`{id, name, type}` label objects are reduced to bare names; GitLab's `tag_list`
and Bitbucket's flat label list are surfaced verbatim).

> **`self_hosted` is the decisive distinction.** The GitHub Actions and
> Bitbucket Pipelines runner endpoints list **only self-hosted runners by
> design** — platform-managed runners do not appear — so `self_hosted` is
> always `true` on those providers. GitLab lists *every* runner reachable from
> the group/project, **including** the platform-managed shared SaaS runners
> (`is_shared: true`); covenant maps those to `self_hosted: false` so an
> operator can tell the org-controlled infrastructure apart from the
> shared compute it does not operate.

> **Only runner identity and labels are surfaced — never a credential.** The
> runner *registration token*, GitHub Actions runner *removal token*, and
> Bitbucket Pipelines runner *OAuth client secret* are all read-only invisible
> to covenant. Endpoints a low-privilege token can't read fail soft to an empty
> result rather than failing the whole audit.

The walk is bounded by the same `--max-pages` flag and honors the scope
guardrail and automatic rate-limit retry/backoff. Like the other
`--enumerate-*`/`--audit-*` flags the feature is purely additive (all may be
combined): without the flag the output is unchanged, and with it the v0.1
`scopes`/`user`/`admin` fields are untouched — only the `runners` array is
added.

```bash
covenant github validate-token \
  --scope-file scope.txt \
  --enumerate-runners \
  --token-env COVENANT_TOKEN
```

Example `runners` array (an org-scoped self-hosted runner alongside a
repo-attached one):

```json
{
  "runners": [
    {
      "scope": "org",
      "owner": "acme-corp",
      "id": 700,
      "name": "acme-org-runner-1",
      "labels": ["self-hosted", "linux", "production"],
      "self_hosted": true
    },
    {
      "scope": "repo",
      "owner": "acme-corp/spellbook",
      "id": 710,
      "name": "spellbook-repo-runner",
      "labels": ["self-hosted"],
      "self_hosted": true
    }
  ]
}
```

### Deployment-environment audit (`--audit-actions-environments`)

A deployment **environment** (GitHub Actions "Environments", GitLab project
environments, Bitbucket Pipelines deployment environments) is where the *most*
sensitive CI/CD secrets are scoped — production cloud keys, registry passwords,
deploy tokens. The environment's **protection rules** are the gate that decides
whether a workflow may deploy to it and thereby *read* those secrets:
required-reviewers force a human to approve the deployment, a wait timer delays
it, and a deployment branch policy restricts which branches may deploy at all.

`--audit-actions-environments` is the **environment-scoped, secret-exfiltration
counterpart** to `--audit-branch-protection`: where branch protection gates code
landing on a branch, this gates *deployments* reaching the secrets. The
high-signal finding is an environment with `required_reviewers: false` **and** a
permissive `branch_policy` of `"all"` — any branch (including an attacker's
feature branch carrying a malicious workflow) can deploy to that environment and
exfiltrate its secrets unreviewed. Pass `--audit-actions-environments` to
`validate-token` and covenant walks the repos the token can reach with a
**read-only** query, adding an `actions_environments` array:

| SCM       | Endpoint(s)                                                                                   | Gate signal mapped to `required_reviewers`                          |
|-----------|-----------------------------------------------------------------------------------------------|----------------------------------------------------------------------|
| GitHub    | `GET /repos/{owner}/{repo}/environments`                                                      | a `required_reviewers` protection rule (with `wait_timer` + branch policy) |
| GitLab    | `GET /api/v4/projects/{id}/environments` + `.../protected_environments`                       | a protected environment with `required_approval_count > 0`           |
| Bitbucket | `GET /2.0/repositories/{full_name}/environments`                                              | the deploy gate's `restrictions.admin_only` flag                     |

Each entry is normalized to `{"repo", "environment", "required_reviewers",
"required_reviewer_count", "wait_timer", "branch_policy"}`. `branch_policy` is
`"protected"` (only protected branches may deploy), `"custom"` (a custom branch
allow-list), or `"all"` (no branch restriction — the weakest posture).

> **Provider parity caveats.** GitLab has no per-environment deploy *wait timer*,
> so `wait_timer` is always `0` there. Bitbucket Cloud exposes no
> per-environment reviewer *count*, wait timer, or branch policy, so
> `required_reviewer_count`/`wait_timer` are `0` and `branch_policy` is `"all"`
> on Bitbucket — the fields are kept for cross-provider shape parity, and
> `required_reviewers` reflects the `admin_only` deploy gate.

Only policy metadata is read — covenant never creates, edits, or triggers a
deployment, and no secret *value* is ever read. The walk is bounded by the same
`--max-pages` flag and honors the scope guardrail and automatic rate-limit
retry/backoff. Like the other `--enumerate-*`/`--audit-*` flags the feature is
purely additive (all may be combined): without the flag the output is unchanged,
and with it the v0.1 `scopes`/`user`/`admin` fields are untouched — only the
`actions_environments` array is added.

```bash
covenant github validate-token \
  --scope-file scope.txt \
  --audit-actions-environments \
  --token-env COVENANT_TOKEN
```

Example `actions_environments` array (a weakly-gated production environment
beside a strongly-gated one):

```json
{
  "actions_environments": [
    {
      "repo": "acme-corp/spellbook",
      "environment": "production",
      "required_reviewers": false,
      "required_reviewer_count": 0,
      "wait_timer": 0,
      "branch_policy": "all"
    },
    {
      "repo": "acme-corp/grimoire",
      "environment": "production",
      "required_reviewers": true,
      "required_reviewer_count": 2,
      "wait_timer": 30,
      "branch_policy": "protected"
    }
  ]
}
```

### Member enumeration (`--enumerate-members`)

Where the rest of the `--enumerate-*` family maps what *this* token reaches (its
keys, its repos, the secrets it can read), `--enumerate-members` maps the **people
who share that reach**: the other members of each org/group/workspace the token
belongs to, and at what role. That is the **lateral-movement surface** — the set
of additional identities an operator could target to widen a foothold (phishing,
credential reuse, a weaker teammate token) — and, for the `role: "admin"` set (the
org owners), the accounts whose compromise grants administrative control of the
whole org. Pass `--enumerate-members` to `validate-token` and covenant walks the
orgs the token can reach (the same set surfaced by `--enumerate-orgs`) and, for
each, lists its members with a **read-only** directory query, adding a `members`
array:

| SCM       | Endpoint                                       | `role: "admin"` derived from                          |
|-----------|------------------------------------------------|--------------------------------------------------------|
| GitHub    | `GET /orgs/{org}/members?role=admin\|member`    | the `admin` (org owner) role view                      |
| GitLab    | `GET /api/v4/groups/{id}/members/all`           | the numeric `access_level` (>= 50 Owner)               |
| Bitbucket | `GET /2.0/workspaces/{slug}/members`            | the `permission` field (`owner`)                       |

Each entry is normalized to `{"scope", "owner", "username", "role"}`, where
`scope` is `org`/`group`/`workspace` and `role` is `admin` or `member`.

> **Identity and role only — never a credential.** covenant surfaces the
> member's username and role; it never reads or echoes an email, SSH/GPG key, or
> any token. This is a directory query, not a data dump.

The walk is bounded by the same `--max-pages` flag and honors the scope guardrail
and automatic rate-limit retry/backoff. Like the other `--enumerate-*`/`--audit-*`
flags the feature is purely additive (all may be combined): without the flag the
output is unchanged, and with it the v0.1 `scopes`/`user`/`admin` fields are
untouched — only the `members` array is added.

```bash
covenant github validate-token \
  --scope-file scope.txt \
  --enumerate-members \
  --token-env COVENANT_TOKEN
```

Example `members` array (an org owner alongside ordinary members — the owner is
the highest-value lateral target):

```json
{
  "members": [
    { "scope": "org", "owner": "acme-corp", "username": "acme-corp-owner", "role": "admin"  },
    { "scope": "org", "owner": "acme-corp", "username": "spellcaster",     "role": "member" },
    { "scope": "org", "owner": "acme-corp", "username": "apprentice",      "role": "member" }
  ]
}
```

### Collaborator enumeration (`--enumerate-collaborators`)

Where `--enumerate-members` maps the people who share an **org/group/workspace's**
reach, `--enumerate-collaborators` is **repo-scoped** and surfaces the
higher-signal blast radius: the accounts granted access **directly on a specific
repository** rather than through org membership. These direct grants are the
classic **ghost-account / ex-employee / leftover-contractor vector** — a personal
account with standing access to a critical repo, invisible to an org-member audit,
that survives long after the person leaves. A write-or-above direct grant is a
direct **supply-chain and persistence** risk. Pass `--enumerate-collaborators` to
`validate-token` and covenant walks the repos the token can reach and, for each,
lists its per-repo grants with a **read-only** query, adding a `collaborators`
array:

| SCM       | Endpoint                                                          | `role` / `outside` derived from                                  |
|-----------|------------------------------------------------------------------|------------------------------------------------------------------|
| GitHub    | `GET /repos/{owner}/{repo}/collaborators?affiliation=outside`     | the `permissions` map; every result is an outside collaborator   |
| GitLab    | `GET /api/v4/projects/{id}/members` (direct, non-`/all`)          | the numeric `access_level`; direct project members               |
| Bitbucket | `GET /2.0/repositories/{workspace}/{repo}/permissions-config/users`| the explicit `permission` (`admin`/`write`/`read`)               |

Each entry is normalized to `{"repo", "username", "role", "outside"}`, where
`role` is the **highest-privilege** level (`admin` > `maintain` > `write` >
`triage` > `read`) and `outside` is `true` for these direct, outside-style grants
(the ghost-account signal). GitHub fetches with `affiliation=outside` so the result
set *is* the outside collaborators; GitLab's non-`/all` members endpoint returns
grants made on the project itself (excluding those inherited from a group); and
Bitbucket's explicit per-repo user-permission config is the equivalent direct
grant. Endpoints that require repo-admin (Bitbucket) **fail soft** for a
low-privilege token so the audit still reports the repos it can read.

> **Identity and permission level only — never a credential.** covenant surfaces
> the collaborator's username and access level; it never reads or echoes an email,
> SSH/GPG key, or any token, and the audit never grants or revokes access.

The walk is bounded by the same `--max-pages` flag and honors the scope guardrail
and automatic rate-limit retry/backoff. Like the other `--enumerate-*`/`--audit-*`
flags the feature is purely additive (all may be combined): without the flag the
output is unchanged, and with it the v0.1 `scopes`/`user`/`admin` fields are
untouched — only the `collaborators` array is added.

```bash
covenant github validate-token \
  --scope-file scope.txt \
  --enumerate-collaborators \
  --token-env COVENANT_TOKEN
```

Example `collaborators` array (a writable outside collaborator — a ghost account
with standing push access — alongside a read-only auditor):

```json
{
  "collaborators": [
    { "repo": "acme-corp/spellbook", "username": "ex-contractor", "role": "write", "outside": true },
    { "repo": "acme-corp/grimoire",  "username": "auditor",       "role": "read",  "outside": true }
  ]
}
```

### Commit-history secret scanning (`--scan-commits`)

`--scan-secrets` (on `recon-code`) only ever sees the **current** file content the
code-search API returns. But a credential scrubbed from a tracked file routinely
**survives verbatim in the commit history** — in a `git commit -m "fix: rotate to
AKIA..."` subject, in a revert/merge body that quotes a diff, or in an automated
bump commit that echoes a token. Commit messages are a notorious, overlooked leak
vector. `--scan-commits` is the recon analogue for that history: pass it to
`validate-token` and covenant walks the recent commits the token can read on each
reachable repo, scanning every **commit message** for leaked credentials with the
same [`necromancer-patterns`](https://github.com/bugsyhewitt/necromancer-patterns)
engine that powers `--scan-secrets`, and adds a `commit_findings` array.

| SCM       | Commit-list endpoint                                       | `author` derived from                          |
|-----------|------------------------------------------------------------|------------------------------------------------|
| GitHub    | `GET /repos/{owner}/{repo}/commits`                        | the commit author's account `login`            |
| GitLab    | `GET /api/v4/projects/{id}/repository/commits`             | the commit's `author_name`                     |
| Bitbucket | `GET /2.0/repositories/{workspace}/{repo}/commits`         | the author's display `nickname`                |

Only commits whose message **actually matched** a pattern are surfaced. Each entry
is normalized to `{"repo", "sha", "author", "secret_findings"}`, where
`secret_findings` is the standard scan-finding list (same shape as
`--scan-secrets`). Requires the `scan` extra (`pip install 'covenant[scan]'`), and
honors `--pattern-set` to narrow the rule bundle (e.g. `aws`) exactly as
`recon-code` does.

> **Share-safe by default, like `--scan-secrets`.** Each discovered secret is
> emitted as a **redacted fingerprint** (`AKIA…[20 chars, sha256:…]`) so covenant's
> own output never becomes a new place the live credential leaks. Pass
> `--show-commit-secrets` to emit the full raw value (use with care). The commit
> **diff/patch is never fetched** and **no author email is surfaced** — covenant
> maps the leak surface in history without dumping repository content.

The walk is bounded by the same `--max-pages` flag and honors the scope guardrail
and automatic rate-limit retry/backoff. Like the other `--enumerate-*`/`--audit-*`
flags the feature is purely additive (all may be combined): without the flag the
output is unchanged, and with it the v0.1 `scopes`/`user`/`admin` fields are
untouched — only the `commit_findings` array is added.

```bash
covenant github validate-token \
  --scope-file scope.txt \
  --scan-commits \
  --token-env COVENANT_TOKEN
```

Example `commit_findings` array (a commit whose message leaked an AWS key, with the
secret redacted by default):

```json
{
  "commit_findings": [
    {
      "repo": "acme-corp/spellbook",
      "sha": "a1b2c3d",
      "author": "ex-contractor",
      "secret_findings": [
        {
          "rule_id": "aws-access-key-id",
          "secret": "AKIA…[20 chars, sha256:9f3a]",
          "fragment_index": 0
        }
      ]
    }
  ]
}
```

## Usage — one example per SCM

GitHub repo recon:

```bash
covenant github recon-repo \
  --scope-file scope.txt \
  --query "internal-secrets" \
  --token-env COVENANT_TOKEN
```

GitLab repo recon (self-hosted via `--target-url`):

```bash
covenant gitlab recon-repo \
  --scope-file scope.txt \
  --query "internal-secrets" \
  --target-url https://gitlab.acme-corp.example \
  --token-env COVENANT_TOKEN
```

Bitbucket token validation:

```bash
covenant bitbucket validate-token \
  --scope-file scope.txt \
  --token-env COVENANT_TOKEN
```

Example `recon-repo` output:

```json
{
  "scm": "github",
  "query": "internal-secrets",
  "results": [
    {
      "name": "acme-corp/internal-secrets",
      "visibility": "private",
      "url": "https://github.com/acme-corp/internal-secrets",
      "description": "..."
    }
  ]
}
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

The test suite stands up in-process mock SCM API servers on **ephemeral ports**
(`socket.bind(('', 0))`) so end-to-end smoke tests run with no live API calls.

## Roadmap (not in v0.1)

- Privilege-escalation modules that modify SCM state (gated behind an explicit
  destructive-action authorization flag)
- Persistence modules (PAT / SSH-key planting)
- GitHub Enterprise Server specifics
- Webhook and CI/CD pipeline modules

## License

See `LICENSE`. Prior-art attribution in `NOTICE`.
