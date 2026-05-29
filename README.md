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
