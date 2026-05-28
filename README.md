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
