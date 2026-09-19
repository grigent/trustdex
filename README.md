# TrustDex

[![CI](https://github.com/grigent/trustdex/actions/workflows/ci.yml/badge.svg)](https://github.com/grigent/trustdex/actions/workflows/ci.yml)
[![CodeQL](https://github.com/grigent/trustdex/actions/workflows/codeql.yml/badge.svg)](https://github.com/grigent/trustdex/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/grigent/trustdex)](https://github.com/grigent/trustdex/releases)
[![npm](https://img.shields.io/npm/v/trustdex)](https://www.npmjs.com/package/trustdex)
[![License](https://img.shields.io/github/license/grigent/trustdex)](LICENSE)

**A local-first trust and provenance gate for AI agent tools.**

TrustDex helps decide which MCP servers, skills, and plugins an AI agent should be allowed to use. Instead of treating every discovered extension as trusted, TrustDex evaluates observable evidence and returns one of three outcomes:

- **ALLOW** - matches an explicit trust policy
- **ASK** - needs human review
- **BLOCK** - not trusted under the current policy

> TrustDex is security-related infrastructure, not a malware scanner, sandbox, or certification service. An ALLOW result only means the inspected evidence matched your policy.

> **Project status:** TrustDex is early-stage and seeking pilot users. The security boundary is documented, changes are tested on supported Node.js versions, and compatibility may still evolve before 1.0. See the [roadmap](docs/ROADMAP.md), [governance](GOVERNANCE.md), and [support guide](SUPPORT.md).

## Why TrustDex?

AI agents increasingly rely on third-party MCP servers, skills, and plugins that may receive credentials, access files, connect to remote services, or execute local programs. A package being installable does not mean it should automatically become available to an agent.

TrustDex adds a decision layer **before tool exposure**:

```text
User request
    |
    v
AI agent / Codex
    |
    v
TrustDex policy + provenance gate
    |-- ALLOW -> tool may be exposed
    |-- ASK   -> require human review
    `-- BLOCK -> keep tool unavailable
```

TrustDex deliberately does not infer "official" status from names, stars, or branding. Provenance must come from explicit, reviewable evidence.

## What the current code can do

- inspect MCP server entries locally without uploading configuration
- distinguish package, remote, local, and unknown sources
- detect trust-relevant signals such as floating versions, install-on-run launchers, shell execution, filesystem-looking arguments, secret-like environment variable names, and remote endpoints
- inspect `SKILL.md` files and plugin manifests for trust-relevant metadata/instructions
- apply built-in `strict`, `official-first`, and `development` policy packs
- attach explicit publisher/provenance assertions from a local trust store
- output **ALLOW / ASK / BLOCK** decisions
- generate a filtered MCP config containing only policy-approved tools
- create snapshots and detect source, provenance, decision, and capability drift
- create Ed25519-signed trust records for reviewed snapshots
- run as a GitHub Action in CI
- fingerprint MCP entries, skills, and plugin manifests without storing secret values
- inspect and filter Codex `config.toml` MCP sections
- perform explicit provenance lookups against GitHub, npm, and the official MCP Registry
- verify whether the latest GitHub release tag/commit has a GitHub-verified signature
- create signed review bundles and automatically require re-review when trust-relevant state drifts
- redact credentials, paths, and query values from remote endpoint details in reports
- block embedded URL credentials and insecure remote transport under strict policies
- recognize Windows executable paths and command wrappers consistently across hosts
- fail closed on unsupported Codex MCP keys and subsections
- verify user-supplied package bytes against npm SRI or MCP Registry SHA-256 metadata
- bind integrity-backed trust evidence to the configured package version and block mismatches

## Compatibility

TrustDex requires Node.js 20 or newer. CI exercises the full test and gate workflow on Ubuntu with Node.js 20 and 22, and on current Windows and macOS runners with Node.js 22. The checked-out composite GitHub Action has a dedicated end-to-end smoke test.

## Quick start

Requires Node.js 20+.

Run directly from npm:

```bash
npx trustdex@0.4.2 --help
npx trustdex@0.4.2 inspect ./mcp.json --pack strict --policy ./trustdex.policy.json
```

Or work from a source checkout:

```bash
git clone https://github.com/grigent/trustdex.git
cd trustdex
npm test
npm run check

node ./bin/trustdex.mjs inspect ./examples/mcp.json \
  --pack strict \
  --policy ./examples/trustdex.policy.json
```

The example intentionally includes an unknown server, so a strict inspection exits non-zero.

Exit codes for inspection:

- `0` - all entries allowed
- `1` - at least one entry needs review
- `2` - at least one entry is blocked, or the command failed

## Built-in policy packs

```bash
node ./bin/trustdex.mjs policy strict
node ./bin/trustdex.mjs policy official-first
node ./bin/trustdex.mjs policy development
```

`official-first` does **not** maintain a hard-coded list of supposedly official vendors. It allows sources only when they have explicit provenance evidence in your trust store (or when you explicitly allowlist them), while unknown third-party sources remain blocked by default.

See [Trust store and provenance](docs/TRUST_STORE.md).

## Filter tools before agent use

```bash
node ./bin/trustdex.mjs gate ./examples/mcp.json \
  --pack official-first \
  --out .trustdex/gated-mcp.json
```

By default, only `ALLOW` entries are written to the gated configuration. `ASK` entries stay out until reviewed.

This is the core TrustDex boundary: the agent receives the filtered configuration instead of the unreviewed source configuration.

## Inspect skills and plugins

```bash
node ./bin/trustdex.mjs inspect-skill ./path/to/SKILL.md --pack strict
node ./bin/trustdex.mjs inspect-plugin ./path/to/plugin.json --pack strict
```

These checks surface observable trust signals. They do not prove that the extension is safe.

## Codex config.toml

Current Codex clients store MCP configuration under `[mcp_servers.<name>]` tables in `config.toml`. TrustDex has a focused adapter for those MCP sections:

```bash
node ./bin/trustdex.mjs inspect-codex ./examples/codex.config.toml --pack strict

node ./bin/trustdex.mjs gate-codex ./examples/codex.config.toml \
  --pack strict \
  --out .trustdex/gated-codex.toml
```

The gate removes non-approved MCP sections while preserving unrelated TOML sections. TrustDex intentionally parses only the MCP-related TOML constructs it needs; unsupported MCP syntax fails rather than being silently trusted.

## Online provenance observations

Normal inspection remains local-only. These commands perform an explicit network lookup only when invoked:

```bash
node ./bin/trustdex.mjs provenance github modelcontextprotocol/servers
node ./bin/trustdex.mjs provenance github-release owner/repository
node ./bin/trustdex.mjs provenance npm @scope/package
node ./bin/trustdex.mjs provenance mcp io.github.user/server
```

A lookup is **evidence, not trust**. To turn evidence into a local trust-store claim, the user must explicitly name the publisher:

```bash
node ./bin/trustdex.mjs trust-source mcp io.github.user/server \
  --publisher "Example Publisher" \
  --out ./trust-store.json
```

For `github-release`, TrustDex refuses to create a trust claim unless GitHub reports the release tag or target commit signature as verified.

### Verify exact package bytes

Registry metadata can identify an expected digest, but metadata alone does not prove that a downloaded file matches it. Supply the exact package archive or artifact you reviewed:

```bash
node ./bin/trustdex.mjs trust-source npm @scope/package \
  --publisher "Example Publisher" \
  --artifact ./scope-package-1.2.3.tgz \
  --out ./trust-store.json

node ./bin/trustdex.mjs trust-source mcp io.github.user/server \
  --publisher "Example Publisher" \
  --artifact ./downloaded-package \
  --out ./trust-store.json
```

TrustDex reads the file locally and compares its bytes with npm SRI metadata or an MCP Registry SHA-256 digest. It does not download or execute the artifact. Integrity-backed evidence is version-bound; a different configured package version receives `artifact-version-mismatch` and is blocked.

## Provenance trust store

Example:

```json
{
  "version": 1,
  "claims": [
    {
      "type": "package",
      "subject": "example-mcp-server",
      "publisher": "Example Publisher",
      "status": "verified",
      "evidence": {
        "kind": "manual-review",
        "reference": "https://example.invalid/security-review"
      }
    }
  ]
}
```

Then:

```bash
node ./bin/trustdex.mjs inspect ./mcp.json \
  --pack official-first \
  --trust-store ./trust-store.json
```

Here, `verified` means verified according to the evidence maintained in that trust store. It does not mean OpenAI, TrustDex, GitHub, npm, or another platform certified the extension.

## Capability and provenance drift

Save a baseline:

```bash
node ./bin/trustdex.mjs snapshot ./examples/mcp.json \
  --pack strict \
  --out .trustdex/baseline.json
```

Save another snapshot after an update and compare them:

```bash
node ./bin/trustdex.mjs diff .trustdex/baseline.json .trustdex/current.json
```

TrustDex reports newly added signals, source changes, provenance changes, decision changes, and content/configuration fingerprint changes.

For a review workflow, generate a signing key once and approve a non-blocked configuration:

```bash
node ./bin/trustdex.mjs keygen \
  --private .trustdex/private.pem \
  --public .trustdex/public.pem

node ./bin/trustdex.mjs approve ./examples/mcp.json \
  --private .trustdex/private.pem \
  --dir .trustdex/review \
  --pack development
```

Later, re-evaluate the current configuration against that signed review:

```bash
node ./bin/trustdex.mjs recheck ./examples/mcp.json \
  --review-dir .trustdex/review \
  --public .trustdex/public.pem
```

The result is `APPROVED`, `NEEDS_REVIEW`, or `INVALID`. A fingerprint, source, provenance, signal, or policy-relevant change invalidates the previous state match.

## Signed trust records

Generate a local signing key:

```bash
node ./bin/trustdex.mjs keygen \
  --private .trustdex/trustdex-private.pem \
  --public .trustdex/trustdex-public.pem
```

Sign a reviewed snapshot:

```bash
node ./bin/trustdex.mjs sign .trustdex/baseline.json \
  --private .trustdex/trustdex-private.pem \
  --out .trustdex/trust-record.json
```

Verify it later:

```bash
node ./bin/trustdex.mjs verify .trustdex/trust-record.json \
  --public .trustdex/trustdex-public.pem \
  --snapshot .trustdex/baseline.json
```

The private key should never be committed.

## GitHub Action

```yaml
- uses: actions/checkout@v4

- uses: grigent/trustdex@v0.4.2
  with:
    config: ./mcp.json
    pack: official-first
    trust-store: ./trust-store.json
    output: .trustdex/gated-mcp.json
```

For production CI, pin the action to a reviewed commit SHA rather than a moving branch.

## Principles

1. **Local first.** Private agent configuration should not need to leave the machine.
2. **No blind trust.** Missing provenance should result in review or denial, not a guessed ALLOW.
3. **No secret values in output.** Environment variable names may be reported; values are not.
4. **Drift matters.** Approval should not silently survive trust-relevant changes.
5. **Simple outcomes.** ALLOW / ASK / BLOCK instead of an opaque risk score.
6. **Evidence over branding.** "Official" is not inferred from a familiar name.
7. **Vendor neutral.** The policy model should work across Codex and other agent runtimes.

## Roadmap

The public roadmap is maintained in [docs/ROADMAP.md](docs/ROADMAP.md). Near-term work focuses on registry integrity verification, reproducible releases, additional agent-runtime adapters, and real-world pilot feedback. Roadmap items are intentions, not promises.

## Security

TrustDex does **not** prove that third-party code is safe and does not replace sandboxing, dependency scanning, code review, or least-privilege credentials.

See [SECURITY.md](SECURITY.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), and [docs/TRUST_STORE.md](docs/TRUST_STORE.md).

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and [AGENTS.md](AGENTS.md).

## License

MIT
