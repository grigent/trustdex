# Using TrustDex with Codex

<p align="right">
  <strong>English</strong> | <a href="./CODEX.ko.md">한국어</a>
</p>

This guide covers two things: gating the MCP servers a Codex client may start, and how TrustDex itself is maintained with Codex.

TrustDex is an independent project. It is not affiliated with, endorsed by, or certified by OpenAI, and an ALLOW decision is not an OpenAI or TrustDex safety certification.

## Gate Codex MCP servers

Codex clients read MCP server definitions from `[mcp_servers.<name>]` tables in `config.toml` (by default under `~/.codex/`). Every entry there can start a local process or connect to a remote endpoint with the credentials you give it.

### 1. Inspect the current configuration

```bash
npx trustdex@0.6.0 inspect-codex ~/.codex/config.toml --pack strict
```

This reads the file locally and makes no network request. The output lists each MCP server, its source type, trust signals, and an ALLOW / ASK / BLOCK decision. Environment variable names may appear; their values never do.

Use `--json` for machine-readable output and `--trust-store ./trust-store.json` to attach explicit publisher evidence (see [TRUST_STORE.md](TRUST_STORE.md)).

### 2. Write a gated copy

```bash
npx trustdex@0.6.0 gate-codex ~/.codex/config.toml \
  --pack official-first \
  --trust-store ./trust-store.json \
  --out ./gated-config.toml
```

The gated file keeps unrelated TOML sections (models, features, profiles) unchanged and removes every MCP section that is not ALLOW. `ASK` entries stay out unless you pass `--include-ask`, which should only be used when another approval layer exists.

Review the difference before using it:

```bash
diff ~/.codex/config.toml ./gated-config.toml
```

TrustDex never edits `config.toml` in place. Replacing the original file, or pointing a Codex installation at the gated copy, is an explicit step you take after review.

### 3. Re-run after every change

MCP entries change when a package version is bumped, a launcher is swapped, or a new environment variable is passed. Re-run `inspect-codex` and `gate-codex` whenever `config.toml` changes; a CI job or a pre-commit hook in a dotfiles repository works well for this.

The signed `snapshot`, `approve`, and `recheck` drift workflow in the [README](../README.md#capability-and-provenance-drift) currently accepts MCP JSON only. Extending it to Codex `config.toml` is tracked in the [roadmap](ROADMAP.md).

### Fail-closed parsing

TrustDex parses only the TOML constructs used by Codex MCP sections. An unsupported MCP key, nested subsection, or syntax is reported as an error instead of being skipped, so a configuration TrustDex cannot fully read never silently becomes ALLOW.

## Inspect Codex execution permissions

MCP gating controls external tools, while Codex approval and sandbox settings control
what the agent can do locally. Inspect those settings separately:

```bash
node ./bin/trustdex.mjs inspect-codex-settings \
  ./examples/codex.permissions.toml \
  --pack strict \
  --json
```

The adapter validates `approval_policy`, `approvals_reviewer`, `sandbox_mode`,
`default_permissions`, `web_search`, and the documented
`sandbox_workspace_write` keys. It reports:

- `danger-full-access` as `BLOCK`
- `workspace-write`, outbound network access, additional writable roots, live web search, automatic review, and `approval_policy = "never"` as at least `ASK`
- explicit multi-agent enablement, custom permission profiles, app/plugin sections, and settings it does not fully inspect as `ASK`

Security-relevant values fail closed when their type or enum value is unsupported.
`default_permissions` also fails when combined with the legacy sandbox settings, as
the official configuration reference says not to combine them. Writable-root paths
and values from unrelated settings are not retained, printed, or fingerprinted.

This first adapter inspects one file at a time; it does not merge user, project,
profile, managed, system, or command-line configuration into an effective policy.
It is static evidence, not the Codex sandbox itself. Confirm the active permission
profile in the client. The official OpenAI documentation distinguishes the sandbox
boundary from approval handling and documents `workspace-write` plus `on-request`
as the lower-risk local automation combination. See the [configuration reference](https://developers.openai.com/codex/config-reference)
and [sandbox guide](https://developers.openai.com/codex/sandboxing).

### Permission posture drift

Create and commit a reviewed structural baseline, then generate a current snapshot in
CI and compare them:

```bash
node ./bin/trustdex.mjs snapshot-codex-settings \
  ~/.codex/config.toml \
  --pack strict \
  --out .trustdex/codex-posture.json

node ./bin/trustdex.mjs diff-permissions \
  .trustdex/approved-codex-posture.json \
  .trustdex/current-codex-posture.json \
  --json
```

Network enablement, broader writable scope, a weaker sandbox or approval posture,
live search, subagent enablement, new risk signals, and policy-semantic changes require
review and exit `1`. Restriction-only changes exit `0`. The snapshot stores structural
counts and documented enums, not the config path, writable-root paths, custom profile
values, or unrelated settings. Its digest detects accidental or unreconciled edits,
but anyone can recompute an unsigned digest; it is not authentication or a replacement
for the Codex runtime sandbox.

### Skills and plugins

Agent skills and plugin manifests can be inspected the same way:

```bash
npx trustdex@0.6.0 inspect-skill ./path/to/SKILL.md --pack strict
npx trustdex@0.6.0 inspect-plugin ./path/to/plugin.json --pack strict
```

These report observable signals such as piped shell installers, references to sensitive paths, network URLs, and wildcard tool scopes. They do not prove a skill or plugin is safe.

## Gate MCP configuration in CI

Repositories that ship an MCP configuration for agents can gate it on every pull request with the [TrustDex GitHub Action](../README.md#github-action). Pin the action to a reviewed commit SHA.

## How TrustDex is maintained with Codex

TrustDex uses Codex as a reviewer and maintainer assistant, with the same trust boundary it asks users to apply:

- [AGENTS.md](../AGENTS.md) holds the development rules and a **Review guidelines** section that Codex code review applies to TrustDex pull requests. The guidelines turn the project's security invariants (no silent ALLOW, no secret values in output, no provenance override of blocking signals, fail-closed parsing, pinned actions) into explicit review findings.
- Codex suggestions are treated like any other contribution: they go through a pull request, must pass the cross-platform CI matrix and CodeQL, and are merged only after maintainer review.
- Codex does not hold release credentials. npm publication uses Trusted Publisher OIDC with Sigstore provenance from `.github/workflows/publish.yml`, triggered by a maintainer.

If you contribute with Codex or another coding agent, the same AGENTS.md rules apply to your changes.
