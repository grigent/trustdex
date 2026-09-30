# Using TrustDex with Codex

This guide covers two things: gating the MCP servers a Codex client may start, and how TrustDex itself is maintained with Codex.

TrustDex is an independent project. It is not affiliated with, endorsed by, or certified by OpenAI, and an ALLOW decision is not an OpenAI or TrustDex safety certification.

## Gate Codex MCP servers

Codex clients read MCP server definitions from `[mcp_servers.<name>]` tables in `config.toml` (by default under `~/.codex/`). Every entry there can start a local process or connect to a remote endpoint with the credentials you give it.

### 1. Inspect the current configuration

```bash
npx trustdex@0.4.2 inspect-codex ~/.codex/config.toml --pack strict
```

This reads the file locally and makes no network request. The output lists each MCP server, its source type, trust signals, and an ALLOW / ASK / BLOCK decision. Environment variable names may appear; their values never do.

Use `--json` for machine-readable output and `--trust-store ./trust-store.json` to attach explicit publisher evidence (see [TRUST_STORE.md](TRUST_STORE.md)).

### 2. Write a gated copy

```bash
npx trustdex@0.4.2 gate-codex ~/.codex/config.toml \
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

### Skills and plugins

Agent skills and plugin manifests can be inspected the same way:

```bash
npx trustdex@0.4.2 inspect-skill ./path/to/SKILL.md --pack strict
npx trustdex@0.4.2 inspect-plugin ./path/to/plugin.json --pack strict
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
