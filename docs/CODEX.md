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
npx trustdex@0.11.0 inspect-codex ~/.codex/config.toml --pack strict
```

This reads the file locally and makes no network request. The output lists each MCP server, its source type, trust signals, and an ALLOW / ASK / BLOCK decision. Environment variable names may appear; their values never do.

Use `--json` for machine-readable output and `--trust-store ./trust-store.json` to attach explicit publisher evidence (see [TRUST_STORE.md](TRUST_STORE.md)).

### 2. Write a gated copy

```bash
npx trustdex@0.11.0 gate-codex ~/.codex/config.toml \
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

### 4. Lock a reviewed configuration with a signed review

Approve the reviewed `config.toml` with a signing key kept off the machine you are protecting, then recheck it before each Codex session or in CI:

```bash
node ./bin/trustdex.mjs approve-codex ~/.codex/config.toml \
  --private .trustdex/private.pem --dir .trustdex/codex-review \
  --pack strict --policy ./trustdex.policy.json

node ./bin/trustdex.mjs recheck-codex ~/.codex/config.toml \
  --review-dir .trustdex/codex-review --public .trustdex/public.pem
```

`approve-codex` refuses configurations that contain BLOCK decisions. `recheck-codex` exits `0` with `APPROVED` when every MCP server still matches the signed review. It exits `1` with `NEEDS_REVIEW` when a server is added or removed, or when a package version, endpoint, environment variable name or origin (static, forwarded, bearer token), header name or the host variable it reads, `enabled_tools`/`disabled_tools`, or tool approval mode changes. It exits `2` with `INVALID` when the review bundle or its policy was altered. `snapshot-codex` writes the same v3 snapshot for use with `diff`. Recheck with the same adapter you approved with: the Codex adapter fingerprints Codex-specific fields, so rechecking an equivalent MCP JSON file reports `NEEDS_REVIEW` instead of `APPROVED`.

Like the other fingerprints, Codex snapshots omit environment, header, and token values, so rotating a credential value alone does not require re-review.

### Fail-closed parsing

TrustDex lexes the whole `config.toml` with a small TOML lexer. It handles basic, literal, and multi-line strings, arrays, inline tables, comments, and dotted or quoted keys, so a value can never swallow the next table and a table header can never be skipped because of spacing or quoting. MCP servers must be written as `[mcp_servers.<name>]` tables, with optional `env`, `http_headers`, and `env_http_headers` subtables. Spaced or quoted spellings such as `[mcp_servers . name]` or `["mcp_servers".name]` reach the same server. These are reported as errors instead of being skipped, so a configuration TrustDex cannot fully read never silently becomes ALLOW:

- a bare `[mcp_servers]` table, root-level `mcp_servers.<name>.*` keys, or a whole server written as an inline table
- arrays of tables
- duplicate keys or repeated server tables
- unsupported MCP keys or subsections
- values other than strings, numbers, booleans, arrays, and inline tables

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

Use the stack command to apply the documented configuration precedence. Repeat
`--project` from the repository root toward the current directory; the closest project
file wins:

```bash
node ./bin/trustdex.mjs inspect-codex-settings-stack \
  --system ./review/system.toml \
  --managed ./review/managed.toml \
  --user ./review/user.toml \
  --profile ./review/profile.toml \
  --project ./review/root-project.toml \
  --project ./review/closest-project.toml \
  --cli ./review/cli-overrides.toml \
  --pack strict --json
```

The stack is merged from system through CLI precedence, one supported security field
at a time. Unsupported syntax in any source fails closed even when a higher source
would override it. Reports retain fixed source-scope counts but not config paths or
unrelated values. Sources are explicit inputs: the command does not discover trusted
projects, active profiles, cloud-managed defaults, requirements, or CLI flags itself.
It is static evidence, not the Codex sandbox. Confirm the active permission profile
in the client. The official OpenAI documentation distinguishes the sandbox boundary
from approval handling. See the [configuration reference](https://developers.openai.com/codex/config-reference)
and [configuration precedence](https://developers.openai.com/codex/config-basic).

### Permission posture drift

Create and commit a reviewed structural baseline, then generate a current snapshot in
CI and compare them:

```bash
node ./bin/trustdex.mjs snapshot-codex-settings \
  ~/.codex/config.toml \
  --pack strict \
  --out .trustdex/codex-posture.json

node ./bin/trustdex.mjs snapshot-codex-settings-stack \
  --system ./review/system.toml \
  --user ./review/user.toml \
  --project ./review/project.toml \
  --pack strict \
  --out .trustdex/codex-stack-posture.json

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
Merged-source snapshots use schema v2. A source-scope count change is unclassified
and therefore returns `NEEDS_REVIEW`, even when the final structural settings match.

### Bind MCP provenance to automatic grants

Codex can automatically approve every tool exposed by one MCP server. Review that
grant together with the server's policy and provenance result:

```bash
node ./bin/trustdex.mjs snapshot-codex-bindings ~/.codex/config.toml \
  --trust-store ./trust-store.json \
  --pack strict \
  --out .trustdex/codex-bindings.json

node ./bin/trustdex.mjs diff-bindings \
  .trustdex/approved-codex-bindings.json \
  .trustdex/current-codex-bindings.json
```

`default_tools_approval_mode = "approve"` is an all-tool automatic grant and therefore
requires review even for an ALLOW source. Wildcard tool scope is recorded as a boolean;
tool names, endpoint paths, and unrelated values are omitted. This static binding does
not prove the configuration is loaded or enforce the Codex runtime sandbox.

### Compare an explicit runtime inventory

An authorized Codex integration can provide `agent-runtime-tool-inventory` JSON with
the MCP server names visible to that session and a tool count for each server. Run
`snapshot-runtime-tools <bindings> <inventory> --out <evidence>` to reconcile it with
the reviewed Codex binding snapshot, and `diff-runtime-tools` to gate exposure growth.
This is an opt-in evidence adapter contract, not automatic config discovery, an official
Codex export format, or runtime enforcement. Confirm the capture path and sandbox in the
client separately. Production evidence should use `sign-runtime-inventory`, a pinned
producer public key, bounded `--max-age-seconds`, and `--require-authenticated` as shown
in [Authenticated runtime evidence](RUNTIME_EVIDENCE.md).

### Skills and plugins

Agent skills and plugin manifests can be inspected the same way:

```bash
npx trustdex@0.11.0 inspect-skill ./path/to/SKILL.md --pack strict
npx trustdex@0.11.0 inspect-plugin ./path/to/plugin.json --pack strict
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
