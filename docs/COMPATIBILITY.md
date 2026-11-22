# Compatibility matrix

<p align="right">
  <strong>English</strong> | <a href="./COMPATIBILITY.ko.md">한국어</a>
</p>

This page lists what TrustDex is tested against. Every row is backed by a test file in this repository, and `test/compatibility.test.mjs` fails if a row names a command, test, or example that does not exist, or if the platform table differs from the CI matrix.

## Platforms

| OS | Node.js |
| --- | --- |
| Linux (`ubuntu-latest`) | 20, 22, 24 |
| Windows (`windows-latest`) | 22 |
| macOS (`macos-latest`) | 22 |

Node.js 20 is the minimum supported version. `trustdex init` supports macOS and Linux only.

## Inputs

| Input | Commands | Tests | ID |
| --- | --- | --- | --- |
| Generic MCP JSON (`mcpServers` / `servers`) | `inspect`, `gate`, `snapshot`, `diff`, `approve`, `recheck` | `test/policy.test.mjs`, `test/hardening.test.mjs`, `test/research-fixtures.test.mjs` | `mcp-json` |
| Claude Code `.mcp.json` and Claude Desktop `mcpServers` | `inspect-claude`, `gate-claude`, `snapshot-claude`, `approve-claude`, `recheck-claude` | `test/claude.test.mjs` | `claude-mcp` |
| Devin CLI `mcp_config.json` | `inspect-devin`, `gate-devin`, `snapshot-devin`, `approve-devin`, `recheck-devin` | `test/devin.test.mjs` | `devin-mcp` |
| Gemini CLI `mcpServers` | `inspect-gemini`, `gate-gemini`, `snapshot-gemini`, `approve-gemini`, `recheck-gemini` | `test/gemini.test.mjs` | `gemini-mcp` |
| Claude Code settings files and merged stacks | `inspect-claude-settings`, `inspect-claude-settings-stack`, `snapshot-claude-settings`, `snapshot-claude-settings-stack`, `diff-permissions` | `test/claude-settings.test.mjs`, `test/settings-stack.test.mjs`, `test/posture.test.mjs` | `claude-settings` |
| Claude Code `PreToolUse` hook | `claude-hook`, `init`, `allow-once` | `test/claude-hook.test.mjs`, `test/init.test.mjs` | `claude-hook` |
| Codex `config.toml` MCP servers | `inspect-codex`, `gate-codex`, `snapshot-codex`, `approve-codex`, `recheck-codex` | `test/codex-toml.test.mjs`, `test/codex-review.test.mjs` | `codex-toml` |
| Codex approval and sandbox settings and merged stacks | `inspect-codex-settings`, `inspect-codex-settings-stack`, `snapshot-codex-settings`, `snapshot-codex-settings-stack` | `test/codex-settings.test.mjs`, `test/settings-stack.test.mjs` | `codex-settings` |
| MCP provenance bound to automatic grants (Claude, Codex) | `snapshot-claude-bindings`, `snapshot-codex-bindings`, `diff-bindings` | `test/bindings.test.mjs` | `bindings` |
| Explicit runtime tool inventory (`claude`, `codex`) | `inventory-claude-init`, `inventory-codex-mcp-status`, `snapshot-runtime-tools`, `diff-runtime-tools`, `sign-runtime-inventory`, `verify-runtime-inventory` | `test/claude-runtime-inventory.test.mjs`, `test/codex-runtime-inventory.test.mjs`, `test/runtime-evidence.test.mjs`, `test/runtime-attestation.test.mjs`, `test/keyset.test.mjs` | `runtime-evidence` |
| `SKILL.md` skill files | `inspect-skill` | `test/v02.test.mjs`, `test/research-fixtures.test.mjs` | `skill` |
| Plugin manifests (`plugin.json`) | `inspect-plugin` | `test/v02.test.mjs`, `test/research-fixtures.test.mjs` | `plugin` |
| VS Code-compatible extension directories (VS Code, Cursor, Remote) | `inspect-ide-extensions`, `snapshot-ide-extensions`, `approve-ide-extensions`, `recheck-ide-extensions` | `test/ide-extensions.test.mjs` | `ide-extensions` |
| npm and PyPI install commands (`registry.npmjs.org`, `pypi.org`) | `check-install` | `test/install-check.test.mjs` | `install-npm-pypi` |
| Online provenance: GitHub, npm, MCP Registry | `provenance`, `trust-source` | `test/integrity.test.mjs`, `test/v03.test.mjs` | `provenance` |

## What "compatible" means here

- TrustDex is tested against **configuration formats**, using the fixtures in this repository. It is not run against releases of Claude Code, Claude Desktop, Codex, Devin CLI, Gemini CLI, VS Code, or Cursor, so no runtime version is certified.
- Each adapter accepts the fields its documentation page lists. A field, transport, or syntax outside that list fails closed (an error, or an ASK/BLOCK signal). If a runtime adds a setting, TrustDex rejects or flags it until an adapter release covers it.
- Runtime evidence accepts the runtime names `claude` and `codex` in an inventory that an authorized integration supplies. TrustDex ships no adapter that reads a running agent. `inventory-claude-init` converts a `system/init` event that you captured from Claude Code's documented `--output-format stream-json`; it is tested against the documented event shape, not against Claude Code releases. `inventory-codex-mcp-status` converts an `mcpServerStatus/list` exchange (requests and responses) that you captured from the documented `codex app-server` protocol; it is tested against the published response schema, not against Codex releases. Gemini CLI and Devin document no machine-readable list of a session's MCP servers and tools, so no converter exists for them.
- Online adapters depend on the public response format of `api.github.com`, `registry.npmjs.org`, `pypi.org`, and the MCP Registry. They are tested with recorded-shape fixtures, not live requests.

## Reporting a mismatch

If a current runtime writes a configuration that TrustDex rejects, open an issue with the field name and the runtime version. Do not include secrets or private endpoints.
