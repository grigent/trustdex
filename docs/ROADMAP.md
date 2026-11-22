# Roadmap

<p align="right">
  <strong>English</strong> | <a href="./ROADMAP.ko.md">한국어</a>
</p>

TrustDex is early-stage. This roadmap communicates direction and is not a release commitment.

## Progress

- TrustDex 0.6.0 added fail-closed Claude Code and Codex permission inspection.
- TrustDex 0.7.0 adds value-free, self-validating permission posture snapshots,
  autonomy-expansion review gates, versioned JSON schemas, and public adversarial
  permission fixtures.
- TrustDex 0.8.0 adds explicit merged-source inspection for documented Claude Code
  and Codex precedence, schema-v2 source topology evidence, and fail-closed stack tests.
- TrustDex 0.9.0 adds value-free Claude/Codex bindings between MCP policy/provenance
  results and automatic tool grants, versioned schemas, drift review, and inert fixtures.
- TrustDex 0.10.0 adds an explicit value-free runtime inventory contract, effective
  boundary reconciliation, exposure-drift review, versioned schemas, and fixtures.
- TrustDex 0.11.0 adds Ed25519 producer authentication for exact runtime inventories,
  bounded expiry/capture age, schema-v2 authentication state, and fail-closed tests for
  replay, wrong-key, future-time, mutation, and unauthenticated evidence.
- TrustDex 0.12.0 adds an IDE extension gate for VS Code and Cursor (exact-version pins,
  installed-file digests, signed recheck), a versioned fail-closed `--decisions` contract
  for agents, strict policy validation, signed Codex config reviews, a TOML lexer for
  Codex configs, per-runner package identity checks, `--keyset` verification-key
  allowlists with rotation and revocation, and an output canary sweep.
- TrustDex 0.13.0 adds atomic, symlink-safe CLI output, bounded provenance lookups,
  fail-closed npm unpublish/integrity checks, and cross-platform path recognition;
  0.13.1 adds resource budgets for IDE extension trees.
- TrustDex 0.14.0 adds `check-install` (offline parsing of npm, pnpm, yarn, bun, npx,
  pip, uv, uvx, pipx, poetry, and pdm installs plus registry metadata checks) and the
  `claude-hook` `PreToolUse` guard for risky installs, settings tampering, credential
  reads, permission bypasses, and startup items.
- TrustDex 0.15.0 checks commands sent over SSH; 0.15.1 binds one-time approvals of
  local scripts to their SHA-256.
- TrustDex 0.16.0 adds `slack-approver` for owner-only Slack approval of stopped
  actions; 0.16.1 treats credential files fed through input redirection as secret access.
- TrustDex 0.17.0 adds one-step `trustdex init` for the Claude Code hook; 0.17.1 blocks
  known malicious PyPI releases from a bundled advisory.
- TrustDex 0.17.2 starts the integrity work: `provenance-dropped` flags recent npm
  releases that lack the provenance earlier versions had, and bundled advisories block
  hijacked npm releases. Releases ship with checksums, an SBOM, and GitHub attestations.
- TrustDex 0.17.3 compares npm build provenance with the repository a package declares
  when a source is trusted (`provenance npm`, `trust-source npm`), and adds registry-drift
  fixtures for ownership transfer, deleted releases, and yanked releases.
- TrustDex 0.18.0 verifies the Sigstore bundle of npm build provenance offline against a
  pinned trust root when a source is trusted, adds adversarial skill, plugin, and MCP JSON
  fixtures with the parser fixes they exposed, and adds `inventory-claude-init`, which turns
  a captured Claude Code `system/init` event into a runtime inventory. It also publishes a
  [compatibility matrix](COMPATIBILITY.md) checked by tests, [schema stability
  rules](SCHEMAS.md), and [design notes](DESIGN_NOTES.md).
- After 0.18.0: `inventory-codex-mcp-status` for a captured Codex `mcpServerStatus/list`
  exchange, and MCP configuration adapters for [Devin CLI](DEVIN.md) and
  [Gemini CLI](GEMINI.md).

## Now: harden the boundary

- keep expanding adversarial fixtures for MCP JSON, Codex TOML, skills, and plugin manifests
- keep expanding adversarial permission fixtures for both Claude Code and Codex
- verify that all human-readable output remains free of secret values
- improve cross-platform source and path normalization
- keep the [schema stability rules](SCHEMAS.md) current as formats change
- keep CI, CodeQL, and release automation reproducible and reviewable

## Next: strengthen effective-runtime evidence

- ship concrete opt-in adapters only where a runtime exposes an authorized stable interface (Claude Code and Codex converters exist; Gemini CLI and Devin document no machine-readable session inventory, see [runtime evidence](RUNTIME_EVIDENCE.md))
- document transport hardening around the message-level producer signature
- extend effective evidence beyond MCP visibility while retaining value-free reports
- extend the [compatibility matrix](COMPATIBILITY.md) to adapter/runtime versions once an adapter ships ([design notes](DESIGN_NOTES.md))

## Then: prove integrity

- verify immutable package artifacts when registries expose cryptographic hashes
- verify the SCT of npm build provenance, and define how the pinned Sigstore trust root is refreshed (the signature, certificate chain, log entry, and Merkle inclusion proof are verified offline; see [design notes](DESIGN_NOTES.md))
- connect registry observations to exact package versions and repository identities
- publish checksums or stronger provenance for TrustDex releases
- add fixtures for ownership transfer, deleted releases, yanked packages, and registry drift

## Later: expand interoperability

- add adapters for additional agent runtimes and registries (Devin CLI and Gemini CLI MCP configuration are covered; their settings and permission files are not)
- extend the test-backed compatibility matrix to new runtimes and registries
- explore organization-managed trust stores and review-key rotation

## Adoption goals

The project is seeking pilot users willing to share non-sensitive feedback about false positives, false negatives, configuration formats, and maintainer workflow. Usage claims will be documented only when they can be verified; stars, branding, and package names are never treated as security evidence.

## How to help

If you ran TrustDex on a real configuration, the **Pilot feedback** issue form is the fastest way to report results. Otherwise, open a focused issue describing the use case and redacted configuration shape. For security-sensitive proposals, include the expected trust boundary and bypass cases.
