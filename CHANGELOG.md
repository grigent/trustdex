# Changelog

<p align="right">
  <strong>English</strong> | <a href="./CHANGELOG.ko.md">한국어</a>
</p>

## Unreleased

- stop printing and snapshotting credentials, query values, and `;params` embedded in package specs (URLs, `name@url`, scp-like remotes, uvx `--from`): simple registry specs are shown as written, any other spec is parsed with the WHATWG URL parser (known schemes only) or as an scp-like remote and shown with scheme, host, path, and git ref only, and a spec that cannot be parsed is shown as `<unparseable-package-spec>` and blocked in every pack (`unparseable-package-spec`); only simple specs can be pinned, and package URLs with query values or `;params` are blocked in every pack (`package-url-query`) because their values can be neither shown nor tracked
- flag `embedded-credentials` for URL or scp-like credentials in any command-line argument, including `--flag=URL` values, and fingerprint that argument without its credentials; other argument values, including query values, still change the fingerprint
- report only known values for IDE extension install source and target platform, and drop the untrusted `displayName` from results
- add a canary sweep regression suite that plants unique values in every supported input format and fails if any command prints or stores one, and document the output redaction contract (names may be reported, values never)
- add `--decisions` to every inspection command: a versioned, value-free `trustdex-decisions` JSON report whose exit code matches the decision and which reports BLOCK when inspection fails
- validate `--policy` files strictly and reject unknown fields, unsupported versions, and invalid actions instead of silently falling back (**compatibility:** a policy with a misspelled field now errors)
- report an empty inventory as ASK in `--decisions` mode, reject `--decisions` on commands that do not implement it, and fail closed on MCP entries that are not objects instead of dropping them
- reject unknown signal names in `signalActions` and IDE extension entries without an exact version when a policy file is loaded
- publish JSON schemas for decision reports, policy files, and v3 trust snapshots, and document agent integration and operating rules
- stop error messages from quoting input content: malformed JSON now reports only the file name, and Codex TOML inline-table errors no longer echo the entry, which could contain a credential
- reject unquoted TOML values (bare words, dates) instead of reading them as strings

- add `inspect-ide-extensions`, `snapshot-ide-extensions`, `approve-ide-extensions`, and `recheck-ide-extensions` for VS Code-compatible editor extension directories (VS Code, Cursor)
- allow IDE extensions only through exact-version `trustedIdeExtensions` pins with optional installed-file digests; add a `blockedIdeExtensions` deny-list that policy overlays cannot shrink
- digest every installed extension file (contents and executable bit) without following symlinks, never let `.obsolete` hide a registered extension, and fail closed on malformed or non-regular registries, missing manifests, registry/manifest mismatches, version ranges, and locations outside the supplied directory or through symlinks
- keep unpinned IDE extensions at ASK or stricter and IDE integrity signals at BLOCK regardless of policy overlays
- pin the npm CLI used by the release and publish workflows to an exact version

## 0.11.0 - 2026-10-24

- add short-lived Ed25519 producer attestations for exact value-free Claude/Codex runtime inventories
- reject wrong-key, mutated, expired, stale, excessive-lifetime, and future-dated runtime evidence
- add schema-v2 effective evidence with fail-closed authentication state, producer-key drift, CLI workflows, tests, and operations guidance

## 0.10.0 - 2026-10-24

- add an explicit value-free Claude/Codex runtime MCP inventory contract and effective-boundary reconciliation
- block observed BLOCK or unconfigured servers and require review for ASK/broad-grant exposure
- add self-validating runtime evidence snapshots, drift classification, versioned schemas, and inert fixtures

## 0.9.0 - 2026-10-24

- bind Claude Code and Codex MCP policy/provenance results to automatic tool grants without retaining permission specifiers or tool names
- add self-validating binding snapshots, drift classification, versioned JSON schemas, and inert adversarial fixtures
- fail closed on unmatched or ambiguous Claude MCP permission rules and blocked/provenance-mismatched automatic grants

## 0.8.0 - 2026-10-24

- add explicit Claude Code and Codex settings-stack inspection using documented source precedence
- add schema-v2 merged permission posture snapshots that omit source paths and require review for source-topology drift
- fail closed on malformed lower-precedence sources even when a higher source would override them

## 0.7.0 - 2026-10-24

- add self-validating Claude and Codex permission posture snapshots and autonomy-expansion review gates
- add inert adversarial permission fixtures that verify value-free inspection, snapshot, and diff output

## 0.6.0 - 2026-10-24

- add static Claude Code permission inspection for automatic shell, filesystem, network, MCP, and subagent grants
- add static Codex approval, sandbox, network, writable-root, web-search, and subagent settings inspection
- fail closed on unsupported security-relevant settings without retaining command, path, domain, hook, credential-helper, or unrelated setting values
- document the project's defensive AI-agent security use case, authorization boundary, CVP evidence boundary, and reproducible evaluation
- include inert examples in the published package so documented local evaluations remain reproducible from npm artifacts

## 0.5.1 - 2026-10-24

- exclude URL credentials, query values, and sensitive command arguments from configuration fingerprints while retaining trust-relevant endpoint structure

## 0.5.0 - 2026-10-07

- add Claude MCP JSON inspection and gating for stdio, HTTP, and SSE configurations
- fail closed on unsupported Claude settings and unresolved command/endpoint expansion
- review authentication header metadata and block shell-based header helpers by default without retaining secret values
- add Claude-specific snapshots and signed approval/recheck commands
- document Claude Code and Claude Desktop gating workflows

## 0.4.4 - 2026-10-06

- add a documented defensive security research policy and reproducible evaluation record
- add inert adversarial MCP fixtures with enforced ALLOW / ASK / BLOCK expectations and drift tests
- produce checksums and a CycloneDX SBOM for future GitHub releases
- create GitHub build-provenance and SBOM attestations for future release packages

## 0.4.3 - 2026-09-30

CLI correctness and Codex maintenance readiness:

- fix `trustdex --version` and the help banner reporting 0.4.0 in the 0.4.2 package; the CLI now reads its version from `package.json`
- add Codex review guidelines to AGENTS.md that encode TrustDex's security invariants as review findings
- add a Codex integration guide (docs/CODEX.md)
- add a pilot feedback issue form
- update CodeQL init and analyze together and group their Dependabot updates

## 0.4.2 - 2026-09-19

Trusted npm publishing migration:

- authorize only `grigent/trustdex` and `.github/workflows/publish.yml` through npm Trusted Publisher OIDC
- remove the long-lived `NPM_TOKEN` fallback from the publication workflow
- retain Sigstore provenance for every npm release
- align npm and GitHub Action examples with the verification release

## 0.4.1 - 2026-09-19

npm packaging correction:

- preserve the `trustdex` command in the published npm manifest with a normalized `bin` path
- normalize repository metadata for npm and provenance tooling
- document direct `npx trustdex` usage and expose the npm version badge

## 0.4.0 - 2026-09-19

Security hardening, artifact integrity, and public maintenance readiness:

- run full cross-platform CI on Ubuntu, Windows, and macOS
- exercise the composite GitHub Action end to end in CI
- verify user-supplied artifact bytes against npm SRI or MCP Registry SHA-256 metadata
- bind integrity evidence to package versions and block configuration mismatches
- redact remote URL credentials, paths, and query values from inspection output
- flag embedded URL credentials, insecure transport, and URL query parameters
- normalize Windows executable paths and command wrappers across platforms
- fail closed on unsupported Codex MCP keys and subsections
- fingerprint supported Codex execution controls
- add CodeQL, immutable GitHub Action pins, dependency updates, and ownership rules
- add governance, support, architecture, roadmap, and contribution templates

## 0.3.0 - 2026-09-19

Reviewable provenance and Codex integration:

- trust-relevant fingerprints for MCP config, skills, and plugin manifests
- signed approval bundles with automatic `APPROVED` / `NEEDS_REVIEW` rechecks
- explicit GitHub repository and npm registry provenance lookups
- official MCP Registry v0.1 provenance lookup
- GitHub latest-release signature verification
- focused Codex `config.toml` MCP parser and section gate
- support for both `mcpServers` and `servers` JSON container shapes
- additional tests for identity mismatch, signature state, fingerprint drift, and Codex gating

## 0.2.0

Trust and provenance gate:

- built-in `strict`, `official-first`, and `development` policy packs
- explicit provenance trust store with evidence metadata
- runtime MCP gate that outputs only policy-approved servers
- Agent Skill and plugin manifest inspection
- snapshot schema v2 with provenance drift detection
- Ed25519-signed trust records
- GitHub Action support
- expanded security tests and documentation

## 0.1.0

Initial working prototype:

- inspect MCP JSON configuration locally
- classify package, remote, local, and unknown sources
- detect trust-relevant signals without printing secret values
- apply ALLOW / ASK / BLOCK policy decisions
- generate deterministic snapshots
- diff snapshots for source and signal drift
- Node.js test suite and GitHub Actions CI
