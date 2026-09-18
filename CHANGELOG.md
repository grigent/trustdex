# Changelog

## 0.3.0 - Unreleased

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
