# Roadmap

TrustDex is early-stage. This roadmap communicates direction and is not a release commitment.

## Now: harden the boundary

- expand adversarial fixtures for MCP JSON, Codex TOML, skills, and plugin manifests
- verify that all human-readable output remains free of secret values
- improve cross-platform source and path normalization
- document stable policy and snapshot schema rules
- keep CI, CodeQL, and release automation reproducible and reviewable

## Next: prove integrity

- verify immutable package artifacts when registries expose cryptographic hashes
- connect registry observations to exact package versions and repository identities
- publish checksums or stronger provenance for TrustDex releases
- add fixtures for ownership transfer, deleted releases, yanked packages, and registry drift

## Later: expand interoperability

- add adapters for additional agent runtimes and registries
- publish a compatibility matrix backed by tests
- define machine-readable decision output for CI and policy tooling
- explore organization-managed trust stores and review-key rotation

## Adoption goals

The project is seeking pilot users willing to share non-sensitive feedback about false positives, false negatives, configuration formats, and maintainer workflow. Usage claims will be documented only when they can be verified; stars, branding, and package names are never treated as security evidence.

## How to help

Open a focused issue describing the use case and redacted configuration shape. For security-sensitive proposals, include the expected trust boundary and bypass cases.
