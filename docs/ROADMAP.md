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

## Now: harden the boundary

- expand adversarial fixtures for MCP JSON, Codex TOML, skills, and plugin manifests
- keep expanding adversarial permission fixtures for both Claude Code and Codex
- verify that all human-readable output remains free of secret values
- improve cross-platform source and path normalization
- document stable policy and snapshot schema rules
- keep CI, CodeQL, and release automation reproducible and reviewable

## Next: make agent action boundaries reviewable

- connect approved tool provenance to the action permissions granted to that tool
- extend the versioned permission-posture JSON schemas to additional decisions and runtimes
- document how advisory settings checks compose with runtime and operating-system sandboxes
- add runtime-produced effective-setting evidence without silently discovering private files

## Then: prove integrity

- verify immutable package artifacts when registries expose cryptographic hashes
- connect registry observations to exact package versions and repository identities
- publish checksums or stronger provenance for TrustDex releases
- add fixtures for ownership transfer, deleted releases, yanked packages, and registry drift

## Later: expand interoperability

- extend signed snapshot, approval, and recheck workflows to Codex `config.toml`
- add adapters for additional agent runtimes and registries
- publish a compatibility matrix backed by tests
- explore organization-managed trust stores and review-key rotation

## Adoption goals

The project is seeking pilot users willing to share non-sensitive feedback about false positives, false negatives, configuration formats, and maintainer workflow. Usage claims will be documented only when they can be verified; stars, branding, and package names are never treated as security evidence.

## How to help

If you ran TrustDex on a real configuration, the **Pilot feedback** issue form is the fastest way to report results. Otherwise, open a focused issue describing the use case and redacted configuration shape. For security-sensitive proposals, include the expected trust boundary and bypass cases.
