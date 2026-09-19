# Governance

TrustDex uses a lightweight maintainer-led governance model appropriate for an early-stage security project.

## Mission

TrustDex provides a reviewable policy boundary between AI agents and third-party extensions. The project favors conservative decisions, explicit evidence, local-first operation, and small auditable implementations.

## Roles

### Users

Users run TrustDex, report defects, propose use cases, and provide compatibility feedback.

### Contributors

Contributors submit issues, documentation, tests, or code. Repeated contribution is welcome but does not by itself grant merge or release authority.

### Maintainers

Maintainers triage issues, review pull requests, define releases, coordinate security reports, and protect the documented trust boundary. The current maintainer is @grigent.

## Decisions

Routine changes are decided through pull-request review. Significant changes should begin with a GitHub issue and include the threat model, compatibility impact, and alternatives considered.

A significant change includes:

- making an ALLOW path less conservative
- changing a public policy or snapshot schema
- adding network access
- adding a dependency
- changing provenance semantics
- changing release or signing behavior

The maintainer has final responsibility for merge and release decisions. Decisions should be explained in public issues or pull requests except where confidentiality is required for security.

## Releases

Releases must pass CI, syntax checks, package-content review, and version/tag validation. Release automation is kept in the repository so the process remains reviewable.

## Becoming a maintainer

Additional maintainers may be invited after sustained, high-quality contributions and demonstrated care with security reports, reviews, and project values. New maintainers are recorded in this file and CODEOWNERS.

## Changes to governance

Governance changes use the same public pull-request process and require approval from the current maintainer.
