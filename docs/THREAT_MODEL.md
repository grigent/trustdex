# Threat model

TrustDex addresses one narrow question:

> **Should an agent be allowed to see and invoke this extension under the user's policy?**

## In scope

- unknown or unapproved MCP sources
- floating package versions that can change without review
- source changes between approved snapshots
- newly observed shell, filesystem, network-endpoint, install-on-run, or secret-environment signals
- policy regressions that turn a previous ASK/BLOCK into an unintended ALLOW

## Out of scope

- proving arbitrary third-party code is non-malicious
- sandboxing tool execution
- detecting every prompt-injection technique
- vulnerability scanning of transitive dependencies
- verifying publisher identity from names alone
- protecting a fully compromised host

## Design principle

TrustDex should never convert missing evidence into trust. Unknown provenance is a policy input, not a reason to guess.
