# Threat model

TrustDex addresses one narrow question:

> **Should an agent be allowed to see and invoke this extension under the user's policy?**

## In scope

- unknown or unapproved MCP sources
- floating package versions that can change without review
- source changes between reviewed snapshots
- provenance assertions changing or disappearing
- newly observed shell, filesystem, network, install, wildcard-tool, or secret-environment signals
- unsafe tool exposure caused by policy regressions
- substitution of package bytes that do not match reviewed registry integrity metadata
- configured package versions drifting from an integrity-verified artifact version
- tampering with a reviewed snapshot when a signed trust record is available

## Trust boundaries

TrustDex trusts:

- the local host enough to read its own policy/configuration
- the user's explicitly configured policy
- provenance evidence only to the extent that the trust-store maintainer reviewed it
- a public key only when the user obtained that key through a trusted channel

TrustDex does **not** treat a familiar project name, star count, package name, or logo as provenance.

## Out of scope

- proving arbitrary third-party code is non-malicious
- sandboxing tool execution
- detecting every prompt-injection technique
- vulnerability scanning of all transitive dependencies
- proving that integrity-matching package bytes are non-malicious
- independently proving publisher ownership from a local trust-store claim
- protecting a fully compromised host
- protecting a stolen signing private key

## Important failure mode

A valid signature proves that a trust record was signed by the corresponding private key and that its bound snapshot digest has not changed. It does not prove that the original review was correct.

## Design principle

TrustDex should never convert missing evidence into trust. Unknown provenance is a policy input, not a reason to guess.
