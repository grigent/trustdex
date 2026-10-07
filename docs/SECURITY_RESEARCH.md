# Defensive security research

<p align="right">
  <strong>English</strong> | <a href="./SECURITY_RESEARCH.ko.md">한국어</a>
</p>

TrustDex is developed for legitimate defensive research into trust decisions made before AI agents receive access to third-party tools. This document defines the authorization, safety, and disclosure boundaries for that work.

## Purpose

The research asks whether observable configuration, provenance, integrity, and capability evidence is sufficient to keep an extension unavailable until a human or policy explicitly trusts it. Current work focuses on:

- unpinned or substituted packages
- install-on-run and shell launchers
- embedded URL credentials and insecure remote transport
- secret-bearing environment variable names without retaining their values
- source, provenance, decision, fingerprint, and capability drift
- signed review records and re-review after trust-relevant change
- parser behavior that must fail closed on unsupported syntax

The intended outputs are reproducible fixtures, regression tests, documented limitations, and practical mitigations for agent developers and operators.

## Authorization boundary

Research is limited to:

- systems and accounts owned by the researcher; or
- systems for which the researcher has explicit authorization to test; and
- isolated local or purpose-built test environments using non-sensitive fixtures.

TrustDex research does not authorize testing unrelated public systems. It excludes credential theft, persistence, destructive actions, data exfiltration, mass exploitation, unauthorized access, malware deployment, and bypassing another party's safeguards.

## Safe test data

Checked-in adversarial fixtures are inert configuration documents. They use reserved `.invalid` domains, nonexistent package namespaces, and unmistakable placeholder values. TrustDex does not execute MCP servers during inspection.

Tests assert that secret-like values, URL credentials, query values, and private paths do not appear in inspection results. A fixture that requires a real credential, private endpoint, personal data, or production service is not acceptable for this repository.

## Method

Each research case should contain:

1. a minimal, reviewable input fixture
2. the expected trust-relevant signals
3. the expected `ALLOW`, `ASK`, or `BLOCK` decision under a named policy
4. an automated regression test
5. a documented limitation or plausible bypass condition

An `ALLOW` result means only that observed evidence matched the selected policy. It is never represented as proof that arbitrary code is safe.

## Handling findings

Potential TrustDex vulnerabilities that could put users at risk should follow [SECURITY.md](../SECURITY.md). Findings in another project should be disclosed through that project's authorized security channel and should not be published before a reasonable coordinated-disclosure process.

Public reports must remove credentials, private endpoints, proprietary prompts, personal data, and exploit details that would create unnecessary risk. Research notes should prefer the minimum evidence needed to reproduce and fix the issue.

## Current reproducible evidence

- [Adversarial MCP fixtures](../examples/adversarial/README.md)
- [Evaluation record](EVALUATION.md)
- [Threat model](THREAT_MODEL.md)
- [Security policy](../SECURITY.md)

The project welcomes verifiable pilot feedback, including false positives and false negatives, through the repository's Pilot feedback issue form. Popularity, branding, and unverifiable testimonials are not treated as security evidence.
