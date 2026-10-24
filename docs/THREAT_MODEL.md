# Threat model

<p align="right">
  <strong>English</strong> | <a href="./THREAT_MODEL.ko.md">한국어</a>
</p>

TrustDex addresses one narrow question:

> **Should an agent see this extension or receive this automatic action capability under the user's policy?**

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
- Claude Code permission rules that silently auto-approve broad shell, filesystem, network, MCP, or subagent actions
- Codex configurations that remove the sandbox, suppress approvals, enable network access, or add writable roots
- action-permission settings changing without an explicit review
- Claude or Codex permission posture expanding relative to a value-free structural baseline
- precedence changes across explicitly supplied Claude or Codex settings sources
- automatic MCP tool grants that no longer match the server's policy/provenance result
- wildcard, unmatched, or ambiguous grants that hide the effective tool boundary
- explicitly reported runtime inventories that expose blocked, review-required, or unconfigured MCP servers
- effective runtime inventories expanding by server visibility or tool count
- mutation, replay past expiry/capture-age limits, future dating, or wrong-key substitution of signed runtime inventories

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
- automatically discovering every active settings source, profile, environment override, requirement, or server-delivered policy
- proving that the explicitly merged settings projection is the policy active at runtime
- enforcing Claude Code or Codex action permissions at runtime
- authenticating the author of an unsigned permission posture snapshot
- proving that a binding snapshot reflects the files actually loaded by a running agent
- intercepting or enforcing individual MCP tool calls at runtime
- proving inventory completeness or preventing a compromised adapter or stolen producer key from signing false evidence
- discovering live Claude/Codex sessions or reading their private state automatically

## Important failure mode

A valid signature proves that a trust record was signed by the corresponding private key and that its bound snapshot digest has not changed. It does not prove that the original review was correct.

Likewise, a valid runtime-inventory attestation proves that the pinned producer key
signed the exact value-free inventory within the checked time limits. It does not prove
that the producer observed every loaded tool or reported the runtime truthfully.

## Design principle

TrustDex should never convert missing evidence into trust. Unknown provenance is a policy input, not a reason to guess.
