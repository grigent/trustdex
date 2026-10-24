# Defensive AI-agent security use case

<p align="right">
  <strong>English</strong> | <a href="./DEFENSIVE_USE_CASE.ko.md">한국어</a>
</p>

This document makes the legitimate defensive purpose and operating boundary of TrustDex easy to verify. It is an evidence index, not an Anthropic endorsement, a CVP approval, or an attestation that any particular operator satisfies account-level security requirements.

## Problem being addressed

As coding agents become more autonomous, their effective attack surface includes more than the model. It also includes the tools they can load, the permissions they receive without a prompt, the credentials those tools can reference, and the configuration changes that may silently widen access over time.

TrustDex researches and implements pre-exposure controls for that surface. The current project asks two concrete questions:

1. Should an agent be allowed to see and invoke a particular MCP server, skill, or plugin under an explicit local policy?
2. Do Claude Code or Codex settings grant automatic shell, filesystem, network, MCP, subagent, or sandbox capabilities that need review or blocking?

## Intended defensive work

The project uses AI assistance for work on TrustDex itself and other systems the operator owns or is explicitly authorized to test. Typical tasks include:

- reviewing parsers and policy code for fail-open behavior
- developing inert adversarial configuration fixtures
- checking that reports, snapshots, and fingerprints do not retain secret values
- threat modeling permission expansion, provenance substitution, and review drift
- writing regression tests for defensive findings and proposed mitigations
- analyzing false positives and false negatives from fully redacted pilot feedback

This work is defensive engineering. It does not require credential theft, persistence, destructive actions, data exfiltration, malware deployment, mass exploitation, or unauthorized access.

## Authorization and data boundary

- Testing is limited to the operator's own repositories and accounts, explicitly authorized systems, and isolated local test environments.
- Checked-in adversarial inputs are inert data. They use reserved `.invalid` domains, nonexistent package identities, and placeholder values.
- Normal inspection is local-only and does not execute inspected MCP servers, Claude permission rules, skills, plugins, or hooks.
- Explicit provenance commands may query public GitHub, npm, or MCP Registry metadata. Observation is never converted into trust without a separate user action.
- Real credentials, private endpoints, customer data, proprietary prompts, and exploit material do not belong in public fixtures or reports.

## Controls evidenced by this repository

| Control objective | Public evidence |
| --- | --- |
| Keep unreviewed tools away from the agent | ALLOW/ASK/BLOCK policy engine and filtered MCP gates |
| Detect capability expansion | MCP, Claude Code, and Codex settings signals plus adversarial regression tests |
| Avoid silent parser bypass | focused adapters reject unsupported security-relevant syntax |
| Keep secrets out of evidence | tests for redaction from output, snapshots, and configuration fingerprints |
| Make approval drift visible | deterministic snapshots, Ed25519 review records, and recheck commands |
| Reconcile source trust with automatic grants | value-free Claude/Codex binding snapshots, schemas, diffs, and inert fixtures |
| Compare reviewed intent with explicit runtime evidence | value-free inventory contract, effective-boundary reconciliation, and exposure drift tests |
| Reduce supply-chain ambiguity | explicit provenance observations, artifact digest verification, release checksums, SBOMs, and build attestations |
| Keep research reproducible | inert fixtures, documented expectations, cross-platform CI, and CodeQL |

An ALLOW result is still only a policy result over observed evidence. TrustDex is not a sandbox, malware scanner, or proof that third-party code is safe.

## Claude Code and Codex permission research

`inspect-claude-settings` examines the documented `permissions` object and reports automatic approval of shell, filesystem, network, MCP, and subagent capabilities. It also surfaces the presence of hooks, credential helpers, environment settings, sandbox configuration, and plugin loading without retaining their values.

`inspect-claude-settings-stack` applies documented precedence to explicitly supplied user, project, local, session, and managed sources. This is static evidence, not runtime enforcement. It does not discover sources or prove that managed settings reached a session, and it does not replace Claude Code sandboxing. The operator must confirm the effective runtime configuration separately.

`inspect-codex-settings` evaluates Codex approval policy, reviewer choice, sandbox
class, network access, additional writable-root count, web-search mode, and explicit
subagent enablement. It reports custom permission, app, and plugin surfaces that it
does not fully parse without retaining their values. `inspect-codex-settings-stack`
applies documented system-through-CLI precedence to supplied files, including ordered
project layers. It does not discover the active layers, enforce requirements, or replace
the active Codex sandbox.

`snapshot-claude-bindings` and `snapshot-codex-bindings` connect each inspected MCP
source decision/provenance state to its automatic tool-grant shape. This makes broad
or blocked grants reviewable without retaining tool names or permission specifiers.
It remains static evidence and does not enforce runtime calls.

`snapshot-runtime-tools` accepts a value-free inventory from an authorized runtime
adapter and reconciles it with those bindings. This can surface loaded blocked sources
and unexpected servers without retaining tool names. The adapter remains outside the
TrustDex trust boundary, so its identity, transport, and completeness need independent
controls.

## CVP application boundary

Anthropic's current Cyber Verification Program application asks for verifiable identity or organization details, a description of security work, and an attestation to the controls for the requested tier. This repository can support the security-work description, but repository changes cannot establish the operator's identity or satisfy account and device controls by themselves.

An individual applicant should verify current requirements directly before applying. As of October 2026, Anthropic states that individuals are eligible for Defense Access only, must use personal access rather than shared sessions, must enable MFA, and must transition to phishing-resistant MFA and away from long-lived credentials by the published cutoff. Claude Code's OAuth sign-in is the intended first-party path. See the official [Cyber Verification Program](https://support.claude.com/en/articles/14604842-cyber-verification-program) and [CVP security requirements](https://support.claude.com/en/articles/17202708-cyber-verification-program-security-requirements).

Do not claim a control in an application unless it is actually implemented and can be evidenced. CVP access for internal work does not automatically authorize a customer-facing security service or product.

## Reproducible evidence

```bash
npm test
npm run check
npm run test:research

node ./bin/trustdex.mjs inspect-claude-settings \
  ./examples/claude.settings.json \
  --pack strict

node ./bin/trustdex.mjs inspect-codex-settings \
  ./examples/codex.permissions.toml \
  --pack strict
```

The Claude command intentionally exits with code `2` because its example contains a shell auto-approval rule. The Codex command exits with code `1` because bounded workspace-write capabilities still require review. See [Defensive evaluation](EVALUATION.md), [Security research](SECURITY_RESEARCH.md), and the [Threat model](THREAT_MODEL.md) for the expected results and limitations.
