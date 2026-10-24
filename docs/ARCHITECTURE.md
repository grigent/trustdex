# Architecture

<p align="right">
  <strong>English</strong> | <a href="./ARCHITECTURE.ko.md">한국어</a>
</p>

TrustDex is a dependency-free Node.js CLI that separates observation, policy, gating, and review evidence.

## Data flow

1. An adapter reads an MCP JSON file, a focused Codex TOML subset, a Claude/Codex permission settings file, a skill, or a plugin manifest.
2. Inspection normalizes the source and emits observable signals. Secret values are not retained in reports.
3. Optional trust-store claims attach explicit provenance evidence.
4. The policy engine produces ALLOW, ASK, or BLOCK.
5. A gate emits only the approved configuration.
6. MCP snapshots, permission posture snapshots, provenance-permission binding snapshots, and signed trust records make later drift reviewable.
7. An explicitly supplied value-free runtime inventory can be reconciled with reviewed bindings; TrustDex does not discover or intercept the runtime.

The gate is the enforcement boundary. Reports alone do not prevent an agent from loading an unreviewed extension.

## Modules

| Area | Responsibility |
| --- | --- |
| src/inspect.mjs | MCP source classification, redaction, fingerprinting, and signals |
| src/codex-config.mjs | Focused fail-closed Codex MCP parsing and section filtering |
| src/codex-settings.mjs | Codex approval, sandbox, network, writable-root, web-search, and subagent settings inspection |
| src/claude-settings.mjs | Claude Code permission rules and adjacent executable settings inspection |
| src/extensions.mjs | Skill and plugin manifest inspection |
| src/provenance.mjs | Explicit local trust-store claims |
| src/provenance-online.mjs | User-invoked GitHub, npm, and MCP Registry observations plus local artifact-digest verification |
| src/policy.mjs | Monotonic policy evaluation; signals may raise severity |
| src/gate.mjs | Output only approved MCP entries |
| src/snapshot.mjs | Deterministic trust-relevant state and drift |
| src/posture.mjs | Value-free Claude/Codex permission posture snapshots and autonomy-expansion classification |
| src/bindings.mjs | Value-free MCP source/provenance to automatic-tool-grant bindings and drift classification |
| src/runtime-evidence.mjs | Explicit runtime inventory validation, effective-boundary reconciliation, and exposure drift |
| src/trust-record.mjs | Ed25519 review-record signing and verification |
| src/review.mjs | Signed-baseline comparison |

## Security invariants

- Inspection must not execute the inspected extension.
- Secret values must not be printed or stored in snapshots.
- Permission rule values, writable-root paths, hook/helper bodies, and unrelated settings values must not be retained in agent-settings reports.
- Permission posture snapshots must omit source paths and setting values; new autonomy or changed policy semantics must require review.
- Binding snapshots must omit permission specifiers and tool names; an automatic grant to ASK/BLOCK, wildcard expansion, provenance change, or ambiguous/unbound rule must never appear as safely bound.
- Runtime evidence must reject raw tool lists and unexpected fields, block observed BLOCK/unconfigured servers, and treat newly observed servers or tool-count growth as reviewable expansion.
- Unknown evidence must not become trust.
- A blocking signal must not be lowered by provenance.
- Unsupported security-relevant syntax must fail closed.
- Network lookup is explicit and observation is not approval.
- ALLOW is a policy result, not a safety certification.

Settings inspection is advisory. It can read one source file or an explicitly supplied
Claude/Codex source stack and calculate the documented precedence for the supported
security fields. It does not discover active files, profiles, environment overrides,
requirements, or server-delivered policy, and it does not prove the reported policy is
active. MCP gates remain the implemented enforcement boundary; operating-system and
runtime sandboxes enforce agent actions.

Binding snapshots compose two static projections: MCP inspection/policy results and
automatic tool grants parsed from explicitly supplied runtime settings. They do not
discover effective settings or intercept tool calls. A `bound` result means the
observed scoped grant points to an ALLOW source under the supplied evidence, not that
the tool implementation is safe or that the runtime loaded those files.

Runtime evidence adds a third, opt-in projection supplied by an authorized adapter. Its
contract contains server names and tool counts, not tool names, endpoints, paths, or
credentials. The inventory digest authenticates internal state only; an operator must
authenticate the producer and confirm completeness through a separate trusted channel.

## Dependency policy

Runtime code currently uses only Node.js built-ins. A new dependency requires an issue explaining why the feature cannot reasonably be implemented with the platform, the package's maintenance and security posture, and the effect on the supply-chain boundary.
