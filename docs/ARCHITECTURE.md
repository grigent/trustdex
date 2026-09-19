# Architecture

TrustDex is a dependency-free Node.js CLI that separates observation, policy, gating, and review evidence.

## Data flow

1. An adapter reads an MCP JSON file, a focused Codex TOML subset, a skill, or a plugin manifest.
2. Inspection normalizes the source and emits observable signals. Secret values are not retained in reports.
3. Optional trust-store claims attach explicit provenance evidence.
4. The policy engine produces ALLOW, ASK, or BLOCK.
5. A gate emits only the approved configuration.
6. Snapshots and signed trust records make later drift reviewable.

The gate is the enforcement boundary. Reports alone do not prevent an agent from loading an unreviewed extension.

## Modules

| Area | Responsibility |
| --- | --- |
| src/inspect.mjs | MCP source classification, redaction, fingerprinting, and signals |
| src/codex-config.mjs | Focused fail-closed Codex MCP parsing and section filtering |
| src/extensions.mjs | Skill and plugin manifest inspection |
| src/provenance.mjs | Explicit local trust-store claims |
| src/provenance-online.mjs | User-invoked GitHub, npm, and MCP Registry observations plus local artifact-digest verification |
| src/policy.mjs | Monotonic policy evaluation; signals may raise severity |
| src/gate.mjs | Output only approved MCP entries |
| src/snapshot.mjs | Deterministic trust-relevant state and drift |
| src/trust-record.mjs | Ed25519 review-record signing and verification |
| src/review.mjs | Signed-baseline comparison |

## Security invariants

- Inspection must not execute the inspected extension.
- Secret values must not be printed or stored in snapshots.
- Unknown evidence must not become trust.
- A blocking signal must not be lowered by provenance.
- Unsupported security-relevant syntax must fail closed.
- Network lookup is explicit and observation is not approval.
- ALLOW is a policy result, not a safety certification.

## Dependency policy

Runtime code currently uses only Node.js built-ins. A new dependency requires an issue explaining why the feature cannot reasonably be implemented with the platform, the package's maintenance and security posture, and the effect on the supply-chain boundary.
