# Defensive evaluation

<p align="right">
  <strong>English</strong> | <a href="./EVALUATION.ko.md">한국어</a>
</p>

This evaluation records the behavior enforced by the checked-in adversarial fixtures. Run `npm run test:research` to reproduce it. The test performs local static inspection only and does not execute or contact any configured server.

## MCP policy cases

The cases use the built-in `strict` policy with the small overlay in `examples/adversarial/policy.json`.

| Case | Required evidence | Expected decision | Reason |
| --- | --- | --- | --- |
| `trusted-pinned-package` | pinned package; explicitly trusted package name | `ALLOW` | the configured version is fixed and the policy contains an explicit package trust rule |
| `floating-version` | `install-on-run`, `unbounded-version` | `BLOCK` | a moving package version can change without review |
| `shell-launcher` | `shell-execution`, `filesystem-path` | `BLOCK` | shell execution is blocked by the strict policy |
| `credential-bearing-url` | `embedded-credentials`, `network-endpoint`, `url-query-parameters` | `BLOCK` | embedded credentials are blocking even when the host is allowlisted |
| `insecure-remote` | `insecure-transport`, `network-endpoint` | `BLOCK` | plaintext transport is blocking even when the host is allowlisted |
| `sensitive-local-env` | `filesystem-path`, `secret-env` | `ASK` | a local extension with a secret-like environment name requires review |
| `unknown-remote` | `network-endpoint` | `BLOCK` | the remote host has no explicit allowlist or provenance evidence |

Expected total: one `ALLOW`, one `ASK`, and five `BLOCK` decisions.

## Drift case

The drift fixture begins with the trusted pinned package and then introduces an `API_TOKEN` environment key. The regression test requires all of the following changes:

- `signals-added` for `secret-env`
- `decision-changed` from `ALLOW` to `ASK`
- `fingerprint-changed`

The placeholder value itself must not appear in either inspection result or snapshot.

## Claude Code permission cases

`test/claude-settings.test.mjs` exercises a focused `settings.json` boundary.

| Case | Required evidence | Expected decision |
| --- | --- | --- |
| restrictive `ask`/`deny`, plan mode, bypass disabled | no added risk signal | `ASK` because the file is local evidence |
| bare shell/filesystem/network/subagent allows plus bypass mode | broad auto-approval and bypass signals | `BLOCK` |
| narrow shell, web, MCP, and subagent allows | capability-specific auto-approval signals | `BLOCK` under `strict` because shell is auto-approved |
| hooks and credential helper | executable adjacent-setting signals | `BLOCK` |
| unsupported permission key or malformed rule | parser error | exit `2` |

The tests place placeholder values in command, domain, directory, hook, helper,
environment, plugin, and unknown settings fields and require that none appear in the
inspection result. No permission-settings fingerprint is created.

## Codex permission cases

`test/codex-settings.test.mjs` exercises approval and sandbox settings in `config.toml`.

| Case | Required evidence | Expected decision |
| --- | --- | --- |
| `read-only`, `on-request`, user review, network disabled | no added risk signal | `ASK` because the file is local evidence |
| `danger-full-access`, `never`, auto-review, live web search | unrestricted sandbox plus reduced human review | `BLOCK` |
| workspace write, network enabled, additional writable root | bounded capability-expansion signals | `ASK` |
| custom permission, plugin, or uninspected sections | explicit uninspected-surface signals | `ASK` |
| unsupported enum/type, mixed permission models, or unknown sandbox key | parser error | exit `2` |

Writable-root paths and unrelated setting values must not appear in results. No
Codex-settings fingerprint is created.

## Permission posture drift cases

`examples/adversarial/permissions/` contains paired restrictive and expanded settings
for both runtimes. `test/posture.test.mjs` requires:

- the restrictive baseline to remain `ASK`, without implying certification
- automatic shell/network/subagent grants and broader filesystem scope to raise risk
- `diff-permissions` to return `needs-review` for autonomy expansion and policy changes
- restriction-only changes to return `restricted` without a failure exit code
- snapshots with recomputed structural digests to omit source paths, rule values,
  writable paths, domains, commands, environment names and values, and adjacent-setting values
- a snapshot whose contents no longer match its digest to fail closed

The digest checks internal consistency, not signer identity. Same-count changes inside
redacted permission rules remain outside this structural comparison.

## Tool provenance and permission binding cases

`examples/adversarial/bindings/` and `test/bindings.test.mjs` join MCP policy/provenance
results to Claude and Codex automatic tool grants. The regression requires:

- a scoped Claude grant to an ALLOW source to be `bound`
- wildcard or all-tool grants and grants to ASK sources to require review
- grants to BLOCK sources or provenance mismatches to be `blocked`
- unmatched and ambiguous Claude rules to be counted without retaining their values
- policy, provenance, trust-store, and grant expansion drift to require review
- tampered summaries, statuses, or digests to fail closed
- endpoint paths, permission specifiers, tool names, and inert marker values to remain absent

The snapshot schemas validate the stable report shape. A signed trust record can
authenticate a reviewed snapshot, but neither the schema nor signature proves runtime
enforcement or tool safety.

## Merged settings stack cases

`test/settings-stack.test.mjs` exercises explicit source stacks for both runtimes. It requires:

- Claude permission lists to combine while managed/session/local/project/user scalar precedence is preserved
- project or local Claude sources not to activate `auto` or `bypassPermissions` default modes
- Codex system/managed/user/profile/project/CLI precedence and closest-project ordering
- invalid lower-precedence input to fail even when a higher source would replace the setting
- schema-v2 snapshots to retain only fixed scope counts and to require review when source topology changes
- source paths, rules, domains, commands, writable paths, environment names, and values to remain absent

## What this does not measure

This benchmark is intentionally narrow. It does not measure runtime behavior, sandbox escape, arbitrary malware, every form of prompt injection, publisher identity ownership, or vulnerabilities in transitive dependencies. The stack cases merge only sources explicitly supplied to the test; they do not discover active settings, requirements, environment overrides, or server-managed policy, and they do not prove that the reported sandbox is active. In particular, tool descriptions returned dynamically by an already-running MCP server are outside the current static configuration boundary.

The small fixture set is a regression baseline, not a statistical claim about detection accuracy. False-positive and false-negative rates require a larger, independently reviewed corpus of redacted real-world configurations.
