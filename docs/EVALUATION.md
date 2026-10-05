# Defensive evaluation

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

## What this does not measure

This benchmark is intentionally narrow. It does not measure runtime behavior, sandbox escape, arbitrary malware, every form of prompt injection, publisher identity ownership, or vulnerabilities in transitive dependencies. In particular, tool descriptions returned dynamically by an already-running MCP server are outside the current static configuration boundary.

The small fixture set is a regression baseline, not a statistical claim about detection accuracy. False-positive and false-negative rates require a larger, independently reviewed corpus of redacted real-world configurations.
