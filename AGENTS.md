# AGENTS.md

TrustDex is a security-sensitive, local-first CLI. Changes should prefer small, auditable code over large dependency trees.

## Development rules

- Node.js 20+ only; prefer built-in Node modules.
- Do not add telemetry or network calls without an explicit design discussion.
- Never print secret values. Environment variable names may be reported; values must not be.
- Treat ALLOW as a high-confidence policy decision. When evidence is incomplete, prefer ASK or BLOCK.
- Never infer an "official" publisher from a name, logo, stars, popularity, or repository description.
- Provenance claims must include explicit evidence metadata and must state what "verified" means.
- A provenance assertion must never override a blocking capability signal.
- Security claims must describe exactly what is checked; do not imply that static inspection proves a tool is safe.
- Add tests for every new trust signal, policy rule, provenance adapter, and trust-record change.

## Review guidelines

Apply these when reviewing a TrustDex pull request, including automated `@codex review` runs. Treat a violation as a P0/P1 finding, not a style nit.

- Flag any change that can turn an ASK or BLOCK into ALLOW without new explicit evidence, or that lets missing, malformed, or unparseable input fall through to ALLOW.
- Flag any code path that can print, log, snapshot, or fingerprint a secret value (environment variable values, URL credentials, URL query values, private keys, tokens).
- Flag provenance or trust-store logic that infers publisher identity from names, branding, stars, or descriptions, or that lets a provenance claim override a blocking capability signal.
- Flag new network access outside the explicit `provenance` and `trust-source` commands, new runtime dependencies, and new `child_process` use in `bin/` or `src/`.
- Flag parser changes (MCP JSON, Codex TOML, `SKILL.md`, plugin manifests) that silently ignore unsupported syntax instead of failing closed.
- Flag signature, fingerprint, or snapshot schema changes that would let an old approval validate a changed configuration.
- Flag GitHub Actions changes that use an unpinned third-party action, widen `permissions`, or expose secrets to pull requests from forks.
- Flag a new trust signal, policy rule, provenance adapter, or trust-record change that has no test.
- Flag documentation that implies TrustDex proves a tool is safe or that "verified" means platform certification.

## Before opening a PR

```bash
npm test
npm run check
node ./bin/trustdex.mjs inspect ./examples/mcp.json \
  --pack strict \
  --policy ./examples/trustdex.policy.json
```

The example intentionally contains an unknown server, so the final command exits non-zero.
