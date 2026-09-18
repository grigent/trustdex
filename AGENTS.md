# AGENTS.md

TrustDex is a security-sensitive, local-first CLI. Changes should prefer small, auditable code over large dependency trees.

## Development rules

- Node.js 20+ only; prefer built-in Node modules.
- Do not add telemetry or network calls without an explicit design discussion.
- Never print secret values. Environment variable names may be reported; values must not be.
- Treat ALLOW as a high-confidence decision. When evidence is incomplete, prefer ASK or BLOCK.
- Security claims must describe exactly what is checked; do not imply that static inspection proves a tool is safe.
- Add tests for every new trust signal or policy rule.

## Before opening a PR

```bash
npm test
npm run check
node ./bin/trustdex.mjs inspect ./examples/mcp.json --policy ./examples/trustdex.policy.json
```

The example intentionally contains an unknown server, so the final command exits non-zero.
