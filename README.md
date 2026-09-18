# TrustDex

**A local-first trust policy layer for AI agent tools.**

TrustDex helps decide which MCP servers, skills, and plugins an AI agent should be allowed to use. Instead of treating every discovered extension as trusted, TrustDex evaluates observable evidence and returns one of three outcomes:

- **ALLOW** - matches an explicit trust policy
- **ASK** - needs human review
- **BLOCK** - not trusted under the current policy

> TrustDex is an early open-source project. It is not a malware scanner, sandbox, or security certification service. An ALLOW result only means the inspected evidence matched your policy.

## Why TrustDex?

AI agents increasingly rely on third-party MCP servers, skills, and plugins that may receive credentials, access files, connect to remote services, or execute local programs. A package being installable does not mean it should automatically become available to an agent.

TrustDex adds a small decision layer **before tool exposure**:

```text
User request
    |
    v
AI agent / Codex
    |
    v
TrustDex policy gate
    |-- ALLOW -> tool may be exposed
    |-- ASK   -> require human review
    `-- BLOCK -> keep tool unavailable
```

The long-term goal is to make extension trust explicit, reviewable, and portable across agent runtimes.

## v0.1 prototype

The first prototype focuses on MCP configuration files and trust-relevant drift. It can:

- inspect MCP server entries locally without uploading the config
- distinguish package, remote, local, and unknown sources
- flag observable signals such as unpinned versions, install-on-run launchers, shell execution, filesystem-looking arguments, secret-like environment variable names, and remote endpoints
- apply a local JSON policy and return ALLOW, ASK, or BLOCK
- create snapshots of reviewed state
- detect source, decision, and signal changes after updates

## Quick start

Requires Node.js 20+.

```bash
git clone https://github.com/grigent/trustdex.git
cd trustdex
npm test

node ./bin/trustdex.mjs inspect ./examples/mcp.json \
  --policy ./examples/trustdex.policy.json
```

Exit codes:

- `0` - all entries allowed
- `1` - at least one entry needs review
- `2` - at least one entry is blocked, or the command failed

## Policy example

```json
{
  "version": 1,
  "unknownAction": "block",
  "localAction": "ask",
  "sensitiveAction": "ask",
  "unpinnedAction": "ask",
  "shellAction": "block",
  "trustedPackages": ["@modelcontextprotocol/server-filesystem"],
  "allowedRemoteHosts": ["mcp.example.com"]
}
```

Trust is deliberately explicit. A familiar package name is not considered "official" by name alone. Publisher verification and registry-backed provenance are roadmap items and must rely on verifiable evidence.

## Capability drift

```bash
node ./bin/trustdex.mjs snapshot ./examples/mcp.json \
  --policy ./examples/trustdex.policy.json \
  --out .trustdex/baseline.json

node ./bin/trustdex.mjs diff .trustdex/baseline.json .trustdex/current.json
```

## Principles

1. **Local first.** Private agent configuration should not need to leave the machine.
2. **No blind trust.** Missing provenance should result in review or denial, not a guessed ALLOW.
3. **No secret values in output.** Environment variable names may be reported; values are not.
4. **Drift matters.** An approval for one version should not silently carry over after trust-relevant changes.
5. **Simple outcomes.** ALLOW / ASK / BLOCK instead of an opaque risk score.
6. **Vendor neutral.** The policy model should work across Codex and other agent runtimes.

## Roadmap

- [x] MCP config inspection prototype
- [x] local ALLOW / ASK / BLOCK policy
- [x] snapshot and drift detection
- [ ] signed trust records bound to source digest / commit SHA
- [ ] verifiable publisher and repository provenance adapters
- [ ] MCP Registry metadata adapter
- [ ] Agent Plugin / Skill manifest inspection
- [ ] GitHub Action with PR annotations
- [ ] policy packs such as `strict`, `official-first`, and `development`
- [ ] runtime adapter that exposes only policy-approved tools to supported agents

## Security

TrustDex does **not** prove that third-party code is safe and does not replace sandboxing, dependency scanning, code review, or least-privilege credentials.

See [SECURITY.md](SECURITY.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md).

## License

MIT
