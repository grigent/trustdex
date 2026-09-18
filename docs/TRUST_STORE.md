# Trust store and provenance

TrustDex does not guess whether a publisher is "official" from a package name, GitHub stars, or branding.

A source can receive a `verified` provenance assertion only when the user or an organization places an explicit claim in a local trust store.

## Format

```json
{
  "version": 1,
  "claims": [
    {
      "type": "package",
      "subject": "example-mcp-server",
      "publisher": "Example Publisher",
      "status": "verified",
      "evidence": {
        "kind": "manual-review",
        "reference": "https://example.invalid/security-review",
        "checkedAt": "2026-09-19T00:00:00Z"
      }
    }
  ]
}
```

Supported claim types:

- `package` - npm/Python-style package subject
- `remote` - remote MCP hostname
- `repository` - repository identity for future repository adapters

The word `verified` means **verified according to the evidence recorded by the trust-store maintainer**. It does not mean OpenAI, TrustDex, GitHub, npm, or another platform certified the extension.

## Use it

```bash
node ./bin/trustdex.mjs inspect ./examples/mcp.json \
  --pack official-first \
  --trust-store ./examples/trust-store.example.json
```

Unknown third-party sources remain blocked in `official-first`. A verified provenance assertion can establish initial trust, but blocking capability signals such as shell execution can still override that trust.

## Recommended practice

- keep trust stores in source control when they are team policy
- link each claim to durable evidence
- pin package versions or source commits where possible
- re-review claims when ownership or capabilities change
- do not record credentials, tokens, private URLs, or secrets in evidence fields
