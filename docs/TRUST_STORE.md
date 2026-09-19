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

## Integrity-backed package evidence

The optional `--artifact` flag on `trust-source npm` and `trust-source mcp` verifies a user-supplied file before recording artifact evidence.

- npm observations require an SRI value using SHA-256, SHA-384, or SHA-512
- MCP Registry observations require a single package with a SHA-256 digest
- the file is read locally and is never executed or uploaded
- the trust-store claim records the registry identifier, version, expected integrity metadata, computed digest, and verification time
- the configured package version must match the verified artifact version

Example evidence shape:

```json
{
  "kind": "npm-registry",
  "reference": "https://www.npmjs.com/package/example-mcp-server",
  "checkedAt": "2026-09-19T00:00:00Z",
  "artifact": {
    "registryType": "npm",
    "identifier": "example-mcp-server",
    "version": "1.2.3",
    "integrity": "sha512-..."
  },
  "artifactVerification": {
    "verified": true,
    "algorithm": "sha512",
    "digest": "...",
    "encoding": "base64",
    "version": "1.2.3",
    "identifier": "example-mcp-server",
    "verifiedAt": "2026-09-19T00:00:01Z"
  }
}
```

Artifact integrity proves only that the supplied bytes match the registry metadata observed at that time. It does not prove that the bytes are safe, that the registry account was uncompromised, or that the publisher name is legitimate.
