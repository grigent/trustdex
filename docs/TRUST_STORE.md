# Trust store and provenance

<p align="right">
  <strong>English</strong> | <a href="./TRUST_STORE.ko.md">한국어</a>
</p>

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

## npm build provenance

`provenance npm` and `trust-source npm` also read the SLSA provenance npm reports for the latest version. They compare its source repository with the repository the package declares now and declared in its previous version:

| Result | Meaning | `trust-source` |
|---|---|---|
| `matched` | built by the declared GitHub repository | records `buildProvenance` (source repository, workflow path) in the claim |
| `absent` | the package never published provenance | records the claim without it |
| `dropped` | the latest version has no provenance although an earlier version did | refuses |
| `mismatch` | built by a different repository than the package declares or declared before, as with a release built from an attacker's fork | refuses |
| `unverifiable` | the attestation could not be fetched or parsed, or its subject does not match the version's sha512 | refuses |

The attestation is fetched from `registry.npmjs.org` for that exact name and version only by these explicit commands; `check-install` and `claude-hook` do not make this request. TrustDex checks that the attestation names the exact version and its sha512 digest, and verifies its Sigstore bundle offline with Node's built-in crypto against a trust root pinned in the package (no extra request, no dependency). A match is recorded with `signatureVerified: true` only when all of these hold: the DSSE signature verifies under the signing certificate; that certificate chains to a pinned Fulcio root and was valid at the logged time; it was issued for GitHub Actions and names the same source repository; it carries an embedded signed certificate timestamp (SCT) from a pinned certificate-transparency log; and the Rekor log entry is for this exact envelope and carries a valid signed entry timestamp from the pinned log key. Anything else is `unverifiable` and `trust-source` refuses it.

The entry's Merkle inclusion proof is also checked, up to a tree head (checkpoint) signed by the pinned log key. Only a bundle in the 2023 format 0.1 whose log-signed time is before 2024 may carry the log's signed promise without a proof; a proof that is present must verify. When every other check passes and only the proof is missing, the result is `unverifiable` with the reason `inclusion-proof-missing`, so it can be told apart from a bad signature or certificate (`signature-not-verified`).

Compatibility: TrustDex 0.19.0 did not check inclusion proofs, so some public bundles that it reported as `matched` are `unverifiable` from 0.20.0. For example, the SLSA provenance npm serves for `sigstore@2.2.1` and `@sigstore/sign@2.2.2` is a format 0.1 bundle logged on 2024-02-08 without an inclusion proof. The 2024 cutoff is unchanged: those releases are refused by `trust-source` with `inclusion-proof-missing`, and a claim recorded for them by 0.19.0 is not changed. Record such a package by manual review or with `--artifact` evidence instead.

Not checked: RFC 3161 timestamps, consistency between tree heads (a log that shows different views to different clients is not detected), and trust-root rotation (the root is pinned, so a release signed under a newer Sigstore key is reported as `unverifiable` until TrustDex is updated; see [Refreshing the pinned Sigstore trust root](TRUST_ROOT.md)). A verified signature shows which repository's workflow built the package; it does not prove that the repository or its workflow is safe.

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

For verified artifact-to-runner matching, TrustDex supports npm evidence for the\n`npx`, `pnpx`, and `bunx` runners, and PyPI evidence for `uvx`. If the\nrunner is unknown, absent, or differs from the artifact registry, the claim\nis treated as a mismatch and cannot authorize execution.\n\nArtifact integrity proves only that the supplied bytes match the registry metadata observed at that time. It does not prove that the bytes are safe, that the registry account was uncompromised, or that the publisher name is legitimate.
