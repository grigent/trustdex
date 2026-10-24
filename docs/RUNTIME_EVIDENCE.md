# Authenticated runtime evidence

<p align="right">
  <strong>English</strong> | <a href="./RUNTIME_EVIDENCE.ko.md">한국어</a>
</p>

TrustDex can authenticate a value-free runtime inventory produced by an authorized
Claude or Codex integration. Authentication proves which pinned Ed25519 key signed the
exact inventory and whether the short-lived attestation is fresh. It does not prove
that the adapter is uncompromised, that the inventory is complete, or that the runtime
enforced the reviewed policy.

## End-to-end workflow

Generate a dedicated producer key pair once. Keep the private key with the adapter and
distribute the public key through a trusted channel to each verifier:

```bash
node ./bin/trustdex.mjs keygen \
  --private .trustdex/runtime-producer-private.pem \
  --public .trustdex/runtime-producer-public.pem
```

The authorized adapter writes `agent-runtime-tool-inventory` JSON containing only the
runtime, capture time/method, server names, and per-server tool counts. Sign that exact
file immediately; the default lifetime is five minutes and the maximum is 24 hours:

```bash
node ./bin/trustdex.mjs sign-runtime-inventory \
  ./runtime-tool-inventory.json \
  --private .trustdex/runtime-producer-private.pem \
  --out .trustdex/runtime-attestation.json \
  --ttl-seconds 300
```

Verify producer identity, signature, expiry, and capture freshness before reconciliation:

```bash
node ./bin/trustdex.mjs verify-runtime-inventory \
  ./runtime-tool-inventory.json \
  --attestation .trustdex/runtime-attestation.json \
  --public .trustdex/runtime-producer-public.pem \
  --max-age-seconds 120 \
  --json

node ./bin/trustdex.mjs snapshot-runtime-tools \
  .trustdex/claude-bindings.json \
  ./runtime-tool-inventory.json \
  --attestation .trustdex/runtime-attestation.json \
  --public .trustdex/runtime-producer-public.pem \
  --max-age-seconds 120 \
  --require-authenticated \
  --out .trustdex/runtime-tools.json
```

An invalid, expired, stale, future-dated, wrong-key, or inventory-mismatched attestation
exits `2`. Without authentication, schema-v2 effective evidence is always at least
`needs-review`; observed blocked or unconfigured servers still produce `block`.

## What is signed

The Ed25519 signature covers the schema and algorithm identifiers, canonical inventory
digest, runtime, capture time and method, producer public-key ID, creation time, and
expiry. The key ID is the SHA-256 digest of the public SPKI bytes. The separate inventory
schema rejects raw tool lists and arbitrary fields, so neither the attestation nor the
effective report contains tool names, endpoints, credentials, or private-key material.

The optional `--max-age-seconds` limit is independent of attestation expiry: expiry caps
how long the signature is usable, while maximum age caps how old the underlying capture
may be. TrustDex also rejects captures and attestations more than five minutes in the
future to tolerate only bounded clock skew.

## Operations and key rotation

- Use a producer-specific key, protect the private file with least privilege, and never
  commit it. A generic review-record key may work cryptographically but should remain a
  separate operational role.
- Pin the expected public key outside the inventory/attestation channel. A signature is
  not an identity claim if an attacker can replace both the evidence and its public key.
- Archive the inventory, attestation, pinned key ID, binding snapshot, and effective
  report together when audit retention is required. The effective report is
  self-consistent but is not independently signed.
- For rotation, distribute the new public key first, update orchestration to accept the
  old or new pinned key during a bounded overlap, then switch the producer and retire the
  old key. TrustDex verifies one supplied key per invocation; key allowlists and revocation
  remain deployment responsibilities.
- Treat `producer-key-changed` and `inventory-authentication-changed` diffs as review
  events. If a private key is suspected to be stolen, remove that key from verifiers and
  reissue evidence with a new key.

The contracts are defined by
[`runtime-tool-inventory-v1.schema.json`](../schemas/runtime-tool-inventory-v1.schema.json),
[`runtime-tool-inventory-attestation-v1.schema.json`](../schemas/runtime-tool-inventory-attestation-v1.schema.json),
[`effective-runtime-tools-v2.schema.json`](../schemas/effective-runtime-tools-v2.schema.json),
and [`effective-runtime-tools-diff-v2.schema.json`](../schemas/effective-runtime-tools-diff-v2.schema.json).

