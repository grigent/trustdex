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
- `--public` pins exactly one key per invocation. For allowlists, rotation overlaps, and
  revocation, use a `--keyset` file as described below.
- Treat `producer-key-changed` and `inventory-authentication-changed` diffs as review
  events. If a private key is suspected to be stolen, revoke it in the keyset (without
  `revokedAt`) and reissue evidence with a new key.

## Keysets: allowlists, rotation, and revocation

Every verifying command accepts `--keyset keyset.json` instead of `--public key.pem`:
`verify`, `recheck`, `recheck-claude`, `recheck-codex`, `recheck-ide-extensions`,
`verify-runtime-inventory`, and `snapshot-runtime-tools`. Giving both flags, or `--keyset`
twice, is an error. `--public` behaves exactly as before.

A keyset is a versioned, operator-written allowlist
([`trustdex-keyset-v1.schema.json`](../schemas/trustdex-keyset-v1.schema.json),
[example](../examples/trustdex-keyset.example.json)):

```json
{
  "schemaVersion": 1,
  "kind": "trustdex-keyset",
  "keys": [
    {
      "id": "<sha256 of the SPKI DER bytes>",
      "publicKey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
      "purposes": ["runtime-producer"],
      "notBefore": "2026-11-01T00:00:00.000Z",
      "notAfter": "2027-11-01T00:00:00.000Z",
      "note": "producer key 2026-11"
    }
  ],
  "revoked": [
    { "id": "<key id>", "note": "suspected compromise" },
    { "id": "<key id>", "revokedAt": "2026-11-01T00:00:00.000Z", "note": "retired" }
  ]
}
```

- **Key ID.** `id` is the SHA-256 of the key's SPKI DER bytes, the same value as an
  attestation's `producerKeyId`. Print it with `node ./bin/trustdex.mjs key-id key.pem`.
- **Strict parsing.** Unknown fields, a wrong `schemaVersion` or `kind`, an empty `keys`
  list, duplicate key or revocation IDs, an `id` that does not match its key, anything
  other than a single canonical `PUBLIC KEY` PEM block (private keys and certificates are
  rejected), non-Ed25519 keys, unknown purposes, timestamps that are not
  `YYYY-MM-DDTHH:mm:ss.sssZ`, and `notAfter` not after `notBefore` are hard errors (exit
  `2`). There is no fallback to `--public` or to a partial keyset.
- **Purposes.** Every key must list its `purposes`: `review` keys verify trust records
  (`verify`, `recheck*`); `runtime-producer` keys verify runtime inventory attestations.
  There is no default, so a key verifies both only when both are listed. Prefer separate
  keys so a review key cannot authenticate runtime evidence or the reverse.
- **Signed time.** Windows and revocation cutoffs are evaluated at the time recorded in the
  signed content: `createdAt` of the trust record or the attestation. `notBefore` is
  inclusive and `notAfter` is exclusive. A review signed inside the window therefore stays
  valid after the window closes; attestation expiry and `--max-age-seconds` still apply at
  verification time.
- **Trust records.** Trust records carry no key ID, so TrustDex finds the signer by trying
  every listed key and then applies revocation, purpose, and window checks to that key.
  With `--keyset`, a record without a valid `createdAt` is `INVALID`, and so is one whose
  `createdAt` is more than five minutes in the future; this stops a signer from
  forward-dating into a pre-distributed key's window. `--public` verification does not
  apply these time checks, as before.
- **Output.** Successful keyset verification prints the signing key ID (`Signing key:` for
  `verify` and `recheck`, `keyId` in `recheck --json`). Errors name field positions such as
  `keys[1].id`, never file contents, key material, or notes.

### Revocation timing

- A revocation **without `revokedAt` is total**: every signature by that key is `INVALID`,
  including reviews signed long before the revocation. This is the default and the right
  choice for a suspected compromise; re-approve affected reviews with a new key.
- A revocation **with `revokedAt`** keeps evidence whose signed time is strictly earlier
  than `revokedAt`; evidence signed at or after it is `INVALID`. The signed time is
  asserted by the key holder, so anyone holding a stolen private key can backdate it. Use
  `revokedAt` only to retire a key that is not suspected to be compromised, or treat it as
  an explicit decision to keep trusting older evidence.
- A revocation may name a key that is no longer listed. Keep the entry after removing a
  key so that an accidental re-add stays rejected.

### Rotation procedure

1. Generate the new key pair and print its ID with `key-id`.
2. Add the new key to the keyset, with `notBefore` set to the planned cutover or earlier,
   and distribute the keyset to every verifier. Both keys are now accepted.
3. Switch the signer (`approve`, `sign`) or the runtime producer
   (`sign-runtime-inventory`) to the new private key.
4. Close the old key: set its `notAfter` to the cutover time so existing reviews keep
   verifying while new signatures are refused, or remove it once every review has been
   re-approved. Runtime attestations live at most 24 hours, so an old producer key can be
   removed one maximum attestation lifetime after the cutover.
5. If the old key may be compromised, add it to `revoked` without `revokedAt` instead.

### Revocation hook

The keyset file itself is the revocation hook. TrustDex reads it on every verification and
performs no network lookup, no CRL or OCSP fetch, no caching, and no process execution.
Deployments supply revocations by updating the file through their own channel, such as a
reviewed repository commit, configuration management, or a CI artifact. Protect the keyset
like a pinned public key: anyone who can write it can add a key or remove a revocation.
TrustDex does not sign the keyset itself.

The contracts are defined by
[`runtime-tool-inventory-v1.schema.json`](../schemas/runtime-tool-inventory-v1.schema.json),
[`runtime-tool-inventory-attestation-v1.schema.json`](../schemas/runtime-tool-inventory-attestation-v1.schema.json),
[`effective-runtime-tools-v2.schema.json`](../schemas/effective-runtime-tools-v2.schema.json),
and [`effective-runtime-tools-diff-v2.schema.json`](../schemas/effective-runtime-tools-diff-v2.schema.json).

