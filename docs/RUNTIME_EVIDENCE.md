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

The `--max-age-seconds` limit is independent of attestation expiry: expiry caps
how long the signature is usable, while maximum age caps how old the underlying capture
may be. **Verification defaults to a one-hour maximum capture age (3600 seconds)** if
this flag is omitted. Use a shorter explicit limit for security-sensitive agents.
TrustDex also rejects captures and attestations more than five minutes in the
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
   verifying, or remove it once every review has been re-approved. Runtime attestations
   live at most 24 hours, so an old producer key can be removed one maximum attestation
   lifetime after the cutover.
5. If the old key may be compromised, remove it or add it to `revoked` without
   `revokedAt` instead.

`notAfter` and `revokedAt` stop only honest signers. The signed time is chosen by whoever
holds the private key, so a holder of the old key can sign a new review dated before the
cutoff, and trust records do not expire. To stop a key holder, remove the key or revoke it
without `revokedAt`. For runtime-producer keys, backdating is bounded by the 24-hour
maximum attestation lifetime.

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


## Build a Claude inventory from the documented init event

Claude Code documents a `system/init` event as part of `--output-format stream-json`. It
lists the session's MCP servers and tools. If you capture that stream yourself, TrustDex
can turn it into the value-free inventory:

```bash
claude -p "ok" --output-format stream-json --verbose \
  --strict-mcp-config --mcp-config ./.trustdex/claude-mcp.json > ./claude-stream.jsonl

node ./bin/trustdex.mjs inventory-claude-init ./claude-stream.jsonl \
  --out ./runtime-tool-inventory.json
```

TrustDex only reads the file. It does not start Claude, read session state, or contact MCP
servers. The inventory keeps server names and per-server tool counts; tool names, paths,
the model, and the session identifier are dropped. `capturedAt` is the time of the
conversion, because the event carries no timestamp, so convert and sign right after
capturing.

The command refuses the input instead of guessing when: there is not exactly one
`system/init` event; a server is still `pending` or has a status TrustDex does not know;
two server names map to the same tool prefix; or an `mcp__` tool does not belong to
exactly one listed server. A server listed as `failed`, `needs-auth`, or `disabled` is kept
with the tools the event shows for it, so a blocked source that is configured still
blocks the result.

Limits: the stream file is as trustworthy as whoever produced it, and the event reports
the session at startup. Servers skipped by config validation (`mcp_server_errors`) are not
in `mcp_servers` and so not in the inventory. This is tested against the documented event
shape with fixtures, not against Claude Code releases. Sources:
[headless output](https://code.claude.com/docs/en/headless) and
[`SDKSystemMessage`](https://code.claude.com/docs/en/agent-sdk/typescript#sdksystemmessage).

## Build a Codex inventory from the documented MCP status list

`codex app-server` documents an `mcpServerStatus/list` request that returns the MCP
servers of a thread with their tools. If your own client captures that exchange, TrustDex
can turn it into the value-free inventory. Send the request with the `threadId` of the
session you are checking and without `serverName`, follow `nextCursor` until it is `null`,
and save every request followed by its response, one JSON document per line:

```bash
node ./bin/trustdex.mjs inventory-codex-mcp-status ./codex-mcp-status.jsonl \
  --out ./runtime-tool-inventory.json
```

TrustDex only reads the file. It does not start Codex, speak the app-server protocol, or
contact MCP servers. The inventory keeps server names and per-server tool counts; tool
names and schemas, origins, plugin identifiers, resources, and status text are dropped.
`capturedAt` is the time of the conversion, so convert and sign right after capturing.

Responses alone cannot show that the first page is there or that the list was not
narrowed to one server, which is why the requests are part of the capture. The command
refuses the input instead of guessing when: the file is not `mcpServerStatus/list`
requests each followed by the response with the same `id`; a request has no `threadId`,
a different `threadId`, or a `serverName` or `environmentId`; the first request has a
`cursor`, a later request does not use the `nextCursor` of the response before it, or the
last response still has a `nextCursor`; a server has no `runtimeStatus`, or is `notStarted`, `starting`, or in
a status TrustDex does not know; tool discovery failed (`toolsError`) for a `connected`
server; or the same server name appears twice. A server that is `failed`, `cancelled`,
`disabled`, or `authenticationRequired` is kept, so a blocked source that is configured
still blocks the result. Servers that Codex adds itself, such as plugin or app servers,
are in the response and appear as servers your `config.toml` bindings do not cover.

Limits: the file is as trustworthy as whoever produced it; the checks above catch an
incomplete capture, not a forged one, which is what the signed attestation is for. This is
tested against the published response schema with fixtures, not against Codex releases. Sources:
[Codex app-server](https://developers.openai.com/codex/app-server) and the
[`ListMcpServerStatusResponse` schema](https://github.com/openai/codex/blob/main/codex-rs/app-server-protocol/schema/json/v2/ListMcpServerStatusResponse.json).

Gemini CLI and Devin have no converter. Gemini CLI's documented `init` stream event carries
the session id and model only, and `gemini mcp list` prints text for people; Devin
documents no export of a session's MCP servers and tools. A converter that parsed
undocumented output would guess, so none is shipped.
