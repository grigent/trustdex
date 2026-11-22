# Schema stability rules

<p align="right">
  <strong>English</strong> | <a href="./SCHEMAS.ko.md">한국어</a>
</p>

TrustDex reads and writes versioned JSON documents: policy files, signed snapshots, decision reports, permission posture, bindings, runtime evidence, and keysets. This page states the rules those formats follow, so that an integration or a stored approval keeps meaning what it meant when it was written.

## Published schemas

| Schema | `kind` | Version |
| --- | --- | --- |
| [`schemas/effective-runtime-tools-diff-v1.schema.json`](../schemas/effective-runtime-tools-diff-v1.schema.json) | — | 1 |
| [`schemas/effective-runtime-tools-diff-v2.schema.json`](../schemas/effective-runtime-tools-diff-v2.schema.json) | — | 2 |
| [`schemas/effective-runtime-tools-v1.schema.json`](../schemas/effective-runtime-tools-v1.schema.json) | `agent-effective-tool-boundary` | 1 |
| [`schemas/effective-runtime-tools-v2.schema.json`](../schemas/effective-runtime-tools-v2.schema.json) | `agent-effective-tool-boundary` | 2 |
| [`schemas/permission-posture-diff-v1.schema.json`](../schemas/permission-posture-diff-v1.schema.json) | — | 1 |
| [`schemas/permission-posture-diff-v2.schema.json`](../schemas/permission-posture-diff-v2.schema.json) | — | 2 |
| [`schemas/permission-posture-v1.schema.json`](../schemas/permission-posture-v1.schema.json) | `agent-permission-posture` | 1 |
| [`schemas/permission-posture-v2.schema.json`](../schemas/permission-posture-v2.schema.json) | `agent-permission-posture` | 2 |
| [`schemas/runtime-tool-inventory-attestation-v1.schema.json`](../schemas/runtime-tool-inventory-attestation-v1.schema.json) | `agent-runtime-tool-inventory-attestation` | 1 |
| [`schemas/runtime-tool-inventory-v1.schema.json`](../schemas/runtime-tool-inventory-v1.schema.json) | `agent-runtime-tool-inventory` | 1 |
| [`schemas/tool-permission-bindings-diff-v1.schema.json`](../schemas/tool-permission-bindings-diff-v1.schema.json) | — | 1 |
| [`schemas/tool-permission-bindings-v1.schema.json`](../schemas/tool-permission-bindings-v1.schema.json) | `agent-tool-permission-bindings` | 1 |
| [`schemas/trust-snapshot-v3.schema.json`](../schemas/trust-snapshot-v3.schema.json) | — | 3 |
| [`schemas/trustdex-decisions-v1.schema.json`](../schemas/trustdex-decisions-v1.schema.json) | `trustdex-decisions` | 1 |
| [`schemas/trustdex-keyset-v1.schema.json`](../schemas/trustdex-keyset-v1.schema.json) | `trustdex-keyset` | 1 |
| [`schemas/trustdex-policy-v1.schema.json`](../schemas/trustdex-policy-v1.schema.json) | — | 1 |

`test/compatibility.test.mjs` fails if a file in `schemas/` is missing from this table.

## Rules for readers

- Reject a document whose `schemaVersion` (or policy `version`) or `kind` you do not know. Do not fall back to an older reading.
- Reject unknown fields. Every published schema sets `additionalProperties: false`, and policy files with unknown fields, unknown signal names, or invalid actions are refused rather than partly applied.
- Treat a missing, empty, or unparseable document as BLOCK, never as "no findings".
- `ask` means a human has to review. It is not permission.

## Rules for changes

- A field keeps its meaning for the life of a schema version. A field is never repurposed.
- A change gets a new integer version and a new schema file when it alters the meaning of a field, adds a value to a decision or action enum, removes a field, or changes what a fingerprint or signature covers.
- A field may be added within a version only when a reader that does not know it stays safe, which in practice means the field cannot turn an ASK or BLOCK into ALLOW. Because readers reject unknown fields, most additions still ship as a new version.
- Older schema files stay in `schemas/` so stored documents can still be validated. Comparing permission posture snapshots of different versions reports a change that needs review.
- A fingerprint or snapshot change must not let an approval recorded before the change validate a configuration that differs from the one reviewed. If the inputs to a fingerprint change, existing approvals must fail recheck and be reviewed again.
- Snapshots and reports stay free of secret values, source paths, and permission specifiers. A new output field is added to the canary sweep in `test/secret-canary.test.mjs`.
- Every schema change ships with a test and a changelog entry that names the new version.

## What these rules do not promise

TrustDex is pre-1.0. Command names, human-readable output, and signal names can still change between minor versions; the changelog records each change. The rules above apply to the versioned JSON documents only.
