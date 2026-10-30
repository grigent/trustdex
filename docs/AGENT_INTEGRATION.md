# Agent integration

<p align="right">
  <strong>English</strong> | <a href="./AGENT_INTEGRATION.ko.md">한국어</a>
</p>

AI agents increasingly install and call tools on their own. TrustDex can be the check an agent or its harness runs before a tool is exposed, but only if two things hold:

1. the agent reads TrustDex's answer in a way that cannot fail open, and
2. the agent cannot change the policy, trust store, or approvals that produce the answer.

This page defines the machine-readable contract for (1) and the operating rules for (2).

## The decision contract

Every inspection command (`inspect`, `inspect-claude`, `inspect-skill`, `inspect-plugin`, `inspect-codex`, `inspect-claude-settings[-stack]`, `inspect-codex-settings[-stack]`, `inspect-ide-extensions`) accepts `--decisions` (on `main` now; first included in the release after 0.11.0):

```bash
npx trustdex@<exact-version> inspect ./.mcp.json --pack strict --policy ./trustdex.policy.json --decisions
```

It prints one JSON object described by [`schemas/trustdex-decisions-v1.schema.json`](../schemas/trustdex-decisions-v1.schema.json):

```json
{
  "schemaVersion": 1,
  "kind": "trustdex-decisions",
  "command": "inspect",
  "trustdexVersion": "<version>",
  "policyDigest": "<sha256 of the effective policy>",
  "decision": "ask",
  "exitCode": 1,
  "counts": { "allow": 1, "ask": 1, "block": 0 },
  "items": [
    {
      "name": "filesystem",
      "kind": "mcp",
      "action": "allow",
      "signals": [],
      "reasons": ["trusted package: @modelcontextprotocol/server-filesystem"],
      "fingerprint": "<sha256>"
    }
  ],
  "digest": "<sha256 over the report body>"
}
```

- `decision` is the most restrictive item action; `exitCode` is `0` for allow, `1` for ask, and `2` for block, and matches the process exit code.
- Items carry only names, actions, signal names, reasons, and fingerprints. Metadata, provenance evidence, environment-variable names, and configuration values are not included.
- If inspection fails (missing file, malformed input, invalid policy), the command still prints a report with `"decision": "block"`, `"exitCode": 2`, an empty `items` list, and a fixed `error` string. Details go to stderr and never quote input contents.
- `digest` is stable for the same results and policy, so a harness can record exactly which decision it acted on.

### Reading it safely

A consumer may expose a tool **only** when all of these are true:

- the process exit code is `0`,
- stdout parses as JSON with `schemaVersion` `1` and `kind` `"trustdex-decisions"`,
- `decision` is `"allow"`.

Everything else, including a timeout, empty output, an unknown `schemaVersion`, or `"ask"`, must be treated as BLOCK. `"ask"` means a human has to review. An agent must not treat it as permission, and must not retry with a different pack, policy, or flags to get a better answer.

A minimal harness check:

```bash
report="$(npx trustdex@<exact-version> inspect ./.mcp.json --pack strict --policy ./policy.json --decisions)"
status=$?
node -e '
  const r = JSON.parse(process.argv[1]);
  const ok = r.schemaVersion === 1 && r.kind === "trustdex-decisions" && r.decision === "allow";
  process.exit(ok ? 0 : 1);
' "$report" && [ "$status" -eq 0 ] || { echo "TrustDex did not allow these tools"; exit 1; }
```

## Keeping the gate out of the agent's reach

TrustDex is only as trustworthy as the inputs the agent cannot touch. Apply these rules wherever an agent can run commands:

| Rule | Why |
|---|---|
| A human owns the policy file, trust store, and review directory. Make them read-only to the agent (file permissions, a separate checkout, or your agent's deny rules for those paths). | An agent that can edit the policy can allow itself. |
| Keep the review signing private key off the machine the agent uses. | Without the key, an agent cannot create an approval that `recheck` accepts. |
| Let the agent run only `inspect*`, `gate*`, and `recheck*`. Never let it run `approve*`, `sign`, `keygen`, or `trust-source`. | These commands create trust; they are human decisions. |
| Prefer `recheck`, `recheck-claude`, or `recheck-ide-extensions` against a human-signed review. | A signed review pins the policy and every fingerprint; any drift becomes `NEEDS_REVIEW`. |
| Pass `--pack` explicitly and do not let the agent choose `development`. | `development` relaxes several BLOCK decisions to ASK. |
| Pin the TrustDex version you run (`npx trustdex@<exact version>`) and verify releases as described in [Releasing](RELEASING.md). | The gate itself is part of your supply chain. |
| Inspect the agent's own permission settings with `inspect-claude-settings` or `inspect-codex-settings`. | Broad automatic shell or filesystem grants let an agent bypass every rule above. |

Policy files are validated strictly. Unknown fields, unsupported versions, and invalid actions are rejected instead of ignored, so a typo or a crafted field cannot silently change a decision. The accepted shape is published in [`schemas/trustdex-policy-v1.schema.json`](../schemas/trustdex-policy-v1.schema.json). Signed snapshots follow [`schemas/trust-snapshot-v3.schema.json`](../schemas/trust-snapshot-v3.schema.json).

## Compatibility rules

- Fields are added to the v1 decision contract only when a consumer that ignores them stays safe. Any change that alters the meaning of an existing field, or adds a value to `decision` or `action`, ships as a new `schemaVersion`.
- Consumers must reject a `schemaVersion` they do not know.
- Human-readable output and `--json` output are not part of this contract and may change.

## Limits

- An ALLOW decision is a policy result over static evidence. It does not prove a tool is safe and does not sandbox it.
- TrustDex cannot stop an agent that already has unrestricted shell or file access from bypassing the harness. Use your agent runtime's permission system and OS-level isolation for enforcement.
