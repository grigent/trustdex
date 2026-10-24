# Using TrustDex with Claude

<p align="right">
  <strong>English</strong> | <a href="./CLAUDE.ko.md">한국어</a>
</p>

TrustDex can inspect Claude MCP JSON before Claude Code or Claude Desktop receives it.
It evaluates configuration evidence locally, does not start MCP servers, and does not
upload your configuration. An ALLOW decision means the evidence matched your policy;
it does not prove that server code is safe.

The Claude-specific commands are available in TrustDex 0.5.0 and later.
Use `npx trustdex@0.11.0` in place of `node ./bin/trustdex.mjs` in the examples
below to run the published CLI, or use the commands directly from a source checkout.

## Supported configuration

Use a dedicated JSON file with a top-level `mcpServers` object:

```json
{
  "mcpServers": {
    "reviewed-tools": {
      "type": "http",
      "url": "https://your-reviewed-server.example/mcp"
    }
  }
}
```

The URL above is illustrative; configure your own reviewed server and trust policy.

Supported server fields:

| Transport | Fields |
| --- | --- |
| `stdio` (also the default when `type` is omitted) | `type`, `command`, `args`, `env` |
| `http` or `sse` | `type`, `url`, `headers`, `headersHelper` |

Remote entries require an explicit `type`. Command arguments and environment/header
values must be strings. Unknown root/server fields, other transports, malformed
entries, unresolved command/argument/endpoint variables, and URLs containing
credentials, query parameters, or fragments fail closed. This intentionally excludes
custom `oauth`, `alwaysLoad`, WebSocket settings, and future controls until they have
an explicit inspection implementation. Ordinary server-managed OAuth needs no
`oauth` field and remains Claude's responsibility.

Authentication headers add `static-http-headers` and/or `env-http-headers` signals.
Built-in packs require review for them. `headersHelper` adds
`header-helper-command`, which built-in packs block because Claude executes it in a
shell. TrustDex never runs the helper.

Fingerprints include the transport, header names, referenced environment-variable
names, and helper presence. Header/variable values, defaults, and helper command text
are omitted. Rotating a credential value alone does not invalidate a review; changing
its header name or environment reference does. Avoid putting credentials in command
arguments or URL paths. Gated files preserve original allowed entries and can contain
credentials supplied in the input: keep them local and out of version control.

## Claude Code

Claude Code reads project MCP configuration from `.mcp.json`. Inspect it using the
Claude adapter, then supply only the generated configuration for that session.

From a source checkout in PowerShell:

```powershell
node ./bin/trustdex.mjs inspect-claude ./.mcp.json --pack strict --policy ./trustdex.policy.json

node ./bin/trustdex.mjs gate-claude ./.mcp.json --pack strict --policy ./trustdex.policy.json --out ./.trustdex/claude-mcp.json
if ($LASTEXITCODE -ne 0) { throw "Resolve the gate error or pending reviews before starting Claude." }

claude --strict-mcp-config --mcp-config ./.trustdex/claude-mcp.json
```

The policy file is your explicit trust policy, not a list inferred from vendor names.
Omit `--policy` to use the strict defaults, which block unknown sources and ask about
local programs. By default, the gate includes only ALLOW entries. ASK and BLOCK entries
stay out. A gate exit code of `1` indicates pending ASK decisions; `2` indicates failure.
Do not launch using an old output file after a failed gate.

The `--strict-mcp-config` flag matters: `--mcp-config` alone adds a configuration
alongside other MCP sources. Organizations using managed MCP configuration should
also verify the managed policy's effective servers. This workflow does not gate
Claude's built-in tools or inspect every skill/plugin automatically.

Inside the resulting Claude Code session, use `/mcp` to verify the actual loaded
servers. Configuration/unit tests do not replace that runtime check.

Official references:
[Claude Code MCP](https://code.claude.com/docs/en/mcp) and
[CLI flags](https://code.claude.com/docs/en/cli-reference).

## Claude Code permission settings

MCP gating controls which external servers are exposed. Claude Code's own permission
rules separately control which agent actions run without prompting. Inspect a user,
project, local, or managed settings file as a separate step:

```bash
node ./bin/trustdex.mjs inspect-claude-settings \
  ./.claude/settings.json \
  --pack strict \
  --json
```

The adapter validates the documented `permissions` fields `allow`, `ask`, `deny`,
`defaultMode`, `additionalDirectories`, `disableBypassPermissionsMode`,
`disableAutoMode`, and `blockReadsOutsideWorkingDirectories`. Unknown permission
fields, malformed rule arrays, empty rules, unsupported modes, unanchored wildcard
allow rules, and parenthesized MCP rules fail closed.

Automatic grants are classified by capability rather than echoing their values:

| Observed setting | Strict result |
| --- | --- |
| narrow shell auto-approval | `BLOCK` |
| broad shell, filesystem, network, or subagent auto-approval | `BLOCK` |
| filesystem, network, MCP, or subagent auto-approval | at least `ASK` |
| `bypassPermissions` default mode | `BLOCK` |
| `auto` or `acceptEdits` default mode | at least `ASK` |
| additional directories or explicitly unblocked outside reads | at least `ASK` |
| hooks or an API-key helper | `BLOCK` |
| environment, sandbox, plugin, or uninspected root settings | at least `ASK` |

`ask` and `deny` rules are restrictive and do not add a risk signal by themselves.
The report includes rule counts and capability categories, but not command patterns,
paths, domains, hook bodies, helper commands, directory values, environment values,
or plugin identifiers. For the same reason, this first adapter does not create a
content fingerprint or signed review record for settings files.

Use the stack command when reviewing multiple active sources:

```bash
node ./bin/trustdex.mjs inspect-claude-settings-stack \
  --user ./review/user.settings.json \
  --project ./.claude/settings.json \
  --local ./.claude/settings.local.json \
  --session ./review/session.settings.json \
  --managed ./review/managed-settings.json \
  --pack strict --json
```

TrustDex applies user, shared project, project-local, session, and managed precedence;
permission lists combine, while supported scalar permission controls use the highest
effective source. It also ignores `auto` and `bypassPermissions` defaults from project
or local sources, matching the documented scope restriction. The report stores only
fixed scope names and counts, never input paths or setting values.

Sources must be passed explicitly. TrustDex does not discover settings, shell environment
overrides, embedded-host policy, or server-delivered managed settings, so confirm loaded
sources with `/status` and use OS-level sandboxing for enforcement. Official references:
[settings files and precedence](https://code.claude.com/docs/en/settings),
[permissions](https://code.claude.com/docs/en/permissions), and
[security](https://code.claude.com/docs/en/security).

### Permission posture drift

Create a baseline after review and compare a later settings state:

```bash
node ./bin/trustdex.mjs snapshot-claude-settings \
  ./.claude/settings.json \
  --pack strict \
  --out .trustdex/claude-posture.json

node ./bin/trustdex.mjs snapshot-claude-settings-stack \
  --user ./review/user.settings.json \
  --project ./.claude/settings.json \
  --managed ./review/managed-settings.json \
  --pack strict \
  --out .trustdex/claude-stack-posture.json

node ./bin/trustdex.mjs diff-permissions \
  .trustdex/approved-claude-posture.json \
  .trustdex/current-claude-posture.json
```

New automatic tool categories, added rules or directories, relaxed protective
switches, a riskier default mode, new risk signals, or changed policy semantics return
`NEEDS_REVIEW` and exit `1`. Restriction-only changes return `RESTRICTED` and exit `0`.
The snapshot excludes source paths and every permission, hook, directory, domain,
credential-helper, plugin, and environment value. Because it intentionally does not
fingerprint redacted rule contents, a same-count change inside one capability category
must still be covered by source review or runtime controls.
Merged-source snapshots use schema v2 and include only source-scope counts. Adding,
removing, or reclassifying a source requires review even when the resulting structural
permission posture is otherwise unchanged.

### Bind MCP provenance to automatic grants

Create a self-validating record that joins each `.mcp.json` server's policy/provenance
result to the merged Claude `permissions.allow` grant that can invoke it:

```bash
node ./bin/trustdex.mjs snapshot-claude-bindings ./.mcp.json \
  --user ./review/user.settings.json \
  --project ./.claude/settings.json \
  --managed ./review/managed-settings.json \
  --trust-store ./trust-store.json \
  --out .trustdex/claude-bindings.json
```

For one settings file, use `--settings <file>`. Scoped rules can bind to an `ALLOW`
source; wildcard grants, grants to ASK/BLOCK sources, unmatched rules, and ambiguous
server-name matches are surfaced for review or blocking. The snapshot records server
names and grant shape only. It omits permission specifiers and tool names, so same-count
changes among scoped tools remain a source-review responsibility. Compare reviewed and
current records with `diff-bindings`; expansion or provenance/policy drift exits `1`.

### Compare an explicit runtime inventory

If an authorized integration can obtain the MCP servers visible to a Claude session,
have it emit `agent-runtime-tool-inventory` JSON with server names and tool counts only.
Then run `snapshot-runtime-tools <bindings> <inventory> --out <evidence>`. Loaded BLOCK
sources and servers absent from `.mcp.json` block the result; loaded review-required
bindings remain review-required. `diff-runtime-tools` detects newly visible servers and
tool-count growth. TrustDex does not call Claude, discover session files, authenticate
the adapter automatically, or prove the inventory is complete. Production evidence
should use `sign-runtime-inventory`, a pinned producer public key, bounded
`--max-age-seconds`, and `--require-authenticated` as shown in
[Authenticated runtime evidence](RUNTIME_EVIDENCE.md).

## Signed review and drift

Keep the Claude adapter throughout a review workflow; generic MCP commands do not
inspect Claude-specific controls.

```bash
node ./bin/trustdex.mjs keygen --private .trustdex/private.pem --public .trustdex/public.pem
node ./bin/trustdex.mjs approve-claude ./.mcp.json --private .trustdex/private.pem --dir .trustdex/claude-review --pack strict --policy ./trustdex.policy.json
node ./bin/trustdex.mjs recheck-claude ./.mcp.json --review-dir .trustdex/claude-review --public .trustdex/public.pem
node ./bin/trustdex.mjs snapshot-claude ./.mcp.json --out .trustdex/claude-snapshot.json --pack strict --policy ./trustdex.policy.json
```

Approval refuses BLOCK decisions. ASK decisions require an explicit human review;
running `approve-claude` records that review but does not automatically change the
gate's policy. Rechecks return APPROVED, NEEDS_REVIEW, or INVALID. A pre-existing
generic review has a different fingerprint and must be reviewed with the Claude adapter.
Private keys must never be committed.

## Claude Desktop

For a local stdio MCP configuration, export just the `mcpServers` object from
`claude_desktop_config.json` into a dedicated input file. Do not feed unrelated
Desktop preferences into the MCP adapter. Use `inspect-claude` and `gate-claude`
on that file, review the result, then replace only the Desktop config's `mcpServers`
section with the gated section and restart Claude Desktop. Keep a backup of the
original configuration.

TrustDex does not modify your active Desktop settings or install a connector.
Desktop extensions and account-level remote connectors require separate review;
this JSON gate does not automatically govern them.

## Inert example

`examples/claude.mcp.json` uses reserved `.invalid` domains, a placeholder
environment-variable reference, and an inert helper string. Do not launch it in
Claude. It is for static inspection only:

```bash
node ./bin/trustdex.mjs inspect-claude ./examples/claude.mcp.json --pack strict --policy ./examples/claude.policy.json
node ./bin/trustdex.mjs gate-claude ./examples/claude.mcp.json --pack strict --policy ./examples/claude.policy.json --out .trustdex/example-claude.json
```

Inspection intentionally exits `2`. The expected decisions are one ALLOW, one ASK,
and two BLOCK; the gate writes only `reviewed` and exits `1` because a review remains.
