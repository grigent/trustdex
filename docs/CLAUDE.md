# Using TrustDex with Claude

TrustDex can inspect Claude MCP JSON before Claude Code or Claude Desktop receives it.
It evaluates configuration evidence locally, does not start MCP servers, and does not
upload your configuration. An ALLOW decision means the evidence matched your policy;
it does not prove that server code is safe.

The Claude-specific commands are available from this source checkout. They are not
included in the published npm 0.4.4 release.

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
