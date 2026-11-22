# Using TrustDex with Gemini CLI

<p align="right">
  <strong>English</strong> | <a href="./GEMINI.ko.md">한국어</a>
</p>

TrustDex can inspect Gemini CLI MCP server definitions before Gemini CLI receives them. It
evaluates configuration evidence locally, does not start MCP servers, and does not upload
your configuration. An ALLOW decision means the evidence matched your policy; it does not
prove that server code is safe.

## Supported configuration

Gemini CLI reads MCP servers from the `mcpServers` object of `settings.json`. Copy just
that object into a dedicated JSON file. A whole `settings.json` is refused, because its
other settings would pass through uninspected:

```json
{
  "mcpServers": {
    "reviewed-tools": {
      "httpUrl": "https://your-reviewed-server.example/mcp"
    }
  }
}
```

The URL above is illustrative; configure your own reviewed server and trust policy.

Supported server fields:

| Kind | Fields |
| --- | --- |
| Local command (stdio) | `command`, `args`, `env`, `cwd`, `timeout`, `trust`, `includeTools`, `excludeTools` |
| SSE endpoint | `url`, `headers`, `timeout`, `trust`, `includeTools`, `excludeTools` |
| HTTP streaming endpoint | `httpUrl`, `headers`, `timeout`, `trust`, `includeTools`, `excludeTools` |

A server must have exactly one of `command`, `url`, or `httpUrl`. Everything else fails
closed: unknown root or server fields, malformed entries, `${...}` in `command`, `args`,
`cwd`, or an endpoint, and URLs containing credentials, query parameters, or fragments.
This intentionally excludes the documented `oauth`, `authProviderType`, `targetAudience`,
and `targetServiceAccount` fields until they have an explicit inspection implementation.
Automatic OAuth discovery needs none of those fields and remains Gemini CLI's
responsibility.

Signals:

- `trust: true` makes Gemini CLI skip every tool-call confirmation for that server. It
  adds `auto-approve-tools`, which built-in packs send to review, so such a server is
  never ALLOW without an explicit policy decision.
- Any header adds `static-http-headers`. Gemini CLI documents variable expansion for
  `env` only, so header values are treated as literal credentials.

Fingerprints include the transport, header names, the environment-variable names
referenced in `env` (`$NAME`, `${NAME}`, `%NAME%`), the `trust` flag, and digests of
`includeTools`, `excludeTools`, and `cwd`. Turning on `trust`, widening a tool filter, or
changing the working directory therefore invalidates a signed review. Header and
environment values, tool names, and the directory path are omitted, so rotating a
credential value alone does not invalidate a review. `timeout` is validated but not
fingerprinted. Avoid putting credentials in command arguments or URL paths. Gated files
preserve original allowed entries and can contain credentials supplied in the input: keep
them local and out of version control.

## Inspect and gate

```bash
node ./bin/trustdex.mjs inspect-gemini ./gemini-mcpServers.json \
  --pack strict --policy ./trustdex.policy.json

node ./bin/trustdex.mjs gate-gemini ./gemini-mcpServers.json \
  --pack strict --policy ./trustdex.policy.json \
  --out ./.trustdex/gemini-mcpServers.json
```

The policy file is your explicit trust policy, not a list inferred from vendor names.
By default, the gate includes only ALLOW entries; ASK and BLOCK entries stay out. A gate
exit code of `1` indicates pending ASK decisions; `2` indicates failure. TrustDex does not
modify your Gemini settings: review the gated file, then replace the `mcpServers` section
of `settings.json` with it yourself and restart Gemini CLI.

Gemini CLI merges user, project, and system settings, and extensions can add MCP servers
of their own. Inspect each `mcpServers` object you use; TrustDex does not discover or
merge them. This workflow does not cover the global `mcp` settings (`mcp.allowed`,
`mcp.excluded`, `mcp.serverCommand`), extensions, Gemini CLI's built-in tools, or its
sandbox.

## Signed review and drift

```bash
node ./bin/trustdex.mjs keygen --private .trustdex/private.pem --public .trustdex/public.pem
node ./bin/trustdex.mjs approve-gemini ./gemini-mcpServers.json --private .trustdex/private.pem --dir .trustdex/gemini-review --pack strict --policy ./trustdex.policy.json
node ./bin/trustdex.mjs recheck-gemini ./gemini-mcpServers.json --review-dir .trustdex/gemini-review --public .trustdex/public.pem
node ./bin/trustdex.mjs snapshot-gemini ./gemini-mcpServers.json --out .trustdex/gemini-snapshot.json --pack strict --policy ./trustdex.policy.json
```

Approval refuses BLOCK decisions. Rechecks return APPROVED, NEEDS_REVIEW, or INVALID.
Private keys must never be committed.

## Inert example

`examples/gemini.mcpServers.json` uses reserved `.invalid` domains and an inert
placeholder header. It is for static inspection only:

```bash
node ./bin/trustdex.mjs inspect-gemini ./examples/gemini.mcpServers.json --pack strict --policy ./examples/claude.policy.json
```

Inspection intentionally exits `2`. The expected decisions are one ALLOW, two ASK (a
header and `trust: true`), and one BLOCK.

This is tested against the documented configuration format with fixtures, not against
Gemini CLI releases. Source:
[MCP servers with Gemini CLI](https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md).
