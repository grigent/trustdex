# Using TrustDex with Devin

<p align="right">
  <strong>English</strong> | <a href="./DEVIN.ko.md">한국어</a>
</p>

TrustDex can inspect a Devin CLI MCP configuration before Devin CLI receives it. It
evaluates configuration evidence locally, does not start MCP servers, and does not upload
your configuration. An ALLOW decision means the evidence matched your policy; it does not
prove that server code is safe.

## Supported configuration

Devin CLI reads MCP servers from the `mcpServers` object of `.devin/mcp_config.json`
(project), `.devin/mcp_config.local.json` (local), and the user-level `mcp_config.json`.
Pass one of those files:

```json
{
  "mcpServers": {
    "reviewed-tools": {
      "url": "https://your-reviewed-server.example/mcp",
      "transport": "http"
    }
  }
}
```

The URL above is illustrative; configure your own reviewed server and trust policy.

Supported server fields:

| Kind | Fields |
| --- | --- |
| Local command (stdio) | `command`, `args`, `env`, `disabled`, `disabledTools` |
| Remote server (`http` by default, or `sse`) | `url`, `transport`, `headers`, `disabled`, `disabledTools` |

A server must have exactly one of `command` or `url`. Everything else fails closed:
unknown root or server fields, other transports, malformed entries, and URLs containing
credentials, query parameters, or fragments. This intentionally excludes the documented
OAuth client fields (`oauthClientId`, `oauthClientSecret`, `oauthResource`, `oauthScopes`)
until they have an explicit inspection implementation. Ordinary `devin mcp login` OAuth
needs none of those fields and remains Devin's responsibility.

Variable expansion: `${env:NAME}` is accepted in `env` and `headers` values, and the
referenced names are recorded. `${file:/path}`, which would send a local file's contents
to the server, and any other `${...}` form are refused, as is any expansion in `command`,
`args`, or `url`.

Headers add `static-http-headers` and/or `env-http-headers` signals. Built-in packs
require review for them.

A server with `"disabled": true` gets the same decision as an enabled one, because the
flag is one edit away from running it. Fingerprints include the transport, header names,
referenced environment-variable names, the `disabled` flag, and a digest of
`disabledTools`. Enabling a server or unhiding a tool therefore invalidates a signed
review. Header and environment values and tool names are omitted, so rotating a
credential value alone does not invalidate a review. Avoid putting credentials in command
arguments or URL paths. Gated files preserve original allowed entries and can contain
credentials supplied in the input: keep them local and out of version control.

## Inspect and gate

```bash
node ./bin/trustdex.mjs inspect-devin ./.devin/mcp_config.json \
  --pack strict --policy ./trustdex.policy.json

node ./bin/trustdex.mjs gate-devin ./.devin/mcp_config.json \
  --pack strict --policy ./trustdex.policy.json \
  --out ./.trustdex/devin-mcp_config.json
```

The policy file is your explicit trust policy, not a list inferred from vendor names.
By default, the gate includes only ALLOW entries; ASK and BLOCK entries stay out. A gate
exit code of `1` indicates pending ASK decisions; `2` indicates failure. TrustDex does not
modify your Devin configuration: review the gated file, then replace the `mcpServers`
section of the file Devin reads with it yourself.

Devin CLI merges the project, local, and user files. Inspect each file you use; TrustDex
does not discover or merge them. This workflow does not cover MCP servers installed for a
Devin organization in the web app, plugins, Devin's built-in tools, or an enterprise
allowlist. The `permissions` rules are inspected separately; see
[Permission settings](#permission-settings).

## Permission settings

`inspect-devin` covers MCP servers. The permission rules live in a different file,
`config.json`, and are inspected separately:

```bash
node ./bin/trustdex.mjs inspect-devin-settings ./.devin/config.json --pack strict --json
```

| Observed setting | Signal | Built-in packs |
| --- | --- | --- |
| `permissions.allow` with an `Exec(...)` rule or the `exec` tool | `devin-auto-approved-exec` | `BLOCK` |
| any other `permissions.allow` rule (`Read`, `Write`, `Fetch`, a tool name, `mcp__...`) | `devin-auto-approved-tools` | `ASK` |
| `permission_mode: "dangerous"` | `devin-permission-mode-bypass` | `BLOCK` |
| `permission_mode: "accept-edits"` or `"smart"` | `devin-permission-mode-auto` | `ASK` |
| a non-empty `hooks` event | `devin-hooks` | `BLOCK` |
| `local_tools_bypass_permissions: true` | `devin-local-tools-bypass` | `ASK` |
| a `mcpServers` key (read by older Devin CLI versions) | `devin-mcp-servers` | `ASK` |
| a setting TrustDex does not inspect, such as `proxy` | `uninspected-devin-settings` | `ASK` |

A config file never reaches ALLOW, whatever the policy says. `ask` and `deny` rules are
restrictive and add no signal. Documented settings that grant the agent no autonomy
(`agent`, display options, `keymap`, `read_config_from`, `sandbox`, and similar) are
skipped without reading their values.

A rule must have one of the documented forms: `Read(...)`, `Write(...)`, `Exec(...)`,
`Fetch(...)`, the tool names `read`, `edit`, `grep`, `glob`, `exec`, or `mcp__*`,
`mcp__server__*`, `mcp__server__tool`. Any other rule, an unknown `permission_mode`, a
malformed section, and a file with comments fail closed. Devin CLI accepts comments in
`config.json`; remove them from the copy you inspect.

The report holds the permission mode, booleans, and counts. It does not hold rule
scopes, MCP server or tool names, hook bodies, or the names of uninspected settings.

Limits: one file is inspected at a time, with no merge of the user, project, and local
files. Not covered: `.devin/hooks.v1.json`, hooks and rules imported from other tools by
`read_config_from`, organization or team settings, the system policy file, grants made
during a session, and the `--permission-mode` flag or `DEVIN_PERMISSION_MODE`. Inspect
the `mcpServers` entries themselves with `inspect-devin`.

This is tested against the documented configuration format with fixtures, not against
Devin CLI releases. Sources:
[Devin CLI permissions](https://docs.devin.ai/cli/reference/permissions) and
[configuration file](https://docs.devin.ai/cli/reference/configuration/config-file).

## Signed review and drift

```bash
node ./bin/trustdex.mjs keygen --private .trustdex/private.pem --public .trustdex/public.pem
node ./bin/trustdex.mjs approve-devin ./.devin/mcp_config.json --private .trustdex/private.pem --dir .trustdex/devin-review --pack strict --policy ./trustdex.policy.json
node ./bin/trustdex.mjs recheck-devin ./.devin/mcp_config.json --review-dir .trustdex/devin-review --public .trustdex/public.pem
node ./bin/trustdex.mjs snapshot-devin ./.devin/mcp_config.json --out .trustdex/devin-snapshot.json --pack strict --policy ./trustdex.policy.json
```

Approval refuses BLOCK decisions. Rechecks return APPROVED, NEEDS_REVIEW, or INVALID.
Private keys must never be committed.

## Inert example

`examples/devin.mcp_config.json` uses reserved `.invalid` domains, a placeholder
environment-variable reference, and a disabled local command that is never run. It is for
static inspection only:

```bash
node ./bin/trustdex.mjs inspect-devin ./examples/devin.mcp_config.json --pack strict --policy ./examples/claude.policy.json
```

Inspection intentionally exits `2`. The expected decisions are one ALLOW, two ASK, and one
BLOCK.

This is tested against the documented configuration format with fixtures, not against
Devin CLI releases. Source:
[Devin CLI MCP configuration](https://docs.devin.ai/cli/extensibility/mcp/configuration).
