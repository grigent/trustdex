# Tool provenance and permission binding fixtures

These inert fixtures exercise TrustDex's value-free link between an MCP server's
policy/provenance result and the automatic tool permission granted to that server.
They use reserved `.invalid` domains and placeholder markers; inspection never
contacts or launches either server.

```bash
node ../../../bin/trustdex.mjs snapshot-claude-bindings ./claude.mcp.json \
  --settings ./claude.settings.json \
  --trust-store ./trust-store.json \
  --out ./claude.bindings.json

node ../../../bin/trustdex.mjs snapshot-codex-bindings ./codex.toml \
  --trust-store ./trust-store.json \
  --out ./codex.bindings.json
```

The reviewed Claude server has a scoped grant bound to an `ALLOW` result. Its
unknown peer has a wildcard grant bound to a `BLOCK` result. The unmatched Claude
permission is counted but not retained. Codex's reviewed server still requires
review because `default_tools_approval_mode = "approve"` grants every tool.

Generated reports intentionally omit endpoint paths, permission specifiers, tool
names, and marker values. `expected.json` records only stable structural outcomes.
