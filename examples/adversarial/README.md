# Inert adversarial fixtures

These files provide a reproducible defensive test of TrustDex's policy boundary.

- `mcp-config.json` contains seven static MCP configuration cases.
- `policy.json` explicitly trusts one fixture package and two fixture hosts so blocking signals can be tested independently of source allowlisting.
- `expected.json` records the required decisions and minimum signals.
- `drift-before.json` and `drift-after.json` model a reviewed package gaining a secret-bearing environment key.

All package names are fictional, all remote endpoints use the reserved `.invalid` top-level domain, and all apparent credentials are placeholders. Do not replace them with real values. TrustDex reads these files but never executes the listed commands or contacts the listed endpoints.

Run the enforced evaluation:

```bash
npm run test:research
```

Inspect the human-readable decisions directly:

```bash
node ./bin/trustdex.mjs inspect \
  ./examples/adversarial/mcp-config.json \
  --pack strict \
  --policy ./examples/adversarial/policy.json
```

The second command exits with code `2` because blocking cases are present. See [the evaluation record](../../docs/EVALUATION.md) for the expected results and limitations.
