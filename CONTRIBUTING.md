# Contributing

Thanks for helping improve TrustDex.

## Good first contributions

- support another MCP configuration shape
- improve package pin detection
- add a conservative trust signal with tests
- document a public, non-sensitive capability drift example
- improve Windows path handling

## Development

```bash
npm test
npm run check
```

Please keep pull requests focused. Security-sensitive changes should include tests and a short explanation of false-positive / false-negative tradeoffs.

Do not submit real credentials, private MCP configs, customer data, or proprietary agent transcripts as fixtures.
