# Contributing

Thank you for helping improve TrustDex. This is security-sensitive software, so changes should be small enough to review and explicit about what they do and do not prove.

## Before you start

- Search open issues and pull requests for related work.
- Open an issue before a large feature, new network integration, policy-default change, or public schema change.
- Report exploitable vulnerabilities privately as described in SECURITY.md.
- Do not include real credentials, private MCP configurations, customer data, or proprietary agent transcripts.

Small documentation fixes and focused test additions can go directly to a pull request.

## Development workflow

1. Create a focused branch.
2. Add or update tests for trust signals, policy behavior, parsing, provenance, or signature handling.
3. Run npm test and npm run check on Node.js 20 or newer.
4. Explain security tradeoffs and compatibility impact in the pull request.
5. Keep generated files, credentials, and private review keys out of commits.

The CI matrix tests Node.js 20 and 22. CodeQL runs on pull requests, pushes to main, and a weekly schedule.

## Security review checklist

For a change that can affect ALLOW, ASK, or BLOCK decisions, describe:

- the evidence being inspected
- false-positive and false-negative tradeoffs
- what secret or private data may enter the code path
- what appears in human-readable output and snapshots
- how an attacker might try to bypass the new check
- the tests that cover the boundary

Missing evidence must never become implicit trust. Provenance cannot override a blocking capability signal.

## Pull request expectations

Pull requests should be focused, have a descriptive title, and leave the repository passing all required checks. Maintainers may ask for a smaller change when a proposal combines unrelated policy, parser, and documentation work.

There is no requirement to assign copyright. Contributions are accepted under the repository's MIT license.

## Good first contributions

- add fixtures for another public MCP configuration shape
- improve package pin detection without weakening conservative defaults
- document a public, non-sensitive capability-drift example
- improve cross-platform path and command handling
- add tests for a documented boundary or failure mode

See docs/ROADMAP.md for larger project directions.
