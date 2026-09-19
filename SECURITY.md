# Security Policy

TrustDex is security-related software, but it is not a sandbox, malware scanner, vulnerability scanner, or certification service. An ALLOW decision means only that the observed evidence matched the selected policy.

## Supported versions

Security fixes are applied to the main branch. When releases are published, users should upgrade to the latest release; older pre-1.0 releases may not receive backports.

| Version | Supported |
| --- | --- |
| main | Yes |
| latest release | Yes |
| older pre-1.0 releases | No guaranteed backports |

## Report a vulnerability

Do not open a public issue for a vulnerability that could put users at risk.

Use GitHub Private Vulnerability Reporting from the repository Security tab when it is available. If it is unavailable, contact the maintainer through a private channel listed on the maintainer's GitHub profile. Include only a minimal public issue asking for private contact if no private channel is available; do not include exploit details there.

Please include:

- affected version or commit
- minimal reproduction or proof of concept
- expected and observed behavior
- realistic impact and prerequisites
- suggested mitigation, if known

The maintainer will validate the report, coordinate a fix, and agree on disclosure timing with the reporter. Response times are best effort because the project is currently maintained by one person.

## Security boundaries

TrustDex is designed around:

- local-first inspection for ordinary commands
- explicit network access only for provenance commands
- no telemetry
- no secret-value logging
- redacted remote endpoint reporting
- conservative ALLOW, ASK, and BLOCK outcomes
- pinned sources preferred over floating versions
- re-review when trust-relevant state changes
- fail-closed handling for unsupported Codex MCP syntax

TrustDex does not execute inspected MCP servers during inspection. It does not independently prove that third-party code is non-malicious, that a publisher identity is legitimate, or that a signed review was correct.

See docs/THREAT_MODEL.md and docs/ARCHITECTURE.md for the detailed boundary.
