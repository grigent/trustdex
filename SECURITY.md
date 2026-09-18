# Security Policy

TrustDex is security-related software, but it is not a sandbox and it cannot prove that a third-party tool is safe.

## Reporting a vulnerability

Please do not open a public issue for an exploitable vulnerability that could put users at risk. Use GitHub private vulnerability reporting for this repository when available.

Include:

- affected version or commit
- minimal reproduction
- expected and observed behavior
- impact
- suggested mitigation, if known

## Security principles

TrustDex is designed around conservative defaults:

- local-first operation
- no telemetry
- no secret-value logging
- explicit ALLOW / ASK / BLOCK outcomes
- pinned sources preferred over floating versions
- trust should be reconsidered when relevant source or capability signals change

A TrustDex ALLOW result means only that the configured policy allowed the evidence TrustDex inspected. It is not a certification of the underlying software.
