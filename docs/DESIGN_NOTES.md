# Design notes: Sigstore verification and runtime adapters

<p align="right">
  <strong>English</strong> | <a href="./DESIGN_NOTES.ko.md">한국어</a>
</p>

These are proposals for discussion. Nothing on this page is implemented, and each item needs an explicit decision before code is written, because each one touches a rule in `AGENTS.md` (no new dependency, network call, or `child_process` use without a design discussion).

## 1. Verifying the Sigstore signature on npm provenance

> Status: option A below is implemented in `src/sigstore.mjs`. [TRUST_STORE.md](TRUST_STORE.md) lists what is and is not checked. A `matched` result now requires a verified signature. The Merkle inclusion proof, SCT, and a reviewed trust-root refresh process remain open. The rest of this section is kept as the design record.

### Today

`provenance npm` and `trust-source npm` download the attestation that `registry.npmjs.org` serves for a version, check that it names the version's sha512, and compare the source repository in it with the repository the package declares. The signature on the attestation is not checked, and the evidence records `signatureVerified: false`. The registry is therefore trusted to serve an honest attestation.

### What verification would add

A check that the attestation was signed by a certificate that Sigstore's CA issued to a GitHub Actions workflow in the named repository, and that the signing was recorded in the transparency log. A registry or network attacker could then no longer present an invented attestation.

### Options

| Option | Dependencies | Network | Main cost |
| --- | --- | --- | --- |
| A. Verify with `node:crypto` against a trust root pinned in the repository | none | none beyond the attestation request already made | TrustDex owns certificate-chain, DSSE, and log-entry checking code, and the pinned root must be refreshed when Sigstore rotates keys |
| B. Use the `sigstore` npm package | a dependency tree in a tool that has none today | fetches the trust root through TUF | supply-chain exposure for TrustDex itself |
| C. Run `npm audit signatures` | none | whatever npm does | needs `child_process`, which `bin/` and `src/` do not use |
| D. Keep the current behavior | none | none | registry stays trusted |

### Recommendation

Option A, limited to these checks: the DSSE envelope signature against the leaf certificate; the leaf certificate chain to the pinned Fulcio root; the certificate's issuer and repository fields against the repository being compared; the signed transparency-log entry against the pinned log key; and the log timestamp inside the certificate's validity window.

Fail-closed rules: any failed or unsupported check leaves `signatureVerified: false` and the result `unverifiable`, which `trust-source` already refuses. An expired or unknown trust root is a failure, not a skip. `check-install` and `claude-hook` stay unchanged.

Open decisions: who refreshes the pinned root and how a refresh is reviewed; whether `matched` without a verified signature should then stop being accepted by `trust-source`; whether PyPI attestations get the same treatment.

## 2. Runtime adapters

> Status: two converters exist. `inventory-claude-init` turns a `system/init` event that the user captured from Claude Code's documented stream output into the inventory, and `inventory-codex-mcp-status` does the same for a captured `mcpServerStatus/list` exchange of the documented `codex app-server` protocol; see [RUNTIME_EVIDENCE.md](RUNTIME_EVIDENCE.md). Both read a file and observe nothing themselves, so the constraint below still holds. Gemini CLI (`init` stream event: session id and model only; `gemini mcp list`: text for people) and Devin document no machine-readable session inventory, so none is shipped for them.

### Today

Runtime evidence is supplied by the user. TrustDex accepts a value-free inventory (`agent-runtime-tool-inventory`, server names and tool counts) for the runtimes `claude` and `codex`, optionally signed by a producer key, and reconciles it with the reviewed configuration. TrustDex does not start MCP servers, call an agent, or read session files.

### Constraint

An adapter that produces the inventory has to observe a running agent. Doing that from inside the CLI would mean running the agent's command line (`child_process`), reading undocumented session state, or connecting to MCP servers, and each of those widens the trust boundary.

### Proposal

- Keep adapters outside `bin/` and `src/`. An adapter is a separate, opt-in program that prints an inventory and signs it with `sign-runtime-inventory`. The CLI keeps accepting only the signed, value-free document.
- Ship an adapter only for an interface the runtime vendor documents as stable and that the user has authorized, and name the tested runtime versions in the [compatibility matrix](COMPATIBILITY.md).
- An adapter never emits tool names, arguments, paths, or environment values. It emits server names and counts only, as the schema already requires.
- Each adapter ships with fixtures recorded from the documented interface, tests for a missing server, an extra server, and a changed tool count, and a canary test for secret values.

Open decisions: which runtime interface to target first; whether adapters live in this repository under `examples/` or in a separate package with its own release; who holds the producer key on a developer machine, since a key the agent can read does not authenticate anything.
