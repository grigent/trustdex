# Design notes: Sigstore verification, runtime adapters, registries, and organization trust stores

<p align="right">
  <strong>English</strong> | <a href="./DESIGN_NOTES.ko.md">한국어</a>
</p>

These are proposals for discussion. Unless a status line says otherwise, nothing on this page is implemented, and each item needs an explicit decision before code is written, because each one touches a rule in `AGENTS.md` (no new dependency, network call, or `child_process` use without a design discussion).

## 1. Verifying the Sigstore signature on npm provenance

> Status: option A below is implemented in `src/sigstore.mjs`. [TRUST_STORE.md](TRUST_STORE.md) lists what is and is not checked. A `matched` result now requires a verified signature. The Merkle inclusion proof and the embedded SCT are verified as well, and [TRUST_ROOT.md](TRUST_ROOT.md) is the reviewed trust-root refresh procedure. The rest of this section is kept as the design record.

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

## 3. Provenance for other package registries

> Status: deferred. The maintainer decided on 2026-11-22 to postpone this item; nothing is implemented.

### Today

`check-install` and `claude-hook` read public metadata from `registry.npmjs.org` and `pypi.org`. Build provenance (`provenance npm`, `trust-source npm`) exists for npm only. A PyPI package can be recorded in a trust store only by manual review or `--artifact` integrity evidence.

### What PyPI documents

PyPI implements PEP 740 and serves a provenance object per release file at `GET https://pypi.org/integrity/<project>/<version>/<filename>/provenance` ([Integrity API](https://docs.pypi.org/api/integrity/)). The simple JSON index names that URL in each file's `provenance` field. Each object groups attestations by the Trusted Publisher that produced them (for GitHub: `repository`, `workflow`, `environment`). Each attestation is a DSSE envelope with a Fulcio certificate and a Rekor entry carrying an inclusion proof; the default predicate is `https://docs.pypi.org/attestations/publish/v1`. PyPI's [security model](https://docs.pypi.org/attestations/security-model/) states that an attestation shows where a file came from, not whether to trust it, and that a change of Trusted Publisher between releases can signal a takeover.

### Options

| Option | Network | Main cost |
| --- | --- | --- |
| A. `provenance pypi` and `trust-source pypi`, reusing `src/sigstore.mjs` | `pypi.org` only, in these two explicit commands | an adapter for the PEP 740 envelope shape; the `dsse` 0.0.1 log entry kind is already supported for npm |
| B. Also check PyPI provenance during `check-install` | one extra request per file on every install check | latency and a new failure mode on the everyday path, against the earlier decision to keep `check-install` offline-light |
| C. RubyGems, crates.io, Go modules | new hosts | RubyGems documents Trusted Publishing for pushing gems but not a per-file attestation API that TrustDex could verify; crates.io and Go were not evaluated here. Each needs its own documented interface first |

### Recommendation

Option A only. Rules:

- Verify every attestation with the existing DSSE, Fulcio, CT, Rekor inclusion-proof, and checkpoint checks against the pinned trust root. The subject digest must equal the file's SHA-256 from the JSON API, and the certificate's repository must equal the `publisher.repository` of the bundle.
- For a GitHub Trusted Publisher, both identity fields must match the certificate, not only the repository. The certificate's Build Config URI ([Fulcio OID 1.3.6.1.4.1.57264.1.18](https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264118--build-config-uri)) must name that repository and the workflow file in `publisher.workflow`: `https://github.com/<publisher.repository>/.github/workflows/<publisher.workflow>@<ref>`, compared without regard to case for the repository and exactly for the workflow file name. A certificate from another workflow in the same repository, or a missing Build Config URI, fails closed. When `publisher.environment` is set it is recorded but not yet compared, because the Fulcio certificate does not carry the environment.
- Compare that repository with the project's declared source URL, as npm does. A missing, mismatched, or unverifiable result is refused by `trust-source`, the same as npm.
- A publisher that differs from the one on the previous release is a new signal (`pypi-publisher-changed`), and an attested project whose new release has no provenance is `provenance-dropped`. Both stop registration.
- Only `GitHub` publishers are accepted at first; other publisher kinds fail closed until their certificate identity is tested.
- Sdists and wheels are separate files with separate provenance. The command takes an exact version and verifies every file of that release, and fails if any file fails.

Open decisions: whether to start with PyPI only; whether to verify all files of a release or only the file that the installer would pick; whether GitLab and Google Cloud publishers are needed.

## 4. Organization-level trust store

> Status: deferred. The maintainer decided on 2026-11-22 to postpone this item; nothing is implemented.

### Today

A trust store is a local JSON file of claims. Teams can commit it to a repository, but nothing proves who wrote a claim, an older copy can be swapped in, and a developer cannot tell a reviewed store from an edited one. Review keys already exist: trust records are signed with Ed25519, and a keyset ([RUNTIME_EVIDENCE.md](RUNTIME_EVIDENCE.md)) lists allowed keys by purpose with validity windows and revocation.

### Goal

An organization publishes one store that every developer machine and CI job can verify offline, and that a single compromised laptop, a malicious pull request, or an old copy cannot widen.

### Proposal

- **Signed document.** A new `trustdex-org-trust-store` kind wraps the existing claims with `organization`, `sequence` (an integer that only increases), `issuedAt`, and `expiresAt`, and is signed with Ed25519 over the canonical JSON that TrustDex already uses for trust records.
- **Key policy.** Verification uses a keyset with a new purpose, `trust-store`, distinct from `review` and `runtime-producer`. Optionally a threshold (for example two of three keys) so one stolen key cannot publish a store.
- **Rollback and freeze.** TrustDex keeps the highest `sequence` it accepted in its state directory and refuses a lower one. An expired store is refused, not skipped, so a stale store cannot keep old trust alive.
- **Local layering.** A developer's own store cannot replace an organization claim for the same subject. A local claim for a subject the organization does not cover stays usable but is reported as local, so policy can require organization claims only. Nothing in either store overrides a capability BLOCK.
- **Distribution.** No new network code. The organization delivers the signed file with its own tooling (a repository, MDM, a CI artifact), and TrustDex reads `--org-trust-store <file> --keyset <file>`.
- **Output.** Decisions record the store's organization, sequence, and key ID, never claim evidence URLs.

### Rejected alternatives

- Fetching the store from a URL at check time: adds network access and a server to compromise.
- Treating a store committed to the repository as trusted without a signature: any merged pull request could then widen trust.
- Reusing `review` keys: a key that signs one configuration review would also be able to rewrite organization trust.

Open decisions: whether to add organization deny entries (claims today have only the `verified` status); whether to require a threshold signature from the start; the default lifetime (`expiresAt`) to require; where the accepted `sequence` is stored on CI runners that start from a clean machine.

