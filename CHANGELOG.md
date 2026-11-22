# Changelog

<p align="right">
  <strong>English</strong> | <a href="./CHANGELOG.ko.md">한국어</a>
</p>

## Unreleased

- `provenance npm` and `trust-source npm`: a Sigstore bundle whose only failure is a missing Rekor inclusion proof is now `unverifiable` with the reason `inclusion-proof-missing` instead of `signature-not-verified`. The verification policy and the 2024 cutoff for format 0.1 bundles are unchanged. Compatibility: bundles that 0.19.0 reported as `matched` and 0.20.0 refuses, such as the 2024-02-08 provenance of `sigstore@2.2.1` and `@sigstore/sign@2.2.2`, stay refused; see [docs/TRUST_STORE.md](docs/TRUST_STORE.md).
- `inspect-gemini-settings`: an explicit `tools.sandbox: false` adds `gemini-sandbox-disabled` (at least `ASK`), and `metadata.sandboxSetting` tells an omitted sandbox (`omitted`) from a disabled (`disabled`) or enabled one.
- `inspect-devin-settings`: `read_config_from` with a provider set to `true` adds `devin-external-config` (`ASK`), because Devin CLI may then import rules, skills, hooks, or MCP servers from that tool's files. Only the number of enabled providers is reported; the imported files are not read. A `read_config_from` that is not an object of booleans now fails closed.
- Design notes: the deferred PyPI provenance design also requires the Fulcio Build Config URI to match `publisher.workflow` for GitHub Trusted Publishers. Documentation only.

## 0.20.0 - 2026-11-22

- `inspect-devin-settings`: classify the permission settings of a Devin CLI `config.json` by capability. An auto-approved `Exec` rule, `permission_mode: "dangerous"`, and hooks are `BLOCK`; other `allow` rules, the `accept-edits` and `smart` modes, `local_tools_bypass_permissions`, a legacy `mcpServers` key, and uninspected settings are `ASK`. A config file never reaches ALLOW under any policy, a rule outside the documented forms fails closed, and the report holds only the permission mode, booleans, and counts. See [docs/DEVIN.md](docs/DEVIN.md).
- `inspect-gemini-settings`: classify the permission settings of a Gemini CLI `settings.json` by capability. An auto-approved shell tool, a tool or MCP command setting, and hooks are `BLOCK`; other automatic grants, a relaxed sandbox, disabled folder trust, extra policy paths, and uninspected settings are at least `ASK`. A settings file never reaches ALLOW under any policy, and the report holds only the approval mode, booleans, and counts. See [docs/GEMINI.md](docs/GEMINI.md).
- Behavior change: a Claude Code, Codex, or Gemini CLI permission settings file (or settings stack) is never ALLOW. A custom policy with `localAction: "allow"` used to approve a settings file that raised no signal; it is now ASK, with the reason `permission settings always require review`. The built-in packs already returned ASK.
- `provenance npm` and `trust-source npm` also require the signing certificate to carry an embedded signed certificate timestamp (SCT) from a pinned certificate-transparency log. A certificate without one is `unverifiable`. No network request is added.
- The pinned Sigstore trust root is now checked by a test against the upstream `trusted_root.json` it was derived from, and [docs/TRUST_ROOT.md](docs/TRUST_ROOT.md) describes how to refresh it.
- `provenance npm` and `trust-source npm` also verify the Merkle inclusion proof of the Sigstore log entry, up to a tree head signed by the pinned log key. A bundle whose proof is missing or does not verify is `unverifiable` and is not recorded. Only a 2023 bundle in format 0.1 may carry the log's signed promise alone. No network request is added.

## 0.19.0 - 2026-11-22

- `inspect-gemini`, `gate-gemini`, `snapshot-gemini`, `approve-gemini`, `recheck-gemini`: inspect and gate Gemini CLI `mcpServers` before Gemini CLI reads them. `trust: true`, which skips every tool-call confirmation, adds `auto-approve-tools` and never reaches ALLOW in a built-in pack. Unknown fields, the OAuth and Google credential fields, other `settings.json` settings, and URL credentials or query values fail closed. Changing `trust`, a tool filter, or the working directory invalidates a signed review. See [docs/GEMINI.md](docs/GEMINI.md).
- `inspect-devin`, `gate-devin`, `snapshot-devin`, `approve-devin`, `recheck-devin`: inspect and gate a Devin CLI `mcp_config.json` before Devin CLI reads it. Unknown fields, the OAuth client fields, `${file:...}` expansion, and URL credentials or query values fail closed. A `disabled` server is decided like an enabled one, and enabling a server or unhiding a tool invalidates a signed review. See [docs/DEVIN.md](docs/DEVIN.md).
- `inventory-codex-mcp-status`: convert a captured `mcpServerStatus/list` exchange (each request with its response) from the documented `codex app-server` protocol into a value-free runtime tool inventory (server names and tool counts only). TrustDex reads the file you pass; it does not start Codex or contact MCP servers. The capture is refused when a page is missing (the first request must start the list and each later one must continue from the previous cursor), a request names no thread or selects a single server, a server has no settled thread status, tool discovery failed for a connected server, or a server name appears twice.

## 0.18.0 - 2026-11-22

- `inventory-claude-init`: convert a `system/init` event captured from Claude Code's documented `--output-format stream-json` into a value-free runtime tool inventory (server names and tool counts only). TrustDex only reads the file; it does not start Claude or contact MCP servers. A pending server, an unknown status, or an MCP tool that does not belong to exactly one listed server is refused
- `provenance npm` and `trust-source npm` verify the Sigstore bundle of npm build provenance offline, with Node's built-in crypto and a pinned trust root (no new dependency or request). A match now requires a valid DSSE signature, a certificate that chains to the pinned Fulcio root and names the same GitHub repository, and a Rekor entry for that envelope with a valid signed timestamp; otherwise the release is `unverifiable` and `trust-source` refuses it. Not checked: SCT, Merkle inclusion proof, RFC 3161 timestamps, trust-root rotation
- skill files: a wildcard tool scope is reported when it is written as a YAML block list, a multi-line flow list, after a byte-order mark or leading blank lines, with a different letter case, with a trailing comment, in a repeated key, or as an unrestricted specifier such as `Bash(*)`. A tool scope in syntax TrustDex does not parse adds `uninspected-tool-scope` (ASK) instead of being read as narrow
- skill files: more download-and-run forms (`| zsh`, `| python`, `| iex`, `bash <(...)`, `bash -c "$(...)"`), more package runners, and more credential locations (`$HOME/.ssh`, `~/.gnupg`, `~/.kube`, `~/.npmrc`, and similar) raise the existing instruction signals. These remain text heuristics
- plugin manifests: `plugin-executable-components` (ASK) when a manifest declares hooks, MCP servers, LSP servers, or scripts; nested wildcard permissions such as `permissions.allow: ["Bash(*)"]` are reported; a manifest nested deeper than 64 levels is rejected
- MCP JSON: `malformed-server-fields` (BLOCK) when `command`, `args`, `env`, `url`, or `endpoint` has the wrong type, and `shell-execution` when a wrapper such as `env`, `sudo`, or `busybox` launches a shell, or the command is `dash` or `ksh`
- new inert fixtures under `examples/adversarial/extensions/` and `examples/adversarial/mcp-evasion.json`
- `slack-approver`: the token file must contain exactly one bot-token-shaped value, so a `tokenFile` pointed at another file cannot send its contents to Slack, and requests to `slack.com` no longer follow redirects
- docs: a [compatibility matrix](docs/COMPATIBILITY.md) and [schema stability rules](docs/SCHEMAS.md), both checked by `test/compatibility.test.mjs`, [design notes](docs/DESIGN_NOTES.md) for Sigstore verification and runtime adapters (proposals, not implemented), and roadmap progress for 0.17.3

## 0.17.3 - 2026-11-22

- `provenance npm` and `trust-source npm` compare the latest version's npm build provenance with the repository the package declares now and declared before. `trust-source` refuses a release built from a different repository (`mismatch`), one that dropped provenance earlier versions had (`dropped`), or provenance it cannot match to the version's sha512 (`unverifiable`), and records the source repository and workflow in the claim when they match. The Sigstore signature is not verified, and `check-install` makes no new request

## 0.17.2 - 2026-11-22

- add `provenance-dropped` (ASK): a recent npm release without provenance, when an earlier version of the package was published with it. Releases pushed with a stolen token instead of the project's CI often look like this. TrustDex compares only whether the registry reports provenance; it does not verify the attestation. Install-policy allowlists cannot silence it
- block hijacked npm releases with `known-malicious-release`: `vant` 2.13.3–2.13.5, 3.6.13–3.6.15, 4.9.11–4.9.14 ([maintainer notice](https://github.com/youzan/vant/discussions/13273)), `@wppconnect-team/wppconnect` 2.4.1 ([GHSA-cxc9-87g6-qrj9](https://github.com/advisories/GHSA-cxc9-87g6-qrj9)), `@wppconnect/server` 2.10.82 ([report confirmed by the maintainers](https://github.com/wppconnect-team/wppconnect-server/issues/2734)), and `qrcode-reader-vue3` 3.1.4 ([GHSA-9q69-8j7m-ppmh](https://github.com/advisories/GHSA-9q69-8j7m-ppmh)). Exact pins are checked offline, resolved versions are blocked, and affected versions are never suggested as alternatives

## 0.17.1 - 2026-11-21

- Block PyPI `agent-framework` releases `1.26.1` and `1.26.2`. Exact pins are checked offline and the Claude Code hook denies the installation even if it was previously approved. [GHSA-764m-3ppc-5m73](https://github.com/advisories/GHSA-764m-3ppc-5m73)

## 0.17.0 - 2026-11-21

- add `trustdex init`: set up the Claude Code hook in one step on macOS and Linux. It shows the plan and asks for `yes` (or `--yes`); `--dry-run` only shows it. It copies the running TrustDex to `~/.local/share/trustdex/<version>`, writes a `trustdex` command to `~/.local/bin`, creates an install policy only if none exists, and adds one fail-closed PreToolUse hook to `~/.claude/settings.json` after backing it up. Other settings and hooks are kept, and running it again replaces only the TrustDex hook. `--strict` denies risky actions instead of asking; `--uninstall` removes only the TrustDex hook
- README: a one-minute start for Claude Code

## 0.16.1 - 2026-11-20

- feeding a credential file to any program through input redirection (`cmd < ~/.ssh/id_rsa`, `<file` attached, `0<`) is now a `secret-access` finding. Before, it passed when the program was an SSH tool (`ssh host 'cmd' < secret`), or when the file name was attached to `<`. Files read through `<` count as reads, so `while read …; done < ~/.zshrc` is no longer a startup-item change

## 0.16.0 - 2026-11-19

- add `slack-approver`: sends each action the hook stopped to the configured owner as a Slack direct message, and records the one-time approval when the owner (by Slack user id, never the bot) reacts with ✅. ❌ refuses. Changes to agent settings or TrustDex itself and unparsed commands near protected files stay terminal-only. At most 20 messages an hour by default. Its message state lives in the protected approval state directory, and the hook now protects `slack-approver.json` next to the install policy. See [docs/SLACK_APPROVER.md](docs/SLACK_APPROVER.md)
- the hook's stop message mentions the Slack message as an alternative to `allow-once`

## 0.15.1 - 2026-11-19

- a one-time approval of a Bash command that runs a local script (`bash x.sh`, `python3 x.py`, `source x`, `./x.sh`) is now also bound to a SHA-256 of each such script, of any size. Changing the script after approval, or creating a script that did not exist yet, makes it a different action that needs its own approval

## 0.15.0 - 2026-11-19

- check commands sent to other computers over SSH (`ssh host 'cmd'`, `ssh host <<EOF`, `scp`/`rsync host:path`) by generic names: reading files that usually hold secrets, printing environment variables or `kubectl` secrets (`remote-secret-access`, ASK), and changing those files, `/etc`, `authorized_keys`, shell startup files or `crontab` (`remote-config-change`, ASK). Approval covers that kind of work on that host for 1 hour. Everyday server work stays quiet, and `ssh` to this same computer is checked like a local command
- the documented hook command now ends with `|| { ...; exit 2; }`, so a missing `node`, a moved TrustDex copy or a crash at start-up stops the action instead of letting it through as a non-blocking hook error
- document what ask mode keeps denied and its trade-off
- less friction in the Claude Code hook, from a day of real use:
  - one-line Python or Node code that only reads (`python3 -c "print(json.load(open(p)))"`, `node -e "...readFileSync(p)..."`) no longer counts as changing agent settings or startup items; code that may write, run another program, or hide what it calls still does
  - `trustdex allow-once --list` is allowed; approving still is not
  - stopping a launchd job (`launchctl unload`, `bootout`, `disable`, `remove`) is no longer a startup-item change
  - new install-policy key `allowStartupItems`: launchd labels of your own jobs (`"com.example.*"`) that agents may start with `launchctl enable`, or `load`/`bootstrap` from `~/Library/LaunchAgents`, without approval. Writing a plist there still needs approval
  - one-time approvals of an exact action now last an hour, the same as codes and startup-item approvals (was 30 minutes)

## 0.14.2 - 2026-11-19

- fewer false positives in the agent guards: each simple command is judged on its own (a read-only command next to unrelated commands stays allowed), redirections to `/dev/null` or another descriptor are not writes, and `bash -n`, `plutil -lint`/`-p`, `launchctl print`/`list`, `defaults read`, read-only `git`, `sed`/`awk` without in-place edits and `find` without `-delete`/`-exec` count as read-only
- approving a startup-item finding (`persistence-change`) now covers startup-item and scheduled-job changes for 1 hour, in any command, instead of one exact command

## 0.14.1 - 2026-11-18

- bind Bash one-time approvals to the effective starting directory plus the command after any leading `cd`, so an approval matches when Claude Code drops a leading `cd` to the current directory, and does not carry over to the same command in another directory

## 0.14.0 - 2026-11-18

- add `check-install`: parse npm, pnpm, yarn, bun, npx, pip, uv, uvx, pipx, poetry, and pdm install commands offline, block download-to-interpreter pipelines (`curl ... | sh`, `bash <(curl ...)`), and look up each registry package on the public npm registry or PyPI (only package names are sent). Missing packages and invalid integrity metadata are BLOCK. Recent releases (48h), new packages (30 days), install scripts and source builds, first-time publishers on recent releases, deprecated or yanked versions, look-alike names, git/URL sources, custom registries, unresolved ranges, manifest installs, and failed lookups are ASK
- add `claude-hook`: a Claude Code `PreToolUse` hook for Bash, Read, Grep, Glob, Write, Edit, MultiEdit, and NotebookEdit. It never approves anything, and fails closed for risky tools. It stops:
  - risky package installs
  - changes to agent settings, MCP configuration, or TrustDex itself (`guard-tamper`)
  - credential-store reads, including keychains, browser logins, and `gh auth token` (`secret-access`)
  - AI coding CLIs launched with permission or sandbox checks off (`agent-permission-bypass`)
  - startup items (`persistence-change`)
- by default a risky action is denied instead of becoming a one-click dialog. Add `trustdex allow-once <code>` to allow that exact action once within 30 minutes. It requires a person at an interactive terminal and cannot be run or forged by the agent. `--on-risk ask` keeps dialogs for ASK-level findings
- the hook also checks:
  - here-document bodies run by a shell or interpreter, local script files run directly, variables assigned in the same command, `cd` within the command, and paths inside one-line code (`python3 -c`, `node -e`)
  - environment dumps and `.env` files sent over the network
  - `claude`/`codex`/`gemini` `mcp add` commands
  - git hooks (`.git/hooks`, `core.hooksPath`)
- block decoded payloads run as programs (`base64 -d | sh`, `eval "$(... base64 -d)"`, `xxd -r | python3`, `gunzip | sh`) as `obfuscated-execution`
- report `disableAllHooks` in Claude settings as `claude-hooks-disabled` (BLOCK in every pack)
- less friction for everyday package use:
  - runners find binaries the project already installed after a `cd` and in parent folders
  - too-recent releases name the newest older version as a safe alternative
  - approving package findings covers those exact versions in any command for 24 hours, instead of one exact command for 30 minutes
- add a strict install policy file (`--install-policy`) for release and package age thresholds, manifest installs, and narrowly scoped allowlists that cannot silence BLOCK signals, `recent-release`, or `publisher-changed`
- accept Codex `approvals_reviewer = "guardian_subagent"` as an automatic reviewer (`codex-auto-review`) in settings inspection and permission posture

## 0.13.1 - 2026-11-08

- **security:** apply fixed budgets to installed IDE extension trees (maximum 50,000 files, 100,000 entries, 2 GiB of content, 64 nested directories), failing closed on any resource limit and streaming directory enumeration
- recognize Windows tilde-home paths and conservatively classify mixed-case Claude permission tool names without weakening shell, filesystem, network, subagent, or MCP risk signals
- require complete, unique, valid MCP policy decisions and avoid prototype-sensitive server-name insertion when constructing a gated configuration
- reject missing, repeated, or chained CLI value flags instead of silently using defaults; expand CLI regression tests for exit codes and help/version
- default signed runtime inventory verification to a maximum 3600-second capture age, with an explicitly validated override; document the expiry/freshness distinction
- accept finite TOML exponent notation and optimize multiline continuation parsing without re-slicing the remaining document
- split GitHub release verification into a read-only CI job and the privileged, dependent artifact/signature/publish job; clarify registry-runner matching and Codex array replacement in documentation

## 0.13.0 - 2026-11-08

- **security:** create CLI outputs through exclusive temporary files and atomic replacement; reject symlink or non-regular output targets and repository-controlled symlink parent directories; preserve 0600 private-key permissions
- bound online provenance lookups to 10 seconds, reject redirects, and remove potentially sensitive URL values from HTTP failure messages
- fail closed when npm packages are unpublished or their version/SRI metadata is invalid, or when a single-package MCP Registry artifact lacks trustworthy metadata; reject duplicate trust claims
- block mismatched verified package versions and cross-ecosystem artifact claims (npm vs PyPI), with inert downgrade, registry-substitution, and missing-artifact regression fixtures
- recognize Windows drive, UNC, and mixed-separator paths across platforms; reject ambiguous dual MCP configuration containers and absent source evidence
- compare snapshot source/provenance objects canonically, without false-positive drift from object key ordering
- add value-free ANSI diff output respecting NO_COLOR/TTY while retaining existing change labels, JSON contracts, and exit codes
- provide copy-ready GitHub policy-check workflow and non-certification status badge guidance, with cross-platform Node.js 24 CI coverage
- connect verified GitHub release creation to npm trusted publishing through an explicit workflow dispatch, keeping the npm package release tied to its tag

## 0.12.0 - 2026-10-30

- determine the installed package from runner options: `uvx --from` names the package, `npx -p/--package` too, and option values such as `uvx --python 3.12` are no longer mistaken for the package; registry overrides (`--registry`, `--userconfig`, `--index-url`, `--extra-index-url`, `--find-links`, ...) add `package-source-override` (BLOCK), extra packages (`uvx --with`, repeated `-p`) add `additional-packages` (BLOCK; ASK in `development`), `npx -c/--call` and `--node-options` add `shell-execution`, and an unrecognised runner option, or a flag written with `=value` (npm expands `-y=x` into `--yes x`), adds `ambiguous-runner-arguments` (BLOCK)
- treat runner options that change where packages, configuration, or installed binaries come from as `package-source-override` (BLOCK): npm `--cache`, `--prefix`, `--workspace`; uv `--config-file`, `--env-file`, `--constraint`, `--override`, `--build-constraint`, `--cache-dir`, `--keyring-provider`, and a `--python` value that is a path or program name rather than a version
- add `runner-command-mismatch` (BLOCK; ASK in `development`) when `npx -p`/`uvx --from` runs a command other than the package's own name, such as `sh` or `python`, which is found on PATH rather than in the reviewed package
- add `runner-environment-override` (BLOCK) when a runner server's `env` sets runner, interpreter, or loader configuration (`npm_config_*`, `UV_*`, `BUN_*` including `BUN_OPTIONS`, `NODE_OPTIONS`, `PYTHONPATH`, `LD_PRELOAD`, `DYLD_*`, `PATH`, `HOME`, `NODE_TLS_REJECT_UNAUTHORIZED`, CA bundle variables, ...); `npx --no` is no longer accepted as a flag, because npx then reads every option after the package
- add `ambiguous-server-transport` (BLOCK) for a server that has both a `command` and a `url` or `endpoint`, which was previously judged only as remote
- count only exact versions as pinned: a full semantic version after `@`, or a PEP 440 version without wildcards after `==` following a PEP 508 name (`name@^1.0.0`, `name@1.2`, `name@1.x`, and `name==1.*` were previously reported as pinned)
- match `trustedPackages` and trust-store package claims by name only for registry specs; a URL, remote, or path that begins with a trusted name (for example `trusted@https://...`) is matched only as a whole

- **security:** replace the line-based Codex TOML handling with a TOML lexer. Before this change, an MCP server written with a spaced or quoted header (`[mcp_servers . x]`, `["mcp_servers".x]`) or as root-level dotted keys was skipped by `inspect-codex` and passed through `gate-codex` uninspected. A literal string ending in a backslash could also hide following tables. Quoted settings headers could hide sandbox and approval settings from `inspect-codex-settings`. All of these are now inspected or rejected.
- record whether each Codex MCP environment variable is a static value, forwarded from the host (with its `source`), or a bearer token, and which host variable each `env_http_headers` header reads; reject malformed `env_vars`, duplicate keys, repeated server tables, arrays of tables, control characters, and malformed bare values (**compatibility:** every Codex MCP fingerprint changes once, so existing Codex snapshots and bindings report a fingerprint change and need one re-review)
- stop printing and snapshotting credentials, query values, and `;params` embedded in package specs (URLs, `name@url`, scp-like remotes, uvx `--from`): simple registry specs, `npm:` aliases, and local paths are shown as written, any other spec is parsed with the WHATWG URL parser (known schemes only) or as an scp-like remote and shown with scheme, host, path, and git ref only, and a spec that cannot be parsed is shown as `<unparseable-package-spec>` and blocked in every pack (`unparseable-package-spec`); only simple specs and `npm:` aliases can be pinned, and package URLs with query values or `;params` are blocked in every pack (`package-url-query`) because their values can be neither shown nor tracked
- flag `embedded-credentials` for URL or scp-like credentials in any command-line argument, including `--flag=URL` values, and fingerprint that argument without its credentials; other argument values, including query values, still change the fingerprint
- report only known values for IDE extension install source and target platform, and drop the untrusted `displayName` from results
- add a canary sweep regression suite that plants unique values in every supported input format and fails if any command prints or stores one, and document the output redaction contract (names may be reported, values never)
- add `--decisions` to every inspection command: a versioned, value-free `trustdex-decisions` JSON report whose exit code matches the decision and which reports BLOCK when inspection fails
- validate `--policy` files strictly and reject unknown fields, unsupported versions, and invalid actions instead of silently falling back (**compatibility:** a policy with a misspelled field now errors)
- report an empty inventory as ASK in `--decisions` mode, reject `--decisions` on commands that do not implement it, and fail closed on MCP entries that are not objects instead of dropping them
- reject unknown signal names in `signalActions` and IDE extension entries without an exact version when a policy file is loaded
- publish JSON schemas for decision reports, policy files, and v3 trust snapshots, and document agent integration and operating rules
- add `snapshot-codex`, `approve-codex`, and `recheck-codex` so a reviewed Codex `config.toml` can be signed and rechecked for drift, including Codex-specific tool and approval-mode changes
- stop error messages from quoting input content: malformed JSON now reports only the file name, and Codex TOML inline-table errors no longer echo the entry, which could contain a credential
- reject unquoted TOML values (bare words, dates) instead of reading them as strings
- add `inspect-ide-extensions`, `snapshot-ide-extensions`, `approve-ide-extensions`, and `recheck-ide-extensions` for VS Code-compatible editor extension directories (VS Code, Cursor)
- allow IDE extensions only through exact-version `trustedIdeExtensions` pins with optional installed-file digests; add a `blockedIdeExtensions` deny-list that policy overlays cannot shrink
- digest every installed extension file (contents and executable bit) without following symlinks, never let `.obsolete` hide a registered extension, and fail closed on malformed or non-regular registries, missing manifests, registry/manifest mismatches, version ranges, and locations outside the supplied directory or through symlinks
- keep unpinned IDE extensions at ASK or stricter and IDE integrity signals at BLOCK regardless of policy overlays
- pin the npm CLI used by the release and publish workflows to an exact version
- add `--keyset keyset.json` as an alternative to `--public` on `verify`, every `recheck*` command, `verify-runtime-inventory`, and `snapshot-runtime-tools`: a strictly validated `trustdex-keyset` v1 allowlist (schema published) with SHA-256 SPKI key IDs, required `purposes` (`review`, `runtime-producer`, or both, with no default), `notBefore`/`notAfter` windows checked at the signed `createdAt`, multiple active keys for rotation, and a revocation list in the same file; giving both flags, either flag twice, or the `--flag=value` form is an error; key-set JSON with a repeated field name is rejected
- reject small-order and non-canonical Ed25519 public keys, which accept forged signatures, and non-canonical base64 signatures in trust records, including with `--public`
- treat a revocation without `revokedAt` as total (every signature by the key is INVALID); with `revokedAt`, keep only evidence signed strictly earlier, and document that this time is asserted by the key holder
- in keyset mode, reject trust records without a valid signed `createdAt` or with one more than five minutes in the future, and print only the signing key ID; add `key-id` to print a public key's ID

## 0.11.0 - 2026-10-24

- add short-lived Ed25519 producer attestations for exact value-free Claude/Codex runtime inventories
- reject wrong-key, mutated, expired, stale, excessive-lifetime, and future-dated runtime evidence
- add schema-v2 effective evidence with fail-closed authentication state, producer-key drift, CLI workflows, tests, and operations guidance

## 0.10.0 - 2026-10-24

- add an explicit value-free Claude/Codex runtime MCP inventory contract and effective-boundary reconciliation
- block observed BLOCK or unconfigured servers and require review for ASK/broad-grant exposure
- add self-validating runtime evidence snapshots, drift classification, versioned schemas, and inert fixtures

## 0.9.0 - 2026-10-24

- bind Claude Code and Codex MCP policy/provenance results to automatic tool grants without retaining permission specifiers or tool names
- add self-validating binding snapshots, drift classification, versioned JSON schemas, and inert adversarial fixtures
- fail closed on unmatched or ambiguous Claude MCP permission rules and blocked/provenance-mismatched automatic grants

## 0.8.0 - 2026-10-24

- add explicit Claude Code and Codex settings-stack inspection using documented source precedence
- add schema-v2 merged permission posture snapshots that omit source paths and require review for source-topology drift
- fail closed on malformed lower-precedence sources even when a higher source would override them

## 0.7.0 - 2026-10-24

- add self-validating Claude and Codex permission posture snapshots and autonomy-expansion review gates
- add inert adversarial permission fixtures that verify value-free inspection, snapshot, and diff output

## 0.6.0 - 2026-10-24

- add static Claude Code permission inspection for automatic shell, filesystem, network, MCP, and subagent grants
- add static Codex approval, sandbox, network, writable-root, web-search, and subagent settings inspection
- fail closed on unsupported security-relevant settings without retaining command, path, domain, hook, credential-helper, or unrelated setting values
- document the project's defensive AI-agent security use case, authorization boundary, CVP evidence boundary, and reproducible evaluation
- include inert examples in the published package so documented local evaluations remain reproducible from npm artifacts

## 0.5.1 - 2026-10-24

- exclude URL credentials, query values, and sensitive command arguments from configuration fingerprints while retaining trust-relevant endpoint structure

## 0.5.0 - 2026-10-07

- add Claude MCP JSON inspection and gating for stdio, HTTP, and SSE configurations
- fail closed on unsupported Claude settings and unresolved command/endpoint expansion
- review authentication header metadata and block shell-based header helpers by default without retaining secret values
- add Claude-specific snapshots and signed approval/recheck commands
- document Claude Code and Claude Desktop gating workflows

## 0.4.4 - 2026-10-06

- add a documented defensive security research policy and reproducible evaluation record
- add inert adversarial MCP fixtures with enforced ALLOW / ASK / BLOCK expectations and drift tests
- produce checksums and a CycloneDX SBOM for future GitHub releases
- create GitHub build-provenance and SBOM attestations for future release packages

## 0.4.3 - 2026-09-30

CLI correctness and Codex maintenance readiness:

- fix `trustdex --version` and the help banner reporting 0.4.0 in the 0.4.2 package; the CLI now reads its version from `package.json`
- add Codex review guidelines to AGENTS.md that encode TrustDex's security invariants as review findings
- add a Codex integration guide (docs/CODEX.md)
- add a pilot feedback issue form
- update CodeQL init and analyze together and group their Dependabot updates

## 0.4.2 - 2026-09-19

Trusted npm publishing migration:

- authorize only `grigent/trustdex` and `.github/workflows/publish.yml` through npm Trusted Publisher OIDC
- remove the long-lived `NPM_TOKEN` fallback from the publication workflow
- retain Sigstore provenance for every npm release
- align npm and GitHub Action examples with the verification release

## 0.4.1 - 2026-09-19

npm packaging correction:

- preserve the `trustdex` command in the published npm manifest with a normalized `bin` path
- normalize repository metadata for npm and provenance tooling
- document direct `npx trustdex` usage and expose the npm version badge

## 0.4.0 - 2026-09-19

Security hardening, artifact integrity, and public maintenance readiness:

- run full cross-platform CI on Ubuntu, Windows, and macOS
- exercise the composite GitHub Action end to end in CI
- verify user-supplied artifact bytes against npm SRI or MCP Registry SHA-256 metadata
- bind integrity evidence to package versions and block configuration mismatches
- redact remote URL credentials, paths, and query values from inspection output
- flag embedded URL credentials, insecure transport, and URL query parameters
- normalize Windows executable paths and command wrappers across platforms
- fail closed on unsupported Codex MCP keys and subsections
- fingerprint supported Codex execution controls
- add CodeQL, immutable GitHub Action pins, dependency updates, and ownership rules
- add governance, support, architecture, roadmap, and contribution templates

## 0.3.0 - 2026-09-19

Reviewable provenance and Codex integration:

- trust-relevant fingerprints for MCP config, skills, and plugin manifests
- signed approval bundles with automatic `APPROVED` / `NEEDS_REVIEW` rechecks
- explicit GitHub repository and npm registry provenance lookups
- official MCP Registry v0.1 provenance lookup
- GitHub latest-release signature verification
- focused Codex `config.toml` MCP parser and section gate
- support for both `mcpServers` and `servers` JSON container shapes
- additional tests for identity mismatch, signature state, fingerprint drift, and Codex gating

## 0.2.0

Trust and provenance gate:

- built-in `strict`, `official-first`, and `development` policy packs
- explicit provenance trust store with evidence metadata
- runtime MCP gate that outputs only policy-approved servers
- Agent Skill and plugin manifest inspection
- snapshot schema v2 with provenance drift detection
- Ed25519-signed trust records
- GitHub Action support
- expanded security tests and documentation

## 0.1.0

Initial working prototype:

- inspect MCP JSON configuration locally
- classify package, remote, local, and unknown sources
- detect trust-relevant signals without printing secret values
- apply ALLOW / ASK / BLOCK policy decisions
- generate deterministic snapshots
- diff snapshots for source and signal drift
- Node.js test suite and GitHub Actions CI
