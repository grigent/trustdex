# IDE extensions

<p align="right">
  <strong>English</strong> | <a href="./IDE_EXTENSIONS.ko.md">한국어</a>
</p>

AI coding agents increasingly ship as editor extensions (for example the Claude Code extension for VS Code and Cursor). An editor extension runs with the user's full local privileges, and marketplaces update it automatically. In October 2026, Cursor reported that a modified `Anthropic.claude-code` build (version `2.1.313`) was available in the Cursor extension marketplace for several hours and tried to add an attacker SSH key and open a reverse tunnel. Users received it through an ordinary update.

TrustDex treats an installed extension the same way it treats an MCP server: nothing is trusted because of its name, publisher label, or marketplace. An extension is ALLOW only when it matches an exact version you pinned, and a signed review lets you detect any later change to the installed files.

## What is inspected

`inspect-ide-extensions` reads one VS Code-compatible extensions directory that you name, such as:

| Editor | Typical directory |
|---|---|
| VS Code | `~/.vscode/extensions` |
| Cursor | `~/.cursor/extensions` |
| VS Code Remote / Codespaces | `~/.vscode-server/extensions` |

For that directory TrustDex:

- reads `extensions.json` (the editor's install registry) and `.obsolete`, and fails closed if either is malformed, oversized, or not a regular file;
- always inspects every registry entry. An entry whose `<id>-<version>[-<platform>]` key is also in `.obsolete` is reported with `ide-extension-marked-obsolete`, never dropped;
- skips an unregistered folder only when `.obsolete` contains its exact manifest key, optionally followed by a known target platform (pending deletion by the editor);
- reads each extension's `package.json` and compares its publisher, name, and version with the registry;
- reports extension folders that contain a `package.json` but are missing from the registry, including hidden folders;
- computes a SHA-256 digest over every file in the installed extension (relative paths, sizes, executable bits, and contents). Symlinks are recorded by target text and never followed;
- treats a registry location as outside the directory when any path component is a symlink, and does not read it; manifests and control files are opened without following symlinks;
- never executes extension code and makes no network requests.

Results contain the extension ID, version, recorded install source (`gallery`, `vsix`, ...), target platform, digest, and signals. Absolute paths are not included in results or snapshots.

## Signals

| Signal | strict | Meaning |
|---|---|---|
| `ide-extension-missing-manifest` | BLOCK | the registered folder is missing or is a symlink, or its `package.json` is missing or unparseable |
| `ide-extension-manifest-mismatch` | BLOCK | `package.json` publisher/name/version differ from the registry, or are invalid |
| `ide-extension-digest-mismatch` | BLOCK | installed files differ from a `#sha256:` digest pinned in policy |
| `ide-extension-external-location` | BLOCK | the registry points outside the supplied directory or through a symlink (not read) |
| `ide-extension-unregistered` | ASK | an extension folder exists that the registry does not list |
| `ide-extension-marked-obsolete` | ASK | the registry lists the extension but `.obsolete` marks it for deletion |
| `ide-extension-non-gallery-source` | ASK | the registry does not record a marketplace (`gallery`) install, for example a `.vsix` |
| `ide-extension-prerelease` | ASK | a pre-release build is installed |
| `ide-extension-startup-activation` | ASK | the extension activates on startup (`*` or `onStartupFinished`) without a user action |
| `ide-extension-untrusted-workspaces` | ASK | the extension declares full support for untrusted workspaces |
| `ide-extension-native-code` | ASK | native executables or modules are present (ELF, Mach-O, PE, `.node`, `.dll`, `.so`, `.dylib`, `.exe`) |
| `ide-extension-bundles-extensions` | ASK | the extension declares `extensionPack` or `extensionDependencies` |
| `ide-extension-non-regular-files` | ASK | symlinks or special files are present in the extension tree |

A `gallery` install source only means the editor recorded a marketplace install. It is not evidence of safety: the October 2026 build was delivered by a marketplace.

## Policy

```json
{
  "trustedIdeExtensions": [
    "anthropic.claude-code@2.1.314",
    "example.formatter@3.2.0#sha256:<digest from inspect output>"
  ],
  "blockedIdeExtensions": [
    "example.abandoned@*"
  ]
}
```

- `trustedIdeExtensions` entries must name an exact semver version. Entries without a version, or with a range such as `1.*`, `^1.0.0`, or `latest`, are rejected, so trusting a publisher never trusts its next update automatically. Malformed IDE entries fail every evaluation, not only IDE inspections.
- An optional `#sha256:<digest>` pin also requires the installed files to match byte-for-byte; a mismatch blocks the extension.
- `blockedIdeExtensions` entries match an exact version or `@*` for every version, and always win over a pin. Policy overlays add to the deny-list; they cannot remove base entries.
- Extensions that are not pinned use the pack's `unknownAction` (BLOCK in `strict` and `official-first`, ASK in `development`), but never better than ASK: only an exact pin produces ALLOW.
- Signals still raise a pinned extension to ASK or BLOCK. The four BLOCK integrity signals (missing manifest, manifest mismatch, digest mismatch, external location) stay BLOCK even if a policy overlay sets their `signalActions` lower.

If your editor installs from a marketplace that distributed a known-bad build, add that exact version to `blockedIdeExtensions`, for example `"anthropic.claude-code@2.1.313"` for editors that use the Cursor extension marketplace. Use the vendor's own advisory to decide which versions and marketplaces are affected.

## Review and recheck

```bash
node ./bin/trustdex.mjs inspect-ide-extensions ~/.cursor/extensions \
  --pack strict --policy ./ide-policy.json

node ./bin/trustdex.mjs approve-ide-extensions ~/.cursor/extensions \
  --private trustdex-private.pem --dir .trustdex/ide-review \
  --pack strict --policy ./ide-policy.json

node ./bin/trustdex.mjs recheck-ide-extensions ~/.cursor/extensions \
  --review-dir .trustdex/ide-review --public trustdex-public.pem
```

`approve-ide-extensions` refuses to sign an inventory that contains BLOCK decisions. `recheck-ide-extensions` exits `0` when the installed extensions still match the signed review, `1` with `NEEDS_REVIEW` when any extension was added, removed, updated, or modified, and `2` when the review is invalid. Try it with the inert example:

```bash
node ./bin/trustdex.mjs inspect-ide-extensions ./examples/ide-extensions \
  --pack strict --policy ./examples/ide-extensions.policy.json
```

The example pins `example.updated-ext@2.0.0` while `2.0.1` is installed, so it is blocked; `example.sideloaded-ext` is on the deny-list.

## Recommended editor settings

TrustDex inspects what is installed; it cannot stop an editor from installing an update. To keep reviews meaningful:

- turn off automatic extension updates (`"extensions.autoUpdate": false`) and update deliberately;
- run `recheck-ide-extensions` before opening the editor, from a login script, or on a schedule, and investigate any `NEEDS_REVIEW`;
- keep the signing private key off the machine being checked when possible.

## Limits

- Static inspection does not prove an extension is safe. A pinned, digest-matched extension can still be malicious; the pin only proves it is the build you reviewed.
- TrustDex does not detect or remove changes an extension has already made elsewhere on the host (for example SSH keys or services). If a known-bad build was installed, follow the vendor's remediation guidance.
- TrustDex trusts the local host enough to read the extensions directory. A fully compromised host can falsify what TrustDex reads, and a process that swaps files while an inspection is running can race it.
- Only the directory you supply is inspected. Editors can load extensions from other locations (for example built-in or `--extensions-dir` folders).
