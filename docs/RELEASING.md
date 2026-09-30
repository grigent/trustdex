# Releasing TrustDex

TrustDex uses two small GitHub Actions workflows:

- `release.yml` creates a GitHub tag and release after tests pass.
- `publish.yml` publishes that exact tag to npm.

This split keeps GitHub release creation separate from registry credentials.

## Bootstrap publication

The one-time token-based bootstrap publication has been completed. Do not repeat it for normal releases.

A short-lived `NPM_TOKEN` may remain only until trusted publishing has been configured and verified. Delete both the npm token and the GitHub repository secret immediately after the first successful OIDC publication.

Do not paste npm credentials into issues, pull requests, source files, logs, or chat.

## npm trusted publishing

After the package exists, configure npm trusted publishing for:

- GitHub user/organization: `grigent`
- repository: `trustdex`
- workflow filename: `publish.yml`
- allowed action: direct `npm publish`

The workflow grants only `contents: read` and `id-token: write`. npm can then authenticate the GitHub-hosted job with OIDC instead of a long-lived write token.

Once trusted publishing works, remove the `NPM_TOKEN` repository secret and revoke the bootstrap token on npm. The workflow deliberately continues to use the standard `npm publish` command so npm can select OIDC authentication.

Both release workflows run `npm pkg fix` and require a clean `package.json` diff before packing or publishing. This prevents npm from silently normalizing away critical metadata such as the CLI entrypoint.

## Provenance

The repository is public and the package is public, so GitHub-hosted publishing can emit npm provenance. The workflow also passes `--provenance` explicitly.

Provenance links the published artifact to its source/build environment. It does not prove that the package contains no malicious behavior.

## Version checklist

Before each release:

1. update `package.json` version
2. move the corresponding changelog section out of `Unreleased`
3. make sure CI is green
4. run the release workflow with exactly `v<package version>`
5. run the publish workflow for that exact release tag

The publish workflow checks out the tag SHA rather than the latest branch head so the npm artifact cannot silently include later commits.
