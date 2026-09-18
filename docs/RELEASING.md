# Releasing TrustDex

TrustDex uses two small GitHub Actions workflows:

- `release.yml` creates a GitHub tag and release after tests pass.
- `publish.yml` publishes that exact tag to npm.

This split keeps GitHub release creation separate from registry credentials.

## First npm publication

npm trusted publishing can only be configured after a package already exists in the npm registry.

For the first publication:

1. Make sure the `trustdex` package name is still available on npm.
2. Create an npm granular access token that is allowed to publish the package and store it as the repository secret `NPM_TOKEN`.
3. Run **Create GitHub Release** for `v0.3.0`.
4. Run **Publish Package to npmjs** for the same tag.
5. Delete the publishing token after the first successful publication.

Do not paste npm credentials into issues, pull requests, source files, logs, or chat.

## Switch to npm trusted publishing

After the package exists, configure npm trusted publishing for:

- GitHub user/organization: `grigent`
- repository: `trustdex`
- workflow filename: `publish.yml`
- allowed action: direct `npm publish`

The workflow grants only `contents: read` and `id-token: write`. npm can then authenticate the GitHub-hosted job with OIDC instead of a long-lived write token.

Once trusted publishing works, remove the `NPM_TOKEN` repository secret. The workflow deliberately continues to use the standard `npm publish` command so npm can select OIDC authentication.

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
