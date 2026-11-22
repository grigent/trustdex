# Refreshing the pinned Sigstore trust root

<p align="right">
  <strong>English</strong> | <a href="./TRUST_ROOT.ko.md">한국어</a>
</p>

`provenance npm` and `trust-source npm` verify npm build provenance against keys pinned
in [`src/sigstore-trust-root.mjs`](../src/sigstore-trust-root.mjs): the Fulcio certificate
chains, the Rekor v1 log key, and the certificate-transparency log keys of the Sigstore
public-good instance. TrustDex never fetches these at run time. This page is the
maintainer procedure for changing them.

## What happens when Sigstore rotates a key

Nothing unsafe: a release signed under a key that is not pinned is reported as
`unverifiable`, and `trust-source` refuses it, until a TrustDex release pins the new key.
The cost of a stale root is refused releases, not accepted forgeries. Install checks
(`check-install`, `claude-hook`) do not use the trust root and are not affected.

## When to refresh

- Sigstore announces a rotation, or `targets/trusted_root.json` in
  [sigstore/root-signing](https://github.com/sigstore/root-signing) changes. The SHA-256 of
  the file the pin was derived from is in the header of `src/sigstore-trust-root.mjs`.
- Releases that verify with a current Sigstore client start to be `unverifiable` here.

## Procedure

1. Obtain the new `trusted_root.json` through a client that verifies Sigstore's TUF
   metadata (for example the copy an up-to-date `@sigstore/tuf` or `cosign initialize`
   writes), not through a plain download. Compare its SHA-256 with
   `targets/trusted_root.json` in sigstore/root-signing at a signed release. Do not use
   a file from an issue, a chat message, or any other third party.
2. Replace `test/fixtures/sigstore-trusted-root.json` with that file, unchanged.
3. Update `src/sigstore-trust-root.mjs`: the SHA-256 and client version in the header,
   and the three constants. Keep the exact values from the file.
4. Run `npm test`. `test/sigstore-trust-root.test.mjs` fails until the header hash
   matches the fixture and the constants are exactly what the fixture yields, so a key
   cannot be added, changed, or dropped by hand without the upstream file saying so.
5. Check real releases with `provenance npm` for a few packages, including one published
   before and one after the rotation.
6. Open a pull request that contains only this change. It needs the usual required
   checks and review; nobody merges their own trust-root change without them.

## Rules

- Do not delete an entry that upstream still lists. A retired key keeps its `validFor`
  end date, which is what lets releases signed while it was valid keep verifying and
  stops it from vouching for anything later.
- Do not widen a `validFor` window or add a key that the upstream file does not contain.
- Only ECDSA P-256 Rekor v1 logs are pinned. The upstream file also lists a Rekor v2 log
  (Ed25519); bundles logged only there are `unverifiable` until the verifier supports
  that log, and pinning its key alone would not change that.
- Timestamp authorities are not pinned because RFC 3161 timestamps are not checked.
