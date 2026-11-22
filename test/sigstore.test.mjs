import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { verifyNpmProvenanceBundle } from '../src/sigstore.mjs';
import { FULCIO_CHAINS, REKOR_LOGS } from '../src/sigstore-trust-root.mjs';

// The public Sigstore bundle npm serves for trustdex@0.17.3 (no secrets; public log entry).
const bundle = () => JSON.parse(fs.readFileSync(new URL('./fixtures/npm-provenance-bundle-trustdex-0.17.3.json', import.meta.url), 'utf8'));
const expected = { repository: 'grigent/trustdex' };
const flip = (value, index = 12) => {
  const bytes = Buffer.from(value, 'base64');
  bytes[index] ^= 1;
  return bytes.toString('base64');
};

test('a real npm provenance bundle verifies against the pinned trust root', () => {
  assert.deepEqual(verifyNpmProvenanceBundle(bundle(), expected), { verified: true });
  assert.deepEqual(verifyNpmProvenanceBundle(bundle(), { repository: 'Grigent/TrustDex' }), { verified: true });
});

test('any altered part of the bundle fails verification', () => {
  const cases = {
    'envelope-signature': [
      (b) => { b.dsseEnvelope.payload = flip(b.dsseEnvelope.payload, 40); },
      (b) => { b.dsseEnvelope.payloadType = 'application/json'; },
      (b) => { b.dsseEnvelope.signatures[0].sig = flip(b.dsseEnvelope.signatures[0].sig, 20); }
    ],
    'log-signature': [
      (b) => { b.verificationMaterial.tlogEntries[0].integratedTime = String(Number(b.verificationMaterial.tlogEntries[0].integratedTime) + 1); },
      (b) => { b.verificationMaterial.tlogEntries[0].logIndex = '1'; },
      (b) => { b.verificationMaterial.tlogEntries[0].canonicalizedBody = Buffer.from('{}').toString('base64'); },
      (b) => { b.verificationMaterial.tlogEntries[0].inclusionPromise.signedEntryTimestamp = flip(b.verificationMaterial.tlogEntries[0].inclusionPromise.signedEntryTimestamp, 20); }
    ],
    'unknown-log': [
      (b) => { b.verificationMaterial.tlogEntries[0].logId.keyId = Buffer.alloc(32, 7).toString('base64'); }
    ],
    'unsupported-log-entries': [
      (b) => { b.verificationMaterial.tlogEntries = []; },
      (b) => { b.verificationMaterial.tlogEntries.push(b.verificationMaterial.tlogEntries[0]); },
      (b) => { delete b.verificationMaterial.tlogEntries; }
    ],
    'unsupported-signatures': [
      (b) => { b.dsseEnvelope.signatures = []; },
      (b) => { b.dsseEnvelope.signatures.push(b.dsseEnvelope.signatures[0]); }
    ],
    'missing-material': [
      (b) => { delete b.verificationMaterial.certificate; },
      (b) => { delete b.dsseEnvelope; },
      (b) => { b.verificationMaterial = { publicKey: { hint: 'x' }, tlogEntries: b.verificationMaterial.tlogEntries }; }
    ],
    'malformed-bundle': [
      (b) => { delete b.verificationMaterial.tlogEntries[0].inclusionPromise; },
      (b) => { b.verificationMaterial.certificate.rawBytes = 'AAAA'; },
      (b) => { b.dsseEnvelope.payload = 'not base64!'; },
      (b) => { b.verificationMaterial.certificate.rawBytes = flip(b.verificationMaterial.certificate.rawBytes, 300); }
    ]
  };
  for (const [reason, mutations] of Object.entries(cases)) {
    mutations.forEach((mutate, index) => {
      const altered = bundle();
      mutate(altered);
      const result = verifyNpmProvenanceBundle(altered, expected);
      assert.equal(result.verified, false, `${reason} ${index}`);
      if (reason !== 'malformed-bundle') assert.equal(result.reason, reason, `${reason} ${index}`);
    });
  }
  for (const input of [null, undefined, {}, [], 'x', { dsseEnvelope: {} }]) {
    assert.equal(verifyNpmProvenanceBundle(input, expected).verified, false);
  }
});

test('the certificate must name the expected source repository', () => {
  for (const repository of ['attacker/trustdex', 'grigent/trustdex-fork', 'grigent', '', undefined, null]) {
    assert.deepEqual(verifyNpmProvenanceBundle(bundle(), { repository }), { verified: false, reason: 'certificate-repository' });
  }
  assert.equal(verifyNpmProvenanceBundle(bundle()).verified, false);
});

test('a bundle is not verified without a pinned root and log key valid at signing time', () => {
  const ended = (list) => list.map((item) => ({ ...item, validFor: { ...item.validFor, end: '2022-01-01T00:00:00Z' } }));
  assert.equal(verifyNpmProvenanceBundle(bundle(), expected, { fulcioChains: [] }).reason, 'certificate-chain');
  assert.equal(verifyNpmProvenanceBundle(bundle(), expected, { fulcioChains: ended(FULCIO_CHAINS) }).reason, 'certificate-chain');
  // A chain whose intermediate is dropped, or whose root is replaced by the intermediate, does not anchor.
  const chains = FULCIO_CHAINS.filter((chain) => chain.certificates.length > 1);
  assert.ok(chains.length > 0);
  assert.equal(verifyNpmProvenanceBundle(bundle(), expected, {
    fulcioChains: chains.map((chain) => ({ ...chain, certificates: chain.certificates.slice(1) }))
  }).reason, 'certificate-chain');
  assert.equal(verifyNpmProvenanceBundle(bundle(), expected, { rekorLogs: [] }).reason, 'unknown-log');
  assert.equal(verifyNpmProvenanceBundle(bundle(), expected, { rekorLogs: ended(REKOR_LOGS) }).reason, 'log-key-validity');
});
