import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import test from 'node:test';
import { verifyNpmProvenanceBundle } from '../src/sigstore.mjs';
import { CT_LOGS, FULCIO_CHAINS, REKOR_LOGS } from '../src/sigstore-trust-root.mjs';

// The public Sigstore bundle npm serves for trustdex@0.17.3 (no secrets; public log entry).
const bundle = () => JSON.parse(fs.readFileSync(new URL('./fixtures/npm-provenance-bundle-trustdex-0.17.3.json', import.meta.url), 'utf8'));
const expected = { repository: 'grigent/trustdex' };
const fixture = (name) => JSON.parse(fs.readFileSync(new URL(`./fixtures/npm-provenance-bundle-${name}.json`, import.meta.url), 'utf8'));
const proof = (b) => b.verificationMaterial.tlogEntries[0].inclusionProof;
// Recomputes the root the (altered) audit path leads to, as an attacker would.
const recomputedRoot = (b) => {
  const hash = (...parts) => crypto.createHash('sha256').update(Buffer.concat(parts)).digest();
  const p = proof(b);
  let node = BigInt(p.logIndex);
  let last = BigInt(p.treeSize) - 1n;
  let current = hash(Buffer.from([0]), Buffer.from(b.verificationMaterial.tlogEntries[0].canonicalizedBody, 'base64'));
  for (const sibling of p.hashes.map((value) => Buffer.from(value, 'base64'))) {
    if (node % 2n === 1n || node === last) {
      current = hash(Buffer.from([1]), sibling, current);
      while (node % 2n === 0n && node !== 0n) { node >>= 1n; last >>= 1n; }
    } else current = hash(Buffer.from([1]), current, sibling);
    node >>= 1n; last >>= 1n;
  }
  return current.toString('base64');
};
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
    'log-inclusion-proof-missing': [
      (b) => { delete b.verificationMaterial.tlogEntries[0].inclusionProof; },
      (b) => { b.verificationMaterial.tlogEntries[0].inclusionProof = null; },
      // Relabelling a current bundle as the 2023 format does not excuse the missing proof.
      (b) => { delete b.verificationMaterial.tlogEntries[0].inclusionProof; b.mediaType = 'application/vnd.dev.sigstore.bundle+json;version=0.1'; }
    ],
    'log-inclusion': [
      (b) => { b.verificationMaterial.tlogEntries[0].inclusionProof = {}; },
      (b) => { const p = proof(b); p.hashes[0] = flip(p.hashes[0]); },
      (b) => { proof(b).hashes.pop(); },
      (b) => { const p = proof(b); p.hashes.push(p.hashes[0]); },
      (b) => { proof(b).hashes = []; },
      (b) => { proof(b).hashes[3] = Buffer.alloc(31).toString('base64'); },
      (b) => { proof(b).hashes = Array.from({ length: 65 }, () => proof(bundle()).hashes[0]); },
      (b) => { const p = proof(b); p.logIndex = String(BigInt(p.logIndex) + 1n); },
      (b) => { const p = proof(b); p.logIndex = p.treeSize; },
      (b) => { proof(b).logIndex = '-1'; },
      (b) => { proof(b).logIndex = 12; },
      (b) => { const p = proof(b); p.treeSize = String(BigInt(p.treeSize) + 1n); },
      (b) => { proof(b).treeSize = '0'; },
      (b) => { const p = proof(b); p.rootHash = flip(p.rootHash); },
      // A root the proof reaches but the log never signed.
      (b) => { const p = proof(b); p.hashes[0] = flip(p.hashes[0]); p.rootHash = recomputedRoot(b); },
      (b) => { delete proof(b).checkpoint; },
      (b) => { proof(b).checkpoint.envelope = 7; },
      (b) => { const c = proof(b).checkpoint; c.envelope = c.envelope.replace('rekor.sigstore.dev - ', 'other.example - '); },
      (b) => { const c = proof(b).checkpoint; c.envelope = c.envelope.replace(/\n\d+\n/, '\n1\n'); },
      (b) => { const c = proof(b).checkpoint; c.envelope = c.envelope.slice(0, c.envelope.indexOf('\n\n') + 2); },
      (b) => { const c = proof(b).checkpoint; c.envelope = c.envelope.replace(/\n\n\u2014 \S+ /, '\n\n\u2014 rekor.sigstore.dev AAAA'); },
      (b) => { const c = proof(b).checkpoint; c.envelope = c.envelope.replace('\n\n', '\nextra line\n\n'); },
      (b) => { const c = proof(b).checkpoint; c.envelope = c.envelope.replace('\n\n', '\n'); },
      // The checkpoint of another tree head, validly signed, does not cover this proof.
      (b) => { proof(b).checkpoint = proof(fixture('gauge-intoto')).checkpoint; }
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

test('an older bundle logged as an intoto 0.0.2 entry verifies, and altered copies do not', () => {
  // The public bundle npm serves for the latest gauge release, logged in the older Rekor entry format.
  const legacy = () => JSON.parse(fs.readFileSync(new URL('./fixtures/npm-provenance-bundle-gauge-intoto.json', import.meta.url), 'utf8'));
  const rebody = (b, edit) => {
    const entry = b.verificationMaterial.tlogEntries[0];
    const body = JSON.parse(Buffer.from(entry.canonicalizedBody, 'base64').toString('utf8'));
    edit(body);
    entry.canonicalizedBody = Buffer.from(JSON.stringify(body)).toString('base64');
  };
  assert.deepEqual(verifyNpmProvenanceBundle(legacy(), { repository: 'npm/gauge' }), { verified: true });
  assert.equal(verifyNpmProvenanceBundle(legacy(), { repository: 'npm/other' }).reason, 'certificate-repository');
  for (const mutate of [
    (b) => { b.dsseEnvelope.payload = flip(b.dsseEnvelope.payload, 40); },
    (b) => { b.dsseEnvelope.signatures[0].sig = flip(b.dsseEnvelope.signatures[0].sig, 20); },
    (b) => rebody(b, (body) => { body.apiVersion = '0.0.1'; }),
    (b) => rebody(b, (body) => { body.kind = 'dsse'; }),
    (b) => rebody(b, (body) => { body.spec.content.payloadHash.value = '0'.repeat(64); }),
    (b) => { b.verificationMaterial.tlogEntries[0].integratedTime = '1'; }
  ]) {
    const altered = legacy();
    mutate(altered);
    assert.equal(verifyNpmProvenanceBundle(altered, { repository: 'npm/gauge' }).verified, false);
  }
});

test('only a 2023 bundle in format 0.1 may carry the log promise without an inclusion proof', () => {
  // The public bundle npm serves for sigstore@1.3.0 (April 2023): format 0.1, no inclusion proof.
  const promiseOnly = () => fixture('sigstore-1.3.0-promise-only');
  const repository = { repository: 'sigstore/sigstore-js' };
  assert.equal(promiseOnly().verificationMaterial.tlogEntries[0].inclusionProof, null);
  assert.deepEqual(verifyNpmProvenanceBundle(promiseOnly(), repository), { verified: true });
  for (const mutate of [
    (b) => { b.mediaType = 'application/vnd.dev.sigstore.bundle+json;version=0.2'; },
    (b) => { b.mediaType = 'application/vnd.dev.sigstore.bundle.v0.3+json'; },
    (b) => { delete b.mediaType; }
  ]) {
    const altered = promiseOnly();
    mutate(altered);
    assert.deepEqual(verifyNpmProvenanceBundle(altered, repository), { verified: false, reason: 'log-inclusion-proof-missing' });
  }
  for (const mutate of [
    // A proof that is present must verify even in the old format.
    (b) => { b.verificationMaterial.tlogEntries[0].inclusionProof = proof(bundle()); },
    (b) => { b.verificationMaterial.tlogEntries[0].inclusionProof = {}; }
  ]) {
    const altered = promiseOnly();
    mutate(altered);
    assert.deepEqual(verifyNpmProvenanceBundle(altered, repository), { verified: false, reason: 'log-inclusion' });
  }
  // The promise itself is still checked.
  const altered = promiseOnly();
  altered.verificationMaterial.tlogEntries[0].integratedTime = '1900000000';
  assert.equal(verifyNpmProvenanceBundle(altered, repository).reason, 'log-signature');
});

test('2024 bundles in format 0.1 without an inclusion proof are reported as such, not as a bad signature', () => {
  // The public SLSA provenance bundles npm serves for sigstore@2.2.1 and @sigstore/sign@2.2.2:
  // format 0.1, logged on 2024-02-08, no inclusion proof. TrustDex 0.19.0 reported them matched.
  const repository = { repository: 'sigstore/sigstore-js' };
  for (const name of ['sigstore-2.2.1', 'sigstore-sign-2.2.2']) {
    const logged = fixture(name);
    const entry = logged.verificationMaterial.tlogEntries[0];
    assert.equal(logged.mediaType, 'application/vnd.dev.sigstore.bundle+json;version=0.1', name);
    assert.equal(entry.inclusionProof, null, name);
    assert.equal(new Date(Number(entry.integratedTime) * 1000).toISOString().slice(0, 10), '2024-02-08', name);
    assert.deepEqual(verifyNpmProvenanceBundle(logged, repository), { verified: false, reason: 'log-inclusion-proof-missing' }, name);
    // The proof check comes last: any other failure keeps its own reason.
    assert.equal(verifyNpmProvenanceBundle(logged, { repository: 'sigstore/other' }).reason, 'certificate-repository', name);
    const signature = fixture(name);
    signature.dsseEnvelope.signatures[0].sig = flip(signature.dsseEnvelope.signatures[0].sig, 20);
    assert.equal(verifyNpmProvenanceBundle(signature, repository).reason, 'envelope-signature', name);
    const time = fixture(name);
    time.verificationMaterial.tlogEntries[0].integratedTime = '1700000000';
    assert.equal(verifyNpmProvenanceBundle(time, repository).reason, 'log-signature', name);
  }
});

test('the certificate must carry an SCT signed by a pinned certificate-transparency log', () => {
  const sets = [['trustdex-0.17.3', expected], ['gauge-intoto', { repository: 'npm/gauge' }], ['sigstore-1.3.0-promise-only', { repository: 'sigstore/sigstore-js' }]];
  const verify = (name, repository, ctLogs) => verifyNpmProvenanceBundle(fixture(name), repository, { ctLogs });
  const current = CT_LOGS.find((log) => !log.validFor.end);
  const retired = CT_LOGS.find((log) => log.validFor.end);
  assert.ok(current && retired);
  for (const [name, repository] of sets) {
    assert.deepEqual(verify(name, repository, CT_LOGS), { verified: true });
    assert.deepEqual(verify(name, repository, [current]), { verified: true });
    for (const ctLogs of [
      [],
      [retired],
      // The right log id with another log's key.
      [{ ...current, publicKey: retired.publicKey }],
      [{ ...current, publicKey: REKOR_LOGS[0].publicKey }],
      // The log key is pinned, but not for the time the SCT was issued.
      [{ ...current, validFor: { start: current.validFor.start, end: '2022-12-31T00:00:00Z' } }],
      [{ ...current, validFor: { start: '2999-01-01T00:00:00Z' } }],
      [{ ...current, validFor: {} }],
      [{ ...current, logId: Buffer.alloc(32, 9).toString('base64') }]
    ]) {
      assert.deepEqual(verify(name, repository, ctLogs), { verified: false, reason: 'certificate-transparency' }, JSON.stringify(ctLogs));
    }
  }
  // Changing any byte of the embedded SCT list breaks the certificate itself.
  const der = Buffer.from(bundle().verificationMaterial.certificate.rawBytes, 'base64');
  const marker = der.indexOf(Buffer.from('060a2b06010401d679020402', 'hex'));
  assert.ok(marker > 0);
  for (const offset of [marker + 20, marker + 40, marker + 60, marker + 100]) {
    const altered = bundle();
    const bytes = Buffer.from(der);
    bytes[offset] ^= 1;
    altered.verificationMaterial.certificate.rawBytes = bytes.toString('base64');
    assert.equal(verifyNpmProvenanceBundle(altered, expected).verified, false, String(offset));
  }
});
