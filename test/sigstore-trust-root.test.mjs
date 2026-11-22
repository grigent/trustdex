import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import test from 'node:test';
import { CT_LOGS, FULCIO_CHAINS, REKOR_LOGS } from '../src/sigstore-trust-root.mjs';

// The upstream trusted_root.json the pinned module was derived from (public keys only).
const raw = fs.readFileSync(new URL('./fixtures/sigstore-trusted-root.json', import.meta.url));
const upstream = JSON.parse(raw);
const moduleText = fs.readFileSync(new URL('../src/sigstore-trust-root.mjs', import.meta.url), 'utf8');
const ECDSA_P256 = 'PKIX_ECDSA_P256_SHA_256';
const key = ({ logId, publicKey }) => ({ logId: logId.keyId, publicKey: publicKey.rawBytes, validFor: publicKey.validFor });

test('the pinned trust root names the upstream file it was derived from', () => {
  const digest = crypto.createHash('sha256').update(raw).digest('hex');
  assert.ok(moduleText.includes(`(sha256 ${digest})`), 'update the hash in src/sigstore-trust-root.mjs together with the fixture');
});

test('the pinned trust root is exactly what the upstream file yields', () => {
  assert.deepEqual(FULCIO_CHAINS, upstream.certificateAuthorities.map(({ validFor, certChain }) => ({
    validFor, certificates: certChain.certificates.map((certificate) => certificate.rawBytes)
  })));
  // Rekor v1 only: the verifier checks the ECDSA signed entry timestamp and checkpoint.
  assert.deepEqual(REKOR_LOGS, upstream.tlogs.filter((log) => log.publicKey.keyDetails === ECDSA_P256).map(key));
  assert.deepEqual(CT_LOGS, upstream.ctlogs.map(key));
  for (const log of [...upstream.ctlogs, ...upstream.tlogs.filter((item) => item.publicKey.keyDetails === ECDSA_P256)]) {
    assert.equal(log.hashAlgorithm, 'SHA2_256');
    assert.equal(log.publicKey.keyDetails, ECDSA_P256);
  }
});

test('every pinned key and certificate parses, and each log id is the hash of its key', () => {
  for (const log of [...REKOR_LOGS, ...CT_LOGS]) {
    const der = Buffer.from(log.publicKey, 'base64');
    assert.equal(crypto.createPublicKey({ key: der, format: 'der', type: 'spki' }).asymmetricKeyType, 'ec');
    assert.equal(crypto.createHash('sha256').update(der).digest('base64'), log.logId);
    assert.ok(Number.isFinite(Date.parse(log.validFor.start)));
  }
  for (const { validFor, certificates } of FULCIO_CHAINS) {
    assert.ok(Number.isFinite(Date.parse(validFor.start)) && certificates.length > 0);
    const chain = certificates.map((certificate) => new crypto.X509Certificate(Buffer.from(certificate, 'base64')));
    const root = chain.at(-1);
    assert.ok(root.checkIssued(root) && root.verify(root.publicKey));
    chain.forEach((certificate, index) => {
      assert.ok(certificate.ca);
      assert.ok(certificate.verify((chain[index + 1] || root).publicKey));
    });
  }
});
