import crypto from 'node:crypto';
import { canonicalJson, sha256Json } from './canonical.mjs';

function payloadFromRecord(record) {
  return {
    schemaVersion: record.schemaVersion,
    algorithm: record.algorithm,
    snapshotDigest: record.snapshotDigest,
    policyDigest: record.policyDigest || null,
    sourceRef: record.sourceRef || null,
    createdAt: record.createdAt
  };
}

export function generateTrustKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  return {
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKey: publicKey.export({ type: 'spki', format: 'pem' })
  };
}

export function createTrustRecord(snapshot, privateKeyPem, options = {}) {
  if (!snapshot?.digest) throw new Error('Snapshot is missing a digest.');
  const record = {
    schemaVersion: 1,
    algorithm: 'ed25519',
    snapshotDigest: snapshot.digest,
    policyDigest: options.policy ? sha256Json(options.policy) : null,
    sourceRef: options.sourceRef || null,
    createdAt: new Date().toISOString()
  };
  const signature = crypto.sign(
    null,
    Buffer.from(canonicalJson(payloadFromRecord(record))),
    privateKeyPem
  );
  return { ...record, signature: signature.toString('base64') };
}

export function verifyTrustRecord(record, publicKeyPem, options = {}) {
  if (!record || record.algorithm !== 'ed25519' || !record.signature) {
    return { valid: false, reason: 'unsupported or incomplete trust record' };
  }
  if (options.snapshot?.digest && options.snapshot.digest !== record.snapshotDigest) {
    return { valid: false, reason: 'snapshot digest does not match trust record' };
  }
  if (options.policy && sha256Json(options.policy) !== record.policyDigest) {
    return { valid: false, reason: 'policy digest does not match trust record' };
  }

  const valid = crypto.verify(
    null,
    Buffer.from(canonicalJson(payloadFromRecord(record))),
    publicKeyPem,
    Buffer.from(record.signature, 'base64')
  );
  return { valid, reason: valid ? null : 'signature verification failed' };
}
