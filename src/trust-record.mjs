import crypto from 'node:crypto';
import { canonicalJson, sha256Json } from './canonical.mjs';
import { isKeyset } from './keyset.mjs';

const MAX_FUTURE_SKEW_SECONDS = 300;

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

  const message = Buffer.from(canonicalJson(payloadFromRecord(record)));
  if (isKeyset(publicKeyPem)) {
    if (typeof record.signature !== 'string') {
      return { valid: false, reason: 'unsupported or incomplete trust record', keyId: null };
    }
    return verifyWithKeyset(record, message, Buffer.from(record.signature, 'base64'), publicKeyPem, options);
  }

  const valid = crypto.verify(null, message, publicKeyPem, Buffer.from(record.signature, 'base64'));
  return { valid, reason: valid ? null : 'signature verification failed' };
}

function verifiesWith(message, key, signature) {
  try {
    return crypto.verify(null, message, key, signature);
  } catch {
    return false;
  }
}

// Trust records carry no key ID, so the signer is found by trying every listed key. The
// signed createdAt is the only time the record asserts, so key windows and revocation
// cutoffs are evaluated against it; a record without a valid createdAt fails closed.
function verifyWithKeyset(record, message, signature, keyset, options) {
  const createdAt = record.createdAt;
  if (typeof createdAt !== 'string' || Number.isNaN(Date.parse(createdAt)) ||
      new Date(createdAt).toISOString() !== createdAt) {
    return { valid: false, reason: 'trust record has no valid signed creation time', keyId: null };
  }
  const nowMs = options.now === undefined ? Date.now() : Date.parse(options.now);
  if (!Number.isFinite(nowMs)) return { valid: false, reason: 'invalid verification time', keyId: null };
  if (Date.parse(createdAt) > nowMs + MAX_FUTURE_SKEW_SECONDS * 1000) {
    return { valid: false, reason: 'trust record creation time is too far in the future', keyId: null };
  }
  const signer = keyset.keys().find((entry) => verifiesWith(message, entry.key, signature));
  if (!signer) return { valid: false, reason: 'signature does not match any key in the keyset', keyId: null };
  const decision = keyset.authorize({ keyId: signer.id, purpose: 'review', signedAt: createdAt });
  if (!decision.ok) return { valid: false, reason: `signing key ${decision.reason}`, keyId: signer.id };
  return { valid: true, reason: null, keyId: signer.id };
}
