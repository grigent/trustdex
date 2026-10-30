import crypto from 'node:crypto';

import { canonicalJson, sha256Json } from './canonical.mjs';
import { isKeyset, spkiKeyId } from './keyset.mjs';
import {
  normalizeRuntimeToolInventory,
  runtimeToolInventoryDigest
} from './runtime-evidence.mjs';

const KIND = 'agent-runtime-tool-inventory-attestation';
const ALGORITHM = 'ed25519';
const MAX_TTL_SECONDS = 86_400;
const MAX_FUTURE_SKEW_SECONDS = 300;
const FIELDS = new Set([
  'schemaVersion', 'kind', 'algorithm', 'inventoryDigest', 'runtime', 'capturedAt',
  'captureMethod', 'producerKeyId', 'createdAt', 'expiresAt', 'signature'
]);

function requireObject(value, message) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(message);
  return value;
}

function requireExactKeys(value, expected, message) {
  const keys = Object.keys(requireObject(value, message));
  if (keys.length !== expected.size || keys.some((key) => !expected.has(key))) throw new Error(message);
  return value;
}

function requireDigest(value, field) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error(`Invalid runtime inventory attestation digest: ${field}`);
  }
  return value;
}

function requireTimestamp(value, field) {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value)) ||
      new Date(value).toISOString() !== value) {
    throw new Error(`Invalid runtime inventory attestation timestamp: ${field}`);
  }
  return value;
}

function publicKeyId(publicKey) {
  const key = publicKey?.type === 'public' ? publicKey : crypto.createPublicKey(publicKey);
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new Error('Runtime inventory attestations require an Ed25519 key.');
  }
  return spkiKeyId(key);
}

function payload(record) {
  return {
    schemaVersion: record.schemaVersion,
    kind: record.kind,
    algorithm: record.algorithm,
    inventoryDigest: record.inventoryDigest,
    runtime: record.runtime,
    capturedAt: record.capturedAt,
    captureMethod: record.captureMethod,
    producerKeyId: record.producerKeyId,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt
  };
}

export function validateRuntimeInventoryAttestation(record) {
  requireExactKeys(record, FIELDS, 'Invalid runtime inventory attestation.');
  if (record.schemaVersion !== 1 || record.kind !== KIND || record.algorithm !== ALGORITHM) {
    throw new Error('Unsupported runtime inventory attestation schema.');
  }
  requireDigest(record.inventoryDigest, 'inventoryDigest');
  requireDigest(record.producerKeyId, 'producerKeyId');
  if (!['claude', 'codex'].includes(record.runtime)) throw new Error('Invalid attested runtime.');
  if (!['runtime-export', 'runtime-adapter'].includes(record.captureMethod)) {
    throw new Error('Invalid attested capture method.');
  }
  requireTimestamp(record.capturedAt, 'capturedAt');
  requireTimestamp(record.createdAt, 'createdAt');
  requireTimestamp(record.expiresAt, 'expiresAt');
  if (Date.parse(record.expiresAt) <= Date.parse(record.createdAt)) {
    throw new Error('Runtime inventory attestation expiry must follow creation time.');
  }
  if (Date.parse(record.expiresAt) - Date.parse(record.createdAt) > MAX_TTL_SECONDS * 1000) {
    throw new Error('Runtime inventory attestation lifetime exceeds 24 hours.');
  }
  if (Date.parse(record.capturedAt) > Date.parse(record.createdAt) + MAX_FUTURE_SKEW_SECONDS * 1000) {
    throw new Error('Runtime inventory capture cannot postdate attestation creation by more than five minutes.');
  }
  if (typeof record.signature !== 'string' ||
      !/^[A-Za-z0-9+/]{86}==$/.test(record.signature) ||
      Buffer.from(record.signature, 'base64').toString('base64') !== record.signature) {
    throw new Error('Invalid runtime inventory attestation signature.');
  }
  return record;
}

export function createRuntimeInventoryAttestation(inventoryInput, privateKeyPem, options = {}) {
  const inventory = normalizeRuntimeToolInventory(inventoryInput);
  const ttlSeconds = options.ttlSeconds === undefined ? 300 : options.ttlSeconds;
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > MAX_TTL_SECONDS) {
    throw new Error('Runtime inventory attestation TTL must be an integer from 1 to 86400 seconds.');
  }
  const createdAt = options.createdAt || new Date().toISOString();
  requireTimestamp(createdAt, 'createdAt');
  if (Date.parse(inventory.capturedAt) > Date.parse(createdAt) + MAX_FUTURE_SKEW_SECONDS * 1000) {
    throw new Error('Runtime inventory capture cannot postdate attestation creation by more than five minutes.');
  }
  const expiresAt = new Date(Date.parse(createdAt) + ttlSeconds * 1000).toISOString();
  const publicKey = crypto.createPublicKey(privateKeyPem);
  const record = {
    schemaVersion: 1,
    kind: KIND,
    algorithm: ALGORITHM,
    inventoryDigest: runtimeToolInventoryDigest(inventory),
    runtime: inventory.runtime,
    capturedAt: inventory.capturedAt,
    captureMethod: inventory.captureMethod,
    producerKeyId: publicKeyId(publicKey),
    createdAt,
    expiresAt
  };
  const signature = crypto.sign(
    null,
    Buffer.from(canonicalJson(payload(record))),
    privateKeyPem
  );
  return { ...record, signature: signature.toString('base64') };
}

function invalid(reason) {
  return { valid: false, reason, producerKeyId: null, inventoryDigest: null, attestationDigest: null };
}

export function verifyRuntimeInventoryAttestation(inventoryInput, recordInput, publicKeyPem, options = {}) {
  let inventory;
  let record;
  try {
    inventory = normalizeRuntimeToolInventory(inventoryInput);
    record = validateRuntimeInventoryAttestation(recordInput);
  } catch (error) {
    return invalid(error.message);
  }

  // A keyset selects the key by the signed producerKeyId and checks revocation, purpose,
  // and the key's validity window at the signed createdAt; a single --public key is pinned.
  let keyId;
  let verificationKey = publicKeyPem;
  if (isKeyset(publicKeyPem)) {
    const decision = publicKeyPem.authorize({
      keyId: record.producerKeyId,
      purpose: 'runtime-producer',
      signedAt: record.createdAt
    });
    if (!decision.ok) return invalid(`Runtime inventory producer key ${decision.reason}.`);
    keyId = record.producerKeyId;
    verificationKey = decision.key;
  } else {
    try { keyId = publicKeyId(publicKeyPem); } catch {
      return invalid('Invalid runtime inventory attestation public key.');
    }
    if (record.producerKeyId !== keyId) return invalid('Runtime inventory producer key does not match.');
  }
  const inventoryDigest = runtimeToolInventoryDigest(inventory);
  if (record.inventoryDigest !== inventoryDigest ||
      record.runtime !== inventory.runtime ||
      record.capturedAt !== inventory.capturedAt ||
      record.captureMethod !== inventory.captureMethod) {
    return invalid('Runtime inventory does not match its attestation.');
  }

  const nowMs = options.now === undefined ? Date.now() : Date.parse(options.now);
  if (!Number.isFinite(nowMs)) return invalid('Invalid runtime inventory verification time.');
  if (nowMs >= Date.parse(record.expiresAt)) return invalid('Runtime inventory attestation expired.');
  const futureSkewSeconds = options.futureSkewSeconds === undefined
    ? MAX_FUTURE_SKEW_SECONDS
    : options.futureSkewSeconds;
  if (!Number.isSafeInteger(futureSkewSeconds) || futureSkewSeconds < 0) {
    return invalid('Invalid runtime inventory future-skew limit.');
  }
  if (Date.parse(record.createdAt) > nowMs + futureSkewSeconds * 1000) {
    return invalid('Runtime inventory attestation creation time is too far in the future.');
  }
  if (Date.parse(inventory.capturedAt) > nowMs + futureSkewSeconds * 1000) {
    return invalid('Runtime inventory capture time is too far in the future.');
  }
  if (options.maxAgeSeconds !== undefined) {
    if (!Number.isSafeInteger(options.maxAgeSeconds) || options.maxAgeSeconds < 0) {
      return invalid('Invalid runtime inventory maximum age.');
    }
    if (nowMs - Date.parse(inventory.capturedAt) > options.maxAgeSeconds * 1000) {
      return invalid('Runtime inventory capture is too old.');
    }
  }

  let valid = false;
  try {
    valid = crypto.verify(
      null,
      Buffer.from(canonicalJson(payload(record))),
      verificationKey,
      Buffer.from(record.signature, 'base64')
    );
  } catch {
    return invalid('Runtime inventory attestation signature verification failed.');
  }
  if (!valid) return invalid('Runtime inventory attestation signature verification failed.');
  return {
    valid: true,
    reason: null,
    producerKeyId: keyId,
    inventoryDigest,
    attestationDigest: sha256Json(record)
  };
}
