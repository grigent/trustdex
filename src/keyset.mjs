import crypto from 'node:crypto';

// A trustdex-keyset v1 file is the deployment-facing allowlist of Ed25519 verification
// keys. It is an operator-written trust input: parsing fails closed on anything it does
// not understand, and error messages name only field positions, never file contents.

export const KEYSET_KIND = 'trustdex-keyset';
export const KEY_PURPOSES = Object.freeze(['review', 'runtime-producer']);

const TOP_FIELDS = new Set(['$schema', 'schemaVersion', 'kind', 'note', 'keys', 'revoked']);
const KEY_FIELDS = new Set(['id', 'publicKey', 'purposes', 'notBefore', 'notAfter', 'note']);
const REVOKED_FIELDS = new Set(['id', 'revokedAt', 'note']);
const KEY_ID_PATTERN = /^[a-f0-9]{64}$/;
// Exactly one SPKI "PUBLIC KEY" block. Private keys, certificates, and other PEM labels
// are rejected even though Node could derive a public key from some of them.
const PEM_PATTERN = /^-----BEGIN PUBLIC KEY-----\r?\n((?:[A-Za-z0-9+/=]+\r?\n)+)-----END PUBLIC KEY-----\r?\n?$/;
const MAX_KEYS = 256;
const MAX_REVOKED = 4096;

/** SHA-256 of the public key's SPKI DER bytes: the key ID used by attestations and keysets. */
export function spkiKeyId(keyObject) {
  return crypto.createHash('sha256').update(keyObject.export({ type: 'spki', format: 'der' })).digest('hex');
}

function fail(message) {
  throw new Error(`Invalid keyset: ${message}`);
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function requireKnownFields(value, allowed, where) {
  if (!isPlainObject(value)) fail(`${where} must be an object.`);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) fail(`${where} has an unknown field.`);
  }
}

function optionalString(value, where) {
  if (value !== undefined && typeof value !== 'string') fail(`${where} must be a string.`);
}

function optionalTimestamp(value, where) {
  if (value === undefined) return null;
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value)) ||
      new Date(value).toISOString() !== value) {
    fail(`${where} must be a UTC timestamp like 2026-01-01T00:00:00.000Z.`);
  }
  return Date.parse(value);
}

function requireKeyId(value, where) {
  if (typeof value !== 'string' || !KEY_ID_PATTERN.test(value)) {
    fail(`${where} must be a lowercase SHA-256 key ID.`);
  }
  return value;
}

/** Parse one PEM-encoded Ed25519 SPKI public key strictly. Throws without echoing the input. */
export function parseEd25519PublicKeyPem(pem, where = 'public key') {
  const match = typeof pem === 'string' ? PEM_PATTERN.exec(pem) : null;
  if (!match) throw new Error(`${where} is not a PEM public key.`);
  const body = match[1].replace(/\r?\n/g, '');
  const der = Buffer.from(body, 'base64');
  // Node's base64 decoder skips junk after padding; require an exact round trip instead.
  if (der.toString('base64') !== body) throw new Error(`${where} is not a PEM public key.`);
  let key;
  try {
    key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch {
    throw new Error(`${where} is not a valid public key.`);
  }
  if (key.asymmetricKeyType !== 'ed25519') throw new Error(`${where} is not an Ed25519 key.`);
  // Reject trailing or non-canonical DER so one key has exactly one accepted encoding.
  if (!key.export({ type: 'spki', format: 'der' }).equals(der)) {
    throw new Error(`${where} is not canonical SPKI.`);
  }
  return key;
}

class Keyset {
  #keys;
  #revoked;

  constructor(keys, revoked) {
    this.#keys = keys;
    this.#revoked = revoked;
    Object.freeze(this);
  }

  /** Every listed key, including revoked or out-of-window keys, for signature matching. */
  keys() {
    return this.#keys.map((entry) => ({ id: entry.id, key: entry.key }));
  }

  get size() {
    return this.#keys.length;
  }

  /**
   * Decide whether a key may verify evidence for `purpose` that was signed at `signedAt`
   * (an ISO timestamp taken from the signed payload). Returns { ok, key, reason }.
   */
  authorize({ keyId, purpose, signedAt }) {
    if (!KEY_PURPOSES.includes(purpose)) return { ok: false, key: null, reason: 'has an unsupported purpose' };
    const entry = this.#keys.find((candidate) => candidate.id === keyId);
    if (!entry) return { ok: false, key: null, reason: 'is not in the keyset' };
    const parsed = typeof signedAt === 'string' ? Date.parse(signedAt) : Number.NaN;
    const signedMs = Number.isFinite(parsed) && new Date(parsed).toISOString() === signedAt ? parsed : null;
    if (signedMs === null) return { ok: false, key: null, reason: 'cannot be checked without a valid signed time' };
    if (this.#revoked.has(keyId)) {
      const revokedAt = this.#revoked.get(keyId);
      // Without revokedAt, revocation is total. With it, only evidence whose signed time is
      // strictly earlier survives; the signed time is asserted by the key holder.
      if (revokedAt === null || signedMs >= revokedAt) return { ok: false, key: null, reason: 'is revoked' };
    }
    if (!entry.purposes.includes(purpose)) {
      return { ok: false, key: null, reason: `is not authorized for ${purpose} use` };
    }
    if (entry.notBefore !== null && signedMs < entry.notBefore) {
      return { ok: false, key: null, reason: 'was not yet valid at the signed time' };
    }
    if (entry.notAfter !== null && signedMs >= entry.notAfter) {
      return { ok: false, key: null, reason: 'had expired at the signed time' };
    }
    return { ok: true, key: entry.key, reason: null };
  }
}

/** Validate a parsed trustdex-keyset v1 document and return a Keyset. Fails closed. */
export function parseKeyset(input) {
  requireKnownFields(input, TOP_FIELDS, 'keyset');
  if (input.schemaVersion !== 1) fail('schemaVersion must be 1.');
  if (input.kind !== KEYSET_KIND) fail(`kind must be "${KEYSET_KIND}".`);
  optionalString(input.$schema, '$schema');
  optionalString(input.note, 'note');
  if (!Array.isArray(input.keys) || input.keys.length === 0) fail('keys must be a non-empty array.');
  if (input.keys.length > MAX_KEYS) fail(`keys must list at most ${MAX_KEYS} entries.`);
  if (input.revoked !== undefined && !Array.isArray(input.revoked)) fail('revoked must be an array.');
  const revokedInput = input.revoked || [];
  if (revokedInput.length > MAX_REVOKED) fail(`revoked must list at most ${MAX_REVOKED} entries.`);

  const keys = [];
  const seen = new Set();
  input.keys.forEach((raw, index) => {
    const where = `keys[${index}]`;
    requireKnownFields(raw, KEY_FIELDS, where);
    const id = requireKeyId(raw.id, `${where}.id`);
    if (seen.has(id)) fail(`${where}.id duplicates another key.`);
    seen.add(id);
    let key;
    try { key = parseEd25519PublicKeyPem(raw.publicKey, `${where}.publicKey`); } catch (error) {
      fail(error.message);
    }
    if (spkiKeyId(key) !== id) fail(`${where}.id does not match its public key.`);
    // Purposes are required: a key never gains a role because a field was left out.
    const purposes = raw.purposes;
    if (!Array.isArray(purposes) || purposes.length === 0 ||
      !purposes.every((purpose) => KEY_PURPOSES.includes(purpose)) || new Set(purposes).size !== purposes.length) {
      fail(`${where}.purposes must be a non-empty list of distinct values from ${KEY_PURPOSES.join(', ')}.`);
    }
    optionalString(raw.note, `${where}.note`);
    const notBefore = optionalTimestamp(raw.notBefore, `${where}.notBefore`);
    const notAfter = optionalTimestamp(raw.notAfter, `${where}.notAfter`);
    if (notBefore !== null && notAfter !== null && notAfter <= notBefore) {
      fail(`${where}.notAfter must follow notBefore.`);
    }
    keys.push(Object.freeze({ id, key, purposes: Object.freeze([...purposes]), notBefore, notAfter }));
  });

  const revoked = new Map();
  revokedInput.forEach((raw, index) => {
    const where = `revoked[${index}]`;
    requireKnownFields(raw, REVOKED_FIELDS, where);
    const id = requireKeyId(raw.id, `${where}.id`);
    if (revoked.has(id)) fail(`${where}.id duplicates another revocation.`);
    optionalString(raw.note, `${where}.note`);
    revoked.set(id, optionalTimestamp(raw.revokedAt, `${where}.revokedAt`));
  });

  return new Keyset(Object.freeze(keys), revoked);
}

/** True only for a Keyset returned by parseKeyset, never for an unvalidated object. */
export function isKeyset(value) {
  return value instanceof Keyset;
}
