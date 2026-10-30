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
// Exactly the form toISOString() produces for years 0000-9999; extended years are rejected.
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
// Small-order points (and their non-canonical encodings), compared with the sign bit
// cleared. A public key on this list accepts forged signatures, so it is never usable.
const SMALL_ORDER_POINTS = [
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'
];
const ED25519_P = (1n << 255n) - 19n;
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

/** True for a UTC timestamp written exactly as 2026-01-01T00:00:00.000Z. */
export function isStrictTimestamp(value) {
  return typeof value === 'string' && TIMESTAMP_PATTERN.test(value) && !Number.isNaN(Date.parse(value)) &&
    new Date(value).toISOString() === value;
}

/** True for an Ed25519 public key of small order or with a non-canonical encoding. */
export function isWeakEd25519Key(keyObject) {
  const raw = Buffer.from(keyObject.export({ format: 'jwk' }).x, 'base64url');
  if (raw.length !== 32) return true;
  const masked = Buffer.from(raw);
  masked[31] &= 0x7f;
  if (SMALL_ORDER_POINTS.includes(masked.toString('hex'))) return true;
  const y = BigInt(`0x${Buffer.from(masked).reverse().toString('hex')}`);
  return y >= ED25519_P;
}

/**
 * Throws when a JSON text repeats a member name inside one object. JSON.parse keeps the
 * last value silently, which would let a later "revoked": [] erase an earlier revocation.
 * Call only on text that JSON.parse accepts.
 */
export function rejectDuplicateJsonMembers(text, where = 'JSON input') {
  const stack = [];
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (char === '"') {
      let end = index + 1;
      while (text[end] !== '"') end += text[end] === '\\' ? 2 : 1;
      const top = stack[stack.length - 1];
      if (top?.expectKey) {
        const name = JSON.parse(text.slice(index, end + 1));
        if (top.names.has(name)) throw new Error(`${where} repeats a field name.`);
        top.names.add(name);
        top.expectKey = false;
      }
      index = end;
    } else if (char === '{') {
      stack.push({ names: new Set(), expectKey: true });
    } else if (char === '[') {
      stack.push({ names: null, expectKey: false });
    } else if (char === '}' || char === ']') {
      stack.pop();
    } else if (char === ',') {
      const top = stack[stack.length - 1];
      if (top?.names) top.expectKey = true;
    }
  }
}

/** Parse keyset JSON text: duplicate member names are rejected before validation. */
export function parseKeysetText(text) {
  let input;
  try {
    input = JSON.parse(text);
  } catch {
    fail('not valid JSON.');
  }
  try {
    rejectDuplicateJsonMembers(text, 'keyset');
  } catch (error) {
    fail(error.message.replace(/^keyset /, ''));
  }
  return parseKeyset(input);
}

function optionalTimestamp(value, where) {
  if (value === undefined) return null;
  if (!isStrictTimestamp(value)) {
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
  if (isWeakEd25519Key(key)) throw new Error(`${where} is a small-order or non-canonical Ed25519 key.`);
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
    const signedMs = isStrictTimestamp(signedAt) ? Date.parse(signedAt) : null;
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
