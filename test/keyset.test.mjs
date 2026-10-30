import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { createToolPermissionBindingSnapshot } from '../src/bindings.mjs';
import { canonicalJson } from '../src/canonical.mjs';
import { getPolicyPack } from '../src/policy-packs.mjs';
import { KEY_PURPOSES, parseKeyset, parseKeysetText, spkiKeyId } from '../src/keyset.mjs';
import { assessReview } from '../src/review.mjs';
import {
  createRuntimeInventoryAttestation,
  verifyRuntimeInventoryAttestation
} from '../src/runtime-attestation.mjs';
import { createTrustRecord, generateTrustKeyPair, verifyTrustRecord } from '../src/trust-record.mjs';

const cli = fileURLToPath(new URL('../bin/trustdex.mjs', import.meta.url));
const root = fileURLToPath(new URL('..', import.meta.url));
const snapshot = { digest: 'a'.repeat(64) };
const createdAt = '2026-10-24T00:00:10.000Z';
const now = '2026-10-24T00:01:00.000Z';

function keyPair() {
  const keys = generateTrustKeyPair();
  return { ...keys, id: spkiKeyId(crypto.createPublicKey(keys.publicKey)) };
}

const BOTH = ['review', 'runtime-producer'];

function entry(keys, extra = {}) {
  return { id: keys.id, publicKey: keys.publicKey, purposes: BOTH, ...extra };
}

function keyset(keys, extra = {}) {
  return { schemaVersion: 1, kind: 'trustdex-keyset', keys, ...extra };
}

// Trust records sign createdAt; tests that need a specific or missing time sign directly.
function signRecord(privateKey, fields = {}) {
  const record = {
    schemaVersion: 1,
    algorithm: 'ed25519',
    snapshotDigest: snapshot.digest,
    policyDigest: null,
    sourceRef: null,
    createdAt,
    ...fields
  };
  const payload = {
    schemaVersion: record.schemaVersion,
    algorithm: record.algorithm,
    snapshotDigest: record.snapshotDigest,
    policyDigest: record.policyDigest,
    sourceRef: record.sourceRef,
    createdAt: record.createdAt
  };
  const signature = crypto.sign(null, Buffer.from(canonicalJson(payload)), privateKey);
  return { ...record, signature: signature.toString('base64') };
}

function inventory(extra = {}) {
  return {
    schemaVersion: 1,
    kind: 'agent-runtime-tool-inventory',
    runtime: 'claude',
    capturedAt: '2026-10-24T00:00:00.000Z',
    captureMethod: 'runtime-adapter',
    servers: [{ name: 'reviewed', toolCount: 2 }],
    ...extra
  };
}

function attest(keys) {
  return createRuntimeInventoryAttestation(inventory(), keys.privateKey, { createdAt, ttlSeconds: 300 });
}

function verifyRuntime(keys, set, options = { now }) {
  return verifyRuntimeInventoryAttestation(inventory(), attest(keys), set, options);
}

function run(...args) {
  const output = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  if (output.error) throw output.error;
  return output;
}

function workspace(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'trustdex-keyset-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return {
    dir,
    write(name, content) {
      const file = path.join(dir, name);
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, typeof content === 'string' ? content : `${JSON.stringify(content, null, 2)}\n`);
      return file;
    }
  };
}

test('a valid keyset verifies review records and runtime attestations and names the key', () => {
  const review = keyPair();
  const producer = keyPair();
  const set = parseKeyset(keyset([
    entry(review, { purposes: ['review'] }),
    entry(producer, { purposes: ['runtime-producer'], notBefore: '2026-01-01T00:00:00.000Z' })
  ]));

  const record = signRecord(review.privateKey);
  assert.deepEqual(verifyTrustRecord(record, set, { snapshot, now }), { valid: true, reason: null, keyId: review.id });

  const runtime = verifyRuntime(producer, set);
  assert.equal(runtime.valid, true, runtime.reason);
  assert.equal(runtime.producerKeyId, producer.id);
  assert.equal(attest(producer).producerKeyId, producer.id, 'keyset IDs align with attestation producer IDs');

  const created = createTrustRecord(snapshot, review.privateKey);
  const verdict = assessReview({ record: created, publicKey: set, baseline: snapshot, current: snapshot });
  assert.equal(verdict.status, 'approved');
  assert.equal(verdict.keyId, review.id);
});

test('a key listing both purposes verifies both roles; an unlisted key verifies nothing', () => {
  const shared = keyPair();
  const outsider = keyPair();
  const set = parseKeyset(keyset([entry(shared)]));
  assert.equal(verifyTrustRecord(signRecord(shared.privateKey), set, { now }).valid, true);
  assert.equal(verifyRuntime(shared, set).valid, true);

  assert.deepEqual(verifyTrustRecord(signRecord(outsider.privateKey), set, { now }), {
    valid: false, reason: 'signature does not match any key in the keyset', keyId: null
  });
  assert.equal(verifyRuntime(outsider, set).reason, 'Runtime inventory producer key is not in the keyset.');
});

test('rotation: old and new keys overlap, then the old key is removed', () => {
  const oldKey = keyPair();
  const newKey = keyPair();
  const oldRecord = signRecord(oldKey.privateKey, { createdAt: '2026-06-01T00:00:00.000Z' });
  const newRecord = signRecord(newKey.privateKey);

  const overlap = parseKeyset(keyset([
    entry(oldKey, { purposes: ['review'], notAfter: '2026-11-01T00:00:00.000Z' }),
    entry(newKey, { purposes: ['review'], notBefore: '2026-10-01T00:00:00.000Z' })
  ]));
  assert.equal(verifyTrustRecord(oldRecord, overlap, { now }).keyId, oldKey.id);
  assert.equal(verifyTrustRecord(newRecord, overlap, { now }).keyId, newKey.id);
  // Old reviews stay valid after the old key's window closes because the window is
  // checked at the signed time, not at verification time.
  assert.equal(verifyTrustRecord(oldRecord, overlap, { now: '2027-01-01T00:00:00.000Z' }).valid, true);

  const overlapProducers = parseKeyset(keyset([
    entry(oldKey, { purposes: ['runtime-producer'] }),
    entry(newKey, { purposes: ['runtime-producer'] })
  ]));
  assert.equal(verifyRuntime(oldKey, overlapProducers).valid, true);
  assert.equal(verifyRuntime(newKey, overlapProducers).valid, true);

  const retired = parseKeyset(keyset([entry(newKey, { purposes: ['review'] })]));
  assert.equal(verifyTrustRecord(oldRecord, retired, { now }).reason, 'signature does not match any key in the keyset');
  assert.equal(verifyTrustRecord(newRecord, retired, { now }).valid, true);
});

test('revocation without revokedAt rejects every signature by the key', () => {
  const keys = keyPair();
  const set = parseKeyset(keyset([entry(keys)], { revoked: [{ id: keys.id }] }));
  const ancient = signRecord(keys.privateKey, { createdAt: '2020-01-01T00:00:00.000Z' });
  assert.deepEqual(verifyTrustRecord(ancient, set, { now }), {
    valid: false, reason: 'signing key is revoked', keyId: keys.id
  });
  assert.equal(verifyRuntime(keys, set).reason, 'Runtime inventory producer key is revoked.');
});

test('revokedAt keeps only evidence signed strictly before the cutoff', () => {
  const keys = keyPair();
  const revokedAfter = parseKeyset(keyset([entry(keys)], {
    revoked: [{ id: keys.id, revokedAt: '2026-10-24T00:00:10.001Z', note: 'retired' }]
  }));
  assert.equal(verifyTrustRecord(signRecord(keys.privateKey), revokedAfter, { now }).valid, true);
  assert.equal(verifyRuntime(keys, revokedAfter).valid, true);

  const revokedExactly = parseKeyset(keyset([entry(keys)], { revoked: [{ id: keys.id, revokedAt: createdAt }] }));
  assert.equal(verifyTrustRecord(signRecord(keys.privateKey), revokedExactly, { now }).reason, 'signing key is revoked');
  assert.equal(verifyRuntime(keys, revokedExactly).reason, 'Runtime inventory producer key is revoked.');

  const revokedBefore = parseKeyset(keyset([entry(keys)], {
    revoked: [{ id: keys.id, revokedAt: '2026-10-01T00:00:00.000Z' }]
  }));
  assert.equal(verifyTrustRecord(signRecord(keys.privateKey), revokedBefore, { now }).reason, 'signing key is revoked');
  assert.equal(verifyRuntime(keys, revokedBefore).valid, false);
});

test('keys are rejected outside their validity window at the signed time', () => {
  const keys = keyPair();
  const notYet = parseKeyset(keyset([entry(keys, { notBefore: '2026-10-24T00:00:10.001Z' })]));
  assert.equal(verifyTrustRecord(signRecord(keys.privateKey), notYet, { now }).reason,
    'signing key was not yet valid at the signed time');
  assert.equal(verifyRuntime(keys, notYet).reason,
    'Runtime inventory producer key was not yet valid at the signed time.');

  const expired = parseKeyset(keyset([entry(keys, { notAfter: createdAt })]));
  assert.equal(verifyTrustRecord(signRecord(keys.privateKey), expired, { now }).reason,
    'signing key had expired at the signed time');
  assert.equal(verifyRuntime(keys, expired).reason,
    'Runtime inventory producer key had expired at the signed time.');

  const inside = parseKeyset(keyset([entry(keys, { notBefore: createdAt, notAfter: '2026-10-24T00:00:10.001Z' })]));
  assert.equal(verifyTrustRecord(signRecord(keys.privateKey), inside, { now }).valid, true);
  assert.equal(verifyRuntime(keys, inside).valid, true);
});

test('keyset mode requires a valid, non-future signed time on trust records', () => {
  const keys = keyPair();
  const set = parseKeyset(keyset([entry(keys)]));
  for (const value of [undefined, null, '2026-10-24', 'not a time']) {
    assert.equal(
      verifyTrustRecord(signRecord(keys.privateKey, { createdAt: value }), set, { now }).reason,
      'trust record has no valid signed creation time'
    );
  }
  // Forward-dating into a pre-distributed key's window is refused.
  assert.equal(
    verifyTrustRecord(signRecord(keys.privateKey, { createdAt: '2026-10-24T00:06:01.000Z' }), set, { now }).reason,
    'trust record creation time is too far in the future'
  );
  const tampered = { ...signRecord(keys.privateKey), createdAt: '2026-10-24T00:00:09.000Z' };
  assert.equal(verifyTrustRecord(tampered, set, { now }).reason, 'signature does not match any key in the keyset');
  assert.equal(verifyTrustRecord({ ...signRecord(keys.privateKey), signature: 7 }, set, { now }).valid, false);
});

test('purpose restricts a key to review records or runtime-producer attestations', () => {
  const keys = keyPair();
  const reviewOnly = parseKeyset(keyset([entry(keys, { purposes: ['review'] })]));
  assert.equal(verifyTrustRecord(signRecord(keys.privateKey), reviewOnly, { now }).valid, true);
  assert.equal(verifyRuntime(keys, reviewOnly).reason,
    'Runtime inventory producer key is not authorized for runtime-producer use.');

  const producerOnly = parseKeyset(keyset([entry(keys, { purposes: ['runtime-producer'] })]));
  assert.equal(verifyRuntime(keys, producerOnly).valid, true);
  assert.deepEqual(verifyTrustRecord(signRecord(keys.privateKey), producerOnly, { now }), {
    valid: false, reason: 'signing key is not authorized for review use', keyId: keys.id
  });
  assert.deepEqual(KEY_PURPOSES, ['review', 'runtime-producer']);
});

test('malformed keysets fail closed', () => {
  const a = keyPair();
  const b = keyPair();
  const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const rsaPem = rsa.publicKey.export({ type: 'spki', format: 'pem' });
  const ecPem = ec.publicKey.export({ type: 'spki', format: 'pem' });
  const cases = [
    [null, /keyset must be an object/],
    [[], /keyset must be an object/],
    [{ ...keyset([entry(a)]), extra: true }, /keyset has an unknown field/],
    [{ ...keyset([entry(a)]), schemaVersion: 2 }, /schemaVersion must be 1/],
    [{ ...keyset([entry(a)]), kind: 'trust-store' }, /kind must be/],
    [keyset([]), /keys must be a non-empty array/],
    [keyset('x'), /keys must be a non-empty array/],
    [keyset([entry(a, { extra: 1 })]), /keys\[0\] has an unknown field/],
    [keyset([entry(a, { purpose: 'review' })]), /keys\[0\] has an unknown field/],
    [keyset([entry(a), entry(a)]), /keys\[1\]\.id duplicates another key/],
    [keyset([entry(a, { id: b.id })]), /keys\[0\]\.id does not match its public key/],
    [keyset([entry(a, { id: a.id.toUpperCase() })]), /keys\[0\]\.id must be a lowercase SHA-256 key ID/],
    [keyset([entry(a, { id: undefined })]), /keys\[0\]\.id must be a lowercase SHA-256 key ID/],
    [keyset([{ id: spkiKeyId(rsa.publicKey), publicKey: rsaPem }]), /keys\[0\]\.publicKey is not an Ed25519 key/],
    [keyset([{ id: spkiKeyId(ec.publicKey), publicKey: ecPem }]), /keys\[0\]\.publicKey is not an Ed25519 key/],
    [keyset([entry(a, { publicKey: a.privateKey })]), /keys\[0\]\.publicKey is not a PEM public key/],
    [keyset([entry(a, { publicKey: 'garbage' })]), /keys\[0\]\.publicKey is not a PEM public key/],
    [keyset([entry(a, { publicKey: `${a.publicKey}${b.publicKey}` })]), /keys\[0\]\.publicKey is not a PEM public key/],
    [keyset([entry(a, { publicKey: '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n' })]),
      /keys\[0\]\.publicKey is not a valid public key/],
    [keyset([entry(a, { publicKey: a.publicKey.replace('\n-----END', 'AAAA\n-----END') })]),
      /keys\[0\]\.publicKey is not a PEM public key/],
    [keyset([entry(a, { purposes: ['admin'] })]), /keys\[0\]\.purposes must be a non-empty list/],
    [keyset([entry(a, { purposes: undefined })]), /keys\[0\]\.purposes must be a non-empty list/],
    [keyset([entry(a, { purposes: [] })]), /keys\[0\]\.purposes must be a non-empty list/],
    [keyset([entry(a, { purposes: 'review' })]), /keys\[0\]\.purposes must be a non-empty list/],
    [keyset([entry(a, { purposes: ['review', 'review'] })]), /keys\[0\]\.purposes must be a non-empty list/],
    [keyset([entry(a, { notBefore: '2026-01-01' })]), /keys\[0\]\.notBefore must be a UTC timestamp/],
    [keyset([entry(a, { notAfter: '2026-01-01T00:00:00Z' })]), /keys\[0\]\.notAfter must be a UTC timestamp/],
    [keyset([entry(a, { notAfter: 1767225600000 })]), /keys\[0\]\.notAfter must be a UTC timestamp/],
    [keyset([entry(a, { notBefore: '2026-02-01T00:00:00.000Z', notAfter: '2026-02-01T00:00:00.000Z' })]),
      /keys\[0\]\.notAfter must follow notBefore/],
    [keyset([entry(a, { note: 5 })]), /keys\[0\]\.note must be a string/],
    [keyset([entry(a)], { revoked: {} }), /revoked must be an array/],
    [keyset([entry(a)], { revoked: [{ id: a.id }, { id: a.id }] }), /revoked\[1\]\.id duplicates another revocation/],
    [keyset([entry(a)], { revoked: [{ id: a.id, reason: 'x' }] }), /revoked\[0\] has an unknown field/],
    [keyset([entry(a)], { revoked: [{ id: 'nope' }] }), /revoked\[0\]\.id must be a lowercase SHA-256 key ID/],
    [keyset([entry(a)], { revoked: [{ id: a.id, revokedAt: 'yesterday' }] }), /revoked\[0\]\.revokedAt must be a UTC timestamp/]
  ];
  for (const [input, pattern] of cases) {
    assert.throws(() => parseKeyset(input), (error) => {
      assert.match(error.message, /^Invalid keyset: /);
      assert.match(error.message, pattern);
      return true;
    });
  }
});

test('an unvalidated keyset-shaped object is never treated as a keyset', () => {
  const keys = keyPair();
  const raw = keyset([entry(keys)]);
  assert.equal(verifyTrustRecord(signRecord(keys.privateKey), raw, { now }).valid, false);
  const runtime = verifyRuntimeInventoryAttestation(inventory(), attest(keys), raw, { now });
  assert.equal(runtime.valid, false);
});

test('the keyset schema and example match the parser contract', () => {
  const schema = JSON.parse(fs.readFileSync(path.join(root, 'schemas/trustdex-keyset-v1.schema.json'), 'utf8'));
  assert.deepEqual(Object.keys(schema.properties).sort(),
    ['$schema', 'keys', 'kind', 'note', 'revoked', 'schemaVersion']);
  assert.deepEqual(Object.keys(schema.properties.keys.items.properties).sort(),
    ['id', 'notAfter', 'notBefore', 'note', 'publicKey', 'purposes']);
  assert.deepEqual(Object.keys(schema.properties.revoked.items.properties).sort(), ['id', 'note', 'revokedAt']);
  assert.deepEqual(schema.properties.keys.items.properties.purposes.items.enum, KEY_PURPOSES);
  assert.equal(schema.additionalProperties, false);

  const example = JSON.parse(fs.readFileSync(path.join(root, 'examples/trustdex-keyset.example.json'), 'utf8'));
  assert.equal(parseKeyset(example).size, example.keys.length);
  assert.equal(JSON.stringify(example).includes('PRIVATE KEY'), false);
});

test('CLI: --keyset verifies every command, rejects --public with --keyset, and keeps --public unchanged', (t) => {
  const { dir, write } = workspace(t);
  const review = keyPair();
  const producer = keyPair();
  const files = {
    reviewPrivate: write('keys/review-private.pem', review.privateKey),
    reviewPublic: write('keys/review-public.pem', review.publicKey),
    producerPrivate: write('keys/producer-private.pem', producer.privateKey),
    producerPublic: write('keys/producer-public.pem', producer.publicKey),
    keyset: write('keyset.json', keyset([
      entry(review, { purposes: ['review'] }),
      entry(producer, { purposes: ['runtime-producer'] })
    ])),
    revokedKeyset: write('revoked-keyset.json', keyset([
      entry(review, { purposes: ['review'] }),
      entry(producer, { purposes: ['runtime-producer'] })
    ], { revoked: [{ id: review.id }, { id: producer.id }] })),
    mcp: write('mcp.json', { mcpServers: { local: { command: 'node', args: ['server.js'] } } }),
    inventory: write('inventory.json', inventory({ capturedAt: new Date().toISOString() }))
  };
  const reviewDir = path.join(dir, 'review');
  const record = path.join(dir, 'record.json');
  const attestation = path.join(dir, 'attestation.json');

  assert.equal(run('key-id', files.reviewPublic).stdout, `${review.id}\n`);
  const keyIdPrivate = run('key-id', files.reviewPrivate);
  assert.equal(keyIdPrivate.status, 2);
  assert.match(keyIdPrivate.stderr, /is not a PEM public key/);
  assert.equal(keyIdPrivate.stderr.includes('PRIVATE'), false);

  assert.equal(run('approve', files.mcp, '--private', files.reviewPrivate, '--dir', reviewDir, '--pack', 'development').status, 0);
  assert.equal(run('sign', path.join(reviewDir, 'snapshot.json'), '--private', files.reviewPrivate, '--out', record).status, 0);
  assert.equal(run('sign-runtime-inventory', files.inventory, '--private', files.producerPrivate, '--out', attestation).status, 0);

  // Existing --public behaviour is unchanged.
  const publicVerify = run('verify', record, '--public', files.reviewPublic);
  assert.equal(publicVerify.status, 0);
  assert.equal(publicVerify.stdout, 'VALID\n');
  const publicRecheck = run('recheck', files.mcp, '--review-dir', reviewDir, '--public', files.reviewPublic, '--json');
  assert.equal(publicRecheck.status, 0);
  assert.equal(Object.hasOwn(JSON.parse(publicRecheck.stdout), 'keyId'), false);
  const publicRuntime = run('verify-runtime-inventory', files.inventory, '--attestation', attestation, '--public', files.producerPublic);
  assert.equal(publicRuntime.stdout, `VERIFIED ${producer.id}\n`);

  // --keyset succeeds on every verifying command.
  const keysetVerify = run('verify', record, '--keyset', files.keyset);
  assert.equal(keysetVerify.status, 0, keysetVerify.stderr);
  assert.equal(keysetVerify.stdout, `VALID\nSigning key: ${review.id}\n`);
  const keysetRecheck = run('recheck', files.mcp, '--review-dir', reviewDir, '--keyset', files.keyset, '--json');
  assert.equal(keysetRecheck.status, 0, keysetRecheck.stderr);
  assert.equal(JSON.parse(keysetRecheck.stdout).keyId, review.id);
  const humanRecheck = run('recheck', files.mcp, '--review-dir', reviewDir, '--keyset', files.keyset);
  assert.match(humanRecheck.stdout, new RegExp(`Signing key: ${review.id}`));
  const keysetRuntime = run('verify-runtime-inventory', files.inventory, '--attestation', attestation, '--keyset', files.keyset);
  assert.equal(keysetRuntime.stdout, `VERIFIED ${producer.id}\n`);
  const bindings = write('bindings.json', createToolPermissionBindingSnapshot({
    runtime: 'claude',
    results: [{ name: 'reviewed', action: 'allow', provenance: { status: 'verified' }, signals: [] }],
    grants: [{ name: 'reviewed', automaticGrant: 'scoped', grantRuleCount: 1, toolScopeWildcard: false }],
    policy: getPolicyPack('strict')
  }));
  const runtimeOut = path.join(dir, 'runtime.json');
  const runtimeSnapshot = run('snapshot-runtime-tools', bindings, files.inventory, '--attestation', attestation,
    '--keyset', files.keyset, '--require-authenticated', '--out', runtimeOut);
  assert.equal(runtimeSnapshot.status, 0, runtimeSnapshot.stderr);
  const report = JSON.parse(fs.readFileSync(runtimeOut, 'utf8'));
  assert.equal(report.status, 'matched');
  assert.equal(report.inventoryAuthentication, 'verified');
  assert.equal(report.producerKeyId, producer.id);

  // Revoked keys make every command INVALID.
  const revokedVerify = run('verify', record, '--keyset', files.revokedKeyset);
  assert.equal(revokedVerify.status, 2);
  assert.equal(revokedVerify.stdout, 'INVALID: signing key is revoked\n');
  const revokedRecheck = run('recheck', files.mcp, '--review-dir', reviewDir, '--keyset', files.revokedKeyset);
  assert.equal(revokedRecheck.status, 2);
  assert.match(revokedRecheck.stdout, /INVALID: signing key is revoked/);
  const revokedRuntime = run('verify-runtime-inventory', files.inventory, '--attestation', attestation, '--keyset', files.revokedKeyset);
  assert.equal(revokedRuntime.status, 2);
  assert.match(revokedRuntime.stdout, /producer key is revoked/);
  const revokedSnapshot = run('snapshot-runtime-tools', bindings, files.inventory, '--attestation', attestation,
    '--keyset', files.revokedKeyset, '--out', runtimeOut);
  assert.equal(revokedSnapshot.status, 2);
  assert.match(revokedSnapshot.stderr, /producer key is revoked/);

  // --public and --keyset together are an error on every verifying command.
  for (const args of [
    ['verify', record, '--public', files.reviewPublic, '--keyset', files.keyset],
    ['recheck', files.mcp, '--review-dir', reviewDir, '--keyset', files.keyset, '--public', files.reviewPublic],
    ['recheck-claude', files.mcp, '--review-dir', reviewDir, '--keyset', files.keyset, '--public', files.reviewPublic],
    ['verify-runtime-inventory', files.inventory, '--attestation', attestation, '--public', files.producerPublic, '--keyset', files.keyset],
    ['snapshot-runtime-tools', bindings, files.inventory, '--attestation', attestation, '--public', files.producerPublic,
      '--keyset', files.keyset, '--out', runtimeOut]
  ]) {
    const result = run(...args);
    assert.equal(result.status, 2, args.join(' '));
    assert.match(result.stderr, /Use either --public or --keyset, not both/);
  }
  for (const args of [
    ['verify', record, '--keyset'],
    ['verify', record, '--keyset', '--json'],
    ['verify', record, '--keyset', files.keyset, '--keyset', files.keyset]
  ]) {
    assert.equal(run(...args).status, 2, args.join(' '));
  }
  const missing = run('verify', record);
  assert.match(missing.stderr, /--public <key\.pem> or --keyset <keyset\.json>/);
});

test('CLI keyset errors never echo keyset or key contents', (t) => {
  const { write } = workspace(t);
  const keys = keyPair();
  const record = write('record.json', signRecord(keys.privateKey));
  const canary = 'KEYSETCANARY';
  const bodies = [
    `{"schemaVersion": 1, "kind": "trustdex-keyset", "keys": [${canary}]}`,
    keyset([entry(keys, { [canary]: canary })]),
    keyset([entry(keys, { [`x${canary}`]: 1 })], { [canary]: canary }),
    keyset([entry(keys, { publicKey: `-----BEGIN PUBLIC KEY-----\n${canary}\n-----END PUBLIC KEY-----\n` })]),
    keyset([entry(keys, { publicKey: keys.privateKey })]),
    keyset([entry(keys, { id: canary })]),
    keyset([entry(keys, { purposes: [canary] })]),
    keyset([entry(keys, { notBefore: canary })]),
    keyset([entry(keys)], { revoked: [{ id: keys.id, revokedAt: canary }] }),
    keyset([entry(keys, { note: canary })], { note: canary, revoked: [{ id: keys.id, note: canary }] })
  ];
  for (const [index, body] of bodies.entries()) {
    const file = write(`keyset-${index}.json`, body);
    const result = run('verify', record, '--keyset', file);
    assert.equal(result.status, 2, `case ${index}`);
    const output = `${result.stdout}${result.stderr}`;
    assert.equal(output.toUpperCase().includes(canary), false, `case ${index}: ${output}`);
    assert.equal(output.includes('PRIVATE KEY'), false);
    assert.equal(output.includes('BEGIN PUBLIC KEY'), false);
  }
});

test('--help lists --keyset and key-id', () => {
  const help = run('--help').stdout;
  assert.match(help, /--keyset keyset\.json/);
  assert.match(help, /trustdex key-id <public\.pem>/);
});

// SPKI DER for an Ed25519 public key with the given 32 raw bytes.
function rawKeyPem(hex) {
  const der = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(hex, 'hex')]);
  return `-----BEGIN PUBLIC KEY-----\n${der.toString('base64')}\n-----END PUBLIC KEY-----\n`;
}

test('small-order and non-canonical Ed25519 public keys are never usable', () => {
  const identity = `01${'00'.repeat(31)}`;
  // R = identity, s = 0 verifies for any message under the identity public key.
  const forged = { ...signRecord(keyPair().privateKey), signature: Buffer.from(`${identity}${'00'.repeat(32)}`, 'hex').toString('base64') };
  assert.equal(verifyTrustRecord(forged, rawKeyPem(identity)).valid, false);
  for (const hex of [identity, `01${'00'.repeat(30)}80`, '00'.repeat(32), `ec${'ff'.repeat(30)}7f`, `ed${'ff'.repeat(30)}7f`,
    `ee${'ff'.repeat(30)}7f`, `ef${'ff'.repeat(30)}7f`, '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a']) {
    const pem = rawKeyPem(hex);
    const id = spkiKeyId(crypto.createPublicKey(pem));
    assert.throws(() => parseKeyset(keyset([{ id, publicKey: pem, purposes: BOTH }])), /small-order or non-canonical/, hex);
  }
});

test('keyset JSON with a repeated field name fails closed', () => {
  const keys = keyPair();
  const member = JSON.stringify(entry(keys)).slice(1, -1);
  const id = JSON.stringify(keys.id);
  for (const text of [
    `{"schemaVersion":1,"kind":"trustdex-keyset","keys":[{${member}}],"revoked":[{"id":${id}}],"revoked":[]}`,
    `{"schemaVersion":1,"kind":"trustdex-keyset","keys":[{${member},"purposes":["review"]}]}`,
    `{"schemaVersion":1,"kind":"trustdex-keyset","keys":[{${member}}],"revoked":[{"id":${id},"\\u0069d":${id}}]}`
  ]) {
    assert.throws(() => parseKeysetText(text), /Invalid keyset: repeats a field name/);
  }
  const ok = `{"schemaVersion":1,"kind":"trustdex-keyset","note":"a \\" {\\"keys\\":1} ,","keys":[{${member}}],"revoked":[{"id":${id}}]}`;
  assert.equal(parseKeysetText(ok).size, 1);
  assert.throws(() => parseKeysetText('{"keys":'), /Invalid keyset: not valid JSON/);
});

test('signatures and signed times must be canonical', () => {
  const keys = keyPair();
  const set = parseKeyset(keyset([entry(keys)]));
  const record = signRecord(keys.privateKey);
  for (const signature of [`${record.signature}!!!AAAA`, ` ${record.signature}`, record.signature.replace(/=+$/, '')]) {
    assert.equal(verifyTrustRecord({ ...record, signature }, set, { now }).valid, false, signature);
    assert.equal(verifyTrustRecord({ ...record, signature }, keys.publicKey).valid, false, signature);
  }
  assert.equal(verifyTrustRecord(record, keys.publicKey).valid, true);
  for (const value of ['-000001-01-01T00:00:00.000Z', '+010000-01-01T00:00:00.000Z']) {
    assert.equal(verifyTrustRecord(signRecord(keys.privateKey, { createdAt: value }), set, { now }).valid, false, value);
    assert.throws(() => parseKeyset(keyset([entry(keys, { notAfter: value })])), /must be a UTC timestamp/, value);
  }
});

test('CLI: --keyset=, --public=, and repeated --public are rejected', (t) => {
  const { write } = workspace(t);
  const a = keyPair();
  const b = keyPair();
  const record = write('record.json', signRecord(a.privateKey));
  const aPub = write('a.pem', a.publicKey);
  const bSet = write('b.json', keyset([entry(b)]));
  for (const args of [
    ['verify', record, `--keyset=${bSet}`, '--public', aPub],
    ['verify', record, `--public=${aPub}`],
    ['verify', record, '--public', aPub, '--public', aPub]
  ]) {
    const result = run(...args);
    assert.equal(result.status, 2, args.join(' '));
    assert.doesNotMatch(result.stdout, /VALID/);
  }
});
