import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { createToolPermissionBindingSnapshot } from '../src/bindings.mjs';
import { getPolicyPack } from '../src/policy-packs.mjs';
import {
  createRuntimeInventoryAttestation,
  validateRuntimeInventoryAttestation,
  verifyRuntimeInventoryAttestation
} from '../src/runtime-attestation.mjs';
import { generateTrustKeyPair } from '../src/trust-record.mjs';

const cli = fileURLToPath(new URL('../bin/trustdex.mjs', import.meta.url));
const createdAt = '2026-10-24T00:00:10.000Z';

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

function run(...args) {
  const output = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  if (output.error) throw output.error;
  return output;
}

test('Ed25519 runtime inventory attestations bind the exact value-free capture', () => {
  const keys = generateTrustKeyPair();
  const input = inventory();
  const attestation = createRuntimeInventoryAttestation(input, keys.privateKey, {
    createdAt,
    ttlSeconds: 300
  });
  const verified = verifyRuntimeInventoryAttestation(input, attestation, keys.publicKey, {
    now: '2026-10-24T00:01:00.000Z',
    maxAgeSeconds: 120
  });

  assert.equal(attestation.algorithm, 'ed25519');
  assert.equal(attestation.expiresAt, '2026-10-24T00:05:10.000Z');
  assert.equal(verified.valid, true);
  assert.equal(verified.reason, null);
  assert.equal(verified.producerKeyId, attestation.producerKeyId);
  assert.match(verified.inventoryDigest, /^[a-f0-9]{64}$/);
  assert.match(verified.attestationDigest, /^[a-f0-9]{64}$/);
  assert.equal(JSON.stringify(attestation).includes('INERT_SECRET_VALUE'), false);
});

test('runtime inventory attestation verification rejects wrong keys, mutation, expiry, and replay', () => {
  const keys = generateTrustKeyPair();
  const otherKeys = generateTrustKeyPair();
  const input = inventory();
  const attestation = createRuntimeInventoryAttestation(input, keys.privateKey, {
    createdAt,
    ttlSeconds: 300
  });

  assert.match(
    verifyRuntimeInventoryAttestation(input, attestation, otherKeys.publicKey, {
      now: '2026-10-24T00:01:00.000Z'
    }).reason,
    /key does not match/
  );
  assert.match(
    verifyRuntimeInventoryAttestation(
      inventory({ servers: [{ name: 'reviewed', toolCount: 3 }] }),
      attestation,
      keys.publicKey,
      { now: '2026-10-24T00:01:00.000Z' }
    ).reason,
    /does not match/
  );
  assert.match(
    verifyRuntimeInventoryAttestation(input, attestation, keys.publicKey, {
      now: '2026-10-24T00:05:10.000Z'
    }).reason,
    /expired/
  );
  assert.match(
    verifyRuntimeInventoryAttestation(input, attestation, keys.publicKey, {
      now: '2026-10-24T00:02:01.000Z',
      maxAgeSeconds: 120
    }).reason,
    /too old/
  );

  const tampered = structuredClone(attestation);
  tampered.expiresAt = '2026-10-24T00:05:11.000Z';
  assert.match(
    verifyRuntimeInventoryAttestation(input, tampered, keys.publicKey, {
      now: '2026-10-24T00:01:00.000Z'
    }).reason,
    /signature verification failed/
  );
});

test('runtime inventory attestations enforce timestamp and lifetime limits', () => {
  const keys = generateTrustKeyPair();
  assert.throws(
    () => createRuntimeInventoryAttestation(inventory(), keys.privateKey, {
      createdAt,
      ttlSeconds: 86_401
    }),
    /1 to 86400/
  );
  assert.throws(
    () => createRuntimeInventoryAttestation(
      inventory({ capturedAt: '2026-10-24T00:05:11.000Z' }),
      keys.privateKey,
      { createdAt }
    ),
    /cannot postdate/
  );
  const { privateKey: rsaPrivateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  assert.throws(
    () => createRuntimeInventoryAttestation(inventory(), rsaPrivateKey, { createdAt }),
    /require an Ed25519 key/
  );

  const futureCapture = inventory({ capturedAt: '2026-10-24T00:04:00.000Z' });
  const futureCaptureAttestation = createRuntimeInventoryAttestation(futureCapture, keys.privateKey, {
    createdAt,
    ttlSeconds: 900
  });
  assert.match(
    verifyRuntimeInventoryAttestation(futureCapture, futureCaptureAttestation, keys.publicKey, {
      now: '2026-10-24T00:00:00.000Z',
      futureSkewSeconds: 120
    }).reason,
    /capture time is too far in the future/
  );

  const futureAttestation = createRuntimeInventoryAttestation(inventory(), keys.privateKey, {
    createdAt: '2026-10-24T00:10:01.000Z',
    ttlSeconds: 300
  });
  assert.match(
    verifyRuntimeInventoryAttestation(inventory(), futureAttestation, keys.publicKey, {
      now: '2026-10-24T00:00:00.000Z',
      futureSkewSeconds: 300
    }).reason,
    /creation time is too far in the future/
  );

  const excessiveLifetime = structuredClone(futureAttestation);
  excessiveLifetime.expiresAt = '2026-10-26T00:10:01.000Z';
  assert.throws(
    () => validateRuntimeInventoryAttestation(excessiveLifetime),
    /lifetime exceeds 24 hours/
  );
});

test('attestation schema covers every signed field', () => {
  const schema = JSON.parse(fs.readFileSync(
    fileURLToPath(new URL('../schemas/runtime-tool-inventory-attestation-v1.schema.json', import.meta.url)),
    'utf8'
  ));
  const keys = generateTrustKeyPair();
  const attestation = createRuntimeInventoryAttestation(inventory(), keys.privateKey, { createdAt });

  for (const key of schema.required) assert.ok(Object.hasOwn(attestation, key));
  assert.deepEqual(Object.keys(attestation).sort(), [...schema.required].sort());
});

test('CLI signs, verifies, and requires authenticated runtime evidence without leaking key material', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'trustdex-runtime-attestation-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const keys = generateTrustKeyPair();
  const privatePath = path.join(directory, 'private.pem');
  const publicPath = path.join(directory, 'public.pem');
  const inventoryPath = path.join(directory, 'inventory.json');
  const bindingsPath = path.join(directory, 'bindings.json');
  const attestationPath = path.join(directory, 'attestation.json');
  const unverifiedPath = path.join(directory, 'unverified.json');
  const verifiedPath = path.join(directory, 'verified.json');
  const freshInventory = inventory({ capturedAt: new Date().toISOString() });
  const bindings = createToolPermissionBindingSnapshot({
    runtime: 'claude',
    results: [{ name: 'reviewed', action: 'allow', provenance: { status: 'verified' }, signals: [] }],
    grants: [{ name: 'reviewed', automaticGrant: 'scoped', grantRuleCount: 1, toolScopeWildcard: false }],
    policy: getPolicyPack('strict')
  });
  fs.writeFileSync(privatePath, keys.privateKey, { mode: 0o600 });
  fs.writeFileSync(publicPath, keys.publicKey);
  fs.writeFileSync(inventoryPath, `${JSON.stringify(freshInventory, null, 2)}\n`);
  fs.writeFileSync(bindingsPath, `${JSON.stringify(bindings, null, 2)}\n`);

  const unverified = run('snapshot-runtime-tools', bindingsPath, inventoryPath, '--out', unverifiedPath);
  assert.equal(unverified.status, 0, unverified.stderr);
  assert.equal(JSON.parse(fs.readFileSync(unverifiedPath, 'utf8')).status, 'needs-review');

  const missingAuthentication = run(
    'snapshot-runtime-tools', bindingsPath, inventoryPath,
    '--out', verifiedPath, '--require-authenticated'
  );
  assert.equal(missingAuthentication.status, 2);
  assert.match(missingAuthentication.stderr, /Authenticated runtime inventory evidence is required/);

  const sign = run(
    'sign-runtime-inventory', inventoryPath,
    '--private', privatePath, '--out', attestationPath, '--ttl-seconds', '300'
  );
  assert.equal(sign.status, 0, sign.stderr);
  const verify = run(
    'verify-runtime-inventory', inventoryPath,
    '--attestation', attestationPath, '--public', publicPath,
    '--max-age-seconds', '60', '--json'
  );
  assert.equal(verify.status, 0, verify.stderr);
  assert.equal(JSON.parse(verify.stdout).valid, true);

  const snapshot = run(
    'snapshot-runtime-tools', bindingsPath, inventoryPath,
    '--attestation', attestationPath, '--public', publicPath,
    '--max-age-seconds', '60', '--require-authenticated', '--out', verifiedPath
  );
  assert.equal(snapshot.status, 0, snapshot.stderr);
  const reportText = fs.readFileSync(verifiedPath, 'utf8');
  const report = JSON.parse(reportText);
  assert.equal(report.status, 'matched');
  assert.equal(report.inventoryAuthentication, 'verified');
  assert.match(report.producerKeyId, /^[a-f0-9]{64}$/);
  assert.equal(reportText.includes('PRIVATE KEY'), false);
  assert.equal(`${sign.stdout}${verify.stdout}${snapshot.stdout}`.includes(keys.privateKey), false);

  const maxAgeWithoutAttestation = run(
    'snapshot-runtime-tools', bindingsPath, inventoryPath,
    '--max-age-seconds', '60', '--out', verifiedPath
  );
  assert.equal(maxAgeWithoutAttestation.status, 2);
  assert.match(maxAgeWithoutAttestation.stderr, /requires --attestation and --public/);
});
