import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { createToolPermissionBindingSnapshot } from '../src/bindings.mjs';
import { sha256Json } from '../src/canonical.mjs';
import {
  createEffectiveRuntimeEvidence,
  diffEffectiveRuntimeEvidence,
  runtimeToolInventoryDigest,
  validateEffectiveRuntimeEvidence
} from '../src/runtime-evidence.mjs';
import { getPolicyPack } from '../src/policy-packs.mjs';

const cli = fileURLToPath(new URL('../bin/trustdex.mjs', import.meta.url));
const fixtureDirectory = fileURLToPath(new URL('../examples/adversarial/bindings/', import.meta.url));

function bindingResult(name, action, status = 'unknown') {
  return { name, action, provenance: { status }, signals: [] };
}

function grant(name, automaticGrant = 'none', toolScopeWildcard = false) {
  return {
    name,
    automaticGrant,
    grantRuleCount: automaticGrant === 'none' ? 0 : 1,
    toolScopeWildcard
  };
}

function bindings(results, grants) {
  return createToolPermissionBindingSnapshot({
    runtime: 'claude',
    results,
    grants,
    policy: getPolicyPack('strict')
  });
}

function inventory(servers, extra = {}) {
  return {
    schemaVersion: 1,
    kind: 'agent-runtime-tool-inventory',
    runtime: 'claude',
    capturedAt: '2026-10-24T00:00:00.000Z',
    captureMethod: 'runtime-adapter',
    servers,
    ...extra
  };
}

function verifiedAuthentication(runtimeInventory, overrides = {}) {
  return {
    valid: true,
    reason: null,
    producerKeyId: 'a'.repeat(64),
    inventoryDigest: runtimeToolInventoryDigest(runtimeInventory),
    attestationDigest: 'b'.repeat(64),
    ...overrides
  };
}

function evidence(bindingSnapshot, runtimeInventory) {
  return createEffectiveRuntimeEvidence(
    bindingSnapshot,
    runtimeInventory,
    verifiedAuthentication(runtimeInventory)
  );
}

function run(...args) {
  const output = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  if (output.error) throw output.error;
  return output;
}

test('effective runtime evidence matches observed ALLOW sources and counts tools', () => {
  const report = evidence(bindings([
    bindingResult('reviewed', 'allow', 'verified'),
    bindingResult('manual', 'allow')
  ], [grant('reviewed', 'scoped'), grant('manual')]), inventory([
    { name: 'reviewed', toolCount: 3 },
    { name: 'manual', toolCount: 1 }
  ]));

  assert.equal(report.status, 'matched');
  assert.equal(report.summary.matchedCount, 2);
  assert.equal(report.summary.observedToolCount, 4);
  assert.equal(report.servers.find((server) => server.name === 'reviewed').bindingStatus, 'bound');
});

test('blocked and unexpected observed servers block the effective boundary', () => {
  const report = evidence(bindings([
    bindingResult('reviewed', 'allow', 'verified'),
    bindingResult('blocked', 'block')
  ], [grant('reviewed', 'scoped'), grant('blocked', 'all', true)]), inventory([
    { name: 'reviewed', toolCount: 2 },
    { name: 'blocked', toolCount: 1 },
    { name: 'shadow', toolCount: 4 }
  ]));

  assert.equal(report.status, 'block');
  assert.equal(report.summary.blockedCount, 1);
  assert.equal(report.summary.unexpectedCount, 1);
  assert.equal(report.servers.find((server) => server.name === 'shadow').status, 'unexpected');
});

test('Codex runtime evidence preserves review for an observed all-tool grant', () => {
  const codexBindings = createToolPermissionBindingSnapshot({
    runtime: 'codex',
    results: [bindingResult('reviewed', 'allow', 'verified')],
    grants: [grant('reviewed', 'all')],
    policy: getPolicyPack('strict')
  });
  const report = evidence(codexBindings, inventory([
    { name: 'reviewed', toolCount: 5 }
  ], { runtime: 'codex', captureMethod: 'runtime-export' }));

  assert.equal(report.runtime, 'codex');
  assert.equal(report.status, 'needs-review');
  assert.equal(report.servers[0].bindingStatus, 'needs-review');
});

test('unobserved configured servers are restriction-only and ASK exposure needs review', () => {
  const baseline = bindings([
    bindingResult('reviewed', 'allow', 'verified'),
    bindingResult('pending', 'ask')
  ], [grant('reviewed', 'scoped'), grant('pending', 'scoped')]);
  const restricted = evidence(baseline, inventory([
    { name: 'reviewed', toolCount: 2 }
  ]));
  const expanded = evidence(baseline, inventory([
    { name: 'reviewed', toolCount: 2 },
    { name: 'pending', toolCount: 1 }
  ], { capturedAt: '2026-10-24T00:05:00.000Z' }));

  assert.equal(restricted.status, 'restricted');
  assert.equal(expanded.status, 'needs-review');
  const diff = diffEffectiveRuntimeEvidence(restricted, expanded);
  assert.equal(diff.status, 'needs-review');
  assert.ok(diff.summary.expansions >= 2);
});

test('runtime inventory and evidence parsing fail closed on extra values and tampering', () => {
  const baseline = bindings([bindingResult('reviewed', 'allow')], [grant('reviewed')]);
  assert.throws(() => createEffectiveRuntimeEvidence(baseline, inventory([
    { name: 'reviewed', toolCount: 1, tools: ['INERT_SECRET_TOOL'] }
  ])), /Invalid runtime tool inventory server/);
  assert.throws(() => createEffectiveRuntimeEvidence(baseline, inventory([
    { name: 'reviewed', toolCount: 1 },
    { name: 'reviewed', toolCount: 2 }
  ])), /must be unique/);
  assert.throws(() => createEffectiveRuntimeEvidence(baseline, inventory([
    { name: 'reviewed', toolCount: 1 }
  ], { capturedAt: 'not-a-time' })), /timestamp/);

  const report = evidence(baseline, inventory([
    { name: 'reviewed', toolCount: 1 }
  ]));
  const tampered = structuredClone(report);
  tampered.servers[0].toolCount = 9;
  assert.throws(() => validateEffectiveRuntimeEvidence(tampered), /summary mismatch|digest mismatch/);

  const replacedDigest = structuredClone(report);
  replacedDigest.inventoryDigest = '0'.repeat(64);
  assert.throws(() => validateEffectiveRuntimeEvidence(replacedDigest), /inventory digest mismatch/);
});

test('zero-tool observation changes do not create contradictory tool-count drift', () => {
  const baseline = bindings([bindingResult('reviewed', 'allow')], [grant('reviewed')]);
  const before = evidence(baseline, inventory([]));
  const after = evidence(baseline, inventory([
    { name: 'reviewed', toolCount: 0 }
  ], { capturedAt: '2026-10-24T00:05:00.000Z' }));
  const diff = diffEffectiveRuntimeEvidence(before, after);

  assert.equal(diff.status, 'needs-review');
  assert.ok(diff.changes.some((change) => change.type === 'observation-changed'));
  assert.equal(diff.changes.some((change) => change.type === 'tool-count-changed'), false);
});

test('unverified runtime inventory fails closed and authentication changes require review', () => {
  const baseline = bindings([bindingResult('reviewed', 'allow', 'verified')], [grant('reviewed', 'scoped')]);
  const input = inventory([{ name: 'reviewed', toolCount: 2 }]);
  const unverified = createEffectiveRuntimeEvidence(baseline, input);
  const verified = evidence(baseline, input);

  assert.equal(unverified.schemaVersion, 2);
  assert.equal(unverified.inventoryAuthentication, 'unverified');
  assert.equal(unverified.producerKeyId, null);
  assert.equal(unverified.attestationDigest, null);
  assert.equal(unverified.status, 'needs-review');
  assert.equal(verified.inventoryAuthentication, 'verified');
  assert.equal(verified.status, 'matched');
  assert.throws(
    () => createEffectiveRuntimeEvidence(baseline, input, verifiedAuthentication(input, {
      inventoryDigest: '0'.repeat(64)
    })),
    /authentication digest mismatch/
  );

  const diff = diffEffectiveRuntimeEvidence(unverified, verified);
  assert.equal(diff.schemaVersion, 2);
  assert.equal(diff.status, 'needs-review');
  assert.ok(diff.changes.some((change) => change.type === 'inventory-authentication-changed'));
  assert.ok(diff.changes.some((change) => change.type === 'producer-key-changed'));
});

test('producer-key rotation requires review while same-key attestation refresh does not', () => {
  const baseline = bindings([bindingResult('reviewed', 'allow', 'verified')], [grant('reviewed', 'scoped')]);
  const input = inventory([{ name: 'reviewed', toolCount: 2 }]);
  const before = evidence(baseline, input);
  const refreshed = createEffectiveRuntimeEvidence(baseline, input, verifiedAuthentication(input, {
    attestationDigest: 'c'.repeat(64)
  }));
  const rotated = createEffectiveRuntimeEvidence(baseline, input, verifiedAuthentication(input, {
    producerKeyId: 'd'.repeat(64)
  }));

  assert.equal(diffEffectiveRuntimeEvidence(before, refreshed).status, 'unchanged');
  const rotation = diffEffectiveRuntimeEvidence(before, rotated);
  assert.equal(rotation.status, 'needs-review');
  assert.ok(rotation.changes.some((change) => change.type === 'producer-key-changed'));
});

test('legacy schema-v1 effective evidence remains valid and diffable', () => {
  const current = evidence(
    bindings([bindingResult('reviewed', 'allow', 'verified')], [grant('reviewed', 'scoped')]),
    inventory([{ name: 'reviewed', toolCount: 2 }])
  );
  const {
    inventoryAuthentication: _inventoryAuthentication,
    producerKeyId: _producerKeyId,
    attestationDigest: _attestationDigest,
    digest: _digest,
    ...payload
  } = current;
  const legacy = { ...payload, schemaVersion: 1 };
  legacy.digest = sha256Json({
    schemaVersion: legacy.schemaVersion,
    kind: legacy.kind,
    runtime: legacy.runtime,
    capturedAt: legacy.capturedAt,
    captureMethod: legacy.captureMethod,
    bindingDigest: legacy.bindingDigest,
    inventoryDigest: legacy.inventoryDigest,
    status: legacy.status,
    summary: legacy.summary,
    servers: legacy.servers
  });

  assert.equal(validateEffectiveRuntimeEvidence(legacy).status, 'matched');
  const diff = diffEffectiveRuntimeEvidence(legacy, legacy);
  assert.equal(diff.schemaVersion, 1);
  assert.equal(diff.status, 'unchanged');
});

test('versioned runtime evidence schemas cover inputs, snapshots, and diffs', () => {
  const inventorySchema = JSON.parse(fs.readFileSync(
    fileURLToPath(new URL('../schemas/runtime-tool-inventory-v1.schema.json', import.meta.url)), 'utf8'
  ));
  const reportSchema = JSON.parse(fs.readFileSync(
    fileURLToPath(new URL('../schemas/effective-runtime-tools-v2.schema.json', import.meta.url)), 'utf8'
  ));
  const diffSchema = JSON.parse(fs.readFileSync(
    fileURLToPath(new URL('../schemas/effective-runtime-tools-diff-v2.schema.json', import.meta.url)), 'utf8'
  ));
  const input = inventory([{ name: 'reviewed', toolCount: 1 }]);
  const report = evidence(bindings([bindingResult('reviewed', 'allow')], [grant('reviewed')]), input);
  const diff = diffEffectiveRuntimeEvidence(report, report);

  for (const key of inventorySchema.required) assert.ok(Object.hasOwn(input, key));
  for (const key of reportSchema.required) assert.ok(Object.hasOwn(report, key));
  for (const key of diffSchema.required) assert.ok(Object.hasOwn(diff, key));
});

test('published inventories expose blocked and unexpected runtime servers without raw values', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'trustdex-runtime-evidence-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const bindingPath = path.join(directory, 'bindings.json');
  const beforePath = path.join(directory, 'before.json');
  const afterPath = path.join(directory, 'after.json');
  const diffPath = path.join(directory, 'diff.json');
  const expected = JSON.parse(fs.readFileSync(path.join(fixtureDirectory, 'expected.json'), 'utf8'));

  assert.equal(run(
    'snapshot-claude-bindings', path.join(fixtureDirectory, 'claude.mcp.json'),
    '--settings', path.join(fixtureDirectory, 'claude.settings.json'),
    '--trust-store', path.join(fixtureDirectory, 'trust-store.json'), '--out', bindingPath
  ).status, 0);
  assert.equal(run(
    'snapshot-runtime-tools', bindingPath, path.join(fixtureDirectory, 'runtime-before.json'),
    '--out', beforePath
  ).status, 0);
  assert.equal(run(
    'snapshot-runtime-tools', bindingPath, path.join(fixtureDirectory, 'runtime-after.json'),
    '--out', afterPath
  ).status, 0);
  const diff = run('diff-runtime-tools', beforePath, afterPath, '--json');
  assert.equal(diff.status, 1);
  fs.writeFileSync(diffPath, diff.stdout);

  for (const [label, file] of [['runtimeBefore', beforePath], ['runtimeAfter', afterPath]]) {
    const contents = fs.readFileSync(file, 'utf8');
    assert.equal(contents.includes('INERT_BINDING_'), false);
    assert.equal(contents.includes(fixtureDirectory), false);
    const report = JSON.parse(contents);
    for (const [key, value] of Object.entries(expected[label])) {
      assert.equal(key === 'status' ? report.status : report.summary[key], value);
    }
  }
  const parsedDiff = JSON.parse(fs.readFileSync(diffPath, 'utf8'));
  assert.equal(parsedDiff.status, 'needs-review');
  assert.ok(parsedDiff.summary.expansions > 0);
});
