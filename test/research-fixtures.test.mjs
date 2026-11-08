import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import crypto from 'node:crypto';

import { inspectMcpConfig } from '../src/inspect.mjs';
import { evaluateAll } from '../src/policy.mjs';
import { getPolicyPack, mergePolicy } from '../src/policy-packs.mjs';
import { createSnapshot, diffSnapshots } from '../src/snapshot.mjs';
import { parseTrustStore, attachProvenanceAll } from '../src/provenance.mjs';
import { inspectNpmPackage, inspectMcpRegistryServer } from '../src/provenance-online.mjs';

const fixtureUrl = new URL('../examples/adversarial/', import.meta.url);

async function readFixture(name) {
  return JSON.parse(await fs.readFile(new URL(name, fixtureUrl), 'utf8'));
}

async function evaluate(configName, policy) {
  return evaluateAll(inspectMcpConfig(await readFixture(configName)), policy);
}

test('adversarial MCP fixtures enforce documented decisions without leaking values', async () => {
  const policy = mergePolicy(getPolicyPack('strict'), await readFixture('policy.json'));
  const expected = await readFixture('expected.json');
  const results = await evaluate('mcp-config.json', policy);
  const byName = new Map(results.map((result) => [result.name, result]));

  assert.equal(results.length, Object.keys(expected).length);

  for (const [name, expectation] of Object.entries(expected)) {
    const result = byName.get(name);
    assert.ok(result, `missing result for ${name}`);
    assert.equal(result.action, expectation.action, `unexpected decision for ${name}`);
    for (const signal of expectation.signals) {
      assert.ok(result.signals.includes(signal), `${name} did not report ${signal}`);
    }
  }

  const counts = { allow: 0, ask: 0, block: 0 };
  for (const result of results) counts[result.action] += 1;
  assert.deepEqual(counts, { allow: 1, ask: 1, block: 5 });

  const serialized = JSON.stringify(results);
  assert.equal(serialized.includes('fixture-password'), false);
  assert.equal(serialized.includes('fixture-token'), false);
  assert.equal(serialized.includes('NOT_A_REAL_SECRET'), false);
});

test('secret-bearing capability drift changes the decision and invalidates the fingerprint', async () => {
  const policy = mergePolicy(getPolicyPack('strict'), await readFixture('policy.json'));
  const beforeResults = await evaluate('drift-before.json', policy);
  const afterResults = await evaluate('drift-after.json', policy);

  assert.equal(beforeResults[0].action, 'allow');
  assert.equal(afterResults[0].action, 'ask');
  assert.ok(afterResults[0].signals.includes('secret-env'));
  assert.equal(JSON.stringify(afterResults).includes('NOT_A_REAL_SECRET'), false);

  const changes = diffSnapshots(createSnapshot(beforeResults), createSnapshot(afterResults));
  assert.ok(changes.some((change) => change.type === 'signals-added' && change.signals.includes('secret-env')));
  assert.ok(changes.some((change) => change.type === 'decision-changed' && change.from === 'allow' && change.to === 'ask'));
  assert.ok(changes.some((change) => change.type === 'fingerprint-changed'));
});

test('immutable npm evidence blocks downgrade, PyPI substitution, and name lookalikes', async () => {
  const digest = crypto.createHash('sha256').update('inert reviewed bytes').digest('base64');
  const artifact = {
    registryType: 'npm', identifier: 'reviewed-agent', version: '2.0.0',
    integrity: `sha256-${digest}`
  };
  const store = parseTrustStore({ version: 1, claims: [{
    type: 'package', subject: 'reviewed-agent', publisher: 'Example Publisher',
    status: 'verified',
    evidence: {
      kind: 'npm-registry', reference: 'https://registry.npmjs.org/reviewed-agent',
      artifact, artifactVerification: {
        verified: true, algorithm: 'sha256', digest, encoding: 'base64',
        version: '2.0.0', identifier: 'reviewed-agent',
        verifiedAt: '2026-10-01T00:00:00Z'
      }
    }
  }] });
  const config = await readFixture('registry-substitution.json');
  const inspected = inspectMcpConfig(config);
  const results = evaluateAll(attachProvenanceAll(inspected, store), getPolicyPack('official-first'));
  const byName = Object.fromEntries(results.map(result => [result.name, result]));
  assert.equal(byName['approved-current'].action, 'allow');
  assert.equal(byName.downgrade.action, 'block');
  assert.ok(byName.downgrade.signals.includes('artifact-version-mismatch'));
  assert.equal(byName['cross-registry'].action, 'block');
  assert.ok(byName['cross-registry'].signals.includes('artifact-registry-mismatch'));
  assert.equal(byName['lookalike-name'].action, 'block');
  assert.notEqual(byName['lookalike-name'].provenance.status, 'verified');
});

test('unpublished or malformed online registry artifacts fail closed', async () => {
  const asResponse = data => ({ ok: true, status: 200, json: async () => data });
  const removed = { name: 'reviewed-agent', time: { unpublished: { time: '2026-10-01' } },
    'dist-tags': { latest: '2.0.0' }, versions: {} };
  await assert.rejects(
    inspectNpmPackage('reviewed-agent', { fetchImpl: async () => asResponse(removed) }),
    /unpublished/
  );
  for (const data of [
    { name: 'reviewed-agent', 'dist-tags': { latest: '2.0.0' }, versions: {} },
    { name: 'reviewed-agent', 'dist-tags': { latest: '2.0.0' },
      versions: { '2.0.0': { dist: {} } } },
    { name: 'reviewed-agent', 'dist-tags': { latest: '2.0.0' },
      versions: { '2.0.0': { yanked: true, dist: { integrity: 'sha256-Zm9v' } } } }
  ]) {
    await assert.rejects(
      inspectNpmPackage('reviewed-agent', { fetchImpl: async () => asResponse(data) }),
      /missing, withdrawn, or invalid/
    );
  }
  for (const server of [
    { name: 'io.github.example/test', packages: [{
      registryType: 'npm', identifier: 'reviewed-agent', version: '2.0.0'
    }] },
    { name: 'io.github.example/test', status: 'deleted', packages: [] }
  ]) {
    await assert.rejects(
      inspectMcpRegistryServer('io.github.example/test', { fetchImpl: async () => asResponse({ server }) }),
      /withdrawn|incomplete/
    );
  }
});

test('Windows paths with mixed separators are classified consistently across hosts', () => {
  for (const value of [
    'C:\\Data\\Tools\\server.js', 'c:/Data/Tools/server.js',
    'c:\\Data/Tools\\server.js', '..\\secrets\\path'
  ]) {
    const result = inspectMcpConfig({
      mcpServers: { sample: { command: 'node', args: ['server.js', value] } }
    })[0];
    assert.ok(result.signals.includes('filesystem-path'), value);
  }
});

test('duplicate trust-store source claims fail closed', () => {
  const c = {
    type: 'remote', subject: 'example.test', status: 'verified', publisher: 'A',
    evidence: { kind: 'manual-review', reference: 'https://example.test/review' }
  };
  assert.throws(() => parseTrustStore({ version: 1, claims: [
    c, { ...c, subject: 'EXAMPLE.TEST.', publisher: 'B' }
  ] }), /duplicate claims/);
});
