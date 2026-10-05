import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';

import { inspectMcpConfig } from '../src/inspect.mjs';
import { evaluateAll } from '../src/policy.mjs';
import { getPolicyPack, mergePolicy } from '../src/policy-packs.mjs';
import { createSnapshot, diffSnapshots } from '../src/snapshot.mjs';

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
