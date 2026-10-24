import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { inspectClaudeMcpPermissionBindings } from '../src/claude-settings.mjs';
import {
  codexAutomaticGrantProjection,
  createToolPermissionBindingSnapshot,
  diffToolPermissionBindingSnapshots
} from '../src/bindings.mjs';
import { getPolicyPack } from '../src/policy-packs.mjs';
import { createTrustRecord, generateTrustKeyPair, verifyTrustRecord } from '../src/trust-record.mjs';

const cli = fileURLToPath(new URL('../bin/trustdex.mjs', import.meta.url));
const fixtureDirectory = fileURLToPath(new URL('../examples/adversarial/bindings/', import.meta.url));

function result(name, action, provenance = { status: 'unknown' }, signals = []) {
  return { name, action, provenance, signals };
}

function snapshot(runtime, results, grants, extra = {}) {
  return createToolPermissionBindingSnapshot({
    runtime,
    results,
    grants,
    policy: getPolicyPack('strict'),
    ...extra
  });
}

function run(...args) {
  const output = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  if (output.error) throw output.error;
  return output;
}

test('Claude bindings connect source decisions to automatic grants without tool values', () => {
  const secret = 'INERT_BINDING_TOOL_SECRET';
  const projection = inspectClaudeMcpPermissionBindings([
    {
      scope: 'session',
      settings: {
        permissions: {
          allow: [
            `mcp__reviewed__read_${secret}`,
            'mcp__unknown__*',
            `mcp__missing__${secret}`
          ]
        }
      }
    }
  ], ['reviewed', 'unknown']);
  const report = snapshot('claude', [
    result('reviewed', 'allow', { status: 'verified', integrityVerified: true }),
    result('unknown', 'block')
  ], projection.grants, {
    unboundAutomaticGrantCount: projection.unboundAllowRuleCount,
    ambiguousAutomaticGrantCount: projection.ambiguousAllowRuleCount
  });

  assert.equal(report.status, 'block');
  assert.equal(report.summary.boundCount, 1);
  assert.equal(report.summary.blockedCount, 1);
  assert.equal(report.summary.unboundAutomaticGrantCount, 1);
  assert.equal(report.bindings.find((binding) => binding.name === 'reviewed').status, 'bound');
  assert.equal(report.bindings.find((binding) => binding.name === 'unknown').automaticGrant, 'all');
  assert.equal(JSON.stringify(report).includes(secret), false);
});

test('Claude bindings fail closed on ambiguous server-name matches', () => {
  const projection = inspectClaudeMcpPermissionBindings([
    {
      scope: 'session',
      settings: { permissions: { allow: ['mcp__alpha__reader'] } }
    }
  ], ['alpha', 'alpha__reader']);

  assert.equal(projection.ambiguousAllowRuleCount, 1);
  assert.ok(projection.grants.every((grant) => grant.automaticGrant === 'none'));
  const report = snapshot('claude', [
    result('alpha', 'allow'),
    result('alpha__reader', 'allow')
  ], projection.grants, {
    ambiguousAutomaticGrantCount: projection.ambiguousAllowRuleCount
  });
  assert.equal(report.status, 'needs-review');
});

test('Codex binding projection retains approval shape without tool lists', () => {
  const results = [
    result('approved', 'allow', { status: 'verified' }, ['auto-approve-tools']),
    result('scoped', 'ask', { status: 'unknown' }, ['wildcard-tool-scope']),
    result('blocked', 'block', { status: 'unknown' }, ['auto-approve-tools', 'wildcard-tool-scope'])
  ];
  const report = snapshot('codex', results, codexAutomaticGrantProjection(results));

  assert.equal(report.status, 'block');
  assert.equal(report.bindings.find((binding) => binding.name === 'approved').status, 'needs-review');
  assert.equal(report.bindings.find((binding) => binding.name === 'scoped').status, 'not-granted');
  assert.equal(report.bindings.find((binding) => binding.name === 'blocked').status, 'blocked');
});

test('binding drift classifies new grants and provenance changes for review', () => {
  const before = snapshot('claude', [result('demo', 'allow', { status: 'verified' })], [{
    name: 'demo', automaticGrant: 'none', grantRuleCount: 0, toolScopeWildcard: false
  }]);
  const after = snapshot('claude', [result('demo', 'ask', { status: 'unknown' })], [{
    name: 'demo', automaticGrant: 'all', grantRuleCount: 1, toolScopeWildcard: true
  }]);
  const diff = diffToolPermissionBindingSnapshots(before, after);

  assert.equal(diff.status, 'needs-review');
  assert.ok(diff.summary.expansions >= 2);
  assert.ok(diff.summary.reviews >= 2);
  assert.ok(diff.changes.some((change) => change.type === 'provenance-changed'));
  assert.ok(diff.changes.some((change) => change.type === 'grant-changed'));
});

test('binding snapshots detect tampering and support generic signed trust records', () => {
  const report = snapshot('claude', [result('demo', 'allow')], [{
    name: 'demo', automaticGrant: 'scoped', grantRuleCount: 1, toolScopeWildcard: false
  }]);
  const changed = structuredClone(report);
  changed.bindings[0].grantRuleCount = 2;
  assert.throws(() => diffToolPermissionBindingSnapshots(report, changed), /summary mismatch|digest mismatch/);

  const injected = structuredClone(report);
  injected.bindings[0].toolName = 'INERT_BINDING_INJECTED_VALUE';
  assert.throws(() => diffToolPermissionBindingSnapshots(report, injected), /Invalid tool permission binding/);

  const invalidTime = structuredClone(report);
  invalidTime.createdAt = 'not-a-date';
  assert.throws(() => diffToolPermissionBindingSnapshots(report, invalidTime), /creation time/);

  const keys = generateTrustKeyPair();
  const record = createTrustRecord(report, keys.privateKey);
  assert.equal(verifyTrustRecord(record, keys.publicKey, { snapshot: report }).valid, true);
});

test('versioned binding schemas cover emitted snapshots and diffs', () => {
  const reportSchema = JSON.parse(fs.readFileSync(
    fileURLToPath(new URL('../schemas/tool-permission-bindings-v1.schema.json', import.meta.url)),
    'utf8'
  ));
  const diffSchema = JSON.parse(fs.readFileSync(
    fileURLToPath(new URL('../schemas/tool-permission-bindings-diff-v1.schema.json', import.meta.url)),
    'utf8'
  ));
  const before = snapshot('codex', [result('demo', 'allow')], [{
    name: 'demo', automaticGrant: 'none', grantRuleCount: 0, toolScopeWildcard: false
  }]);
  const after = snapshot('codex', [result('demo', 'allow')], [{
    name: 'demo', automaticGrant: 'all', grantRuleCount: 1, toolScopeWildcard: false
  }]);
  const diff = diffToolPermissionBindingSnapshots(before, after);

  assert.equal(reportSchema.properties.schemaVersion.const, 1);
  assert.equal(diffSchema.properties.schemaVersion.const, 1);
  for (const key of reportSchema.required) assert.ok(Object.hasOwn(before, key));
  for (const key of diffSchema.required) assert.ok(Object.hasOwn(diff, key));
});

test('Claude and Codex binding CLI snapshots omit config and permission values', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'trustdex-bindings-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const secret = 'INERT_BINDING_CLI_SECRET';
  const claudeMcp = path.join(directory, 'claude.mcp.json');
  const claudeSettings = path.join(directory, 'claude.settings.json');
  const codex = path.join(directory, 'codex.toml');
  const trustStore = path.join(directory, 'trust-store.json');
  const claudeOut = path.join(directory, 'claude.bindings.json');
  const codexOut = path.join(directory, 'codex.bindings.json');

  fs.writeFileSync(claudeMcp, JSON.stringify({
    mcpServers: {
      reviewed: { type: 'http', url: `https://reviewed.invalid/${secret}` },
      unknown: { type: 'http', url: `https://unknown.invalid/${secret}` }
    }
  }));
  fs.writeFileSync(claudeSettings, JSON.stringify({
    permissions: { allow: [`mcp__reviewed__read_${secret}`, 'mcp__unknown__*'] }
  }));
  fs.writeFileSync(codex, `
[mcp_servers.reviewed]
url = "https://reviewed.invalid/${secret}"
default_tools_approval_mode = "approve"
enabled_tools = ["${secret}"]
`);
  fs.writeFileSync(trustStore, JSON.stringify({
    version: 1,
    claims: [{
      type: 'remote',
      subject: 'reviewed.invalid',
      publisher: 'Reviewed Publisher',
      status: 'verified',
      evidence: { kind: 'manual-review', reference: 'https://evidence.invalid/review' }
    }]
  }));

  assert.equal(run(
    'snapshot-claude-bindings', claudeMcp, '--settings', claudeSettings,
    '--trust-store', trustStore, '--out', claudeOut
  ).status, 0);
  assert.equal(run(
    'snapshot-codex-bindings', codex, '--trust-store', trustStore, '--out', codexOut
  ).status, 0);

  for (const file of [claudeOut, codexOut]) {
    const contents = fs.readFileSync(file, 'utf8');
    assert.equal(contents.includes(secret), false);
    assert.equal(contents.includes(directory), false);
    const report = JSON.parse(contents);
    assert.equal(report.kind, 'agent-tool-permission-bindings');
    assert.match(report.digest, /^[a-f0-9]{64}$/);
  }
});

test('published binding fixtures enforce provenance-grant outcomes without retaining markers', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'trustdex-binding-fixtures-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const expected = JSON.parse(fs.readFileSync(path.join(fixtureDirectory, 'expected.json'), 'utf8'));
  const trustStore = path.join(fixtureDirectory, 'trust-store.json');
  const outputs = {
    claude: path.join(directory, 'claude.json'),
    codex: path.join(directory, 'codex.json')
  };

  assert.equal(run(
    'snapshot-claude-bindings', path.join(fixtureDirectory, 'claude.mcp.json'),
    '--settings', path.join(fixtureDirectory, 'claude.settings.json'),
    '--trust-store', trustStore, '--out', outputs.claude
  ).status, 0);
  assert.equal(run(
    'snapshot-codex-bindings', path.join(fixtureDirectory, 'codex.toml'),
    '--trust-store', trustStore, '--out', outputs.codex
  ).status, 0);

  for (const runtime of ['claude', 'codex']) {
    const contents = fs.readFileSync(outputs[runtime], 'utf8');
    const report = JSON.parse(contents);
    assert.equal(contents.includes('INERT_BINDING_'), false);
    assert.equal(contents.includes(fixtureDirectory), false);
    for (const [key, value] of Object.entries(expected[runtime])) {
      assert.equal(key === 'status' ? report.status : report.summary[key], value);
    }
  }
});

