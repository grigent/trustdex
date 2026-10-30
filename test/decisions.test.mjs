import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createDecisionReport } from '../src/decisions.mjs';
import { getPolicyPack, validatePolicyOverlay } from '../src/policy-packs.mjs';
import { createSnapshot } from '../src/snapshot.mjs';

const cli = fileURLToPath(new URL('../bin/trustdex.mjs', import.meta.url));
const example = (name) => fileURLToPath(new URL(`../examples/${name}`, import.meta.url));
const schema = (name) => JSON.parse(fs.readFileSync(fileURLToPath(new URL(`../schemas/${name}`, import.meta.url)), 'utf8'));

function run(...args) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
}

function tempFile(name, content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'trustdex-decisions-'));
  const file = path.join(dir, name);
  fs.writeFileSync(file, content);
  return file;
}

function assertMatchesDecisionSchema(report) {
  const decisions = schema('trustdex-decisions-v1.schema.json');
  const allowed = new Set(Object.keys(decisions.properties));
  for (const key of Object.keys(report)) assert.ok(allowed.has(key), `unexpected field ${key}`);
  for (const key of decisions.required) assert.ok(Object.hasOwn(report, key), `missing ${key}`);
  const itemSchema = decisions.properties.items.items;
  for (const item of report.items) {
    assert.deepEqual(Object.keys(item).sort(), [...itemSchema.required].sort());
    assert.ok(['allow', 'ask', 'block'].includes(item.action));
  }
  assert.equal(report.schemaVersion, 1);
  assert.equal(report.kind, 'trustdex-decisions');
}

const item = (name, action, extra = {}) => ({ name, kind: 'mcp', action, signals: [], reasons: [], fingerprint: null, ...extra });

test('the overall decision is the most restrictive item and maps to the exit code', () => {
  const policy = getPolicyPack('strict');
  const base = { command: 'inspect', trustdexVersion: '0.0.0', policy };
  assert.equal(createDecisionReport([], base).decision, 'allow');
  assert.equal(createDecisionReport([item('a', 'allow')], base).exitCode, 0);
  const ask = createDecisionReport([item('a', 'allow'), item('b', 'ask')], base);
  assert.equal(ask.decision, 'ask');
  assert.equal(ask.exitCode, 1);
  const block = createDecisionReport([item('b', 'ask'), item('c', 'block'), item('a', 'allow')], base);
  assert.equal(block.decision, 'block');
  assert.equal(block.exitCode, 2);
  assert.deepEqual(block.counts, { allow: 1, ask: 1, block: 1 });
  assert.deepEqual(block.items.map((entry) => entry.name), ['a', 'b', 'c']);
});

test('results without a valid action fail instead of being reported', () => {
  assert.throws(() => createDecisionReport([item('a', 'maybe')], { command: 'inspect', trustdexVersion: '0', policy: {} }), /no valid action/);
  assert.throws(() => createDecisionReport([{ name: 'a' }], { command: 'inspect', trustdexVersion: '0', policy: {} }), /no valid action/);
});

test('the report digest is deterministic and covers decisions and policy', () => {
  const policy = getPolicyPack('strict');
  const base = { command: 'inspect', trustdexVersion: '0.0.0', policy };
  const first = createDecisionReport([item('a', 'allow'), item('b', 'ask')], base);
  const reordered = createDecisionReport([item('b', 'ask'), item('a', 'allow')], base);
  assert.equal(first.digest, reordered.digest);
  assert.notEqual(first.digest, createDecisionReport([item('a', 'allow'), item('b', 'block')], base).digest);
  assert.notEqual(first.digest, createDecisionReport([item('a', 'allow'), item('b', 'ask')], { ...base, policy: getPolicyPack('development') }).digest);
});

test('reports carry no metadata, provenance evidence, or environment names', () => {
  const report = createDecisionReport([{
    ...item('a', 'ask'),
    metadata: { secret: 'META-VALUE' },
    envKeys: ['API_TOKEN'],
    provenance: { status: 'verified', evidence: { reference: 'https://evidence.invalid/x' } },
    source: { type: 'package', package: 'pkg' }
  }], { command: 'inspect', trustdexVersion: '0', policy: {} });
  const text = JSON.stringify(report);
  for (const marker of ['META-VALUE', 'API_TOKEN', 'evidence.invalid']) assert.ok(!text.includes(marker), marker);
});

test('every inspection command emits a schema-conforming report whose exit code matches', () => {
  for (const args of [
    ['inspect', example('mcp.json'), '--policy', example('trustdex.policy.json')],
    ['inspect-claude', example('claude.mcp.json'), '--policy', example('claude.policy.json')],
    ['inspect-claude-settings', example('claude.settings.json')],
    ['inspect-codex', example('codex.config.toml')],
    ['inspect-codex-settings', example('codex.permissions.toml')],
    ['inspect-ide-extensions', example('ide-extensions'), '--policy', example('ide-extensions.policy.json')]
  ]) {
    const result = run(...args, '--decisions');
    const report = JSON.parse(result.stdout);
    assertMatchesDecisionSchema(report);
    assert.equal(report.command, args[0]);
    assert.equal(result.status, report.exitCode, args.join(' '));
    assert.ok(report.items.length > 0);
  }
});

test('a failed inspection still prints a parseable BLOCK report without input content', () => {
  const bad = tempFile('bad.json', '{"mcpServers": {"x": {"env": {"TOKEN": sk-live-SECRET}}}}');
  for (const args of [['inspect', bad], ['inspect', path.join(path.dirname(bad), 'missing.json')]]) {
    const result = run(...args, '--decisions');
    assert.equal(result.status, 2);
    const report = JSON.parse(result.stdout);
    assertMatchesDecisionSchema(report);
    assert.equal(report.decision, 'block');
    assert.equal(report.exitCode, 2);
    assert.deepEqual(report.items, []);
    assert.ok(!result.stdout.includes('SECRET'));
  }
});

test('snapshots match the published v3 snapshot schema', () => {
  const snapshotSchema = schema('trust-snapshot-v3.schema.json');
  const snapshot = createSnapshot([
    { name: 'x', source: { type: 'remote', host: 'example.invalid' }, signals: ['b', 'a'], action: 'ask' }
  ]);
  assert.equal(snapshot.schemaVersion, snapshotSchema.properties.schemaVersion.const);
  assert.deepEqual(Object.keys(snapshot).sort(), [...snapshotSchema.required].sort());
  const required = snapshotSchema.properties.servers.items.required;
  assert.deepEqual(Object.keys(snapshot.servers[0]).sort(), [...required].sort());
});

test('policy files reject unknown fields and invalid values', () => {
  for (const [overlay, message] of [
    [[], /JSON object/],
    [{ trustedPackage: ['x'] }, /Unknown policy field "trustedPackage"/],
    [{ shellActon: 'block' }, /Unknown policy field/],
    [{ version: 2 }, /Unsupported policy version/],
    [{ unknownAction: 'alow' }, /unknownAction must be/],
    [{ trustedPackages: 'pkg' }, /trustedPackages must be an array/],
    [{ allowedRemoteHosts: [''] }, /allowedRemoteHosts must be an array/],
    [{ signalActions: { 'shell-execution': 'permit' } }, /signalActions\.shell-execution must be/],
    [{ signalActions: [] }, /signalActions must be an object/],
    [{ note: 1 }, /note must be a string/]
  ]) {
    assert.throws(() => validatePolicyOverlay(overlay), message, JSON.stringify(overlay));
  }
  for (const file of ['trustdex.policy.json', 'claude.policy.json', 'ide-extensions.policy.json', 'adversarial/policy.json']) {
    assert.doesNotThrow(() => validatePolicyOverlay(JSON.parse(fs.readFileSync(example(file), 'utf8'))), file);
  }
  for (const name of ['strict', 'official-first', 'development']) {
    assert.doesNotThrow(() => validatePolicyOverlay(getPolicyPack(name)), name);
  }
});

test('the CLI refuses a policy file with a typo instead of ignoring it', () => {
  const policy = tempFile('policy.json', JSON.stringify({ trustedPackage: ['example-mcp-server'] }));
  const result = run('inspect', example('mcp.json'), '--policy', policy);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /Unknown policy field "trustedPackage"/);
});

test('the policy schema lists exactly the fields the validator accepts', () => {
  const policySchema = schema('trustdex-policy-v1.schema.json');
  const fields = Object.keys(policySchema.properties).sort();
  for (const field of fields) {
    const sample = { $schema: 's', version: 1, note: 'n', signalActions: {} }[field] ??
      (field.endsWith('Action') ? 'ask' : []);
    assert.doesNotThrow(() => validatePolicyOverlay({ [field]: sample }), field);
  }
  assert.throws(() => validatePolicyOverlay({ notInSchema: true }), /Unknown policy field/);
  assert.equal(policySchema.additionalProperties, false);
});
