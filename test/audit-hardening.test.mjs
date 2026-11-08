import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { inspectMcpConfig } from '../src/inspect.mjs';
import { inspectClaudeSettings } from '../src/claude-settings.mjs';
import { gateMcpConfig } from '../src/gate.mjs';
import { digestExtensionTree } from '../src/ide-extensions.mjs';
import { decodeTomlValue, parseTomlStatements } from '../src/toml-lite.mjs';
import { createRuntimeInventoryAttestation, verifyRuntimeInventoryAttestation } from '../src/runtime-attestation.mjs';
import { generateTrustKeyPair } from '../src/trust-record.mjs';

test('Windows tilde-home path is recognized as filesystem-sensitive', () => {
  const result = inspectMcpConfig({ mcpServers: {
    test: { command: 'node', args: ['server.mjs', String.raw`~\.config\mcp`] }
  } });
  assert.ok(result[0].signals.includes('filesystem-path'));
});

test('mixed-case Claude dangerous tool names never downgrade to other category', () => {
  const inspected = inspectClaudeSettings({ permissions: {
    allow: ['bash', 'POWERSHELL', 'read', 'WEBFETCH', 'AGENT', 'MCP__reviewed__run']
  } });
  for (const signal of [
    'claude-auto-approve', 'claude-shell-auto-approve', 'claude-broad-auto-approve',
    'claude-filesystem-auto-approve', 'claude-network-auto-approve',
    'claude-subagent-auto-approve', 'claude-mcp-auto-approve'
  ]) assert.ok(inspected.signals.includes(signal), signal);
  assert.deepEqual(inspected.metadata.allowCategories, [
    'filesystem', 'mcp', 'network', 'shell', 'subagent'
  ]);
});

test('gate requires complete, unique, known decisions and handles prototype-looking names', () => {
  const config = JSON.parse('{"mcpServers":{"__proto__":{"command":"node"},"constructor":{"command":"node"}}}');
  const results = [
    { name: '__proto__', action: 'allow' },
    { name: 'constructor', action: 'block' }
  ];
  const gated = gateMcpConfig(config, results);
  assert.equal(gated.summary.total, 2);
  assert.equal(gated.summary.exposed, 1);
  assert.equal(Object.hasOwn(gated.config.mcpServers, '__proto__'), true);
  assert.equal(Object.hasOwn(gated.config.mcpServers, 'constructor'), false);
  assert.equal(gated.config.mcpServers.__proto__.command, 'node');
  assert.equal(Object.getPrototypeOf(gated.config.mcpServers), Object.prototype);
  assert.equal(Object.prototype.command, undefined);
  assert.throws(() => gateMcpConfig(config, [results[0]]), /do not cover/);
  assert.throws(() => gateMcpConfig(config, [...results, results[0]]), /duplicate/);
  assert.throws(() => gateMcpConfig(config, [...results, { name: 'unknown', action: 'allow' }]), /unknown/);
  assert.throws(() => gateMcpConfig(config, [{ name: '__proto__', action: 'maybe' }, results[1]]), /invalid/);
});

test('extension tree hash enforces maximum files, entries, bytes, depth, and invalid overrides', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'trustdex-tree-budget-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  await fs.writeFile(path.join(dir, 'one.txt'), 'one');
  await fs.writeFile(path.join(dir, 'two.txt'), 'two');
  await fs.mkdir(path.join(dir, 'sub'));
  await fs.writeFile(path.join(dir, 'sub', 'deep.txt'), 'three');
  const ordinary = await digestExtensionTree(dir);
  assert.equal(ordinary.files, 3);
  assert.match(ordinary.digest, /^sha256:[0-9a-f]{64}$/);
  await assert.rejects(digestExtensionTree(dir, { maxFiles: 2 }), /file-count/);
  await assert.rejects(digestExtensionTree(dir, { maxEntries: 2 }), /entry-count/);
  await assert.rejects(digestExtensionTree(dir, { maxBytes: 5 }), /total byte/);
  await assert.rejects(digestExtensionTree(dir, { maxDepth: 0 }), /directory-depth/);
  await assert.rejects(digestExtensionTree(dir, { maxFiles: 1000000 }), /resource limit/);
});

test('TOML numeric exponent notation decodes while infinity and strings stay unsupported', () => {
  for (const [value, expected] of [
    ['1e-3', 0.001], ['1.5e+10', 15e9], ['-2E2', -200], ['2', 2]
  ]) assert.equal(decodeTomlValue({ kind: 'bare', value }), expected);
  for (const value of ['1e9999', 'inf', 'nan', 'word']) {
    assert.throws(() => decodeTomlValue({ kind: 'bare', value }), /Unsupported TOML/);
  }
});

test('TOML multiline backslash continuation preserves semantics without repeated slicing', () => {
  const input = ['description = """', 'alpha\\', '  beta', '"""'].join('\n');
  const statements = parseTomlStatements(input);
  assert.equal(statements[0].value.kind, 'string');
  assert.equal(statements[0].value.value, 'alphabeta\n');
});

test('attestation verification applies a default one-hour capture freshness limit', () => {
  const keys = generateTrustKeyPair();
  const inventory = {
    schemaVersion: 1, kind: 'agent-runtime-tool-inventory',
    runtime: 'claude', capturedAt: '2026-10-24T00:00:00.000Z',
    captureMethod: 'runtime-adapter',
    servers: [{ name: 'reviewed', toolCount: 1 }]
  };
  const attestation = createRuntimeInventoryAttestation(inventory, keys.privateKey, {
    createdAt: '2026-10-24T02:00:10.000Z', ttlSeconds: 300
  });
  const now = '2026-10-24T02:00:40.000Z';
  assert.match(verifyRuntimeInventoryAttestation(inventory, attestation, keys.publicKey, {
    now
  }).reason, /too old/);
  assert.equal(verifyRuntimeInventoryAttestation(inventory, attestation, keys.publicKey, {
    now, maxAgeSeconds: 10800
  }).valid, true);
});
