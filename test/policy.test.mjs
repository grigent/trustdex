import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectMcpConfig, isPinnedPackage } from '../src/inspect.mjs';
import { evaluateAll } from '../src/policy.mjs';
import { createSnapshot, diffSnapshots } from '../src/snapshot.mjs';

test('detects pinned package specs', () => {
  assert.equal(isPinnedPackage('@modelcontextprotocol/server-filesystem@1.2.3'), true);
  assert.equal(isPinnedPackage('@modelcontextprotocol/server-filesystem'), false);
  assert.equal(isPinnedPackage('example@2.0.0'), true);
  assert.equal(isPinnedPackage('example@latest'), false);
});

test('allows trusted pinned package', () => {
  const servers = inspectMcpConfig({
    mcpServers: {
      files: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@1.2.3'] }
    }
  });
  const [result] = evaluateAll(servers, {
    trustedPackages: ['@modelcontextprotocol/server-filesystem'],
    unknownAction: 'block'
  });
  assert.equal(result.action, 'allow');
});

test('requires review when trusted package is unpinned', () => {
  const servers = inspectMcpConfig({
    mcpServers: {
      files: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem'] }
    }
  });
  const [result] = evaluateAll(servers, {
    trustedPackages: ['@modelcontextprotocol/server-filesystem'],
    unknownAction: 'block',
    unpinnedAction: 'ask'
  });
  assert.equal(result.action, 'ask');
  assert.ok(result.signals.includes('unbounded-version'));
});

test('blocks unknown package in strict policy', () => {
  const servers = inspectMcpConfig({
    mcpServers: { mystery: { command: 'npx', args: ['mystery-mcp@1.0.0'] } }
  });
  const [result] = evaluateAll(servers, { unknownAction: 'block' });
  assert.equal(result.action, 'block');
});

test('raises trusted secret-bearing configuration to ask', () => {
  const servers = inspectMcpConfig({
    mcpServers: {
      github: {
        command: 'npx',
        args: ['trusted-server@1.0.0'],
        env: { GITHUB_TOKEN: '${GITHUB_TOKEN}' }
      }
    }
  });
  const [result] = evaluateAll(servers, {
    trustedPackages: ['trusted-server'],
    sensitiveAction: 'ask'
  });
  assert.equal(result.action, 'ask');
  assert.ok(result.signals.includes('secret-env'));
});

test('diff detects newly added trust signal', () => {
  const before = createSnapshot([
    { name: 'x', source: { type: 'local', command: 'node' }, signals: [], action: 'ask' }
  ]);
  const after = createSnapshot([
    { name: 'x', source: { type: 'local', command: 'node' }, signals: ['shell-execution'], action: 'block' }
  ]);
  const changes = diffSnapshots(before, after);
  assert.ok(changes.some((change) => change.type === 'signals-added'));
  assert.ok(changes.some((change) => change.type === 'decision-changed'));
});
