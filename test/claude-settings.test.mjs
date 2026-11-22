import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { inspectClaudeSettings } from '../src/claude-settings.mjs';
import { evaluateAll } from '../src/policy.mjs';
import { getPolicyPack } from '../src/policy-packs.mjs';

const cli = fileURLToPath(new URL('../bin/trustdex.mjs', import.meta.url));

function evaluate(settings, pack = 'strict') {
  return evaluateAll([inspectClaudeSettings(settings)], getPolicyPack(pack))[0];
}

function run(...args) {
  const result = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  if (result.error) throw result.error;
  return result;
}

test('Claude settings that switch off every hook are blocked', () => {
  for (const pack of ['strict', 'official-first', 'development']) {
    const result = evaluate({ disableAllHooks: true }, pack);
    assert.equal(result.action, 'block', pack);
    assert.ok(result.signals.includes('claude-hooks-disabled'));
    assert.ok(!result.signals.includes('uninspected-claude-settings'));
  }
  assert.ok(!evaluate({ disableAllHooks: false }).signals.includes('claude-hooks-disabled'));
});

test('Claude settings inspection treats deny and ask rules as restrictions', () => {
  const result = evaluate({
    permissions: {
      ask: ['Bash(git push *)', 'Agent(model:opus)'],
      deny: ['Bash', 'WebFetch(domain:*)', 'mcp__*'],
      defaultMode: 'plan',
      disableBypassPermissionsMode: 'disable',
      disableAutoMode: 'disable',
      blockReadsOutsideWorkingDirectories: true
    }
  });

  assert.equal(result.action, 'ask');
  assert.deepEqual(result.signals, []);
  assert.equal(result.metadata.bypassDisabled, true);
  assert.equal(result.metadata.autoModeDisabled, true);
  assert.equal(result.metadata.outsideReadsBlocked, true);
});

test('Claude settings inspection blocks broad automatic approval and bypass mode', () => {
  const result = evaluate({
    permissions: {
      allow: ['Bash', 'WebFetch(domain:*)', 'Read', 'Agent', 'mcp__reviewed__*'],
      defaultMode: 'bypassPermissions'
    }
  });

  assert.equal(result.action, 'block');
  assert.ok(result.signals.includes('claude-auto-approve'));
  assert.ok(result.signals.includes('claude-broad-auto-approve'));
  assert.ok(result.signals.includes('claude-shell-auto-approve'));
  assert.ok(result.signals.includes('claude-network-auto-approve'));
  assert.ok(result.signals.includes('claude-filesystem-auto-approve'));
  assert.ok(result.signals.includes('claude-subagent-auto-approve'));
  assert.ok(result.signals.includes('claude-mcp-auto-approve'));
  assert.ok(result.signals.includes('claude-mcp-wildcard'));
  assert.ok(result.signals.includes('claude-bypass-permissions'));
  assert.deepEqual(result.metadata.allowCategories, ['filesystem', 'mcp', 'network', 'shell', 'subagent']);
});

test('Claude settings inspection reports narrow auto-approval without retaining rule values', () => {
  const secret = 'INERT_RULE_SECRET';
  const result = evaluate({
    permissions: {
      allow: [
        `Bash(tool --api-token ${secret})`,
        `WebFetch(domain:${secret}.invalid)`,
        'Agent(Explore)',
        'mcp__reviewed__read_item'
      ],
      additionalDirectories: [`../${secret}`]
    }
  });

  assert.equal(result.action, 'block');
  assert.ok(result.signals.includes('claude-additional-directories'));
  assert.ok(!result.signals.includes('claude-broad-auto-approve'));
  assert.equal(JSON.stringify(result).includes(secret), false);
  assert.equal('fingerprint' in result, false);
});

test('Claude settings inspection surfaces adjacent executable settings without values', () => {
  const secret = 'INERT_SETTINGS_SECRET';
  const result = evaluate({
    permissions: { defaultMode: 'default' },
    env: { API_TOKEN: secret, SAFE_NAME: secret },
    hooks: { PreToolUse: [{ hooks: [{ type: 'command', command: secret }] }] },
    apiKeyHelper: secret,
    sandbox: { network: { allowedDomains: [secret] } },
    enabledPlugins: { [secret]: true },
    [secret]: secret
  });

  assert.equal(result.action, 'block');
  for (const signal of [
    'claude-environment',
    'secret-env',
    'claude-hooks',
    'claude-credential-helper',
    'claude-sandbox-settings',
    'claude-extension-loading',
    'uninspected-claude-settings'
  ]) assert.ok(result.signals.includes(signal));
  assert.deepEqual(result.envKeys, ['API_TOKEN', 'SAFE_NAME']);
  assert.equal(result.metadata.uninspectedRootKeyCount, 1);
  assert.equal(JSON.stringify(result).includes(secret), false);
});

test('Claude settings recognize executable helpers and restrictions without their values', () => {
  const secret = 'INERT_EXECUTABLE_VALUE';
  for (const key of ['awsAuthRefresh', 'awsCredentialExport', 'gcpAuthRefresh', 'otelHeadersHelper']) {
    const result = evaluate({ [key]: secret });
    assert.equal(result.action, 'block', key);
    assert.deepEqual(result.signals, ['claude-credential-helper']);
    assert.ok(!JSON.stringify(result).includes(secret));
  }
  for (const key of ['statusLine', 'fileSuggestion', 'policyHelper']) {
    const result = evaluate({ [key]: { type: 'command', command: secret, path: secret } });
    assert.equal(result.action, 'block', key);
    assert.deepEqual(result.signals, ['claude-hooks']);
    assert.ok(!JSON.stringify(result).includes(secret));
  }
  assert.deepEqual(evaluate({ allowManagedHooksOnly: true }).signals, ['claude-hooks-disabled']);
  const result = evaluate({
    disableAutoMode: 'disable',
    permissions: { blockWritesOutsideWorkingDirectories: true, denyInsteadOfPrompting: true }
  });
  assert.equal(result.action, 'ask');
  assert.equal(result.metadata.autoModeDisabled, true);
  assert.equal(result.metadata.outsideWritesBlocked, true);
  assert.equal(result.metadata.denyInsteadOfPrompting, true);
});

test('Claude settings report anchored MCP tool globs as wildcard grants', () => {
  const result = evaluate({ permissions: { allow: ['mcp__demo__get_*__item'] } });
  assert.equal(result.action, 'ask');
  assert.ok(result.signals.includes('claude-mcp-wildcard'));
});

test('Claude settings parser fails closed on malformed or unsupported permission syntax', () => {
  for (const settings of [
    null,
    [],
    { permissions: [] },
    { permissions: { futureControl: true } },
    { permissions: { allow: 'Bash(npm test)' } },
    { permissions: { allow: [''] } },
    { permissions: { allow: ['Bash()'] } },
    { permissions: { allow: ['*'] } },
    { permissions: { allow: ['mcp__*'] } },
    { permissions: { allow: ['mcp__demo*__get_item'] } },
    { permissions: { allow: ['mcp__de*mo'] } },
    { permissions: { allow: ['mcp__demo__tool(param:value)'] } },
    { permissions: { defaultMode: 'futureMode' } },
    { permissions: { additionalDirectories: [1] } },
    { permissions: { disableBypassPermissionsMode: false } },
    { permissions: { blockReadsOutsideWorkingDirectories: 'true' } },
    { permissions: { blockWritesOutsideWorkingDirectories: 'true' } },
    { permissions: { denyInsteadOfPrompting: 'true' } },
    { disableAutoMode: true },
    { allowManagedPermissionRulesOnly: 'true' },
    { allowManagedHooksOnly: 'true' },
    { disableAllHooks: 'true' },
    { env: { TOKEN: 123 } },
    { env: [] }
  ]) assert.throws(() => inspectClaudeSettings(settings));
});

test('Claude settings CLI inspects the inert example and does not leak malformed input', t => {
  const example = fileURLToPath(new URL('../examples/claude.settings.json', import.meta.url));
  const inspected = run('inspect-claude-settings', example, '--pack', 'strict', '--json');
  assert.equal(inspected.status, 2);
  const result = JSON.parse(inspected.stdout)[0];
  assert.equal(result.kind, 'claude-settings');
  assert.ok(result.signals.includes('claude-shell-auto-approve'));
  assert.ok(result.signals.includes('claude-additional-directories'));

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'trustdex-settings-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const invalid = path.join(directory, 'invalid.json');
  fs.writeFileSync(invalid, '{"permissions":{"allow":["Bash(INERT_SECRET)"],"INERT_KEY":"INERT_SECRET"}}');
  const failed = run('inspect-claude-settings', invalid, '--json');
  assert.equal(failed.status, 2);
  assert.match(failed.stderr, /Unsupported Claude permission setting/);
  assert.doesNotMatch(failed.stderr, /INERT_(KEY|SECRET)/);
});
