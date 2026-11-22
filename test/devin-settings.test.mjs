import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { inspectDevinSettings } from '../src/devin-settings.mjs';
import { evaluateAll } from '../src/policy.mjs';
import { getPolicyPack } from '../src/policy-packs.mjs';

const cli = fileURLToPath(new URL('../bin/trustdex.mjs', import.meta.url));

function evaluate(settings, pack = 'strict') {
  return evaluateAll([inspectDevinSettings(settings)], getPolicyPack(pack))[0];
}

test('empty and restriction-only Devin configs are ASK under every pack and a permissive policy', () => {
  const permissive = { version: 1, unknownAction: 'allow', localAction: 'allow', sensitiveAction: 'allow',
    unpinnedAction: 'allow', shellAction: 'allow', verifiedPublisherAction: 'allow' };
  const configs = [
    {},
    { permission_mode: null },
    { permission_mode: 'normal', permissions: { deny: ['Exec(sudo)', 'exec', 'mcp__*'], ask: ['Write(**)', 'edit'] } },
    { agent: { model: 'x' }, sandbox: { denied_domains: ['a.invalid'] }, respect_gitignore: true, local_tools_bypass_permissions: false }
  ];
  for (const config of configs) {
    assert.deepEqual(inspectDevinSettings(config).signals, [], JSON.stringify(config));
    for (const pack of ['strict', 'official-first', 'development']) assert.equal(evaluate(config, pack).action, 'ask', pack);
    assert.equal(evaluateAll([inspectDevinSettings(config)], permissive)[0].action, 'ask');
  }
});

test('Devin settings inspection classifies autonomy by capability', () => {
  const cases = [
    [{ permission_mode: 'accept-edits' }, 'devin-permission-mode-auto', 'ask'],
    [{ permission_mode: 'smart' }, 'devin-permission-mode-auto', 'ask'],
    [{ permission_mode: 'dangerous' }, 'devin-permission-mode-bypass', 'block'],
    [{ permissions: { allow: ['Read(src/**)'] } }, 'devin-auto-approved-tools', 'ask'],
    [{ permissions: { allow: ['Write(src/**)'] } }, 'devin-auto-approved-tools', 'ask'],
    [{ permissions: { allow: ['Fetch(domain:registry.invalid)'] } }, 'devin-auto-approved-tools', 'ask'],
    [{ permissions: { allow: ['mcp__reviewed__list'] } }, 'devin-auto-approved-tools', 'ask'],
    [{ permissions: { allow: ['mcp__*'] } }, 'devin-auto-approved-tools', 'ask'],
    [{ permissions: { allow: ['edit'] } }, 'devin-auto-approved-tools', 'ask'],
    [{ permissions: { allow: ['Exec(git status)'] } }, 'devin-auto-approved-exec', 'block'],
    [{ permissions: { allow: ['exec'] } }, 'devin-auto-approved-exec', 'block'],
    [{ hooks: { PreToolUse: [{ matcher: 'exec', hooks: [{ type: 'command', command: 'inert' }] }] } }, 'devin-hooks', 'block'],
    [{ local_tools_bypass_permissions: true }, 'devin-local-tools-bypass', 'ask'],
    [{ mcpServers: { inert: { command: 'inert' } } }, 'devin-mcp-servers', 'ask'],
    [{ proxy: { mode: 'manual', url: 'http://proxy.invalid' } }, 'uninspected-devin-settings', 'ask'],
    [{ permissions: { future: [] } }, 'uninspected-devin-settings', 'ask']
  ];
  for (const [config, signal, action] of cases) {
    const result = evaluate(config);
    assert.ok(result.signals.includes(signal), `${signal}: ${JSON.stringify(config)}`);
    assert.equal(result.action, action, JSON.stringify(config));
    for (const pack of ['official-first', 'development']) {
      assert.notEqual(evaluate(config, pack).action, 'allow', JSON.stringify(config));
      if (action === 'block') assert.equal(evaluate(config, pack).action, 'block', JSON.stringify(config));
    }
  }
  assert.deepEqual(inspectDevinSettings({ hooks: { PreToolUse: [] } }).signals, []);
});

test('malformed or unsupported Devin configs fail closed', () => {
  const invalid = [
    null, [], 'text',
    { permission_mode: 'bypass' },
    { permission_mode: true },
    { permissions: [] },
    { permissions: { allow: 'exec' } },
    { permissions: { allow: [5] } },
    { permissions: { allow: [''] } },
    { permissions: { allow: ['Exec()'] } },
    { permissions: { allow: ['exec(git)'] } },
    { permissions: { allow: ['EXEC'] } },
    { permissions: { allow: [' exec'] } },
    { permissions: { allow: ['Shell(git)'] } },
    { permissions: { allow: ['mcp__'] } },
    { permissions: { allow: ['mcp__server'] } },
    { permissions: { allow: ['mcp__ser*__tool'] } },
    { permissions: { deny: ['unknown-tool'] } },
    { permissions: { ask: [null] } },
    { hooks: [] },
    { hooks: { PreToolUse: { command: 'inert' } } },
    { mcpServers: [] },
    { local_tools_bypass_permissions: 'true' }
  ];
  for (const config of invalid) {
    assert.throws(() => inspectDevinSettings(config), /Devin/, JSON.stringify(config));
  }
});

test('Devin settings inspection retains no rule scope, name, hook body, or setting name', () => {
  const marker = 'MARKER-VALUE';
  const result = inspectDevinSettings({
    [marker]: marker,
    agent: { model: marker },
    sandbox: { allowed_domains: [marker] },
    permissions: {
      allow: [`Exec(${marker})`, `Read(${marker})`, `Write(${marker})`, `Fetch(${marker})`, `mcp__${marker}__${marker}`, `mcp__${marker}__*`],
      ask: [`Write(${marker})`], deny: [`Exec(${marker})`], [marker]: [marker]
    },
    hooks: { [marker]: [{ matcher: marker, hooks: [{ type: 'command', command: marker }] }] },
    mcpServers: { [marker]: { command: marker, env: { T: marker } } }
  }, 'config.json');
  assert.equal(JSON.stringify(result).includes(marker), false);
  assert.deepEqual(result.metadata, {
    permissionMode: null, allowRuleCount: 6, askRuleCount: 1, denyRuleCount: 1,
    autoApprovedExecCount: 1, autoApprovedWriteCount: 1, autoApprovedReadCount: 1,
    autoApprovedFetchCount: 1, autoApprovedMcpCount: 2, hookCount: 1, mcpServerCount: 1,
    localToolsBypassPermissions: false, externalConfigProviderCount: 0, uninspectedSettingCount: 2
  });
});

test('read_config_from that enables a provider is ASK under every policy, unlike a missing or all-false one', () => {
  const permissive = { version: 1, unknownAction: 'allow', localAction: 'allow', sensitiveAction: 'allow',
    unpinnedAction: 'allow', shellAction: 'allow', verifiedPublisherAction: 'allow' };
  const marker = 'MARKER-VALUE';
  for (const config of [{ read_config_from: { claude: true } }, { read_config_from: { cursor: false, [marker]: true, windsurf: true } }]) {
    const result = inspectDevinSettings(config);
    assert.deepEqual(result.signals, ['devin-external-config']);
    assert.equal(JSON.stringify(result).includes(marker), false);
    for (const pack of ['strict', 'official-first', 'development']) assert.equal(evaluate(config, pack).action, 'ask', pack);
    const custom = { ...permissive, signalActions: { 'devin-external-config': 'allow' } };
    for (const policy of [permissive, custom]) assert.equal(evaluateAll([inspectDevinSettings(config)], policy)[0].action, 'ask');
  }
  assert.equal(inspectDevinSettings({ read_config_from: { a: true, b: false, c: true } }).metadata.externalConfigProviderCount, 2);
  for (const config of [{}, { read_config_from: {} }, { read_config_from: { claude: false, cloud: false } }]) {
    const result = inspectDevinSettings(config);
    assert.deepEqual(result.signals, [], JSON.stringify(config));
    assert.equal(result.metadata.externalConfigProviderCount, 0);
  }
  for (const value of [true, 'claude', ['claude'], null, { claude: 'true' }, { claude: 1 }, { claude: { path: marker } }]) {
    assert.throws(() => inspectDevinSettings({ read_config_from: value }), /Devin read_config_from/, JSON.stringify(value));
  }
});

test('Devin settings CLI inspects the inert example and refuses invalid input without echoing it', () => {
  const run = (...args) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  const example = fileURLToPath(new URL('../examples/devin.config.json', import.meta.url));
  const inspected = run('inspect-devin-settings', example, '--pack', 'strict', '--json');
  assert.equal(inspected.status, 2);
  const result = JSON.parse(inspected.stdout)[0];
  assert.equal(result.kind, 'devin-settings');
  assert.deepEqual(result.signals, ['devin-auto-approved-exec', 'devin-auto-approved-tools', 'devin-permission-mode-auto']);
  assert.equal(inspected.stdout.includes('npm run lint'), false);
  assert.equal(inspected.stdout.includes('reviewed'), false);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'trustdex-devin-settings-'));
  try {
    const commented = path.join(dir, 'config.json');
    fs.writeFileSync(commented, '{\n  // MARKER-VALUE\n  "permissions": {}\n}\n');
    const refused = run('inspect-devin-settings', commented, '--json');
    assert.equal(refused.status, 2);
    assert.equal((refused.stdout + refused.stderr).includes('MARKER-VALUE'), false);

    const quiet = path.join(dir, 'quiet.json');
    fs.writeFileSync(quiet, '{"permissions": {"deny": ["exec"]}}');
    assert.equal(run('inspect-devin-settings', quiet, '--pack', 'development').status, 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  assert.equal(run('inspect-devin-settings').status, 2);
});
