import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { inspectGeminiSettings } from '../src/gemini-settings.mjs';
import { evaluateAll } from '../src/policy.mjs';
import { getPolicyPack } from '../src/policy-packs.mjs';

const cli = fileURLToPath(new URL('../bin/trustdex.mjs', import.meta.url));

function evaluate(settings, pack = 'strict') {
  return evaluateAll([inspectGeminiSettings(settings)], getPolicyPack(pack))[0];
}

test('empty and restriction-only Gemini settings never reach ALLOW in a built-in pack', () => {
  for (const pack of ['strict', 'official-first', 'development']) {
    for (const settings of [{}, { security: { disableYoloMode: true, disableAlwaysAllow: true }, tools: { exclude: ['run_shell_command'] } }]) {
      const result = evaluate(settings, pack);
      assert.notEqual(result.action, 'allow', pack);
      assert.deepEqual(result.signals, []);
    }
  }
});

test('automatic grants and command-running settings are classified by capability', () => {
  const cases = [
    [{ general: { defaultApprovalMode: 'auto_edit' } }, 'gemini-auto-edit', 'ask'],
    [{ tools: { allowed: ['read_file'] } }, 'gemini-auto-approved-tools', 'ask'],
    [{ tools: { allowed: ['run_shell_command(git status)'] } }, 'gemini-auto-approved-shell', 'block'],
    [{ tools: { allowed: [' run_shell_command'] } }, 'gemini-auto-approved-shell', 'block'],
    [{ tools: { allowed: ['ShellTool(npm test)'] } }, 'gemini-auto-approved-shell', 'block'],
    [{ tools: { allowed: ['*'] } }, 'gemini-auto-approved-shell', 'block'],
    [{ tools: { discoveryCommand: 'inert-discover' } }, 'gemini-tool-commands', 'block'],
    [{ tools: { callCommand: 'inert-call' } }, 'gemini-tool-commands', 'block'],
    [{ mcp: { serverCommand: 'inert-server' } }, 'gemini-tool-commands', 'block'],
    [{ hooks: { BeforeTool: [{ hooks: [{ type: 'command', command: 'inert-hook' }] }] } }, 'gemini-hooks', 'block'],
    [{ hooksConfig: { enabled: false }, hooks: { SessionStart: [{}] } }, 'gemini-hooks', 'block'],
    [{ tools: { sandboxAllowedPaths: ['../shared'] } }, 'gemini-sandbox-relaxed', 'ask'],
    [{ tools: { sandboxNetworkAccess: true } }, 'gemini-sandbox-relaxed', 'ask'],
    [{ security: { enablePermanentToolApproval: true } }, 'gemini-persistent-approvals', 'ask'],
    [{ security: { autoAddToPolicyByDefault: true } }, 'gemini-persistent-approvals', 'ask'],
    [{ security: { folderTrust: { enabled: false } } }, 'gemini-folder-trust-disabled', 'ask'],
    [{ security: { environmentVariableRedaction: { enabled: true, allowed: ['INERT_NAME'] } } }, 'gemini-env-redaction-bypass', 'ask'],
    [{ policyPaths: ['./policies'] }, 'gemini-policy-paths', 'ask'],
    [{ adminPolicyPaths: ['./admin'] }, 'gemini-policy-paths', 'ask'],
    [{ mcpServers: { a: { command: 'node' } } }, 'gemini-mcp-servers', 'ask'],
    [{ admin: { mcp: { requiredConfig: { a: {} } } } }, 'gemini-mcp-servers', 'ask'],
    [{ ui: { theme: 'x' } }, 'uninspected-gemini-settings', 'ask'],
    [{ tools: { futureSwitch: true } }, 'uninspected-gemini-settings', 'ask'],
    [{ security: { folderTrust: { futureSwitch: true } } }, 'uninspected-gemini-settings', 'ask'],
    [{ admin: { extensions: { futureSwitch: true } } }, 'uninspected-gemini-settings', 'ask']
  ];
  for (const [settings, signal, action] of cases) {
    const result = evaluate(settings);
    assert.ok(result.signals.includes(signal), `${JSON.stringify(settings)} -> ${signal}`);
    assert.equal(result.action, action, JSON.stringify(settings));
    assert.notEqual(evaluate(settings, 'development').action, 'allow', JSON.stringify(settings));
  }
});

test('a policy overlay cannot be needed to see a shell grant: every pack blocks it', () => {
  for (const pack of ['strict', 'official-first', 'development']) {
    assert.equal(evaluate({ tools: { allowed: ['run_shell_command'] } }, pack).action, 'block', pack);
  }
});

test('malformed Gemini settings fail closed', () => {
  for (const settings of [
    null, [], 'text',
    { general: 'auto_edit' },
    { general: { defaultApprovalMode: 'yolo' } },
    { general: { defaultApprovalMode: ['auto_edit'] } },
    { tools: [] },
    { tools: { allowed: 'run_shell_command' } },
    { tools: { allowed: [5] } },
    { tools: { allowed: [''] } },
    { tools: { sandbox: 5 } },
    { tools: { sandboxNetworkAccess: 'true' } },
    { tools: { discoveryCommand: ['x'] } },
    { tools: { callCommand: '' } },
    { mcp: { serverCommand: 5 } },
    { mcp: { allowed: 'a' } },
    { security: { folderTrust: false } },
    { security: { folderTrust: { enabled: 'false' } } },
    { security: { enablePermanentToolApproval: 1 } },
    { security: { disableYoloMode: 'true' } },
    { security: { environmentVariableRedaction: { allowed: 'A' } } },
    { hooks: [] },
    { hooks: { BeforeTool: {} } },
    { hooksConfig: { enabled: 'no' } },
    { policyPaths: './policies' },
    { mcpServers: [] },
    { admin: { mcp: { config: [] } } },
    { admin: { secureModeEnabled: 'yes' } }
  ]) assert.throws(() => inspectGeminiSettings(settings), /Gemini/, JSON.stringify(settings));
});

test('the report holds counts and enums, never tool names, commands, paths, or setting names', () => {
  const marker = 'MARKER-VALUE';
  const result = inspectGeminiSettings({
    [marker]: marker,
    general: { defaultApprovalMode: 'plan', [marker]: marker },
    tools: {
      allowed: [`run_shell_command(${marker})`, marker], core: [marker], exclude: [marker],
      confirmationRequired: [marker], sandbox: marker, sandboxAllowedPaths: [marker],
      discoveryCommand: marker, callCommand: marker
    },
    mcp: { serverCommand: marker, allowed: [marker], excluded: [marker] },
    security: {
      allowedExtensions: [marker],
      environmentVariableRedaction: { allowed: [marker], blocked: [marker] }
    },
    hooksConfig: { disabled: [marker] },
    hooks: { [marker]: [{ command: marker }] },
    policyPaths: [marker],
    mcpServers: { [marker]: { command: marker } }
  }, 'settings.json');
  assert.equal(JSON.stringify(result).includes(marker), false);
  assert.equal(result.metadata.autoApprovedToolCount, 2);
  assert.equal(result.metadata.autoApprovedShellCount, 1);
  assert.equal(result.metadata.commandSettingCount, 3);
  assert.equal(result.metadata.hookCount, 1);
  assert.equal(result.metadata.uninspectedSettingCount, 2);
  assert.equal(result.metadata.defaultApprovalMode, 'plan');
});

test('Gemini settings CLI inspects the inert example and refuses invalid JSON without echoing it', () => {
  const run = (...args) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  const example = fileURLToPath(new URL('../examples/gemini.settings.json', import.meta.url));
  const inspected = run('inspect-gemini-settings', example, '--pack', 'strict', '--json');
  assert.equal(inspected.status, 2);
  const result = JSON.parse(inspected.stdout)[0];
  assert.equal(result.kind, 'gemini-settings');
  assert.deepEqual(result.signals, [
    'gemini-auto-approved-shell', 'gemini-auto-approved-tools', 'gemini-auto-edit', 'gemini-sandbox-relaxed'
  ]);
  assert.equal(inspected.stdout.includes('reviewed-shared'), false);
  assert.equal(inspected.stdout.includes('git status'), false);
  assert.equal(result.metadata.yoloModeDisabled, true);

  const missing = run('inspect-gemini-settings');
  assert.equal(missing.status, 2);
});
