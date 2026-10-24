import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { inspectClaudeSettingsStack } from '../src/claude-settings.mjs';
import { inspectCodexSettingsStack } from '../src/codex-settings.mjs';
import { evaluateAll } from '../src/policy.mjs';
import { getPolicyPack } from '../src/policy-packs.mjs';
import {
  createPermissionPostureSnapshot,
  diffPermissionPostureSnapshots
} from '../src/posture.mjs';

const cli = fileURLToPath(new URL('../bin/trustdex.mjs', import.meta.url));

function evaluate(result) {
  return evaluateAll([result], getPolicyPack('strict'))[0];
}

function snapshot(result) {
  return createPermissionPostureSnapshot(evaluate(result), getPolicyPack('strict'));
}

function run(...args) {
  const result = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  if (result.error) throw result.error;
  return result;
}

test('Claude stack merges permission lists and applies documented scalar precedence', () => {
  const result = inspectClaudeSettingsStack([
    {
      scope: 'managed',
      settings: { permissions: { defaultMode: 'plan', deny: ['WebFetch(domain:*)'] } }
    },
    {
      scope: 'user',
      settings: { permissions: { defaultMode: 'default', allow: ['Bash(git status)'] } }
    },
    {
      scope: 'project',
      settings: { permissions: { allow: ['WebFetch(domain:example.invalid)'] } }
    }
  ]);

  assert.equal(result.metadata.defaultMode, 'plan');
  assert.equal(result.metadata.allowRuleCount, 2);
  assert.equal(result.metadata.denyRuleCount, 1);
  assert.deepEqual(result.metadata.allowCategories, ['network', 'shell']);
  assert.deepEqual(result.source.scopes, {
    user: 1,
    project: 1,
    local: 0,
    session: 0,
    managed: 1
  });
  assert.equal(evaluate(result).action, 'block');
});

test('Claude project and local sources cannot activate auto or bypass default modes', () => {
  const result = inspectClaudeSettingsStack([
    { scope: 'user', settings: { permissions: { defaultMode: 'plan' } } },
    { scope: 'project', settings: { permissions: { defaultMode: 'bypassPermissions' } } },
    { scope: 'local', settings: { permissions: { defaultMode: 'auto' } } }
  ]);

  assert.equal(result.metadata.defaultMode, 'plan');
  assert.equal(result.signals.includes('claude-bypass-permissions'), false);
  assert.equal(result.signals.includes('claude-auto-mode'), false);
});

test('Codex stack applies system-to-CLI precedence and closest project wins', () => {
  const result = inspectCodexSettingsStack([
    { scope: 'cli', text: 'approval_policy = "never"' },
    { scope: 'system', text: 'approval_policy = "on-request"\nsandbox_mode = "read-only"' },
    { scope: 'user', text: 'sandbox_mode = "workspace-write"' },
    { scope: 'project', text: 'web_search = "cached"' },
    { scope: 'project', text: 'web_search = "live"' },
    { scope: 'managed', text: '[sandbox_workspace_write]\nnetwork_access = false' }
  ]);

  assert.equal(result.metadata.approvalPolicy, 'never');
  assert.equal(result.metadata.sandboxMode, 'workspace-write');
  assert.equal(result.metadata.webSearch, 'live');
  assert.equal(result.metadata.networkAccess, false);
  assert.deepEqual(result.source.scopes, {
    system: 1,
    managed: 1,
    user: 1,
    profile: 0,
    project: 2,
    cli: 1
  });
  assert.equal(evaluate(result).action, 'ask');
});

test('settings stacks fail closed on invalid lower-precedence security settings', () => {
  assert.throws(() => inspectClaudeSettingsStack([
    { scope: 'user', settings: { permissions: { futureControl: true } } },
    { scope: 'managed', settings: { permissions: { defaultMode: 'plan' } } }
  ]), /Unsupported Claude permission setting/);
  assert.throws(() => inspectClaudeSettingsStack([
    { scope: 'user', settings: { env: [] } },
    { scope: 'managed', settings: { env: {} } }
  ]), /Claude settings env must be a JSON object/);

  assert.throws(() => inspectCodexSettingsStack([
    { scope: 'system', text: 'sandbox_mode = "future-mode"' },
    { scope: 'cli', text: 'sandbox_mode = "read-only"' }
  ]), /Unsupported Codex sandbox_mode/);
});

test('stack snapshots use schema v2 without retaining paths, rules, or environment names', () => {
  const secret = 'INERT_STACK_SECRET';
  const posture = snapshot(inspectClaudeSettingsStack([
    {
      scope: 'user',
      settings: {
        permissions: { allow: [`Bash(tool --token ${secret})`] },
        env: { API_TOKEN: secret }
      }
    },
    { scope: 'managed', settings: { permissions: { defaultMode: 'plan' } } }
  ]));

  assert.equal(posture.schemaVersion, 2);
  assert.equal(posture.sources.sourceCount, 2);
  assert.equal(posture.sources.activeSourceCount, 2);
  assert.equal(posture.sources.sourceCounts.user, 1);
  assert.equal(JSON.stringify(posture).includes(secret), false);
  assert.equal(JSON.stringify(posture).includes('API_TOKEN'), false);
});

test('source topology changes require review even when effective permissions match', () => {
  const before = snapshot(inspectCodexSettingsStack([
    { scope: 'user', text: 'sandbox_mode = "read-only"' }
  ]));
  const after = snapshot(inspectCodexSettingsStack([
    { scope: 'system', text: '' },
    { scope: 'user', text: 'sandbox_mode = "read-only"' }
  ]));
  const diff = diffPermissionPostureSnapshots(before, after);

  assert.equal(diff.schemaVersion, 2);
  assert.equal(diff.status, 'needs-review');
  assert.ok(diff.changes.some((change) => change.field === 'sources.system'));
});

test('versioned v2 schemas cover merged posture and source topology diffs', () => {
  const postureSchema = JSON.parse(fs.readFileSync(
    fileURLToPath(new URL('../schemas/permission-posture-v2.schema.json', import.meta.url)),
    'utf8'
  ));
  const diffSchema = JSON.parse(fs.readFileSync(
    fileURLToPath(new URL('../schemas/permission-posture-diff-v2.schema.json', import.meta.url)),
    'utf8'
  ));
  const before = snapshot(inspectClaudeSettingsStack([
    { scope: 'user', settings: { permissions: { defaultMode: 'plan' } } }
  ]));
  const after = snapshot(inspectClaudeSettingsStack([
    { scope: 'user', settings: { permissions: { defaultMode: 'default' } } }
  ]));
  const diff = diffPermissionPostureSnapshots(before, after);

  assert.equal(postureSchema.properties.schemaVersion.const, 2);
  assert.ok(postureSchema.required.includes('sources'));
  assert.deepEqual(
    postureSchema.$defs.claudeSources.properties.sourceCounts.required,
    ['user', 'project', 'local', 'session', 'managed']
  );
  assert.equal(diffSchema.properties.schemaVersion.const, 2);
  for (const key of postureSchema.required) assert.ok(Object.hasOwn(before, key));
  for (const key of diffSchema.required) assert.ok(Object.hasOwn(diff, key));
});

test('stack CLI writes sanitized Claude and Codex posture snapshots', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'trustdex-stack-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const secret = 'INERT_STACK_CLI_SECRET';
  const user = path.join(directory, 'user.json');
  const project = path.join(directory, 'project.json');
  const system = path.join(directory, 'system.toml');
  const codexProject = path.join(directory, 'project.toml');
  const claudeOut = path.join(directory, 'claude.posture.json');
  const codexOut = path.join(directory, 'codex.posture.json');

  fs.writeFileSync(user, JSON.stringify({ permissions: { defaultMode: 'plan' } }));
  fs.writeFileSync(project, JSON.stringify({ permissions: { allow: [`Bash(tool ${secret})`] } }));
  fs.writeFileSync(system, 'sandbox_mode = "read-only"\nweb_search = "disabled"');
  fs.writeFileSync(codexProject, `sandbox_mode = "workspace-write"\n[sandbox_workspace_write]\nwritable_roots = ["../${secret}"]`);

  assert.equal(run(
    'snapshot-claude-settings-stack', '--user', user, '--project', project, '--out', claudeOut
  ).status, 0);
  assert.equal(run(
    'snapshot-codex-settings-stack', '--system', system, '--project', codexProject, '--out', codexOut
  ).status, 0);

  for (const file of [claudeOut, codexOut]) {
    const contents = fs.readFileSync(file, 'utf8');
    assert.equal(contents.includes(secret), false);
    assert.equal(contents.includes(directory), false);
    assert.equal(JSON.parse(contents).schemaVersion, 2);
  }
});

