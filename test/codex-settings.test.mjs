import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { inspectCodexSettingsText } from '../src/codex-settings.mjs';
import { evaluateAll } from '../src/policy.mjs';
import { getPolicyPack } from '../src/policy-packs.mjs';

const cli = fileURLToPath(new URL('../bin/trustdex.mjs', import.meta.url));

function evaluate(text, pack = 'strict') {
  return evaluateAll([inspectCodexSettingsText(text)], getPolicyPack(pack))[0];
}

function run(...args) {
  const result = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  if (result.error) throw result.error;
  return result;
}

test('Codex settings inspection recognizes the restrictive local preset', () => {
  const result = evaluate(`
approval_policy = "on-request"
approvals_reviewer = "user"
sandbox_mode = "read-only"
web_search = "disabled"

[sandbox_workspace_write]
network_access = false
writable_roots = []
exclude_slash_tmp = true
exclude_tmpdir_env_var = true
`);

  assert.equal(result.action, 'ask');
  assert.deepEqual(result.signals, []);
  assert.equal(result.metadata.approvalPolicy, 'on-request');
  assert.equal(result.metadata.approvalsReviewer, 'user');
  assert.equal(result.metadata.sandboxMode, 'read-only');
  assert.equal(result.metadata.networkAccess, false);
  assert.equal(result.metadata.tempRootsExcluded, true);
});

test('Codex settings inspection blocks unrestricted sandbox access', () => {
  const result = evaluate(`
approval_policy = "never"
approvals_reviewer = "auto_review"
sandbox_mode = "danger-full-access"
web_search = "live"
`);

  assert.equal(result.action, 'block');
  assert.ok(result.signals.includes('codex-no-approvals'));
  assert.ok(result.signals.includes('codex-auto-review'));
  assert.ok(result.signals.includes('codex-full-access'));
  assert.ok(result.signals.includes('codex-live-web-search'));
});

test('Codex settings inspection reports bounded write and network expansion without values', () => {
  const secret = 'INERT_CODEX_PATH_SECRET';
  const result = evaluate(`
approval_policy = { granular = { sandbox_approval = true, rules = true, mcp_elicitations = false } }
sandbox_mode = "workspace-write"

[sandbox_workspace_write]
network_access = true
writable_roots = ["../${secret}"]
exclude_slash_tmp = false
exclude_tmpdir_env_var = false
`);

  assert.equal(result.action, 'ask');
  assert.ok(result.signals.includes('codex-workspace-write'));
  assert.ok(result.signals.includes('codex-network-access'));
  assert.ok(result.signals.includes('codex-additional-writable-roots'));
  assert.ok(result.signals.includes('codex-temp-write-access'));
  assert.deepEqual(result.metadata.granularPromptCategories, ['rules', 'sandbox_approval']);
  assert.equal(result.metadata.additionalWritableRootCount, 1);
  assert.equal(JSON.stringify(result).includes(secret), false);
  assert.equal('fingerprint' in result, false);
});

test('Codex settings inspection accepts granular approval tables', () => {
  const result = evaluate(`
sandbox_mode = "read-only"

[approval_policy.granular]
sandbox_approval = true
rules = false
request_permissions = true
`);
  assert.equal(result.metadata.approvalPolicy, 'granular');
  assert.deepEqual(result.metadata.granularPromptCategories, ['request_permissions', 'sandbox_approval']);
  assert.ok(!result.signals.includes('uninspected-codex-sections'));
});

test('Codex settings inspection surfaces custom permission and extension sections', () => {
  const secret = 'INERT_CODEX_SETTING_SECRET';
  const result = evaluate(`
model = "${secret}"
default_permissions = "reviewed-profile"

[permissions.reviewed-profile]
description = "${secret}"

[agents]
enabled = true

[plugins."${secret}"]
enabled = true
`);

  assert.equal(result.action, 'ask');
  assert.ok(result.signals.includes('codex-custom-permissions'));
  assert.ok(result.signals.includes('codex-subagents-enabled'));
  assert.ok(result.signals.includes('codex-extension-settings'));
  assert.ok(result.signals.includes('uninspected-codex-settings'));
  assert.ok(result.signals.includes('uninspected-codex-sections'));
  assert.deepEqual(result.metadata.uninspectedRootKeys, ['model']);
  assert.deepEqual(result.metadata.uninspectedSectionKinds, ['permissions', 'plugins']);
  assert.equal(JSON.stringify(result).includes(secret), false);
});

test('Codex settings parser fails closed on malformed security-relevant settings', () => {
  for (const text of [
    'approval_policy = "untrusted"',
    'approval_policy = { granular = { future_prompt = true } }',
    'approvals_reviewer = "nobody"',
    'sandbox_mode = "future-mode"',
    'web_search = "raw"',
    'default_permissions = []',
    'default_permissions = ":workspace"\nsandbox_mode = "workspace-write"',
    '[sandbox_workspace_write]\nnetwork_access = "true"',
    '[sandbox_workspace_write]\nwritable_roots = [1]',
    '[sandbox_workspace_write]\nfuture_key = true',
    '[sandbox_workspace_write.future]\nenabled = true',
    '[approval_policy.future]\nenabled = true',
    'approval_policy = "on-request"\n[approval_policy.granular]\nrules = true',
    '[agents]\nenabled = "true"',
    'sandbox_workspace_write.network_access = true\n[sandbox_workspace_write]\nnetwork_access = false'
  ]) assert.throws(() => inspectCodexSettingsText(text));
});

test('Codex settings CLI inspects the inert permissions example', () => {
  const example = fileURLToPath(new URL('../examples/codex.permissions.toml', import.meta.url));
  const inspected = run('inspect-codex-settings', example, '--pack', 'strict', '--json');
  assert.equal(inspected.status, 1);
  const result = JSON.parse(inspected.stdout)[0];
  assert.equal(result.kind, 'codex-settings');
  assert.ok(result.signals.includes('codex-workspace-write'));
  assert.ok(result.signals.includes('codex-additional-writable-roots'));
  assert.equal(JSON.stringify(result).includes('../reviewed-shared'), false);
});
