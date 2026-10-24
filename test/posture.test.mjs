import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { inspectClaudeSettings } from '../src/claude-settings.mjs';
import { inspectCodexSettingsText } from '../src/codex-settings.mjs';
import { evaluateAll } from '../src/policy.mjs';
import { getPolicyPack } from '../src/policy-packs.mjs';
import {
  createPermissionPostureSnapshot,
  diffPermissionPostureSnapshots
} from '../src/posture.mjs';

const cli = fileURLToPath(new URL('../bin/trustdex.mjs', import.meta.url));

function evaluateClaude(settings, policy = getPolicyPack('strict'), sourceName = 'settings.json') {
  return {
    policy,
    result: evaluateAll([inspectClaudeSettings(settings, sourceName)], policy)[0]
  };
}

function evaluateCodex(text, policy = getPolicyPack('strict'), sourceName = 'config.toml') {
  return {
    policy,
    result: evaluateAll([inspectCodexSettingsText(text, sourceName)], policy)[0]
  };
}

function snapshot(evaluated) {
  return createPermissionPostureSnapshot(evaluated.result, evaluated.policy);
}

function run(...args) {
  const result = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  if (result.error) throw result.error;
  return result;
}

test('Claude posture snapshots retain structural evidence without values or source paths', () => {
  const secret = 'INERT_POSTURE_SECRET';
  const evaluated = evaluateClaude({
    permissions: {
      allow: [`Bash(tool --token ${secret})`],
      additionalDirectories: [`../${secret}`]
    },
    env: { API_TOKEN: secret },
    futureSetting: secret
  }, getPolicyPack('strict'), `/private/${secret}/settings.json`);

  const posture = snapshot(evaluated);
  const serialized = JSON.stringify(posture);
  assert.equal(serialized.includes(secret), false);
  assert.equal(serialized.includes('/private/'), false);
  assert.equal(serialized.includes('API_TOKEN'), false);
  assert.equal(posture.kind, 'agent-permission-posture');
  assert.equal(posture.runtime, 'claude');
  assert.equal(posture.posture.metadata.additionalDirectoryCount, 1);
  assert.equal(posture.posture.metadata.uninspectedRootKeyCount, 1);
  assert.match(posture.digest, /^[a-f0-9]{64}$/);
});

test('Claude permission expansion requires review and restriction does not', () => {
  const restrictive = snapshot(evaluateClaude({
    permissions: {
      ask: ['Bash(git status)'],
      deny: ['WebFetch'],
      defaultMode: 'plan',
      disableBypassPermissionsMode: 'disable',
      disableAutoMode: 'disable',
      blockReadsOutsideWorkingDirectories: true
    }
  }));
  const expanded = snapshot(evaluateClaude({
    permissions: {
      allow: ['Bash(tool *)', 'Agent(Explore)'],
      defaultMode: 'auto',
      additionalDirectories: ['../shared']
    }
  }));

  const expansion = diffPermissionPostureSnapshots(restrictive, expanded);
  assert.equal(expansion.status, 'needs-review');
  assert.ok(expansion.summary.expansions > 0);
  assert.ok(expansion.changes.some((change) =>
    change.impact === 'expansion' && change.field === 'signals'
  ));

  const restriction = diffPermissionPostureSnapshots(expanded, restrictive);
  assert.equal(restriction.status, 'restricted');
  assert.equal(restriction.summary.expansions, 0);
  assert.equal(restriction.summary.reviews, 0);
  assert.ok(restriction.summary.restrictions > 0);
});

test('Codex network, write, search, and subagent expansion requires review', () => {
  const restrictive = snapshot(evaluateCodex(`
approval_policy = "on-request"
approvals_reviewer = "user"
sandbox_mode = "read-only"
web_search = "disabled"

[sandbox_workspace_write]
network_access = false
writable_roots = []
exclude_slash_tmp = true
exclude_tmpdir_env_var = true

[agents]
enabled = false
`));
  const expanded = snapshot(evaluateCodex(`
approval_policy = "never"
approvals_reviewer = "auto_review"
sandbox_mode = "workspace-write"
web_search = "live"

[sandbox_workspace_write]
network_access = true
writable_roots = ["../shared"]
exclude_slash_tmp = false
exclude_tmpdir_env_var = false

[agents]
enabled = true
`));

  const diff = diffPermissionPostureSnapshots(restrictive, expanded);
  assert.equal(diff.status, 'needs-review');
  for (const field of [
    'approvalPolicy',
    'approvalsReviewer',
    'sandboxMode',
    'webSearch',
    'networkAccess',
    'additionalWritableRootCount',
    'tempRootsExcluded',
    'subagentsEnabled'
  ]) assert.ok(diff.changes.some((change) => change.field === field && change.impact === 'expansion'));
});

test('policy changes and tampered posture snapshots fail closed', () => {
  const settings = { permissions: { defaultMode: 'plan' } };
  const strictEvaluation = evaluateClaude(settings, getPolicyPack('strict'));
  const strict = snapshot(strictEvaluation);
  const development = snapshot(evaluateClaude(settings, getPolicyPack('development')));
  const changedPolicy = diffPermissionPostureSnapshots(strict, development);
  assert.equal(changedPolicy.status, 'needs-review');
  assert.ok(changedPolicy.changes.some((change) => change.type === 'policy-changed'));

  const tampered = structuredClone(strict);
  tampered.posture.metadata.allowRuleCount = 99;
  assert.throws(
    () => diffPermissionPostureSnapshots(strict, tampered),
    /digest mismatch/
  );

  const unsupportedSignal = structuredClone(strictEvaluation.result);
  unsupportedSignal.signals.push('INERT_UNSUPPORTED_SIGNAL_SECRET');
  assert.throws(
    () => createPermissionPostureSnapshot(unsupportedSignal, strictEvaluation.policy),
    /unsupported signal/
  );

  const unsupportedMetadata = structuredClone(strictEvaluation.result);
  unsupportedMetadata.metadata.futureValue = 'INERT_UNSUPPORTED_METADATA_SECRET';
  assert.throws(
    () => createPermissionPostureSnapshot(unsupportedMetadata, strictEvaluation.policy),
    /Unsupported permission posture metadata/
  );
});

test('CLI writes sanitized Claude and Codex posture snapshots and detects expansion', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'trustdex-posture-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const secret = 'INERT_CLI_POSTURE_SECRET';
  const claudeBefore = path.join(directory, 'claude-before.json');
  const claudeAfter = path.join(directory, 'claude-after.json');
  const codex = path.join(directory, 'codex.toml');
  const beforeSnapshot = path.join(directory, 'claude-before.posture.json');
  const afterSnapshot = path.join(directory, 'claude-after.posture.json');
  const codexSnapshot = path.join(directory, 'codex.posture.json');

  fs.writeFileSync(claudeBefore, JSON.stringify({
    permissions: {
      defaultMode: 'plan',
      disableBypassPermissionsMode: 'disable',
      disableAutoMode: 'disable',
      blockReadsOutsideWorkingDirectories: true
    }
  }));
  fs.writeFileSync(claudeAfter, JSON.stringify({
    permissions: {
      allow: [`Bash(tool --token ${secret})`],
      additionalDirectories: [`../${secret}`]
    }
  }));
  fs.writeFileSync(codex, `
approval_policy = "on-request"
sandbox_mode = "workspace-write"
[sandbox_workspace_write]
writable_roots = ["../${secret}"]
`);

  assert.equal(run('snapshot-claude-settings', claudeBefore, '--out', beforeSnapshot).status, 0);
  assert.equal(run('snapshot-claude-settings', claudeAfter, '--out', afterSnapshot).status, 0);
  assert.equal(run('snapshot-codex-settings', codex, '--out', codexSnapshot).status, 0);

  for (const file of [beforeSnapshot, afterSnapshot, codexSnapshot]) {
    const contents = fs.readFileSync(file, 'utf8');
    assert.equal(contents.includes(secret), false);
    assert.equal(contents.includes(directory), false);
  }

  const diff = run('diff-permissions', beforeSnapshot, afterSnapshot, '--json');
  assert.equal(diff.status, 1);
  const report = JSON.parse(diff.stdout);
  assert.equal(report.status, 'needs-review');
  assert.ok(report.summary.expansions > 0);
  assert.equal(diff.stdout.includes(secret), false);
});

test('published adversarial permission fixtures enforce review without leaking markers', () => {
  const fixtures = fileURLToPath(new URL('../examples/adversarial/permissions/', import.meta.url));
  const expected = JSON.parse(fs.readFileSync(path.join(fixtures, 'expected.json'), 'utf8'));
  const claudeBefore = snapshot(evaluateClaude(JSON.parse(
    fs.readFileSync(path.join(fixtures, 'claude-restrictive.settings.json'), 'utf8')
  )));
  const claudeAfter = snapshot(evaluateClaude(JSON.parse(
    fs.readFileSync(path.join(fixtures, 'claude-expanded.settings.json'), 'utf8')
  )));
  const codexBefore = snapshot(evaluateCodex(
    fs.readFileSync(path.join(fixtures, 'codex-restrictive.toml'), 'utf8')
  ));
  const codexAfter = snapshot(evaluateCodex(
    fs.readFileSync(path.join(fixtures, 'codex-expanded.toml'), 'utf8')
  ));

  assert.equal(claudeBefore.posture.action, expected.claude.restrictiveAction);
  assert.equal(claudeAfter.posture.action, expected.claude.expandedAction);
  assert.equal(
    diffPermissionPostureSnapshots(claudeBefore, claudeAfter).status,
    expected.claude.diffStatus
  );
  assert.equal(codexBefore.posture.action, expected.codex.restrictiveAction);
  assert.equal(codexAfter.posture.action, expected.codex.expandedAction);
  assert.equal(
    diffPermissionPostureSnapshots(codexBefore, codexAfter).status,
    expected.codex.diffStatus
  );

  const output = JSON.stringify({ claudeBefore, claudeAfter, codexBefore, codexAfter });
  for (const marker of expected.forbiddenOutputMarkers) {
    assert.equal(output.includes(marker), false);
  }
});

test('versioned JSON schemas cover emitted posture and diff fields', () => {
  const postureSchema = JSON.parse(fs.readFileSync(
    fileURLToPath(new URL('../schemas/permission-posture-v1.schema.json', import.meta.url)),
    'utf8'
  ));
  const diffSchema = JSON.parse(fs.readFileSync(
    fileURLToPath(new URL('../schemas/permission-posture-diff-v1.schema.json', import.meta.url)),
    'utf8'
  ));
  const before = snapshot(evaluateClaude({ permissions: { defaultMode: 'plan' } }));
  const after = snapshot(evaluateClaude({ permissions: { defaultMode: 'auto' } }));
  const diff = diffPermissionPostureSnapshots(before, after);

  assert.equal(postureSchema.$schema, 'https://json-schema.org/draft/2020-12/schema');
  assert.equal(diffSchema.$schema, 'https://json-schema.org/draft/2020-12/schema');
  for (const key of postureSchema.required) assert.ok(Object.hasOwn(before, key));
  for (const key of postureSchema.properties.posture.required) {
    assert.ok(Object.hasOwn(before.posture, key));
  }
  for (const key of postureSchema.$defs.claudeMetadata.required) {
    assert.ok(Object.hasOwn(before.posture.metadata, key));
  }
  for (const key of diffSchema.required) assert.ok(Object.hasOwn(diff, key));
  for (const key of diffSchema.properties.summary.required) {
    assert.ok(Object.hasOwn(diff.summary, key));
  }
  assert.equal(before.schemaVersion, 1);
  assert.equal(diff.schemaVersion, 1);
});
