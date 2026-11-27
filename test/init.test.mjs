import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { HOOK_MATCHER, applyInit, applyUninstall, describePlan, planInit } from '../src/init.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const cli = path.join(root, 'bin', 'trustdex.mjs');
const posixOnly = { skip: process.platform === 'win32' };

function home(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'trustdex-init-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

const plan = (dir, extra = {}) => planInit({ home: dir, sourceRoot: root, version: '9.9.9', nodePath: process.execPath, platform: 'linux', ...extra });
const settingsOf = (dir) => JSON.parse(fs.readFileSync(path.join(dir, '.claude', 'settings.json'), 'utf8'));
const trustdexHooks = (settings) => (settings.hooks?.PreToolUse || []).flatMap((group) => group.hooks)
  .filter((hook) => /trustdex\.mjs['"]?\s+claude-hook/.test(hook.command));

test('init installs a versioned copy, a wrapper, a policy and one fail-closed hook', posixOnly, (t) => {
  const dir = home(t);
  const p = plan(dir);
  const result = applyInit(p);
  assert.ok(fs.existsSync(path.join(dir, '.local/share/trustdex/9.9.9/bin/trustdex.mjs')));
  assert.ok(fs.existsSync(path.join(dir, '.local/share/trustdex/9.9.9/src/agent-guard.mjs')));
  assert.equal(fs.statSync(path.join(dir, '.local/bin/trustdex')).mode & 0o777, 0o755);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(dir, '.config/trustdex/install-policy.json'), 'utf8')), { version: 1 });
  assert.equal(result.policyCreated, true);
  assert.equal(result.backupPath, null);
  const [hook] = trustdexHooks(settingsOf(dir));
  assert.match(hook.command, /--on-risk ask/);
  assert.match(hook.command, /exit 2; }$/);
  assert.ok(hook.command.includes(path.join(dir, '.local/share/trustdex/9.9.9/bin/trustdex.mjs')));
  assert.equal(settingsOf(dir).hooks.PreToolUse.at(-1).matcher, HOOK_MATCHER);
  assert.match(describePlan(p), /backed up first/);
});

test('the installed hook actually runs and stops a credential read', posixOnly, (t) => {
  const dir = home(t);
  const p = plan(dir);
  applyInit(p);
  const command = trustdexHooks(settingsOf(dir))[0].command;
  const input = JSON.stringify({ tool_name: 'Bash', cwd: dir, tool_input: { command: 'cat ~/.ssh/id_rsa' } });
  const out = spawnSync('/bin/sh', ['-c', command], { input, encoding: 'utf8', env: { ...process.env, HOME: dir } });
  assert.equal(out.status, 0);
  assert.equal(JSON.parse(out.stdout).hookSpecificOutput.permissionDecision, 'deny');
});

test('init keeps other settings and hooks, backs up, and is idempotent', posixOnly, (t) => {
  const dir = home(t);
  fs.mkdirSync(path.join(dir, '.claude'));
  fs.writeFileSync(path.join(dir, '.claude/settings.json'), JSON.stringify({
    model: 'example',
    hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'echo mine' }] }], Stop: [{ hooks: [] }] }
  }));
  const first = applyInit(plan(dir));
  assert.ok(first.backupPath && fs.existsSync(first.backupPath));
  applyInit(plan(dir, { onRisk: 'deny' }));
  const settings = settingsOf(dir);
  assert.equal(settings.model, 'example');
  assert.ok(settings.hooks.Stop);
  assert.ok(settings.hooks.PreToolUse.some((group) => group.hooks.some((hook) => hook.command === 'echo mine')));
  const ours = trustdexHooks(settings);
  assert.equal(ours.length, 1, 'running init twice leaves one TrustDex hook');
  assert.match(ours[0].command, /--on-risk deny/);
});

test('init keeps an existing policy and refuses broken settings without changing anything', posixOnly, (t) => {
  const dir = home(t);
  fs.mkdirSync(path.join(dir, '.config/trustdex'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.config/trustdex/install-policy.json'), '{"version":1,"minReleaseAgeHours":72}');
  assert.equal(applyInit(plan(dir)).policyCreated, false);
  assert.match(fs.readFileSync(path.join(dir, '.config/trustdex/install-policy.json'), 'utf8'), /72/);

  const broken = home(t);
  fs.mkdirSync(path.join(broken, '.claude'));
  fs.writeFileSync(path.join(broken, '.claude/settings.json'), '{ not json');
  assert.throws(() => applyInit(plan(broken)), /not valid JSON/);
  assert.equal(fs.readFileSync(path.join(broken, '.claude/settings.json'), 'utf8'), '{ not json');
  assert.equal(fs.existsSync(path.join(broken, '.local')), false, 'nothing else was written either');
});

test('uninstall removes only the TrustDex hook', posixOnly, (t) => {
  const dir = home(t);
  fs.mkdirSync(path.join(dir, '.claude'));
  fs.writeFileSync(path.join(dir, '.claude/settings.json'), JSON.stringify({ hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'echo mine' }] }] } }));
  applyInit(plan(dir));
  const result = applyUninstall({ settingsPath: path.join(dir, '.claude/settings.json') });
  assert.equal(result.removed, 1);
  const settings = settingsOf(dir);
  assert.equal(trustdexHooks(settings).length, 0);
  assert.equal(settings.hooks.PreToolUse[0].hooks[0].command, 'echo mine');
  assert.equal(applyUninstall({ settingsPath: path.join(dir, '.claude/settings.json') }).removed, 0);
});

test('on Windows init needs Git Bash and plans Windows paths, both wrappers and a Git Bash hook', () => {
  assert.throws(() => plan('C:\\Users\\tester', { platform: 'win32' }), /Git Bash/);
  const p = plan('C:\\Users\\tester', { platform: 'win32', nodePath: 'C:\\Program Files\\nodejs\\node.exe', gitBash: 'C:\\Program Files\\Git\\bin\\bash.exe' });
  assert.equal(p.installDir, 'C:\\Users\\tester\\.local\\share\\trustdex\\9.9.9');
  assert.equal(p.wrapper, 'C:\\Users\\tester\\.local\\bin\\trustdex');
  assert.equal(p.wrapperCmd, 'C:\\Users\\tester\\.local\\bin\\trustdex.cmd');
  assert.equal(p.settingsPath, 'C:\\Users\\tester\\.claude\\settings.json');
  assert.equal(p.hookShell, 'bash');
  assert.ok(p.hookCommand.startsWith("'C:/Program Files/nodejs/node.exe' 'C:/Users/tester/.local/share/trustdex/9.9.9/bin/trustdex.mjs' claude-hook"));
  assert.match(p.hookCommand, /--protect 'C:\/Users\/tester\/\.local\/bin\/trustdex' --protect 'C:\/Users\/tester\/\.local\/bin\/trustdex\.cmd'/);
  assert.match(p.hookCommand, /exit 2; }$/);
  assert.doesNotMatch(p.hookCommand, /\\/);
  assert.match(describePlan(p), /Git Bash/);
  assert.match(HOOK_MATCHER, /(^|\|)PowerShell(\||$)/);
});

test('on Windows the installed hook runs through Git Bash and stops a credential read', { skip: process.platform !== 'win32' }, (t) => {
  const bash = ['C:\\Program Files\\Git\\bin\\bash.exe', 'C:\\Program Files (x86)\\Git\\bin\\bash.exe'].find((candidate) => fs.existsSync(candidate));
  if (!bash) return t.skip('Git Bash is not installed');
  const dir = home(t);
  const p = planInit({ home: dir, sourceRoot: root, version: '9.9.9', nodePath: process.execPath, platform: 'win32', gitBash: bash });
  applyInit(p);
  assert.ok(fs.existsSync(path.join(dir, '.local', 'bin', 'trustdex.cmd')));
  const [hook] = trustdexHooks(settingsOf(dir));
  assert.equal(hook.shell, 'bash');
  for (const input of [
    { tool_name: 'Read', cwd: dir, tool_input: { file_path: path.join(dir, '.ssh', 'id_rsa') } },
    { tool_name: 'PowerShell', cwd: dir, tool_input: { command: `Get-Content ${path.join(dir, '.ssh', 'id_rsa')}` } }
  ]) {
    const out = spawnSync(bash, ['-c', hook.command], { input: JSON.stringify(input), encoding: 'utf8', env: { ...process.env, USERPROFILE: dir } });
    assert.equal(out.status, 0, out.stderr);
    assert.equal(JSON.parse(out.stdout).hookSpecificOutput.permissionDecision, 'deny', input.tool_name);
  }
  const wrapper = spawnSync('cmd.exe', ['/d', '/c', path.join(dir, '.local', 'bin', 'trustdex.cmd'), '--version'], { encoding: 'utf8' });
  assert.match(wrapper.stdout, /\d+\.\d+\.\d+/);
});

test('init refuses bad options and unattended runs without --yes', (t) => {
  assert.throws(() => plan('/tmp/x', { onRisk: 'allow' }), /onRisk/);
  if (process.platform === 'win32') return;
  const dir = home(t);
  const env = { ...process.env, HOME: dir };
  const dry = spawnSync(process.execPath, [cli, 'init', '--dry-run'], { encoding: 'utf8', env });
  assert.equal(dry.status, 0);
  assert.match(dry.stdout, /TrustDex will:/);
  assert.equal(fs.existsSync(path.join(dir, '.claude')), false, 'dry run writes nothing');
  const unattended = spawnSync(process.execPath, [cli, 'init'], { encoding: 'utf8', env, input: 'yes\n' });
  assert.notEqual(unattended.status, 0);
  assert.match(unattended.stderr, /run it yourself in a terminal, or pass --yes/);
  assert.equal(fs.existsSync(path.join(dir, '.claude')), false);
  const yes = spawnSync(process.execPath, [cli, 'init', '--yes'], { encoding: 'utf8', env });
  assert.equal(yes.status, 0, yes.stderr);
  assert.equal(trustdexHooks(settingsOf(dir)).length, 1);
});
