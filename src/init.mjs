// `trustdex init`: set up the Claude Code hook in one step.
//
// It copies the running TrustDex into a stable, versioned folder (so the hook
// never downloads code at run time), writes a small `trustdex` wrapper, creates
// an install policy only if none exists, and adds one PreToolUse hook to
// ~/.claude/settings.json. Existing settings and other hooks are kept, the
// settings file is backed up first, and running it again replaces only the
// TrustDex hook. `--uninstall` removes only the TrustDex hook.
//
// On Windows the files go under %USERPROFILE% and the hook runs through Git
// Bash, which Claude Code uses for hooks there; Git Bash is required so that a
// missing node or TrustDex copy still stops the action (exit 2). A `trustdex.cmd`
// wrapper is written next to the `trustdex` one for PowerShell and cmd.

import fs from 'node:fs';
import path from 'node:path';

export const HOOK_MATCHER = 'Bash|PowerShell|Read|Grep|Glob|Write|Edit|MultiEdit|NotebookEdit';
// Matches our hook with or without quoted paths.
const HOOK_MARKER = /trustdex\.mjs['"]?\s+claude-hook/;
const isTrustdexHook = (hook) => HOOK_MARKER.test(String(hook.command || ''));
const COPIED = ['bin', 'src', 'package.json', 'LICENSE'];

const quote = (value) => `'${String(value).replace(/'/g, `'\\''`)}'`;

export function planInit({ home, sourceRoot, version, nodePath, onRisk = 'ask', platform = process.platform, gitBash = null }) {
  if (!['ask', 'deny'].includes(onRisk)) throw new Error('onRisk must be "ask" or "deny".');
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(String(version))) throw new Error('Unexpected TrustDex version.');
  const windows = platform === 'win32';
  if (windows && !gitBash) {
    throw new Error('On Windows, Claude Code runs hooks with Git Bash, and the TrustDex hook needs it to stop an action when the check itself cannot run. Install Git for Windows (or set CLAUDE_CODE_GIT_BASH_PATH), then run init again. Nothing was changed.');
  }
  const p = windows ? path.win32 : path.posix;
  const installDir = p.join(home, '.local', 'share', 'trustdex', version);
  const wrapper = p.join(home, '.local', 'bin', 'trustdex');
  const wrapperCmd = windows ? `${wrapper}.cmd` : null;
  const policyPath = p.join(home, '.config', 'trustdex', 'install-policy.json');
  const settingsPath = p.join(home, '.claude', 'settings.json');
  const entry = p.join(installDir, 'bin', 'trustdex.mjs');
  // Git Bash accepts C:/x paths; backslashes would need escaping.
  const forShell = (value) => (windows ? String(value).replace(/\\/g, '/') : String(value));
  const hookCommand = [
    quote(forShell(nodePath)), quote(forShell(entry)), 'claude-hook',
    '--install-policy', quote(forShell(policyPath)),
    '--protect', quote(forShell(wrapper)),
    ...(wrapperCmd ? ['--protect', quote(forShell(wrapperCmd))] : []),
    '--on-risk', onRisk
  ].join(' ') + " || { echo 'TrustDex could not run, so this action was stopped.' >&2; exit 2; }";
  return {
    home, sourceRoot, version, nodePath, onRisk, platform, installDir, wrapper, wrapperCmd, policyPath, settingsPath, entry, hookCommand,
    gitBash: windows ? gitBash : null,
    hookShell: windows ? 'bash' : null
  };
}

export function describePlan(plan) {
  return [
    'TrustDex will:',
    `  1. copy TrustDex ${plan.version} to ${plan.installDir}`,
    plan.wrapperCmd
      ? `  2. write small "trustdex" commands to ${plan.wrapper} (Git Bash) and ${plan.wrapperCmd} (PowerShell, cmd)`
      : `  2. write a small "trustdex" command to ${plan.wrapper}`,
    `  3. create ${plan.policyPath} if it does not exist (an existing policy is kept)`,
    `  4. add one PreToolUse hook to ${plan.settingsPath} (backed up first; other settings and hooks are kept)`,
    ...(plan.gitBash ? [`The hook runs through Git Bash (${plan.gitBash}) and also checks the PowerShell tool.`] : []),
    `Risky actions are ${plan.onRisk === 'ask' ? 'shown as a Claude Code dialog when they are ASK level, and denied when they are BLOCK level' : 'denied; you allow one with trustdex allow-once in your own terminal'}.`,
    'If node or this copy goes missing later, the hook stops actions instead of letting them through.'
  ].join('\n');
}

function readSettings(settingsPath) {
  let text;
  try {
    text = fs.readFileSync(settingsPath, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') return { settings: {}, existed: false };
    throw error;
  }
  let settings;
  try {
    settings = JSON.parse(text);
  } catch {
    throw new Error(`${settingsPath} is not valid JSON; fix it first, nothing was changed.`);
  }
  if (!settings || typeof settings !== 'object' || Array.isArray(settings)) throw new Error(`${settingsPath} must hold a JSON object; nothing was changed.`);
  return { settings, existed: true };
}

function writeAtomic(file, text, mode) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temporary = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(temporary, text, { mode });
  fs.renameSync(temporary, file);
}

function backup(file, now) {
  const stamp = new Date(now).toISOString().replace(/[-:]/g, '').replace(/\..*/, '');
  const target = `${file}.bak-trustdex-${stamp}`;
  fs.copyFileSync(file, target);
  return target;
}

function withoutTrustdexHooks(groups) {
  return (Array.isArray(groups) ? groups : [])
    .map((group) => ({ ...group, hooks: (group.hooks || []).filter((hook) => !isTrustdexHook(hook)) }))
    .filter((group) => group.hooks.length > 0);
}

export function applyInit(plan, { now = Date.now() } = {}) {
  // Read and check the settings before touching anything else.
  const { settings, existed } = readSettings(plan.settingsPath);
  if (settings.hooks !== undefined && (typeof settings.hooks !== 'object' || Array.isArray(settings.hooks))) {
    throw new Error(`"hooks" in ${plan.settingsPath} is not an object; nothing was changed.`);
  }

  // 1. A versioned copy of the running TrustDex.
  if (!fs.existsSync(path.join(plan.installDir, 'bin', 'trustdex.mjs'))) {
    const staging = `${plan.installDir}.${process.pid}.tmp`;
    fs.rmSync(staging, { recursive: true, force: true });
    fs.mkdirSync(staging, { recursive: true });
    for (const item of COPIED) {
      const from = path.join(plan.sourceRoot, item);
      if (fs.existsSync(from)) fs.cpSync(from, path.join(staging, item), { recursive: true });
    }
    fs.mkdirSync(path.dirname(plan.installDir), { recursive: true });
    fs.renameSync(staging, plan.installDir);
  }

  // 2. The wrapper (and on Windows a .cmd one; % is doubled so cmd keeps it literal).
  const shellPath = (value) => (plan.wrapperCmd ? String(value).replace(/\\/g, '/') : value);
  writeAtomic(plan.wrapper, `#!/bin/sh\nexec ${quote(shellPath(plan.nodePath))} ${quote(shellPath(plan.entry))} "$@"\n`, 0o755);
  if (plan.wrapperCmd) {
    const cmdPath = (value) => `"${String(value).replace(/%/g, '%%')}"`;
    writeAtomic(plan.wrapperCmd, `@echo off\r\n${cmdPath(plan.nodePath)} ${cmdPath(plan.entry)} %*\r\n`, 0o755);
  }

  // 3. A policy only if none exists.
  let policyCreated = false;
  if (!fs.existsSync(plan.policyPath)) {
    writeAtomic(plan.policyPath, `${JSON.stringify({ version: 1 }, null, 2)}\n`, 0o600);
    policyCreated = true;
  }

  // 4. Exactly one TrustDex hook, everything else kept.
  const backupPath = existed ? backup(plan.settingsPath, now) : null;
  const hooks = { ...(settings.hooks || {}) };
  hooks.PreToolUse = [
    ...withoutTrustdexHooks(hooks.PreToolUse),
    { matcher: HOOK_MATCHER, hooks: [{ type: 'command', ...(plan.hookShell ? { shell: plan.hookShell } : {}), command: plan.hookCommand, timeout: 60 }] }
  ];
  writeAtomic(plan.settingsPath, `${JSON.stringify({ ...settings, hooks }, null, 2)}\n`, 0o600);
  return { backupPath, policyCreated };
}

// With dryRun it only counts the TrustDex hooks it would remove and writes nothing.
export function applyUninstall({ settingsPath, now = Date.now(), dryRun = false }) {
  const { settings, existed } = readSettings(settingsPath);
  if (!existed) return { removed: 0, backupPath: null };
  const before = (settings.hooks?.PreToolUse || []).flatMap((group) => group.hooks || [])
    .filter(isTrustdexHook).length;
  if (!before || dryRun) return { removed: before, backupPath: null };
  const backupPath = backup(settingsPath, now);
  const hooks = { ...settings.hooks, PreToolUse: withoutTrustdexHooks(settings.hooks.PreToolUse) };
  if (!hooks.PreToolUse.length) delete hooks.PreToolUse;
  writeAtomic(settingsPath, `${JSON.stringify({ ...settings, hooks }, null, 2)}\n`, 0o600);
  return { removed: before, backupPath };
}
