// Claude Code PreToolUse hook.
//
// Combines the pre-install package checks with the agent guards and turns the
// result into a hook decision:
//
// - nothing risky: no output, so Claude Code's normal permission flow continues.
//   TrustDex never approves anything by itself.
// - risky (default "deny" mode): the call is denied with plain-language reasons
//   and a one-time approval code that only a person can redeem, with
//   `trustdex allow-once <code>` in an interactive terminal. A permission dialog
//   is one click away from "allow"; people approve them without reading,
//   especially after turning prompts off because they are tiring. Risky
//   actions therefore never become a dialog by default.
// - "ask" mode (--on-risk ask): ASK-level findings become Claude Code's own
//   permission dialog instead; BLOCK-level findings are still denied.

import { evaluateInstallCommand, overallAction } from './install-check.mjs';
import nodePath from 'node:path';

import { guardBashCommand, guardFileTool, guardPaths, toPosix } from './agent-guard.mjs';
import { actionDigest } from './approvals.mjs';
import { mentionsPackageTool } from './install-command.mjs';

const posixPath = nodePath.posix;

export const HOOK_TOOLS =['Bash', 'Read', 'Grep', 'Glob', 'Write', 'Edit', 'MultiEdit', 'NotebookEdit'];

// Package findings that an approval may cover by name for a day: they concern one
// exact package version, not the command around it.
const ITEM_SCOPED_SIGNALS = new Set([
  'recent-release', 'new-package', 'install-scripts', 'source-build', 'publisher-changed',
  'deprecated', 'yanked', 'similar-to-popular'
]);

// ASK-level guard findings about routine maintenance that one approval may cover
// as a kind of work for a short time, instead of one exact command.
export const SIGNAL_SCOPED = new Set(['persistence-change']);

export function itemApprovalKeys(items) {
  const risky = items.filter((item) => item.action !== 'allow');
  if (!risky.length) return null;
  const keys = [];
  for (const item of risky) {
    if (item.action === 'block') return null;
    if (item.signals.length && item.signals.every((signal) => SIGNAL_SCOPED.has(signal))) {
      for (const signal of item.signals) keys.push(`signal:${signal}`);
      continue;
    }
    if (!/^(?:npm|pypi):[^:\s]+@[^\s]+$/.test(item.name)) return null;
    for (const signal of item.signals) {
      if (!ITEM_SCOPED_SIGNALS.has(signal) && signal !== 'install-scripts-disabled') return null;
      if (ITEM_SCOPED_SIGNALS.has(signal)) keys.push(`${item.name}#${signal}`);
    }
  }
  return keys.length ? [...new Set(keys)] : null;
}

function scopeText(keys) {
  const parts = [];
  if (keys.some((key) => !key.startsWith('signal:'))) parts.push('these exact package versions for 24 hours');
  if (keys.includes('signal:persistence-change')) parts.push('changes to startup items and scheduled jobs for 1 hour');
  return `That allows ${parts.join(' and ')}, in any command.`;
}

function reasonText(items, code, itemKeys) {
  const itemScoped = Array.isArray(itemKeys) && itemKeys.length > 0;
  const packageScoped = itemScoped && itemKeys.some((key) => !key.startsWith('signal:'));
  const risky = items.filter((item) => item.action !== 'allow');
  const lines = risky.map((item) => `- ${item.name} [${item.signals.join(', ')}]: ${item.reasons.join(' ')}`);
  const head = packageScoped
    ? 'TrustDex stopped this action because a package version looks risky.'
    : itemScoped
      ? 'TrustDex stopped this action because it changes what runs automatically on this computer.'
      : 'TrustDex stopped this action because it could harm this computer or leak credentials.';
  const next = [];
  if (itemScoped) {
    if (packageScoped) next.push('If a safer alternative is named above (an older exact version, or --ignore-scripts), use it without asking the user.');
    if (code) {
      next.push(`${packageScoped ? 'Only if no alternative works: explain' : 'Explain'} what will run automatically in plain words; if the user wants it, they type this in their own terminal app (not in this chat): trustdex allow-once ${code}`);
      next.push(scopeText(itemKeys));
    }
  } else if (code) {
    next.push(
      'Do not retry it in another form or work around this check.',
      'Explain the risk to the user in plain words.',
      `If the user understands it and still wants it, they type this in their own terminal app (not in this chat): trustdex allow-once ${code}`,
      'That allows this exact action once within 30 minutes; then run the identical action again.'
    );
  } else {
    next.push('Do not retry it in another form or work around this check. Explain the risk to the user in plain words.');
  }
  return [head, ...lines, ...next].join('\n');
}

function summary(items) {
  return items
    .filter((item) => item.action !== 'allow')
    .map((item) => ({ name: item.name, signals: item.signals, reasons: item.reasons }));
}

// The part of a tool call an approval is bound to: what the action does, not
// incidental fields (descriptions, timeouts, client metadata) that can differ
// between two otherwise identical calls.
const APPROVAL_FIELDS = {
  Bash: ['command'],
  Read: ['file_path'],
  Grep: ['path', 'pattern', 'glob'],
  Glob: ['path', 'pattern'],
  Write: ['file_path', 'content'],
  Edit: ['file_path', 'old_string', 'new_string', 'replace_all'],
  MultiEdit: ['file_path', 'edits'],
  NotebookEdit: ['notebook_path', 'cell_id', 'new_source', 'cell_type', 'edit_mode']
};

const LEADING_CD_RE = /^\s*cd\s+("[^"]*"|'[^']*'|[^\s;&|]+)\s*(?:&&|;)\s*/;

// A Bash command means "run this in that directory". Claude Code may drop a
// leading `cd <current dir> &&` before hooks see the command, so the same action
// can arrive with or without it. Bind Bash approvals to the directory the command
// effectively starts in plus the rest of the command, so both forms match and an
// approval given for one directory does not cover the same command elsewhere.
export function bashApprovalSubject(command, cwd = null) {
  let rest = String(command);
  let dir = typeof cwd === 'string' && cwd ? toPosix(cwd) : null;
  for (let i = 0; i < 8; i += 1) {
    const match = LEADING_CD_RE.exec(rest);
    if (!match) break;
    const target = toPosix(match[1].replace(/^["']|["']$/g, ''));
    if (target.startsWith('/')) dir = posixPath.normalize(target);
    else if (/^~(?:\/|$)|\$/.test(target)) dir = `unresolved:${target}`;
    else dir = dir ? posixPath.resolve(dir, target) : `unresolved:${target}`;
    rest = rest.slice(match[0].length);
  }
  return { command: rest, cwd: dir };
}

export function approvalSubject(toolName, toolInput, cwd = null) {
  const input = toolInput && typeof toolInput === 'object' ? toolInput : {};
  if (toolName === 'Bash' && typeof input.command === 'string') return bashApprovalSubject(input.command, cwd);
  const fields = APPROVAL_FIELDS[toolName];
  if (!fields) return input;
  return Object.fromEntries(fields.filter((field) => input[field] !== undefined).map((field) => [field, input[field]]));
}

export async function evaluateToolCall(input, options = {}) {
  const tool = input.tool_name;
  const toolInput = input.tool_input && typeof input.tool_input === 'object' ? input.tool_input : {};
  const cwd = typeof input.cwd === 'string' ? input.cwd : null;
  const paths = options.paths ?? guardPaths(options.pathOptions);
  const items = [];
  if (tool === 'Bash') {
    const command = toolInput.command;
    if (typeof command !== 'string' || !command.trim()) return items;
    items.push(...guardBashCommand(command, paths, { cwd, readScript: options.readScript }));
    items.push(...(await evaluateInstallCommand(command, options)).items);
  } else {
    items.push(...guardFileTool(tool, toolInput, paths, { cwd }));
  }
  return items;
}

export async function claudeHookResponse(input, options = {}) {
  if (!input || typeof input !== 'object' || typeof input.tool_name !== 'string') {
    throw new Error('Invalid hook input.');
  }
  const items = await evaluateToolCall(input, options);
  const action = overallAction(items);
  if (action === 'allow') return null;

  const digest = actionDigest(input.tool_name, approvalSubject(input.tool_name, input.tool_input, input.cwd));
  const itemKeys = itemApprovalKeys(items);
  const store = options.approvals ?? null;
  if (store?.consume(digest, itemKeys ?? [])) return null;

  if (action === 'ask' && options.onRisk === 'ask') {
    return {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'ask',
        permissionDecisionReason: reasonText(items, null, itemKeys).replace('TrustDex stopped', 'TrustDex flagged')
      }
    };
  }

  let code = null;
  try {
    code = store ? store.recordPending(digest, summary(items), itemKeys) : null;
  } catch {
    code = null;
  }
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reasonText(items, code, itemKeys)
    }
  };
}

// Used when the hook cannot evaluate its input or configuration. Unreadable
// input is denied. A readable call is denied only when it could be risky (a
// file tool or a Bash command), so a broken policy file stops risky actions but
// not unrelated tools.
export function claudeHookFailure(input = null) {
  if (input && typeof input === 'object' && typeof input.tool_name === 'string') {
    if (!['Bash', 'Read', 'Grep', 'Glob', 'Write', 'Edit', 'MultiEdit', 'NotebookEdit'].includes(input.tool_name)) return null;
    if (input.tool_name === 'Bash' && !mentionsPackageTool(input.tool_input?.command) &&
        !/[~/]|\$HOME|security|launchctl|crontab|claude|codex|gemini/i.test(String(input.tool_input?.command || ''))) {
      return null;
    }
  }
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: 'TrustDex could not evaluate this action, so it stopped it. Tell the user; the TrustDex policy or installation may need attention.'
    }
  };
}
