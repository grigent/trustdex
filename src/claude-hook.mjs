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
import { guardBashCommand, guardFileTool, guardPaths } from './agent-guard.mjs';
import { actionDigest } from './approvals.mjs';
import { mentionsPackageTool } from './install-command.mjs';

export const HOOK_TOOLS = ['Bash', 'Read', 'Grep', 'Glob', 'Write', 'Edit', 'MultiEdit', 'NotebookEdit'];

function reasonText(items, code) {
  const risky = items.filter((item) => item.action !== 'allow');
  const lines = risky.map((item) => `- ${item.name} [${item.signals.join(', ')}]: ${item.reasons.join(' ')}`);
  const head = 'TrustDex stopped this action because it could harm this computer or leak credentials.';
  const next = code
    ? [
        'Do not retry it in another form or work around this check.',
        'Explain the risk to the user in plain words.',
        `If the user understands it and still wants it, they type this in their own terminal app (not in this chat): trustdex allow-once ${code}`,
        'That allows this exact action once within 30 minutes; then run the identical action again.'
      ]
    : ['Do not retry it in another form or work around this check. Explain the risk to the user in plain words.'];
  return [head, ...lines, ...next].join('\n');
}

function summary(items) {
  return items
    .filter((item) => item.action !== 'allow')
    .map((item) => ({ name: item.name, signals: item.signals, reasons: item.reasons }));
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

  const digest = actionDigest(input.tool_name, input.tool_input ?? null);
  const store = options.approvals ?? null;
  if (store?.consume(digest)) return null;

  if (action === 'ask' && options.onRisk === 'ask') {
    return {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'ask',
        permissionDecisionReason: reasonText(items, null).replace('TrustDex stopped this action', 'TrustDex flagged this action')
      }
    };
  }

  let code = null;
  try {
    code = store ? store.recordPending(digest, summary(items)) : null;
  } catch {
    code = null;
  }
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reasonText(items, code)
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
