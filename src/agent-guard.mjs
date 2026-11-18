// Guards for agent tool calls beyond package installs.
//
// These checks look at a Claude Code tool call (Bash command, file read/write) and
// report signals for actions that an inattentive approval should never let
// through:
//
// - guard-tamper: changing agent settings, MCP configuration, TrustDex itself,
//   its policy or approval state (a disabled gate protects nothing)
// - secret-access: reading credential stores (SSH keys, cloud and registry
//   tokens, keychains, browser login data)
// - agent-permission-bypass: launching an AI coding CLI with its permission or
//   sandbox checks turned off, as the 2025 Nx "s1ngularity" malware did
// - persistence-change: login items, launch agents, cron, shell startup files
//
// Matching is static and conservative. It cannot follow arbitrary code (for
// example a Python script that builds a path at run time), so it is one layer
// next to sandboxing and least-privilege credentials, not a replacement.

import os from 'node:os';
import path from 'node:path';

import { lexShell, splitHeredocs, CommandParseError } from './install-command.mjs';

export const GUARD_SIGNAL_ACTIONS = Object.freeze({
  'guard-tamper': 'block',
  'secret-access': 'block',
  'agent-permission-bypass': 'block',
  'unparseable-guarded-command': 'block',
  'persistence-change': 'ask'
});

const READ_ONLY_PROGRAMS = new Set([
  'cat', 'head', 'tail', 'less', 'more', 'grep', 'egrep', 'fgrep', 'rg', 'ls', 'stat', 'wc', 'jq',
  'diff', 'file', 'test', '[', 'echo', 'printf', 'true', 'cmp', 'shasum', 'sha256sum', 'md5', 'plutil'
]);
const EXISTENCE_PROGRAMS = new Set(['ls', 'stat', 'test', '[', 'true', 'echo', 'printf']);
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'fish']);
// SSH tools use private keys without revealing them; passing a key path to them is normal.
const KEY_USERS = new Set(['ssh', 'scp', 'sftp', 'ssh-add', 'ssh-keygen', 'autossh', 'mosh']);
const WRAPPERS = new Set(['sudo', 'doas', 'command', 'env', 'time', 'exec', 'nohup', 'nice', 'builtin', 'xargs']);

function programName(word) {
  return String(word).split('/').pop().toLowerCase();
}

// ------------------------------------------------------------ paths

export function guardPaths({ home = os.homedir(), trustdexRoot = null, policyPath = null, stateDir = null, secretPaths = [] } = {}) {
  const h = (rel) => path.join(home, rel);
  return {
    config: [
      h('.claude/settings.json'), h('.claude/settings.local.json'), h('.claude.json'),
      h('.claude/hooks/'), h('.codex/config.toml'), h('.gemini/settings.json'), h('.cursor/mcp.json'),
      '/Library/Application Support/ClaudeCode/', '/etc/claude-code/',
      ...(trustdexRoot ? [path.resolve(trustdexRoot) + path.sep] : []),
      ...(policyPath ? [path.resolve(expandHome(policyPath, home))] : []),
      ...(stateDir ? [path.resolve(expandHome(stateDir, home)) + path.sep] : [])
    ],
    // Project-level files matched by name wherever they are.
    configNames: [/(^|\/)\.claude\/settings(\.local)?\.json$/i, /(^|\/)\.mcp\.json$/i, /(^|\/)\.claude\/hooks\//i, /(^|\/)\.codex\/config\.toml$/i],
    secrets: [
      h('.ssh/id_*'), h('.ssh/*.pem'), h('.ssh/*_key'), h('.aws/credentials'), h('.aws/sso/cache/'),
      h('.config/gh/hosts.yml'), h('.npmrc'), h('.yarnrc.yml'), h('.pypirc'), h('.netrc'), h('.git-credentials'),
      h('.docker/config.json'), h('.kube/config'), h('.config/gcloud/'), h('.azure/'), h('.gnupg/'),
      h('.cloudflared/'), h('.wrangler/config/'), h('.config/op/'), h('.claude/.credentials.json'),
      h('.codex/auth.json'), h('Library/Keychains/'), h('Library/Cookies/'),
      h('Library/Application Support/Google/Chrome/*/Login Data'), h('Library/Application Support/Google/Chrome/*/Cookies'),
      h('Library/Application Support/Firefox/Profiles/'), h('Library/Application Support/BraveSoftware/'),
      h('Library/Application Support/Microsoft Edge/'), h('Library/Safari/'),
      ...secretPaths.map((entry) => path.resolve(expandHome(entry, home)) + (entry.endsWith('/') ? path.sep : ''))
    ],
    secretNames: [/(^|\/)\.codex[^/]*\/auth\.json$/i, /(^|\/)id_(rsa|ecdsa|ed25519|dsa)$/i],
    persistence: [
      h('Library/LaunchAgents/'), '/Library/LaunchAgents/', '/Library/LaunchDaemons/', '/etc/cron.d/',
      '/etc/crontab', '/etc/profile', '/etc/zshrc', '/etc/bashrc',
      ...['.zshrc', '.zshenv', '.zprofile', '.zlogin', '.bashrc', '.bash_profile', '.profile', '.config/fish/config.fish'].map(h),
      h('.config/autostart/'), h('.config/systemd/user/')
    ]
  };
}

function expandHome(value, home) {
  return String(value)
    .replace(/^~(?=\/|$)/, home)
    .replace(/^\$HOME(?=\/|$)/, home)
    .replace(/^\$\{HOME\}(?=\/|$)/, home);
}

function globToRegExp(pattern) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*');
  return new RegExp(`^${escaped}$`, 'i');
}

function matchesAny(file, patterns, names = []) {
  const lower = file.toLowerCase();
  for (const pattern of patterns) {
    if (pattern.endsWith(path.sep)) {
      if (lower.startsWith(pattern.toLowerCase()) || `${lower}${path.sep}` === pattern.toLowerCase()) return true;
    } else if (pattern.includes('*')) {
      if (globToRegExp(pattern).test(file)) return true;
    } else if (lower === pattern.toLowerCase()) {
      return true;
    }
  }
  return names.some((re) => re.test(file));
}

export function classifyPath(file, paths, { cwd = null, home = os.homedir() } = {}) {
  if (typeof file !== 'string' || !file) return [];
  let resolved = expandHome(file.trim(), home);
  if (!path.isAbsolute(resolved)) resolved = cwd && path.isAbsolute(cwd) ? path.resolve(cwd, resolved) : resolved;
  else resolved = path.resolve(resolved);
  const kinds = [];
  if (matchesAny(resolved, paths.secrets, paths.secretNames)) kinds.push('secret');
  if (matchesAny(resolved, paths.config, paths.configNames)) kinds.push('config');
  if (matchesAny(resolved, paths.persistence)) kinds.push('persistence');
  return kinds;
}

// ------------------------------------------------------- file tools

const WRITE_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit']);
const READ_TOOLS = new Set(['Read', 'Grep', 'Glob']);

function signalItem(name, signal, reason) {
  return { name, kind: 'agent-action', signals: [signal], reasons: [reason], action: GUARD_SIGNAL_ACTIONS[signal] };
}

export function guardFileTool(toolName, toolInput, paths, options = {}) {
  const input = toolInput && typeof toolInput === 'object' ? toolInput : {};
  const target = input.file_path ?? input.notebook_path ?? input.path;
  if (typeof target !== 'string') return [];
  const kinds = classifyPath(target, paths, options);
  const items = [];
  if (WRITE_TOOLS.has(toolName)) {
    if (kinds.includes('config')) items.push(signalItem('file:agent-or-gate-config', 'guard-tamper', 'Changes agent settings, MCP configuration, or TrustDex itself; a changed gate can no longer protect you.'));
    if (kinds.includes('secret')) items.push(signalItem('file:credential-store', 'secret-access', 'Writes to a credential store.'));
    if (kinds.includes('persistence')) items.push(signalItem('file:startup-item', 'persistence-change', 'Adds or changes something that runs automatically at login or on a schedule.'));
  } else if (READ_TOOLS.has(toolName) && kinds.includes('secret')) {
    items.push(signalItem('file:credential-store', 'secret-access', 'Reads a credential store such as an SSH key, token file, keychain, or browser login data.'));
  }
  return items;
}

// ------------------------------------------------------- Bash

const AGENT_PROGRAMS = /^(?:claude|claude-code|@anthropic-ai\/claude-code(?:@.*)?|codex[\w.-]*|@openai\/codex(?:@.*)?|gemini|@google\/gemini-cli(?:@.*)?|cursor-agent|aider|amp|@sourcegraph\/amp(?:@.*)?|q|opencode|goose|qwen)$/i;
const BYPASS_FLAGS = new Set([
  '--dangerously-skip-permissions', '--allow-dangerously-skip-permissions',
  '--dangerously-bypass-approvals-and-sandbox', '--yolo', '--yes-always', '--trust-all-tools',
  '--dangerously-allow-all', '--sandbox=danger-full-access', '--permission-mode=bypasspermissions',
  '--approval-mode=yolo', 'sandbox_mode=danger-full-access', 'sandbox_mode="danger-full-access"',
  'approval_policy=never', 'approval_policy="never"'
]);
const BYPASS_VALUE_FLAGS = new Set(['--permission-mode', '--approval-mode', '-s', '--sandbox']);
const BYPASS_VALUES = new Set(['bypasspermissions', 'yolo', 'danger-full-access']);

function startsAgentWithoutGuardrails(words) {
  const agentIndex = words.findIndex((word) => AGENT_PROGRAMS.test(programName(word)) || AGENT_PROGRAMS.test(word));
  if (agentIndex < 0) return false;
  const agent = programName(words[agentIndex]);
  const args = words.slice(agentIndex + 1).map((word) => word.toLowerCase());
  return args.some((arg, index) =>
    BYPASS_FLAGS.has(arg) ||
    BYPASS_VALUE_FLAGS.has(arg) && BYPASS_VALUES.has(args[index + 1]) ||
    agent === 'gemini' && arg === '-y' ||
    agent === 'cursor-agent' && (arg === '--force' || arg === '-f'));
}

// Lex a command into simple commands, following `sh -c '...'`, `eval ...` and
// `$(...)` substitutions up to a fixed depth.
const SCRIPT_INTERPRETERS = new Set(['python', 'node', 'perl', 'ruby', 'php', 'osascript', 'swift']);
const BODY_PATH_RE = /(?:~|\$HOME|\$\{HOME\}|\/)[^\s'"`,;()[\]{}<>|]*|\.(?:claude|mcp\.json|ssh|aws|npmrc|config)[^\s'"`,;()[\]{}<>|]*/g;

function collectCommands(fullText, depth = 0) {
  const commands = [];
  const { text, bodies } = splitHeredocs(fullText);
  const heredocCommands = [];
  for (const body of bodies) {
    const program = body.program.replace(/\d+(?:\.\d+)*$/, '');
    if (SHELLS.has(program) && depth < 4) heredocCommands.push(...collectCommands(body.text, depth + 1));
    else if (SCRIPT_INTERPRETERS.has(program)) {
      // Code we cannot follow: treat every path it mentions as touched by a program
      // that may write, so protected files are still recognised.
      heredocCommands.push([program, ...(body.text.match(BODY_PATH_RE) || [])]);
    }
  }
  let current = [];
  const flush = () => { if (current.length) commands.push(current); current = []; };
  for (const token of lexShell(text)) {
    if (token.type === 'word') current.push(token.value);
    else flush();
  }
  flush();
  if (depth >= 4) return commands;
  const nested = [];
  for (const argv of commands) {
    const words = stripWrappers(argv);
    const program = programName(words[0] || '');
    if (SHELLS.has(program) || program === 'eval') {
      const index = words.findIndex((word) => /^-[A-Za-z]*c[A-Za-z]*$/.test(word));
      const script = program === 'eval' ? words.slice(1).join(' ') : index >= 0 ? words[index + 1] : null;
      if (script) nested.push(...collectCommands(script, depth + 1));
    }
    for (const word of argv) {
      const sub = /\$\(([^]*)\)/.exec(word) || /`([^`]*)`/.exec(word);
      if (sub) nested.push(...collectCommands(sub[1], depth + 1));
    }
  }
  return [...commands, ...nested, ...heredocCommands];
}

// When a command runs a local script file (bash x.sh, python3 x.py, source x),
// read that file through options.readScript and check it like a here-document:
// shell scripts are parsed, other interpreters have their mentioned paths
// checked. An unreadable or oversized script yields nothing extra.
const MAX_SCRIPT_BYTES = 1024 * 1024;

function scriptFileCommands(commands, options, depth = 0) {
  if (typeof options.readScript !== 'function' || depth > 2) return [];
  const extra = [];
  for (const argv of commands) {
    const words = stripWrappers(argv);
    const program = programName(words[0] || '').replace(/\d+(?:\.\d+)*$/, '');
    let script = null;
    if (program === 'source' || program === '.') script = words[1];
    else if (SHELLS.has(program) || SCRIPT_INTERPRETERS.has(program)) {
      if (words.slice(1).some((word) => /^-[A-Za-z]*[cem]$/.test(word) || word === '-')) continue;
      script = words.slice(1).find((word) => !word.startsWith('-'));
    } else if (/^\.{0,2}\//.test(words[0] || '') && /\.(?:sh|bash|zsh|py|js|mjs|cjs|rb|pl)$/.test(words[0])) {
      script = words[0];
    }
    if (!script) continue;
    let content;
    try {
      content = options.readScript(script, options.cwd, MAX_SCRIPT_BYTES);
    } catch {
      content = null;
    }
    if (typeof content !== 'string') continue;
    const isShell = SHELLS.has(program) || program === 'source' || program === '.' || /\.(?:sh|bash|zsh)$/.test(script);
    if (isShell) {
      let nested;
      try {
        nested = collectCommands(content, 1);
      } catch {
        nested = [[program, ...(content.match(BODY_PATH_RE) || [])]];
      }
      extra.push(...nested, ...scriptFileCommands(nested, options, depth + 1));
    } else {
      extra.push([program || 'script', ...(content.match(BODY_PATH_RE) || [])]);
    }
  }
  return extra;
}

function stripWrappers(argv) {
  let i = 0;
  while (i < argv.length) {
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(argv[i])) { i += 1; continue; }
    if (WRAPPERS.has(programName(argv[i]))) {
      i += 1;
      while (i < argv.length && argv[i].startsWith('-')) i += 1;
      continue;
    }
    break;
  }
  return argv.slice(i);
}

function pathCandidates(word) {
  const out = [];
  for (const part of String(word).split(/[=:,]/)) {
    const cleaned = part.replace(/^\d*[<>]+&?/, '').replace(/^["']|["']$/g, '');
    if (!cleaned) continue;
    if (/^(?:~|\$HOME|\$\{HOME\}|\/|\.{1,2}\/)/.test(cleaned) || cleaned.includes('/') || /^\.[A-Za-z]/.test(cleaned)) out.push(cleaned);
  }
  return out;
}

const KEYCHAIN_READ = /^(?:find-generic-password|find-internet-password|find-certificate|dump-keychain|export)$/;

export function guardBashCommand(command, paths, options = {}) {
  const items = [];
  const add = (name, signal, reason) => {
    if (!items.some((item) => item.signals[0] === signal)) items.push(signalItem(name, signal, reason));
  };
  const text = String(command || '');

  let commands;
  try {
    commands = collectCommands(text);
    commands.push(...scriptFileCommands(commands, options));
  } catch (error) {
    if (!(error instanceof CommandParseError)) throw error;
    const lower = text.toLowerCase();
    const mentions = [...paths.config, ...paths.secrets, ...paths.persistence]
      .some((entry) => lower.includes(entry.replace(/[*/]+$/, '').toLowerCase().split('/').slice(-2).join('/')));
    if (mentions || /\.claude|\.ssh|launchagents|keychain/i.test(text)) {
      add('command:unparsed', 'unparseable-guarded-command', 'The command could not be parsed and refers to protected files.');
    }
    return items;
  }

  const allPrograms = commands.map((argv) => programName(stripWrappers(argv)[0] || ''));
  const writesSomewhere = commands.some((argv) => argv.some((word) => /^\d*>/.test(word) || /^\d*>>/.test(word)));
  const readOnly = !writesSomewhere && allPrograms.every((program) => !program || READ_ONLY_PROGRAMS.has(program));
  const existenceOnly = !writesSomewhere && allPrograms.every((program) => !program || EXISTENCE_PROGRAMS.has(program));

  for (const argv of commands) {
    const words = stripWrappers(argv);
    const program = programName(words[0] || '');

    const trustdexIndex = argv.findIndex((word) => /^trustdex(?:\.mjs)?$/i.test(programName(word)));
    if (trustdexIndex >= 0 && argv.slice(trustdexIndex + 1).some((word) => /^allow-once$/i.test(word))) {
      add('command:trustdex-approve', 'guard-tamper', 'Approvals must be given by a person in their own terminal, not by the agent.');
    }
    if (startsAgentWithoutGuardrails(words)) {
      add('command:agent-without-guardrails', 'agent-permission-bypass', 'Starts an AI coding agent with its permission or sandbox checks switched off.');
    }

    if (program === 'security' && KEYCHAIN_READ.test(words[1] || '') &&
        (words[1] === 'dump-keychain' || words[1] === 'export' || words.some((word) => /^-[A-Za-z]*[wg]/.test(word)))) {
      add('command:keychain-secret', 'secret-access', 'Reads a password or key out of the macOS keychain.');
    }
    if (program === 'gh' && words[1] === 'auth' && (words[2] === 'token' || words.includes('--show-token') || words.includes('-t'))) {
      add('command:credential-store', 'secret-access', 'Prints the GitHub access token.');
    }
    if (program === 'crontab' && !words.slice(1).every((word) => word === '-l')) {
      add('command:startup-item', 'persistence-change', 'Changes scheduled jobs (crontab).');
    }
    if (program === 'launchctl' && /^(?:load|bootstrap|enable|submit)$/.test(words[1] || '')) {
      add('command:startup-item', 'persistence-change', 'Loads a background job with launchctl.');
    }
    if (program === 'osascript' && words.some((word) => /login item/i.test(word))) {
      add('command:startup-item', 'persistence-change', 'Adds a login item.');
    }

    for (const word of argv.slice(1)) {
      for (const candidate of pathCandidates(word)) {
        const kinds = classifyPath(candidate, paths, options);
        if (kinds.includes('secret') && !existenceOnly && !KEY_USERS.has(program)) {
          add('command:credential-store', 'secret-access', 'Reads or copies a credential store such as an SSH key, token file, keychain, or browser login data.');
        }
        if (kinds.includes('config') && !readOnly) {
          add('command:agent-or-gate-config', 'guard-tamper', 'Changes agent settings, MCP configuration, or TrustDex itself; a changed gate can no longer protect you.');
        }
        if (kinds.includes('persistence') && !readOnly) {
          add('command:startup-item', 'persistence-change', 'Adds or changes something that runs automatically at login or on a schedule.');
        }
      }
    }
  }
  return items;
}
