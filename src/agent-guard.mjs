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
// - remote-secret-access / remote-config-change: over SSH, reading files that
//   look like secrets, or changing server settings, secret files, SSH keys or
//   scheduled jobs
//
// Matching is static and conservative. It cannot follow arbitrary code (for
// example a Python script that builds a path at run time), so it is one layer
// next to sandboxing and least-privilege credentials, not a replacement.

import fs from 'node:fs';
import os from 'node:os';
import nodePath from 'node:path';

// Shell commands and tool paths are matched with POSIX semantics on every
// platform. Windows paths (C:\Users\x) are first turned into /C:/Users/x so the
// same rules apply to them.
const path = nodePath.posix;

export function toPosix(value) {
  const forward = String(value).replace(/\\/g, '/');
  return /^[A-Za-z]:\//.test(forward) ? `/${forward}` : forward;
}

import { lexShell, splitHeredocs, CommandParseError } from './install-command.mjs';

export const GUARD_SIGNAL_ACTIONS = Object.freeze({
  'guard-tamper': 'block',
  'secret-access': 'block',
  'agent-permission-bypass': 'block',
  'unparseable-guarded-command': 'block',
  'persistence-change': 'ask',
  'remote-secret-access': 'ask',
  'remote-config-change': 'ask'
});

const READ_ONLY_PROGRAMS = new Set([
  'cat', 'head', 'tail', 'less', 'more', 'grep', 'egrep', 'fgrep', 'rg', 'ls', 'stat', 'wc', 'jq',
  'diff', 'file', 'test', '[', 'echo', 'printf', 'true', 'cmp', 'shasum', 'sha256sum', 'md5',
  'cd', 'pwd', 'sort', 'uniq', 'cut', 'tr', 'basename', 'dirname', 'realpath', 'readlink', 'du', 'tree', 'nl', 'column'
]);
const EXISTENCE_PROGRAMS = new Set(['ls', 'stat', 'test', '[', 'true', 'echo', 'printf', 'cd', 'pwd']);
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'fish']);
// SSH tools use private keys without revealing them; passing a key path to them is normal.
const KEY_USERS = new Set(['ssh', 'scp', 'sftp', 'ssh-add', 'ssh-keygen', 'autossh', 'mosh']);
const WRAPPERS = new Set(['sudo', 'doas', 'command', 'env', 'time', 'exec', 'nohup', 'nice', 'builtin', 'xargs']);

function programName(word) {
  return String(word).split('/').pop().toLowerCase();
}

// ------------------------------------------------------------ paths

export function guardPaths({ home: rawHome = os.homedir(), trustdexRoot: rawRoot = null, policyPath: rawPolicy = null, stateDir: rawState = null, secretPaths = [] } = {}) {
  const home = canonicalGuardPath(rawHome, { home: rawHome });
  const absolute = (value) => canonicalGuardPath(value, { home: rawHome, cwd: process.cwd() });
  const trustdexRoot = rawRoot ? absolute(rawRoot) : null;
  const policyPath = rawPolicy ? absolute(rawPolicy) : null;
  const stateDir = rawState ? absolute(rawState) : null;
  // Not path.join: it would fold the leading "//" of a UNC home into "/".
  const h = (rel) => `${home.replace(/\/+$/, '')}/${rel}`;
  return {
    config: [
      h('.claude/settings.json'), h('.claude/settings.local.json'), h('.claude.json'),
      h('.claude/hooks/'), h('.codex/config.toml'), h('.gemini/settings.json'), h('.cursor/mcp.json'),
      '/Library/Application Support/ClaudeCode/', '/etc/claude-code/',
      ...(trustdexRoot ? [trustdexRoot + path.sep] : []),
      ...(policyPath ? [policyPath] : []),
      ...(stateDir ? [stateDir + path.sep] : [])
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
      ...secretPaths.map((entry) => absolute(entry) + (/[\\/]$/.test(entry) ? path.sep : ''))
    ],
    secretNames: [/(^|\/)\.codex[^/]*\/auth\.json$/i, /(^|\/)id_(rsa|ecdsa|ed25519|dsa)$/i],
    persistence: [
      h('Library/LaunchAgents/'), '/Library/LaunchAgents/', '/Library/LaunchDaemons/', '/etc/cron.d/',
      '/etc/crontab', '/etc/profile', '/etc/zshrc', '/etc/bashrc',
      ...['.zshrc', '.zshenv', '.zprofile', '.zlogin', '.bashrc', '.bash_profile', '.profile', '.config/fish/config.fish'].map(h),
      h('.config/autostart/'), h('.config/systemd/user/')
    ],
    // Git hooks run code on every commit, checkout or push.
    persistenceNames: [/(^|\/)\.git\/hooks\/[^/]+$/i]
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
  for (const rawPattern of patterns) {
    const pattern = toPosix(rawPattern);
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

// Spellings that name the same file as a plain absolute path. Win32 namespace prefixes
// (\\?\C:\x, \\.\C:\x, \??\C:\x), \\?\UNC\host\share, and this computer's
// administrative shares (\\localhost\C$\x) become drive or UNC paths.
function windowsPath(value) {
  return value
    .replace(/^(?:\/\/[?.]\/|\/\?\?\/)(?=[A-Za-z]:(?:\/|$))/, '')
    .replace(/^(?:\/\/[?.]\/|\/\?\?\/)UNC\//i, '//')
    .replace(/^\/\/(?:localhost|127\.0\.0\.1|\[::1\]|::1)\/([A-Za-z])\$(?=\/|$)/i, '$1:');
}

// Windows ignores trailing dots and spaces in a name and reads "name::$DATA" as "name".
function windowsSegments(rest) {
  return rest.split('/').map((part) => (part === '.' || part === '..' ? part : part.replace(/:.*$/, '').replace(/[. ]+$/, ''))).join('/');
}

const HOME_PREFIX_RE = /^(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|\$env:USERPROFILE|\$\{env:USERPROFILE\}|%HOMEDRIVE%%HOMEPATH%|\$env:HOMEDRIVE\$env:HOMEPATH)(?=\/|$)/i;

// One absolute POSIX-style spelling for a tool path: home notation expanded, Windows
// prefixes and drive letters normalized, `.` and `..` resolved without leaving a drive,
// and kernel or firmlink aliases (/proc/self/root, /private/etc, /System/Volumes/Data)
// removed. Symbolic links are resolved separately, against the file system.
export function canonicalGuardPath(file, { cwd: rawCwd = null, home: rawHome = os.homedir() } = {}) {
  const home = toPosix(windowsPath(toPosix(rawHome)).replace(/^\/(?=[A-Za-z]:)/, ''));
  // A leading "//" is a UNC share only in Windows notation; on POSIX it is "/".
  const unc = /^\\\\/.test(String(file).trim()) || /^(?:\/[A-Za-z]:|\/\/)/.test(home) && !/^\/\//.test(String(rawHome).trim());
  const cwd = rawCwd ? canonicalGuardPath(rawCwd, { home: rawHome }) : null;
  let value = windowsPath(String(file).trim().replace(/\\/g, '/'));
  const user = path.basename(home);
  value = value.replace(HOME_PREFIX_RE, home);
  if (user && value.toLowerCase().startsWith(`~${user.toLowerCase()}`) && /^(?:\/|$)/.test(value.slice(user.length + 1))) {
    value = home + value.slice(user.length + 1);
  }
  value = toPosix(value);
  let drive = value.match(/^\/([A-Za-z]):(\/.*|)$/);
  const relativeDrive = value.match(/^([A-Za-z]):(?!\/)(.*)$/);
  if (relativeDrive) {
    // "C:x" is relative to the current directory on drive C:, or to its root.
    const base = cwd?.match(/^\/([A-Za-z]):(\/.*|)$/);
    const root = base && base[1].toLowerCase() === relativeDrive[1].toLowerCase() ? base[2] || '/' : '/';
    drive = [null, relativeDrive[1], path.join(root, relativeDrive[2])];
  } else if (!drive && !path.isAbsolute(value)) {
    if (!cwd) return value;
    value = cwd.endsWith('/') ? cwd + value : `${cwd}/${value}`;
    drive = value.match(/^\/([A-Za-z]):(\/.*|)$/);
  }
  if (drive) return `/${drive[1].toUpperCase()}:${path.resolve('/', windowsSegments(drive[2] || '/'))}`;
  if (unc && value.startsWith('//')) return `//${windowsSegments(path.resolve('/', value.slice(2))).slice(1)}`;
  // Aliases are removed before `..` is resolved: /proc/self/cwd/.. is the parent of cwd.
  let aliased = value.replace(/\/{2,}/g, '/');
  if (cwd) aliased = aliased.replace(/^\/proc\/(?:self|thread-self)\/cwd(?=\/|$)/, () => cwd);
  aliased = aliased
    .replace(/^\/proc\/(?:self|thread-self|\d+)\/root(?=\/|$)/, '')
    .replace(/^\/private(?=\/(?:etc|var|tmp)(?:\/|$))/, '')
    .replace(/^\/System\/Volumes\/Data(?=\/|$)/, '');
  return path.resolve('/', aliased);
}

// The same path with symbolic links resolved through its deepest existing ancestor, in
// the notation of the configured home, or null when it cannot be resolved here.
// UNC paths are never resolved: on Windows that would contact the named server (and can
// send it the user's credentials) before the guard has decided.
function realGuardPath(resolved, home) {
  const native = /^\/[A-Za-z]:\//.test(resolved) ? resolved.slice(1) : resolved;
  if (!nodePath.isAbsolute(native) || native.startsWith('//')) return null;
  const real = (target) => {
    let dir = target;
    const rest = [];
    for (;;) {
      try {
        return path.join(toPosix(fs.realpathSync.native(dir)), ...rest);
      } catch {
        const parent = nodePath.dirname(dir);
        if (parent === dir) return null;
        rest.unshift(nodePath.basename(dir));
        dir = parent;
      }
    }
  };
  const target = real(native);
  if (!target) return null;
  const realHome = home.startsWith('//') ? null : real(/^\/[A-Za-z]:\//.test(home) ? home.slice(1) : home);
  const inHome = realHome && realHome !== home && (target === realHome || target.startsWith(`${realHome}/`));
  return inHome ? home + target.slice(realHome.length) : target;
}

export function classifyPath(file, paths, { cwd = null, home = os.homedir() } = {}) {
  if (typeof file !== 'string' || !file) return [];
  const resolved = canonicalGuardPath(file, { cwd, home });
  const candidates = [resolved];
  if (path.isAbsolute(resolved)) {
    const real = realGuardPath(resolved, canonicalGuardPath(home, { home }));
    if (real && real !== resolved) candidates.push(real);
  }
  const kinds = [];
  const matches = (patterns, names) => candidates.some((candidate) => matchesAny(candidate, patterns, names));
  if (matches(paths.secrets, paths.secretNames)) kinds.push('secret');
  if (matches(paths.config, paths.configNames)) kinds.push('config');
  if (matches(paths.persistence, paths.persistenceNames || [])) kinds.push('persistence');
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
    // ssh to this same computer runs the command here: check it like a local one.
    if (program === 'ssh') {
      const remote = sshRemote(words);
      if (remote && isLoopbackHost(remote.host) && remote.command.trim()) nested.push(...collectCommands(remote.command, depth + 1));
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
      // bash -n only checks syntax; the script does not run.
      if (SHELLS.has(program) && words.slice(1).some((word) => /^-[A-Za-z]*n[A-Za-z]*$/.test(word))) continue;
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
    const cleaned = part.replace(/^\d*[<>]+&?/, '').replace(/^[@"']|["']$/g, '');
    if (!cleaned) continue;
    if (/^(?:~|\$HOME|\$\{HOME\}|\/|\.{1,2}\/)/.test(cleaned) || cleaned.includes('/') || /^\.[A-Za-z]/.test(cleaned)) out.push(cleaned);
  }
  // Paths embedded in code strings (python3 -c "open('~/.ssh/id_rsa')", node -e ...).
  for (const match of String(word).match(BODY_PATH_RE) || []) {
    if (!out.includes(match)) out.push(match);
  }
  return out;
}

const NETWORK_SENDERS = new Set(['curl', 'wget', 'nc', 'ncat', 'netcat', 'socat', 'http', 'https', 'xh', 'telnet', 'ftp', 'sftp', 'scp', 'rsync']);
const ENV_DUMPERS = new Set(['env', 'printenv', 'set', 'declare', 'compgen']);
const DOTENV_RE = /(?:^|[/@'"=])\.env(?:\.(?!example\b|sample\b|template\b|dist\b)[\w-]+)?['"]?$/;
const AGENT_CONFIG_CLIS = /^(?:claude|codex[\w.-]*|gemini|cursor-agent|amp|q)$/;

// ------------------------------------------------------- SSH (remote)
//
// The local guards above know this computer's paths. Commands run on another
// computer over SSH (ssh host 'cmd', ssh host <<EOF, scp/rsync host:path) are
// checked by generic names instead: files that usually hold secrets, server
// settings under /etc, SSH authorized keys, shell startup files and scheduled
// jobs. The finding is scoped to the host, so approving work on one server
// does not cover another.

const SSH_VALUE_OPTIONS = new Set('BbcDEeFIiJLlmOoPpQRSWw'.split(''));
const REMOTE_SECRET_NAME = /(?:^|\/)(?:\.env(?:\.(?!example\b|sample\b|template\b|dist\b)[\w-]+)?|[\w.-]+\.env|id_(?:rsa|ecdsa|ed25519|dsa)|[\w.-]+\.(?:pem|key|p12|pfx|jks|keystore|kdbx)|\.netrc|\.npmrc|\.pypirc|\.pgpass|\.my\.cnf|\.git-credentials|credentials(?:\.[\w-]+)?|shadow|gshadow|[\w.-]*(?:secret|token|password|passwd|api[_-]?key)s?(?:\.[\w-]+)?)$/i;
const REMOTE_CONFIG_PATH = /^\/etc\/|(?:^|\/)\.ssh\/authorized_keys2?$|(?:^|\/)\.(?:bashrc|bash_profile|profile|zshrc|zshenv|zprofile)$|^\/var\/spool\/cron\//;
const REMOTE_METADATA_PROGRAMS = new Set([...EXISTENCE_PROGRAMS, 'chmod', 'chown', 'touch', 'du', 'wc', 'file', 'basename', 'dirname', 'realpath', 'readlink']);

// The command an `ssh` invocation runs remotely, and the host it runs on.
export function sshRemote(words) {
  let i = 1;
  while (i < words.length && words[i].startsWith('-') && words[i] !== '--') {
    const flags = words[i].slice(1);
    const at = [...flags].findIndex((flag) => SSH_VALUE_OPTIONS.has(flag));
    i += at >= 0 && at === flags.length - 1 ? 2 : 1;
  }
  if (words[i] === '--') i += 1;
  const host = words[i];
  if (!host) return null;
  return { host: normalizeHost(host), hostIndex: i, command: words.slice(i + 1).join(' ') };
}

function isLoopbackHost(host) {
  const names = new Set(['localhost', '127.0.0.1', '::1', '[::1]', '0.0.0.0', '?']);
  try {
    const own = os.hostname().toLowerCase();
    names.add(own);
    names.add(own.split('.')[0]);
    names.add(own.replace(/\.local$/, ''));
  } catch { /* hostname unavailable */ }
  return names.has(host) || /^127\./.test(host) || /^\$|`/.test(host);
}

function normalizeHost(host) {
  return String(host).replace(/^ssh:\/\//i, '').replace(/^[^@]*@/, '').replace(/[:/].*$/, '').toLowerCase() || '?';
}

function remotePathParts(word) {
  const out = [];
  for (const part of String(word).split(/[=,\s]/)) {
    const cleaned = part.replace(/^\d*[<>]+&?/, '').replace(/^[@"'(]+|["');]+$/g, '');
    if (cleaned) out.push(cleaned);
  }
  return out;
}

function remoteCommandFindings(text, host, add, depth = 0) {
  let commands;
  try {
    commands = collectCommands(text, 1);
  } catch {
    if (REMOTE_SECRET_NAME.test(text) || /\/etc\//.test(text)) add(host, 'remote-config-change', 'Runs a command on a remote server that could not be parsed and mentions secrets or server settings.');
    return;
  }
  for (const argv of commands) {
    const words = stripWrappers(argv);
    const program = programName(words[0] || '');
    if (program === 'ssh' && depth < 2) {
      const nested = sshRemote(words);
      if (nested) remoteCommandFindings(nested.command, nested.host, add, depth + 1);
      continue;
    }
    const readOnly = commandIsReadOnly(words);
    const metadataOnly = REMOTE_METADATA_PROGRAMS.has(program);
    const args = words.slice(1);
    // Not stripWrappers: a bare `env` is the dump itself, not a wrapper.
    const bare = argv.filter((word) => !/^[A-Za-z_][A-Za-z0-9_]*=/.test(word) && !isRedirection(word));
    const dumpsEnv = bare.length === 1 && ENV_DUMPERS.has(programName(bare[0])) || program === 'sudo' && bare.length === 2 && ENV_DUMPERS.has(programName(bare[1]));
    if (dumpsEnv ||
        program === 'docker' && args[0] === 'exec' && args.some((word, index) => index > 0 && ENV_DUMPERS.has(programName(word)) && index === args.length - 1) ||
        program === 'kubectl' && /^(?:get|describe|edit)$/.test(args[0] || '') && /^secrets?$/.test(args[1] || '')) {
      add(host, 'remote-secret-access', 'Prints secrets on a remote server (environment variables or stored secrets).');
    }
    if (program === 'crontab' && !args.every((word) => word === '-l')) {
      add(host, 'remote-config-change', 'Changes scheduled jobs on a remote server.');
    }
    for (const target of redirectionTargets(argv)) {
      if (REMOTE_SECRET_NAME.test(target) || REMOTE_CONFIG_PATH.test(target)) {
        add(host, 'remote-config-change', 'Writes a secret file or server setting on a remote server.');
      }
    }
    // kubectl names resources, not files.
    if (program === 'kubectl') continue;
    for (const word of argv) {
      if (isRedirection(word)) continue;
      for (const candidate of remotePathParts(word)) {
        const secret = REMOTE_SECRET_NAME.test(candidate) && candidate !== words[0];
        const config = REMOTE_CONFIG_PATH.test(candidate);
        if (secret && !metadataOnly) {
          if (readOnly) add(host, 'remote-secret-access', 'Reads a file that usually holds secrets (keys, tokens, passwords, .env) on a remote server.');
          else add(host, 'remote-config-change', 'Changes or copies a file that usually holds secrets on a remote server.');
        }
        if (config && !readOnly && !metadataOnly) {
          add(host, 'remote-config-change', 'Changes server settings, SSH authorized keys, or shell startup files on a remote server.');
        }
      }
    }
  }
}

function remoteFindings(text, commands) {
  const items = [];
  const add = (host, signal, reason) => {
    const name = `remote:${host}`;
    if (!items.some((item) => item.name === name && item.signals[0] === signal)) {
      items.push({ ...signalItem(name, signal, reason), scope: host });
    }
  };
  const { bodies } = splitHeredocs(text);
  for (const body of bodies) {
    if (body.program !== 'ssh') continue;
    const remote = sshRemote(['ssh', ...body.args]);
    remoteCommandFindings(body.text, remote ? remote.host : '?', add);
  }
  for (const argv of commands) {
    const words = stripWrappers(argv);
    const program = programName(words[0] || '');
    if (program === 'ssh') {
      const remote = sshRemote(words);
      if (remote && remote.command.trim()) remoteCommandFindings(remote.command, remote.host, add);
    } else if (program === 'scp' || program === 'rsync' || program === 'sftp') {
      const specs = words.slice(1).filter((word) => !word.startsWith('-') && /^[^/\s:]+:/.test(word));
      const last = words[words.length - 1];
      for (const spec of specs) {
        const remotePath = spec.slice(spec.indexOf(':') + 1);
        const host = normalizeHost(spec.slice(0, spec.indexOf(':')));
        if (spec === last && words.length > 2) {
          if (REMOTE_SECRET_NAME.test(remotePath) || REMOTE_CONFIG_PATH.test(remotePath) || /\/(?:etc|\.ssh)\/?$/.test(remotePath)) {
            add(host, 'remote-config-change', 'Copies a file over a secret file, server setting, or SSH key on a remote server.');
          }
        } else if (REMOTE_SECRET_NAME.test(remotePath)) {
          add(host, 'remote-secret-access', 'Copies a file that usually holds secrets off a remote server.');
        }
      }
    }
  }
  return items;
}

// ------------------------------------------------- read-only judgement

const HARMLESS_REDIRECT = /^(?:\/dev\/(?:null|stdout|stderr|tty|fd\/\d+)|&?\d*|-)$/;
const REDIRECTION_RE = /^(\d*|&)(>>?|>\||<)(&?)(.*)$/s;

function isRedirection(word) {
  return REDIRECTION_RE.test(word);
}

// Files written by output redirections (>, >>, &>, 2>), skipping descriptor
// duplication (2>&1) and harmless targets such as /dev/null.
function redirectionTargets(argv) {
  const targets = [];
  for (let i = 0; i < argv.length; i += 1) {
    const match = REDIRECTION_RE.exec(argv[i]);
    if (!match || match[2] === '<') {
      if (match && !match[4]) i += 1;
      continue;
    }
    if (match[3] === '&' && /^\d*-?$/.test(match[4])) continue;
    let target = match[4];
    if (!target) {
      target = argv[i + 1];
      i += 1;
    }
    if (target && !HARMLESS_REDIRECT.test(target)) targets.push(target);
  }
  return targets;
}

// Files read through input redirection (< file, 0<file). The shell opens them and
// hands their content to the program, whatever the program is (cat, curl, ssh,
// an interpreter), so a protected file read this way is read. Here-documents,
// here-strings, process substitution and descriptor duplication are not files.
function inputRedirectionSources(argv) {
  const sources = [];
  for (let i = 0; i < argv.length; i += 1) {
    const match = REDIRECTION_RE.exec(argv[i]);
    if (!match || match[2] !== '<' || match[3] === '&') continue;
    let source = match[4];
    if (!source) {
      source = argv[i + 1];
      i += 1;
    }
    if (source && !/^[<(]/.test(source) && !HARMLESS_REDIRECT.test(source)) sources.push(source);
  }
  return sources;
}

const READ_ONLY_SUBCOMMANDS = {
  launchctl: /^(?:print|print-cache|print-disabled|list|blame|dumpstate|managerpid|managername|error)$/,
  git: /^(?:status|log|diff|show|rev-parse|ls-files|ls-tree|blame|grep|cat-file|describe|shortlog)$/,
  defaults: /^(?:read|read-type|domains|find|export)$/,
  plutil: /^(?:-lint|-p|-help)$/,
  brew: /^(?:list|info|outdated|search|doctor|config)$/,
  security: /^(?:list-keychains|default-keychain|show-keychain-info)$/
};

// launchctl subcommands that stop or unload a job; they never add one.
const LAUNCHCTL_STOP = /^(?:unload|bootout|disable|remove|kill|stop)$/;

// One-line Python or Node code (python3 -c, node -e/-p) that only reads files,
// such as json.load(open(p)) or fs.readFileSync(p). Anything that may write,
// start another program, or hide what it calls keeps the code treated as a
// possible writer. This is deliberately strict: when in doubt, it is a writer.
const INLINE_CODE_FLAG = { python: /^-[A-Za-z]*c$/, node: /^(?:-e|-p|--eval|--print)$/ };
const INLINE_WRITE_RE = new RegExp([
  'write', 'dump\\b', 'append', 'unlink', 'remove', 'rename', 'replace', 'rmtree', '\\brm', '\\bcp\\b', 'cpsync',
  '\\bmove', 'copy', 'chmod', 'chown', 'utime', 'truncate', 'mkdir', 'makedirs', 'touch', 'symlink', 'hardlink', '\\blink',
  'system', 'popen', 'subprocess', 'spawn', 'exec', 'eval', 'compile', 'import\\s*\\(', '__', 'importlib', 'getattr',
  'setattr', 'globals', '\\bvars\\b', 'chr\\s*\\(', 'fromcharcode', '\\\\x', '\\\\u', 'base64', 'codecs', 'decode',
  'pickle', 'marshal', 'socket', 'urllib', 'requests', 'http', 'fetch', 'shutil', 'child_process', 'binding', 'dlopen',
  'ctypes', 'ffi', 'mode\\s*=', '\\bfunction\\s*\\(', 'constructor', '\\bvm\\b', 'worker', '\\bmodule\\b', 'reflect',
  'require\\s*\\(\\s*[^\'"\\s]', '\\b(?:fs|os|process|globalthis|global)\\s*\\[', '\\[[^\\]]*\\+'
].join('|'), 'i');

function inlineCodeIsReadOnly(program, words) {
  const kind = program.replace(/\d+(?:\.\d+)*$/, '');
  const flag = INLINE_CODE_FLAG[kind];
  if (!flag) return false;
  const index = words.findIndex((word, i) => i > 0 && flag.test(word));
  if (index < 0 || typeof words[index + 1] !== 'string') return false;
  const code = words[index + 1]
    // open(p, 'r') and open(p, mode='rb') read; any other second argument may write.
    .replace(/,\s*(?:encoding\s*=\s*|\{\s*encoding\s*:\s*)?['"]utf-?8['"]\s*\}?\s*\)/gi, ')')
    .replace(/,\s*(?:mode\s*=\s*)?['"]r[bt]?['"]\s*\)/g, ')');
  if (INLINE_WRITE_RE.test(code)) return false;
  // open() with a second argument, open passed around or called with *args,
  // openSync, or any short string that looks like a write mode ('w', "a+").
  if (/open\s*\([^)]*,|open(?!\s*\()|open\s*\(\s*\*/i.test(code)) return false;
  if (/(['"`])(?![rbt]{1,2}\1)[rwaxbt+]{1,3}\1/i.test(code)) return false;
  if (/\bos\.(?!path\.|environ\b|getenv\b|listdir\b|stat\b|getcwd\b|scandir\b)/.test(code)) return false;
  if (/\bfs\.(?!readFileSync\b|existsSync\b|statSync\b|lstatSync\b|readdirSync\b)/.test(code)) return false;
  return true;
}

// launchd labels allowed by the install policy (allowStartupItems).
function startupLabelAllowed(label, patterns) {
  return patterns.some((pattern) => (pattern.endsWith('.*')
    ? label.length > pattern.length - 1 && label.startsWith(pattern.slice(0, -1))
    : label === pattern));
}

// Starting one of the user's own launchd jobs that the policy lists:
// `launchctl enable gui/<uid>/<label>`, or `launchctl load|bootstrap` of
// plists in ~/Library/LaunchAgents whose file name is an allowed label. Writing
// into ~/Library/LaunchAgents is still checked, so an agent cannot plant a new
// job under an allowed name without the user's approval.
function launchctlStartAllowed(words, options, cwd) {
  const patterns = Array.isArray(options.allowStartupItems) ? options.allowStartupItems : [];
  if (!patterns.length) return false;
  const sub = words[1];
  const args = words.slice(2);
  if (sub === 'enable') {
    const match = /^(?:gui|user)\/\d+\/([^/]+)$/.exec(args[0] || '');
    return args.length === 1 && !!match && startupLabelAllowed(match[1], patterns);
  }
  if (sub !== 'load' && sub !== 'bootstrap') return false;
  let rest = args;
  if (sub === 'bootstrap') {
    if (!/^(?:gui|user)\/\d+$/.test(rest[0] || '')) return false;
    rest = rest.slice(1);
  } else {
    rest = rest.filter((word) => word !== '-w' && word !== '-F');
  }
  if (!rest.length) return false;
  const home = toPosix(options.home || os.homedir());
  const agentsDir = path.join(home, 'Library', 'LaunchAgents');
  return rest.every((word) => {
    if (word.startsWith('-')) return false;
    let resolved = expandHome(toPosix(word), home);
    if (!path.isAbsolute(resolved)) {
      if (!cwd) return false;
      resolved = path.resolve(cwd, resolved);
    } else {
      resolved = path.resolve(resolved);
    }
    const base = path.basename(resolved);
    return path.dirname(resolved) === agentsDir && base.endsWith('.plist') &&
      startupLabelAllowed(base.slice(0, -'.plist'.length), patterns);
  });
}

// Is this simple command read-only for the files it names?
function commandIsReadOnly(words) {
  // Only variable assignments (S=~/.claude/settings.json): nothing is written.
  if (!words.length) return true;
  const program = programName(words[0] || '');
  if (READ_ONLY_PROGRAMS.has(program)) return true;
  if (program === 'launchctl' && LAUNCHCTL_STOP.test(words[1] || '')) return true;
  if (inlineCodeIsReadOnly(program, words)) return true;
  if (READ_ONLY_SUBCOMMANDS[program]) return READ_ONLY_SUBCOMMANDS[program].test(words[1] || '');
  if (program === 'sed' || program === 'awk') {
    return !words.some((word) => /^-[A-Za-z]*i|^--in-place|system\(|print\s*>|>\s*"/.test(word));
  }
  // A shell syntax check (bash -n) reads the script without running it.
  if (SHELLS.has(program)) return words.slice(1).some((word) => /^-[A-Za-z]*n[A-Za-z]*$/.test(word));
  if (program === 'find') return !words.some((word) => /^-(?:delete|exec|execdir|ok|okdir|fprint\w*)$/.test(word));
  return false;
}

const KEYCHAIN_READ =/^(?:find-generic-password|find-internet-password|find-certificate|dump-keychain|export)$/;

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

  // Variables assigned within the command (D=~/x; export D=~/x) are substituted,
  // so `D=<path> && rm -rf "$D"` is recognised. Values are resolved in order and
  // may refer to earlier ones. Variables from the environment are not known.
  const vars = new Map([['HOME', toPosix(options.home || os.homedir())]]);
  const substitute = (word) => String(word).replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g,
    (whole, braced, bare) => (vars.has(braced || bare) ? vars.get(braced || bare) : whole));
  for (const argv of commands) {
    const first = programName(argv[0] || '');
    const start = first === 'export' || first === 'local' || first === 'declare' ? 1 : 0;
    for (const word of argv.slice(start)) {
      const assignment = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s.exec(word);
      if (!assignment) break;
      vars.set(assignment[1], substitute(assignment[2]));
    }
  }

  // Environment dumps or .env files sent anywhere over the network.
  const sendsToNetwork = allPrograms.some((program) => NETWORK_SENDERS.has(program));
  if (sendsToNetwork) {
    const dumpsEnv = commands.some((argv) => {
      // Not stripWrappers: a bare `env` is the dump itself, not a wrapper.
      const words = argv.filter((word) => !/^[A-Za-z_][A-Za-z0-9_]*=/.test(word));
      const program = programName(words[0] || '');
      const args = words.slice(1).filter((word, index, all) =>
        !/^\d*[<>]/.test(word) && !(index > 0 && /^\d*[<>]{1,2}&?$/.test(all[index - 1])));
      return ENV_DUMPERS.has(program) && args.length === 0 || program === 'export' && args[0] === '-p';
    });
    const touchesDotenv = commands.some((argv) => argv.some((word) => DOTENV_RE.test(word)));
    if (dumpsEnv || touchesDotenv) {
      add('command:secrets-to-network', 'secret-access', 'Sends environment variables or a .env file over the network; they usually hold API keys and passwords.');
    }
  }

  // `cd` inside the command changes where later relative paths point.
  let currentCwd = options.cwd && path.isAbsolute(toPosix(options.cwd)) ? toPosix(options.cwd) : null;
  // After a cd, bare file names (cat id_ed25519) may name protected files too.
  let movedDirectory = false;

  for (const rawArgv of commands) {
    const argv = rawArgv.map(substitute);
    const words = stripWrappers(argv);
    const program = programName(words[0] || '');
    if (program === 'cd') {
      const target = words[1] && words[1] !== '-' ? expandHome(toPosix(words[1]), toPosix(options.home || os.homedir())) : toPosix(options.home || os.homedir());
      currentCwd = path.isAbsolute(target) ? path.resolve(target) : currentCwd ? path.resolve(currentCwd, target) : null;
      movedDirectory = true;
      continue;
    }
    const pathOptions = { ...options, cwd: currentCwd };

    if (AGENT_CONFIG_CLIS.test(program) && words[1] === 'mcp' && /^(?:add|add-json|add-from-claude-desktop|remove|login)$/.test(words[2] || '')) {
      add('command:agent-or-gate-config', 'guard-tamper', 'Adds or removes an MCP server for an AI agent; a new server gets access to your tools and data.');
    }
    if (program === 'git' && words.some((word) => /^core\.hookspath$/i.test(word)) && words[1] === 'config' && words.length > 3) {
      add('command:startup-item', 'persistence-change', 'Points git at a different hooks directory, which runs code on every commit or checkout.');
    }

    const trustdexIndex = argv.findIndex((word) => /^trustdex(?:\.mjs)?$/i.test(programName(word)));
    const trustdexArgs = trustdexIndex >= 0 ? argv.slice(trustdexIndex + 1) : [];
    // Listing what is waiting is harmless; approving is for the person only.
    const listsOnly = trustdexArgs.length === 2 && /^allow-once$/i.test(trustdexArgs[0]) && trustdexArgs[1] === '--list';
    if (trustdexIndex >= 0 && !listsOnly && trustdexArgs.some((word) => /^allow-once$/i.test(word))) {
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
    const allowedStart = program === 'launchctl' && launchctlStartAllowed(words, options, currentCwd);
    if (program === 'launchctl' && /^(?:load|bootstrap|enable|submit)$/.test(words[1] || '') && !allowedStart) {
      add('command:startup-item', 'persistence-change', 'Loads a background job with launchctl.');
    }
    if (program === 'osascript' && words.some((word) => /login item/i.test(word))) {
      add('command:startup-item', 'persistence-change', 'Adds a login item.');
    }

    // Each simple command is judged on its own: a read-only command touching a
    // protected file stays allowed even when other, unrelated commands in the
    // same line write elsewhere. Writes through redirection are checked by
    // target, and redirections to /dev/null or another descriptor are harmless.
    const readOnly = commandIsReadOnly(words) || allowedStart;
    const existenceOnly = EXISTENCE_PROGRAMS.has(program);
    const redirectTargets = redirectionTargets(argv);
    for (const target of redirectTargets) {
      const kinds = classifyPath(target, paths, pathOptions);
      if (kinds.includes('config')) add('command:agent-or-gate-config', 'guard-tamper', 'Changes agent settings, MCP configuration, or TrustDex itself; a changed gate can no longer protect you.');
      if (kinds.includes('persistence')) add('command:startup-item', 'persistence-change', 'Adds or changes something that runs automatically at login or on a schedule.');
      if (kinds.includes('secret')) add('command:credential-store', 'secret-access', 'Writes into a credential store.');
    }
    const inputSources = inputRedirectionSources(argv);
    for (const source of inputSources) {
      if (classifyPath(source, paths, pathOptions).includes('secret')) {
        add('command:credential-store', 'secret-access', 'Feeds a credential store such as an SSH key or token file into a program through input redirection (<).');
      }
    }
    // For ssh, words after the host are a command for the remote computer, where
    // ~ and paths mean something else; they are checked by remoteFindings.
    const remote = program === 'ssh' ? sshRemote(words) : null;
    const localWords = remote ? argv.slice(0, argv.length - words.length + remote.hostIndex + 1) : argv;
    for (const word of localWords) {
      if (isRedirection(word)) continue;
      const candidates = pathCandidates(word);
      if (movedDirectory && currentCwd && /^[\w@][\w.@+-]*$/.test(word) && word !== words[0]) candidates.push(word);
      for (const candidate of candidates) {
        // Redirection files are judged above: output targets as writes, input sources as reads.
        if (redirectTargets.includes(candidate) || inputSources.includes(candidate)) continue;
        const kinds = classifyPath(candidate, paths, pathOptions);
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
  items.push(...remoteFindings(text, commands));
  return items;
}
