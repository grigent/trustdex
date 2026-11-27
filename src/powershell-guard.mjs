// Guards for Claude Code's PowerShell tool.
//
// The PowerShell tool runs commands in PowerShell instead of Bash (on Windows,
// and elsewhere when it is switched on). These checks apply the same rules as
// the Bash guard to PowerShell syntax:
//
// - reading credential stores (SSH keys, tokens, browser logins, the Windows
//   credential vault) is denied, except for existence checks such as Test-Path;
// - changing agent settings, MCP configuration or TrustDex itself is denied;
// - adding startup items (Startup folder, Run registry keys, scheduled tasks,
//   services, PowerShell profiles) asks;
// - running downloaded or decoded content (iwr ... | iex, -EncodedCommand) is denied;
// - sending environment variables or .env files over the network is denied.
//
// External programs started from PowerShell (git, ssh, npm, claude, ...) are
// handed to the Bash guard and the package checks with their arguments quoted,
// so they get exactly the same treatment as in Bash. A command that cannot be
// parsed is denied when it mentions protected files or risky tools.
//
// These are static checks of the command text. They do not follow values that
// are computed at run time, and they cannot see what a script file does.

import os from 'node:os';
import nodePath from 'node:path';

import { classifyPath, canonicalGuardPath, guardBashCommand, signalItem, toPosix } from './agent-guard.mjs';

const path = nodePath.posix;

export class PowerShellParseError extends Error {}

// Built-in aliases (Windows PowerShell 5.1 and PowerShell 7) for the cmdlets the
// checks care about. `curl` and `wget` are aliases only in 5.1; they are network
// senders either way. `sc` is Set-Content in 5.1; `sc.exe` is the service tool.
const ALIASES = new Map(Object.entries({
  cat: 'get-content', type: 'get-content', gc: 'get-content',
  ls: 'get-childitem', dir: 'get-childitem', gci: 'get-childitem',
  cp: 'copy-item', copy: 'copy-item', cpi: 'copy-item',
  mv: 'move-item', move: 'move-item', mi: 'move-item',
  rm: 'remove-item', del: 'remove-item', erase: 'remove-item', ri: 'remove-item', rd: 'remove-item', rmdir: 'remove-item',
  sc: 'set-content', ac: 'add-content', clc: 'clear-content',
  ni: 'new-item', md: 'new-item', mkdir: 'new-item',
  ren: 'rename-item', rni: 'rename-item', si: 'set-item', cli: 'clear-item',
  sls: 'select-string', gi: 'get-item', gp: 'get-itemproperty', sp: 'set-itemproperty',
  iwr: 'invoke-webrequest', curl: 'invoke-webrequest', wget: 'invoke-webrequest', irm: 'invoke-restmethod',
  iex: 'invoke-expression', icm: 'invoke-command', ii: 'invoke-item',
  tee: 'tee-object', echo: 'write-output', write: 'write-output',
  select: 'select-object', where: 'where-object', '?': 'where-object', foreach: 'foreach-object', '%': 'foreach-object',
  saps: 'start-process', start: 'start-process', sajb: 'start-job',
  rvpa: 'resolve-path', fhx: 'format-hex', ipcsv: 'import-csv', epcsv: 'export-csv',
  cd: 'set-location', chdir: 'set-location', sl: 'set-location', pushd: 'push-location', popd: 'pop-location'
}));

// Cmdlets that only report that a path exists or what it is called.
const EXISTENCE = new Set([
  'test-path', 'get-childitem', 'get-item', 'resolve-path', 'split-path', 'join-path', 'get-acl', 'get-filehash',
  'write-output', 'write-host', 'set-location', 'push-location', 'pop-location', 'out-null'
]);

// Cmdlets that read or format data without writing files.
const READ_ONLY = new Set([
  ...EXISTENCE, 'get-content', 'select-string', 'import-csv', 'import-clixml', 'format-hex', 'get-itemproperty',
  'convertfrom-json', 'convertto-json', 'convertfrom-csv', 'convertto-csv', 'select-object', 'where-object',
  'foreach-object', 'sort-object', 'group-object', 'measure-object', 'compare-object', 'get-member', 'test-json',
  'out-string', 'out-host', 'format-list', 'format-table', 'format-wide', 'get-date', 'get-location', 'get-command',
  'get-process', 'get-service', 'get-scheduledtask', 'get-psdrive', 'get-variable', 'get-help'
]);

const NETWORK_CMDLETS = new Set(['invoke-webrequest', 'invoke-restmethod', 'send-mailmessage', 'start-bitstransfer']);
const NETWORK_EXTERNAL = new Set(['curl', 'wget', 'nc', 'ncat', 'netcat', 'socat', 'scp', 'sftp', 'rsync', 'ftp', 'telnet']);
const DOWNLOAD_TEXT = /net\.webclient|\.download(?:string|data|file)\b|system\.net\.http|httpclient|invoke-webrequest|invoke-restmethod|start-bitstransfer/i;
const UPLOAD_TEXT = /net\.webclient|\.upload(?:string|data|file|values)\b|system\.net\.http|httpclient/i;
const SHELL_PROGRAMS = new Set(['powershell', 'pwsh', 'cmd', 'bash', 'sh', 'wsl', 'python', 'python3', 'py', 'node']);
const ENCODED_FLAG = /^[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)$/i;
const RUN_KEY = /\\(?:run|runonce|runservices|runservicesonce)(?:\\|$)|\\winlogon(?:\\|$)|\\image file execution options\\|\\policies\\explorer\\run(?:\\|$)/i;
const REGISTRY_WRITERS = new Set(['new-itemproperty', 'set-itemproperty', 'new-item', 'set-item', 'copy-itemproperty', 'move-itemproperty', 'rename-itemproperty']);
const TASK_CMDLETS = new Set(['register-scheduledtask', 'set-scheduledtask', 'new-service', 'set-service', 'register-scheduledjob', 'register-wmievent', 'register-ciminidicationevent', 'register-cimindicationevent']);
const PACKAGE_PROGRAMS = new Set(['npm', 'npx', 'pnpm', 'pnpx', 'yarn', 'bun', 'bunx', 'uv', 'uvx', 'pipx', 'poetry', 'pdm']);
const PROTECTED_TEXT = /\.claude|\.mcp\.json|\.codex|\.gemini|\.ssh|\.aws|\.npmrc|\.netrc|\.git-credentials|\.kube|\.docker|credentials|login data|cookies|trustdex|\\run\b|startup|\$profile|schtasks|scheduledtask|new-service|invoke-expression|\biex\b|encodedcommand|frombase64string|downloadstring|\b(?:npm|npx|pnpm|yarn|bun|pip[0-9.]*|uv|uvx|pipx|poetry|pdm)\b/i;

// ------------------------------------------------------------ lexer

// Splits a PowerShell command into simple statements. Statements end at ; | &&
// || newlines and brackets, so the inside of (...), $(...), @(...) and {...} is
// checked as statements of its own. Words keep their text without quotes; a
// word records whether it was quoted. Redirection targets are collected per
// statement. Throws PowerShellParseError on unterminated quotes, here-strings or
// block comments.
export function lexPowerShell(input) {
  const text = String(input ?? '');
  const statements = [];
  let words = [];
  let redirects = [];
  let word = '';
  let hasWord = false;
  let quoted = false;
  let pendingRedirect = false;
  // Whether the statement being read receives the previous one's output (|).
  let pipedFrom = false;

  const endWord = () => {
    if (hasWord && !(!quoted && (word === '$' || word === '@'))) {
      if (pendingRedirect) {
        redirects.push(word);
        pendingRedirect = false;
      } else {
        words.push({ text: word, quoted });
      }
    }
    word = '';
    hasWord = false;
    quoted = false;
  };
  const endStatement = (piped = false) => {
    endWord();
    if (pendingRedirect) throw new PowerShellParseError('A redirection has no target.');
    if (words.length || redirects.length) statements.push({ words, redirects, pipedFrom });
    words = [];
    redirects = [];
    pipedFrom = piped;
  };

  let i = 0;
  while (i < text.length) {
    const c = text[i];
    const next = text[i + 1];

    // Here-strings: @' or @" at the start of a word, then a line break.
    if (!hasWord && c === '@' && (next === "'" || next === '"') && /^\r?\n/.test(text.slice(i + 2))) {
      const close = `\n${next}@`;
      const end = text.indexOf(close, i + 2);
      if (end < 0) throw new PowerShellParseError('Unterminated here-string.');
      word += text.slice(text.indexOf('\n', i) + 1, end).replace(/\r$/, '');
      hasWord = true;
      quoted = true;
      i = end + close.length;
      continue;
    }
    // Comments.
    if (!hasWord && c === '<' && next === '#') {
      const end = text.indexOf('#>', i + 2);
      if (end < 0) throw new PowerShellParseError('Unterminated block comment.');
      i = end + 2;
      continue;
    }
    if (!hasWord && c === '#') {
      while (i < text.length && text[i] !== '\n') i += 1;
      continue;
    }
    // Backtick escapes and line continuation outside quotes.
    if (c === '`') {
      if (next === '\n') { i += 2; continue; }
      if (next === '\r' && text[i + 2] === '\n') { i += 3; continue; }
      if (next === undefined) throw new PowerShellParseError('Dangling escape character.');
      word += next;
      hasWord = true;
      i += 2;
      continue;
    }
    if (c === "'") {
      let j = i + 1;
      let value = '';
      for (;;) {
        if (j >= text.length) throw new PowerShellParseError('Unterminated single-quoted string.');
        if (text[j] === "'") {
          if (text[j + 1] === "'") { value += "'"; j += 2; continue; }
          break;
        }
        value += text[j];
        j += 1;
      }
      word += value;
      hasWord = true;
      quoted = true;
      i = j + 1;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      let value = '';
      const escapes = { 0: '\0', a: '\x07', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v', e: '\x1b' };
      for (;;) {
        if (j >= text.length) throw new PowerShellParseError('Unterminated double-quoted string.');
        const d = text[j];
        if (d === '`') {
          if (j + 1 >= text.length) throw new PowerShellParseError('Unterminated double-quoted string.');
          value += escapes[text[j + 1]] ?? text[j + 1];
          j += 2;
          continue;
        }
        if (d === '"') {
          if (text[j + 1] === '"') { value += '"'; j += 2; continue; }
          break;
        }
        value += d;
        j += 1;
      }
      word += value;
      hasWord = true;
      quoted = true;
      i = j + 1;
      continue;
    }
    // ${braced variable names} stay part of the word.
    if (c === '$' && next === '{') {
      const end = text.indexOf('}', i + 2);
      if (end < 0) throw new PowerShellParseError('Unterminated variable name.');
      word += text.slice(i, end + 1);
      hasWord = true;
      i = end + 1;
      continue;
    }
    // Redirection: >, >>, 2>, *>, with 2>&1 style merges ignored.
    const redirect = /^(?:[1-6*])?>>?(?:&[1-6])?/.exec(text.slice(i));
    if (redirect && (!hasWord || /^>/.test(redirect[0]))) {
      if (!/&[1-6]$/.test(redirect[0]) && (!hasWord || !/^\d$/.test(word))) {
        endWord();
        pendingRedirect = true;
      } else {
        word = '';
        hasWord = false;
      }
      i += redirect[0].length;
      continue;
    }
    if (c === ' ' || c === '\t' || c === ',' || c === '\u00a0') {
      endWord();
      i += 1;
      continue;
    }
    if (c === '|') {
      if (next === '|') { endStatement(); i += 2; continue; }
      endStatement(true);
      i += 1;
      continue;
    }
    if (c === '&') {
      if (next === '&') { endStatement(); i += 2; continue; }
      if (hasWord) { endStatement(); i += 1; continue; }
      // The call operator: & 'C:\tools\x.exe' args
      words.push({ text: '&', quoted: false, call: true });
      i += 1;
      continue;
    }
    if (c === ';' || c === '\n' || c === '\r' || c === '(' || c === ')' || c === '{' || c === '}') {
      endStatement();
      i += 1;
      continue;
    }
    word += c;
    hasWord = true;
    i += 1;
  }
  endStatement();
  return statements;
}

// ------------------------------------------------------------ helpers

function commandName(word) {
  const raw = String(word.text);
  const base = raw.replace(/\\/g, '/').split('/').pop().toLowerCase();
  const external = /\.(?:exe|cmd|bat|com)$/.test(base);
  const bare = base.replace(/\.(?:exe|cmd|bat|com)$/, '');
  if (!external && ALIASES.has(bare)) return { name: ALIASES.get(bare), cmdlet: true };
  if (!external && /^[a-z]+-[a-z][\w]*$/.test(bare)) return { name: bare, cmdlet: true };
  return { name: bare, cmdlet: false };
}

// [Type]::Method calls: what they do with the paths given to them.
function methodKind(name) {
  if (!/^\[[^\]]+\]::/.test(name)) return null;
  if (/::(?:exists|getattributes|getfilename|getfilenamewithoutextension|getdirectoryname|getextension|combine|getfullpath|join)$/i.test(name)) return 'exists';
  if (/::(?:read\w*|openread|opentext)$/i.test(name)) return 'read';
  if (/::(?:frombase64string|tobase64string|getstring|getbytes|tostring|parse|now|getenvironmentvariable)$/i.test(name)) return 'data';
  return 'write';
}

function looksLikeCommand(word) {
  if (!word || word.quoted || word.call) return Boolean(word?.call);
  const base = String(word.text).replace(/\\/g, '/').split('/').pop().toLowerCase();
  return ALIASES.has(base) || /^[a-z]+-[a-z]\w*$/.test(base) || methodKind(word.text) !== null || /\.(?:exe|cmd|bat|com)$/.test(base);
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

function makeVars(home) {
  const h = toPosix(home).replace(/^\/(?=[A-Za-z]:)/, '');
  return new Map([
    ['home', h], ['env:home', h], ['env:userprofile', h],
    ['env:appdata', `${h}/AppData/Roaming`], ['env:localappdata', `${h}/AppData/Local`],
    ['env:programdata', 'C:/ProgramData'], ['env:programfiles', 'C:/Program Files'], ['env:systemdrive', 'C:']
  ]);
}

function substitute(text, vars) {
  return String(text).replace(/\$\{([^}]+)\}|\$((?:env:)?[A-Za-z_][\w]*)/gi, (whole, braced, bare) => {
    const key = String(braced || bare).toLowerCase();
    return vars.has(key) ? vars.get(key) : whole;
  });
}

function parameterValue(word) {
  const match = /^-[A-Za-z][\w-]*:(.+)$/s.exec(word);
  return match ? match[1] : null;
}

function isParameter(word) {
  return /^-[A-Za-z]/.test(word) && !/^-\d/.test(word);
}

// ------------------------------------------------------------ guard

// Returns { items, externalCommands }. `externalCommands` are Bash-quoted
// versions of external program calls (npm, pip, ...) for the package checks.
export function guardPowerShellCommand(command, paths, options = {}) {
  const items = [];
  const add = (name, signal, reason, action) => {
    if (items.some((item) => item.signals[0] === signal)) return;
    const item = signalItem(name, signal, reason);
    if (action) item.action = action;
    items.push(item);
  };
  const text = String(command ?? '');
  const home = options.home || os.homedir();
  const platform = options.platform;
  const externalCommands = [];

  let statements;
  try {
    statements = lexPowerShell(text);
  } catch (error) {
    if (!(error instanceof PowerShellParseError)) throw error;
    if (PROTECTED_TEXT.test(text)) {
      add('command:unparsed', 'unparseable-guarded-command', 'The PowerShell command could not be parsed and refers to protected files or risky tools.');
    }
    return { items, externalCommands };
  }

  const vars = makeVars(home);
  let cwd = typeof options.cwd === 'string' && options.cwd ? options.cwd : null;
  const psStatements = [];
  const programs = [];

  for (const statement of statements) {
    // Variables are substituted before anything else, so $env:USERPROFILE and
    // names assigned earlier in the same command resolve to their paths.
    let words = statement.words.map((word) => ({ ...word, text: substitute(word.text, vars) }));
    // $name = value: a literal value (a string or a path, possibly joined with +)
    // is remembered; a command after = is checked like any other command.
    const head = words.length ? /^\$((?:env:)?[A-Za-z_]\w*)(?:(=)(.*))?$/s.exec(statement.words[0].text) : null;
    let rest = null;
    if (head && head[2] !== undefined) {
      rest = head[3] !== '' ? [{ text: substitute(head[3], vars), quoted: words[0].quoted }, ...words.slice(1)] : words.slice(1);
    } else if (head && words[1]?.text === '=') {
      rest = words.slice(2);
    } else if (head && words[1]?.text.startsWith('=') && !words[1].quoted) {
      rest = [{ text: words[1].text.slice(1), quoted: false }, ...words.slice(2)].filter((w) => w.text !== '' || w.quoted);
    }
    if (rest) {
      if (!rest.length || !looksLikeCommand(rest[0])) {
        const value = rest.filter((w) => w.text !== '+').map((w) => w.text).join('');
        if (value) vars.set(head[1].toLowerCase(), toPosix(value).replace(/^\/(?=[A-Za-z]:)/, ''));
        psStatements.push({ kind: 'data', name: null, args: value ? [value] : [], redirects: statement.redirects, cwd });
        continue;
      }
      words = rest;
    }
    if (!words.length) {
      psStatements.push({ kind: 'data', name: null, args: [], redirects: statement.redirects, cwd });
      continue;
    }
    let called = false;
    if (words[0].call || words[0].text === '.') {
      called = true;
      words = words.slice(1);
      if (!words.length) continue;
    }
    const first = words[0];
    const args = words.slice(1).map((w) => w.text);
    const method = methodKind(first.text);
    if (method) {
      psStatements.push({ kind: 'method', name: first.text.toLowerCase(), method, args, redirects: statement.redirects, cwd, pipedFrom: statement.pipedFrom });
      programs.push(first.text.toLowerCase());
      continue;
    }
    if (!called && (first.quoted || /^\$/.test(first.text) || /^-?\d/.test(first.text))) {
      psStatements.push({ kind: 'data', name: null, args: words.map((w) => w.text), redirects: statement.redirects, cwd });
      continue;
    }
    const { name, cmdlet } = commandName(first);
    programs.push(name);
    const entry = { kind: cmdlet ? 'cmdlet' : 'external', name, args, words: words.map((w) => w.text), redirects: statement.redirects, cwd, pipedFrom: statement.pipedFrom };
    psStatements.push(entry);
    if (cmdlet && (name === 'set-location' || name === 'push-location')) {
      const target = args.find((arg) => !isParameter(arg)) ?? parameterValue(args.find((arg) => parameterValue(arg)) ?? '');
      cwd = target ? canonicalGuardPath(target, { cwd, home, platform }).replace(/^\/(?=[A-Za-z]:)/, '') : null;
    } else if (cmdlet && name === 'pop-location') {
      cwd = null;
    }
  }

  // ---- whole-command signals

  const lowerText = text.toLowerCase();
  const has = (name) => programs.includes(name);
  const downloads = programs.some((name) => NETWORK_CMDLETS.has(name) && name !== 'send-mailmessage') || DOWNLOAD_TEXT.test(text) ||
    psStatements.some((s) => s.kind === 'external' && (s.name === 'curl' || s.name === 'wget'));
  const runsText = has('invoke-expression') || /\[scriptblock\]::create/i.test(text);
  const pipedIntoShell = psStatements.some((s, index) => s.pipedFrom && s.kind === 'external' && SHELL_PROGRAMS.has(s.name) &&
    psStatements.slice(0, index).some((before) => (before.kind === 'cmdlet' && NETWORK_CMDLETS.has(before.name)) || (before.kind === 'external' && (before.name === 'curl' || before.name === 'wget'))));
  if ((runsText && downloads) || pipedIntoShell) {
    add('command:download-to-interpreter', 'pipe-to-shell', 'Downloaded content is executed directly by PowerShell or another interpreter without review.', 'block');
  }
  const encoded = psStatements.some((s) => s.kind === 'external' && (s.name === 'powershell' || s.name === 'pwsh') && s.args.some((arg) => ENCODED_FLAG.test(arg)));
  if (encoded || (runsText && /frombase64string|\.getstring\(/i.test(text))) {
    add('command:decoded-to-interpreter', 'obfuscated-execution', 'Decodes hidden content (base64 or an encoded command) and runs it as a program, a common way to hide malicious commands.', 'block');
  }

  // Environment variables or .env files sent over the network.
  const sends = programs.some((name) => NETWORK_CMDLETS.has(name) || NETWORK_EXTERNAL.has(name)) || UPLOAD_TEXT.test(text);
  if (sends) {
    const dumpsEnv = psStatements.some((s) => (s.kind === 'cmdlet' && ['get-childitem', 'get-item'].includes(s.name) && s.args.some((arg) => /^env:[\\/]?\*?$/i.test(arg)))) ||
      /\[(?:system\.)?environment\]::getenvironmentvariables\(/i.test(text) || /\bgci\s+env:|\bls\s+env:|\bdir\s+env:/i.test(lowerText);
    const dotenv = psStatements.some((s) => [...(s.args || []), ...(s.redirects || [])].some((arg) => /(?:^|[\\/])\.env(?:\.(?!example\b|sample\b|template\b|dist\b)[\w-]+)?$/i.test(arg)));
    if (dumpsEnv || dotenv) {
      add('command:secrets-to-network', 'secret-access', 'Sends environment variables or a .env file over the network; they usually hold API keys and passwords.');
    }
  }

  // Scheduled tasks, services and Run registry keys start programs automatically.
  const registryWrite = psStatements.some((s) => (s.kind === 'cmdlet' && REGISTRY_WRITERS.has(s.name) && s.args.some((arg) => RUN_KEY.test(arg.replace(/\//g, '\\')))) ||
    (s.kind === 'external' && s.name === 'reg' && /^(?:add|import|copy|restore|load)$/i.test(s.args[0] || '') && s.args.some((arg) => RUN_KEY.test(arg.replace(/\//g, '\\')))));
  const tasks = psStatements.some((s) => (s.kind === 'cmdlet' && TASK_CMDLETS.has(s.name)) ||
    (s.kind === 'external' && s.name === 'schtasks' && s.args.some((arg) => /^[-/](?:create|change)$/i.test(arg))) ||
    // PowerShell 7 dropped the `sc` alias, so there `sc create` runs the service tool.
    ((s.kind === 'external' ? s.name === 'sc' : /^sc$/i.test(s.words?.[0] || '')) && /^(?:create|config)$/i.test(s.args[0] || '')) ||
    (s.kind === 'external' && s.name === 'reg' && /^import$/i.test(s.args[0] || '')));
  if (registryWrite || tasks) {
    add('command:startup-item', 'persistence-change', 'Adds or changes something that runs automatically (a scheduled task, service, or Run registry key).');
  }

  // ---- files named by PowerShell statements

  // A command touching a protected file counts as a write unless every
  // PowerShell statement in it only reads; a credential path counts as read
  // unless every statement only checks existence. Being strict across the whole
  // command covers paths passed between statements, as in Get-Content (Join-Path ...).
  const psLevel = psStatements.filter((s) => s.kind !== 'external');
  const psPrograms = psLevel.filter((s) => s.kind !== 'data').map((s) => (s.kind === 'method' ? `method:${s.method}` : s.name));
  const allExistence = psPrograms.every((name) => EXISTENCE.has(name) || name === 'method:exists' || name === 'method:data');
  const allReadOnly = psPrograms.every((name) => READ_ONLY.has(name) || name === 'method:exists' || name === 'method:read' || name === 'method:data');
  const writesSomething = !allReadOnly;
  const classify = (candidate, at) => classifyPath(candidate, paths, { cwd: at, home, platform });

  // Join-Path a b c names one more path.
  const joined = [];
  for (const s of psLevel) {
    if ((s.kind === 'cmdlet' && s.name === 'join-path') || (s.kind === 'method' && /::combine$/i.test(s.name))) {
      const parts = s.args.filter((arg) => !isParameter(arg)).slice(0, 4);
      if (parts.length >= 2) joined.push({ value: parts.join('/'), cwd: s.cwd });
    }
  }
  const candidates = [];
  for (const s of psLevel) {
    for (const arg of s.args || []) {
      if (isParameter(arg)) {
        const value = parameterValue(arg);
        if (value) candidates.push({ value, cwd: s.cwd });
        continue;
      }
      candidates.push({ value: arg, cwd: s.cwd });
    }
  }
  candidates.push(...joined);
  const profileWrite = writesSomething && psStatements.some((s) => [...(s.args || []), ...(s.redirects || [])].some((arg) => /^\$profile\b/i.test(arg)));
  if (profileWrite) add('command:startup-item', 'persistence-change', 'Changes a PowerShell profile, which runs in every new PowerShell session.');

  for (const { value, cwd: at } of candidates) {
    if (!value || /^\$/.test(value)) continue;
    const kinds = classify(value, at);
    if (kinds.includes('secret') && !allExistence) {
      add('command:credential-store', 'secret-access', 'Reads or copies a credential store such as an SSH key, token file, browser login data, or the Windows credential vault.');
    }
    if (kinds.includes('config') && writesSomething) {
      add('command:agent-or-gate-config', 'guard-tamper', 'Changes agent settings, MCP configuration, or TrustDex itself; a changed gate can no longer protect you.');
    }
    if (kinds.includes('persistence') && writesSomething) {
      add('command:startup-item', 'persistence-change', 'Adds or changes something that runs automatically at sign-in or in every new shell.');
    }
  }
  for (const s of psStatements) {
    for (const target of s.redirects || []) {
      if (/^\$null$/i.test(target)) continue;
      if (/^\$profile\b/i.test(target)) {
        add('command:startup-item', 'persistence-change', 'Changes a PowerShell profile, which runs in every new PowerShell session.');
        continue;
      }
      const kinds = classify(target, s.cwd);
      if (kinds.includes('config')) add('command:agent-or-gate-config', 'guard-tamper', 'Changes agent settings, MCP configuration, or TrustDex itself; a changed gate can no longer protect you.');
      if (kinds.includes('persistence')) add('command:startup-item', 'persistence-change', 'Adds or changes something that runs automatically at sign-in or in every new shell.');
      if (kinds.includes('secret')) add('command:credential-store', 'secret-access', 'Writes into a credential store.');
    }
  }

  // ---- external programs: same checks as in Bash

  for (const s of psStatements.filter((entry) => entry.kind === 'external')) {
    const quotedCommand = [s.name, ...s.args].map(shellQuote).join(' ');
    for (const item of guardBashCommand(quotedCommand, paths, { ...options, cwd: s.cwd ? s.cwd : options.cwd, home, platform })) {
      if (!items.some((existing) => existing.signals[0] === item.signals[0])) items.push(item);
    }
    const isPip = /^pip[0-9.]*$/.test(s.name) || ((s.name === 'python' || s.name === 'python3' || s.name === 'py') && s.args.includes('-m') && /^pip/.test(s.args[s.args.indexOf('-m') + 1] || ''));
    if (PACKAGE_PROGRAMS.has(s.name) || isPip) externalCommands.push(quotedCommand);
  }

  return { items, externalCommands };
}
