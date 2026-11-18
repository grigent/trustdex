// Offline parser for shell commands that install or run packages.
//
// It recognises npm, pnpm, yarn, bun, npx/bunx/pnpm dlx, pip, uv/uvx, pipx, poetry
// and pdm commands, and download-to-interpreter pipelines such as `curl ... | sh`.
// It never executes anything and never reports raw argument values: registry and
// URL arguments can carry credentials, so only structural facts leave this module.
//
// This is a best-effort lexer, not a full shell. Commands it cannot lex are
// reported as `unparseable-command` when they mention a package tool or downloader,
// so callers can fail toward review instead of silently allowing them.

const PACKAGE_TOOL_RE = /\b(?:npm|npx|pnpm|pnpx|yarn|bun|bunx|pip[0-9.]*|uv|uvx|pipx|poetry|pdm|curl|wget)\b/;

const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'fish']);
const INTERPRETERS = new Set([...SHELLS, 'python', 'perl', 'ruby', 'node', 'php']);
const DOWNLOADERS = new Set(['curl', 'wget']);
const PREFIX_COMMANDS = new Set(['sudo', 'doas', 'command', 'env', 'time', 'exec', 'nohup', 'nice', 'builtin']);
const PREFIX_VALUE_FLAGS = new Set(['-u', '-g', '-n', '-C', '-h', '-p', '-U']);
const MAX_DEPTH = 4;

export class CommandParseError extends Error {}

// ------------------------------------------------------------ heredocs

const HEREDOC_RE = /(?<!<)<<(?!<)(-?)\s*(?:'([^'\n]+)'|"([^"\n]+)"|\\?([A-Za-z_][A-Za-z0-9_.-]*))/g;

// Removes here-document bodies from a command so their text is not lexed as
// shell syntax. Each body is returned with the program that receives it, so a
// body fed to a shell (bash <<'EOF') can be analysed as a script while a body
// fed to git, cat or tee stays data. An unterminated body runs to the end.
export function splitHeredocs(text) {
  const lines = String(text).split('\n');
  const kept = [];
  const bodies = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    kept.push(line);
    i += 1;
    for (const match of line.matchAll(HEREDOC_RE)) {
      const strip = match[1] === '-';
      const delimiter = match[2] ?? match[3] ?? match[4];
      const body = [];
      while (i < lines.length) {
        const current = strip ? lines[i].replace(/^\t+/, '') : lines[i];
        i += 1;
        if (current === delimiter) break;
        body.push(lines[i - 1]);
      }
      const segment = line.slice(0, match.index).split(/&&|\|\||;|\||\(/).pop().trim();
      const words = segment.split(/\s+/).filter((word) => word && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(word));
      while (words.length && /^(?:sudo|doas|command|env|time|exec|nohup|nice)$/.test(words[0].split('/').pop())) words.shift();
      bodies.push({ program: programName(words[0] || ''), args: words.slice(1), text: body.join('\n') });
    }
  }
  return { text: kept.join('\n'), bodies };
}

// ------------------------------------------------------------ lexer

const OPERATORS = ['&&', '||', '|&', ';;', '|', ';', '&', '\n'];

export function lexShell(text) {
  const tokens = [];
  let word = null;
  let i = 0;
  const push = () => {
    if (word !== null) tokens.push({ type: 'word', value: word });
    word = null;
  };
  while (i < text.length) {
    const ch = text[i];
    if (ch === '\\') {
      if (text[i + 1] === '\n') { i += 2; continue; }
      word = (word ?? '') + (text[i + 1] ?? '');
      i += 2;
      continue;
    }
    if (ch === "'") {
      const end = text.indexOf("'", i + 1);
      if (end < 0) throw new CommandParseError('unterminated single quote');
      word = (word ?? '') + text.slice(i + 1, end);
      i = end + 1;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      let value = '';
      while (j < text.length && text[j] !== '"') {
        if (text[j] === '\\' && j + 1 < text.length && '"\\$`\n'.includes(text[j + 1])) {
          value += text[j + 1];
          j += 2;
        } else {
          value += text[j];
          j += 1;
        }
      }
      if (j >= text.length) throw new CommandParseError('unterminated double quote');
      word = (word ?? '') + value;
      i = j + 1;
      continue;
    }
    if (ch === '$' && text[i + 1] === '(') {
      // Keep command substitutions inside the current word; their contents are
      // checked separately by the raw-text substitution rules.
      let depth = 0;
      let j = i + 1;
      for (; j < text.length; j += 1) {
        if (text[j] === '(') depth += 1;
        else if (text[j] === ')') { depth -= 1; if (depth === 0) break; }
      }
      if (j >= text.length) throw new CommandParseError('unterminated command substitution');
      word = (word ?? '') + text.slice(i, j + 1);
      i = j + 1;
      continue;
    }
    if (ch === '#' && word === null) {
      const end = text.indexOf('\n', i);
      i = end < 0 ? text.length : end;
      continue;
    }
    if (ch === '&' && word !== null && /[<>]$/.test(word)) {
      // Redirections such as 2>&1 belong to the current word.
      word += ch;
      i += 1;
      continue;
    }
    const op = OPERATORS.find((candidate) => text.startsWith(candidate, i));
    if (op) {
      push();
      tokens.push({ type: 'op', value: op });
      i += op.length;
      continue;
    }
    if (ch === '(' || ch === ')' || ch === '{' && word === null || ch === '}' && word === null) {
      push();
      tokens.push({ type: 'op', value: ';' });
      i += 1;
      continue;
    }
    if (/\s/.test(ch)) {
      push();
      i += 1;
      continue;
    }
    word = (word ?? '') + ch;
    i += 1;
  }
  push();
  return tokens;
}

// Split tokens into pipelines (separated by ; && || & newline), each a list of
// simple commands (separated by | or |&).
function toPipelines(tokens) {
  const pipelines = [];
  let pipeline = [];
  let command = [];
  const endCommand = () => {
    if (command.length) pipeline.push(command);
    command = [];
  };
  const endPipeline = () => {
    endCommand();
    if (pipeline.length) pipelines.push(pipeline);
    pipeline = [];
  };
  for (const token of tokens) {
    if (token.type === 'word') command.push(token.value);
    else if (token.value === '|' || token.value === '|&') endCommand();
    else endPipeline();
  }
  endPipeline();
  return pipelines;
}

// ------------------------------------------------------------ helpers

function programName(word) {
  const base = String(word).split('/').pop().toLowerCase();
  if (/^pip\d+(?:\.\d+)*$/.test(base)) return 'pip';
  if (/^python\d+(?:\.\d+)*$/.test(base)) return 'python';
  return base;
}

// Strip redirections, leading VAR=value assignments and wrapper commands
// (sudo, env, time, ...). Returns the remaining argv.
function stripPrefixes(argv) {
  const words = argv.filter((word, index) => {
    if (/^\d*[<>]{1,2}&?\d*$/.test(word)) return false;
    if (index > 0 && /^\d*[<>]{1,2}&?$/.test(argv[index - 1])) return false;
    return true;
  });
  let i = 0;
  while (i < words.length) {
    const word = words[i];
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(word)) { i += 1; continue; }
    if (PREFIX_COMMANDS.has(programName(word))) {
      i += 1;
      while (i < words.length && words[i].startsWith('-')) {
        i += PREFIX_VALUE_FLAGS.has(words[i]) ? 2 : 1;
      }
      continue;
    }
    break;
  }
  return words.slice(i);
}

// Does an interpreter invocation read its program from stdin?
function readsProgramFromStdin(program, args) {
  for (const arg of args) {
    if (arg === '--') return true;
    if (arg === '-' || arg === '-s') return true;
    if (arg.startsWith('-')) {
      if (SHELLS.has(program) && /^-[A-Za-z]*c[A-Za-z]*$/.test(arg)) return false;
      if (program === 'python' && /^-[A-Za-z]*[cm]/.test(arg)) return false;
      if (program === 'node' && /^(?:-e|-p|--eval|--print)(?:=|$)/.test(arg)) return false;
      if ((program === 'perl' || program === 'ruby') && /^-[A-Za-z]*[eE]/.test(arg)) return false;
      if (program === 'php' && /^-[A-Za-z]*r/.test(arg)) return false;
      continue;
    }
    return false;
  }
  return true;
}

const SHELL_ALT = '(?:ba|z|k|da|a)?sh|fish';
const SUBSTITUTION_RULES = [
  new RegExp(`(?:^|[\\s;&|(])(?:sudo\\s+(?:-\\S+\\s+)*)?(?:${SHELL_ALT})\\s+(?:-\\S+\\s+)*<\\(\\s*(?:curl|wget)\\b`),
  new RegExp(`(?:^|[\\s;&|(])(?:sudo\\s+(?:-\\S+\\s+)*)?(?:${SHELL_ALT})\\s+(?:-\\S+\\s+)*-[A-Za-z]*c[A-Za-z]*\\s+["']?(?:\\$\\(|\`)\\s*(?:curl|wget)\\b`),
  /(?:^|[\s;&|(])(?:source|\.)\s+<\(\s*(?:curl|wget)\b/,
  /(?:^|[\s;&|(])eval\s+["']?(?:\$\(|`)\s*(?:curl|wget)\b/,
  /(?:^|[\s;&|(])python[0-9.]*\s+(?:-\S+\s+)*-c\s+["']?(?:\$\(|`)\s*(?:curl|wget)\b/
];

// Decoders that turn an opaque payload back into a program: base64, hex dumps,
// openssl, and compression wrappers.
const DECODE_RE = /\b(?:base64\s+(?:-\S*\s+)*(?:-d|-D|--decode)\b|xxd\s+(?:-\S+\s+)*-r\b|openssl\s+(?:enc|base64)\b[^|)]*\s-d\b|(?:gunzip|zcat|gzip\s+-d|bzip2\s+-d|xz\s+-d)\b)/;
const DECODED_SUBSTITUTION_RULES = [
  new RegExp(`(?:^|[\\s;&|(])(?:eval|(?:sudo\\s+(?:-\\S+\\s+)*)?(?:${SHELL_ALT})\\s+(?:-\\S+\\s+)*-[A-Za-z]*c[A-Za-z]*)\\s+["']?(?:\\$\\(|\`)[^)\`]*${DECODE_RE.source}`),
  new RegExp(`(?:^|[\\s;&|(])(?:source|\\.|(?:${SHELL_ALT}))\\s+(?:-\\S+\\s+)*<\\([^)]*${DECODE_RE.source}`)
];

function isDecoder(program, args) {
  if (program === 'base64') return args.some((arg) => /^(?:-d|-D|--decode)$/.test(arg));
  if (program === 'xxd') return args.some((arg) => /^-[A-Za-z]*r/.test(arg));
  if (program === 'openssl') return /^(?:enc|base64)$/.test(args[0] || '') && args.includes('-d');
  if (program === 'gunzip' || program === 'zcat' || program === 'bzcat' || program === 'xzcat') return true;
  if (program === 'gzip' || program === 'bzip2' || program === 'xz') return args.some((arg) => /^-[A-Za-z]*d/.test(arg));
  return false;
}

// ------------------------------------------------------- npm family

const NPM_INSTALL = new Set(['install', 'i', 'in', 'ins', 'inst', 'insta', 'instal', 'isnt', 'isnta', 'isntal', 'isntall', 'add']);
const NPM_VALUE_FLAGS = new Set([
  '--prefix', '-w', '--workspace', '--tag', '--save-prefix', '--cache', '--omit', '--include',
  '--install-strategy', '--before', '--loglevel', '--filter', '-F', '-C', '--dir', '--cwd',
  '--network-concurrency', '--child-concurrency', '--reporter', '--node-options', '--shell', '--script-shell'
]);
const NPM_SOURCE_FLAGS = new Set(['--registry', '--userconfig', '--globalconfig']);

function npmArgs(args) {
  const positionals = [];
  const flags = new Set();
  let customRegistry = false;
  let ignoreScripts = false;
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '--') { positionals.push(...args.slice(i + 1)); break; }
    if (arg.startsWith('-')) {
      const [flag] = arg.split('=');
      if (NPM_SOURCE_FLAGS.has(flag) || /^--@[^:]+:registry$/.test(flag) || flag.startsWith('--//')) {
        customRegistry = true;
        if (!arg.includes('=')) i += 1;
        continue;
      }
      if (flag === '--ignore-scripts') ignoreScripts = arg !== '--ignore-scripts=false';
      if (NPM_VALUE_FLAGS.has(flag) && !arg.includes('=')) i += 1;
      flags.add(flag);
      continue;
    }
    positionals.push(arg);
  }
  return { positionals, flags, customRegistry, ignoreScripts };
}

function runnerPackages(args, packageFlags) {
  const packages = [];
  let command = null;
  let callString = false;
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    const [flag, inline] = arg.split(/=(.*)/s);
    if (arg === '--') { if (!command && args[i + 1]) command = args[i + 1]; break; }
    if (packageFlags.has(flag)) {
      const value = inline ?? args[i + 1];
      if (inline === undefined) i += 1;
      if (value) packages.push(value);
      continue;
    }
    if (flag === '-c' || flag === '--call') { callString = true; if (inline === undefined) i += 1; continue; }
    if (arg.startsWith('-')) {
      if (NPM_VALUE_FLAGS.has(flag) && inline === undefined) i += 1;
      continue;
    }
    command = arg;
    break;
  }
  return { packages, command, callString };
}

function npmFamily(program, args) {
  const findings = [];
  const add = (finding) => findings.push({ ecosystem: 'npm', ...finding });

  const runner = (runArgs, packageFlags) => {
    const parsed = runnerPackages(runArgs, packageFlags);
    const regs = npmArgs(runArgs);
    if (regs.customRegistry) add({ kind: 'custom-registry' });
    if (parsed.packages.length) {
      for (const spec of parsed.packages) add({ kind: 'package', mode: 'run', spec });
    } else if (parsed.command) {
      add({ kind: 'package', mode: 'run', spec: parsed.command, localBinCandidate: true });
    }
  };

  if (program === 'npx' || program === 'pnpx' || program === 'bunx') {
    runner(args, new Set(['-p', '--package']));
    return findings;
  }

  // Global flags may come before the subcommand (pnpm --filter x add y).
  let index = 0;
  while (index < args.length && args[index].startsWith('-')) {
    const [flag] = args[index].split('=');
    if (NPM_SOURCE_FLAGS.has(flag)) add({ kind: 'custom-registry' });
    index += NPM_VALUE_FLAGS.has(flag) || NPM_SOURCE_FLAGS.has(flag) ? (args[index].includes('=') ? 1 : 2) : 1;
  }
  let sub = args[index];
  let rest = args.slice(index + 1);

  if (program === 'yarn' && sub === 'global') { sub = rest[0]; rest = rest.slice(1); }
  if (program === 'npm' && (sub === 'exec' || sub === 'x')) { runner(rest, new Set(['-p', '--package'])); return findings; }
  if ((program === 'pnpm' || program === 'yarn') && sub === 'dlx') { runner(rest, new Set(['-p', '--package'])); return findings; }
  if (program === 'bun' && sub === 'x') { runner(rest, new Set(['-p', '--package'])); return findings; }

  const installSubs = {
    npm: NPM_INSTALL,
    pnpm: new Set(['add', 'install', 'i']),
    yarn: new Set(['add', 'install']),
    bun: new Set(['add', 'a', 'install', 'i'])
  }[program];
  const manifestSubs = {
    npm: new Set(['ci', 'clean-install', 'install-clean', 'update', 'up', 'upgrade', 'udpate']),
    pnpm: new Set(['update', 'up', 'upgrade']),
    yarn: new Set(['up', 'upgrade']),
    bun: new Set(['update'])
  }[program];

  if (program === 'yarn' && sub === undefined) {
    add({ kind: 'manifest' });
    return findings;
  }
  if (!sub) return findings;

  if (manifestSubs.has(sub) || installSubs.has(sub)) {
    const parsed = npmArgs(rest);
    if (parsed.customRegistry) add({ kind: 'custom-registry' });
    const specs = manifestSubs.has(sub) ? [] : parsed.positionals;
    if (!specs.length) {
      add({ kind: 'manifest', ignoreScripts: parsed.ignoreScripts });
    } else {
      for (const spec of specs) add({ kind: 'package', mode: 'install', spec, ignoreScripts: parsed.ignoreScripts });
    }
  }
  return findings;
}

// ------------------------------------------------------- PyPI family

const PIP_VALUE_FLAGS = new Set([
  '-c', '--constraint', '-t', '--target', '--prefix', '--root', '--src', '--python-version',
  '--platform', '--implementation', '--abi', '--only-binary', '--no-binary', '--progress-bar',
  '--log', '--cache-dir', '--python', '-p', '--group', '--optional', '--extra', '--package',
  '--script', '--bounds', '--tag', '--branch', '--rev', '--upgrade-package', '-P', '--with-editable',
  '--resolution', '--prerelease', '--exclude-newer', '--directory', '--project', '--source',
  '--suffix', '--pip-args', '--spec', '--venv', '--editable-mode'
]);
const PIP_SOURCE_FLAGS = new Set([
  '-i', '--index-url', '--extra-index-url', '-f', '--find-links', '--trusted-host',
  '--index', '--default-index', '--keyring-provider', '--config-file'
]);
const PIP_MANIFEST_FLAGS = new Set(['-r', '--requirement', '--requirements']);

function pipArgs(args, { withFlags = new Set() } = {}) {
  const positionals = [];
  const extraPackages = [];
  let customRegistry = false;
  let manifest = false;
  let editable = [];
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '--') break;
    if (arg.startsWith('-')) {
      const [flag, inline] = arg.split(/=(.*)/s);
      const value = inline ?? args[i + 1];
      const consumes = inline === undefined;
      if (PIP_SOURCE_FLAGS.has(flag)) { customRegistry = true; if (consumes) i += 1; continue; }
      if (PIP_MANIFEST_FLAGS.has(flag)) { manifest = true; if (consumes) i += 1; continue; }
      if (flag === '-e' || flag === '--editable') { if (value) editable.push(value); if (consumes) i += 1; continue; }
      if (withFlags.has(flag)) { if (value) extraPackages.push(value); if (consumes) i += 1; continue; }
      if (PIP_VALUE_FLAGS.has(flag) && consumes) i += 1;
      continue;
    }
    // PEP 508 direct reference split by the shell: "name @ url".
    if (args[i + 1] === '@' && args[i + 2]) {
      positionals.push(`${arg} @ ${args[i + 2]}`);
      i += 2;
      continue;
    }
    positionals.push(arg);
  }
  return { positionals, extraPackages, customRegistry, manifest, editable };
}

function pypiFamily(program, args) {
  const findings = [];
  const add = (finding) => findings.push({ ecosystem: 'pypi', ...finding });
  const install = (installArgs, mode, options = {}) => {
    const parsed = pipArgs(installArgs, options);
    if (parsed.customRegistry) add({ kind: 'custom-registry' });
    for (const target of parsed.editable) add({ kind: 'package', mode, spec: target, editable: true });
    for (const spec of parsed.extraPackages) add({ kind: 'package', mode, spec });
    if (mode === 'run') {
      if (parsed.positionals[0] && !options.fromGiven) add({ kind: 'package', mode, spec: parsed.positionals[0], runner: true });
      return;
    }
    if (parsed.manifest) add({ kind: 'manifest' });
    for (const spec of parsed.positionals) add({ kind: 'package', mode, spec });
  };

  if (program === 'pip') {
    if (args[0] === 'install' || args[0] === 'download') install(args.slice(1), 'install');
    return findings;
  }
  if (program === 'python') {
    const m = args.indexOf('-m');
    if (m >= 0 && args[m + 1] === 'pip' && (args[m + 2] === 'install' || args[m + 2] === 'download')) {
      install(args.slice(m + 3), 'install');
    }
    return findings;
  }
  if (program === 'uvx') {
    const hasFrom = args.some((arg) => arg === '--from' || arg.startsWith('--from='));
    install(args, 'run', { withFlags: new Set(['--from', '--with', '-w', '--with-requirements']), fromGiven: hasFrom });
    return findings;
  }
  if (program === 'uv') {
    let index = 0;
    while (index < args.length && args[index].startsWith('-')) {
      const [flag] = args[index].split('=');
      if (PIP_SOURCE_FLAGS.has(flag)) add({ kind: 'custom-registry' });
      index += (PIP_VALUE_FLAGS.has(flag) || PIP_SOURCE_FLAGS.has(flag) || flag === '--cache-dir') && !args[index].includes('=') ? 2 : 1;
    }
    const sub = args[index];
    const rest = args.slice(index + 1);
    if (sub === 'pip' && (rest[0] === 'install' || rest[0] === 'sync')) {
      if (rest[0] === 'sync') add({ kind: 'manifest' });
      else install(rest.slice(1), 'install');
    } else if (sub === 'add') {
      install(rest, 'install');
    } else if (sub === 'sync' || sub === 'lock') {
      add({ kind: 'manifest' });
    } else if (sub === 'tool' && rest[0] === 'install') {
      install(rest.slice(1), 'install', { withFlags: new Set(['--with', '-w', '--from']) });
    } else if (sub === 'tool' && rest[0] === 'run') {
      const runArgs = rest.slice(1);
      const hasFrom = runArgs.some((arg) => arg === '--from' || arg.startsWith('--from='));
      install(runArgs, 'run', { withFlags: new Set(['--from', '--with', '-w']), fromGiven: hasFrom });
    } else if (sub === 'run') {
      const parsed = pipArgs(rest, { withFlags: new Set(['--with', '-w']) });
      if (parsed.customRegistry) add({ kind: 'custom-registry' });
      for (const spec of parsed.extraPackages) add({ kind: 'package', mode: 'run', spec });
    }
    return findings;
  }
  if (program === 'pipx') {
    const sub = args[0];
    if (sub === 'install') install(args.slice(1), 'install', { withFlags: new Set(['--spec']) });
    else if (sub === 'inject') install(args.slice(2), 'install');
    else if (sub === 'run') {
      const hasSpec = args.some((arg) => arg === '--spec' || arg.startsWith('--spec='));
      install(args.slice(1), 'run', { withFlags: new Set(['--spec']), fromGiven: hasSpec });
    }
    return findings;
  }
  if (program === 'poetry' || program === 'pdm') {
    if (args[0] === 'add') install(args.slice(1), 'install');
    else if (args[0] === 'install' || args[0] === 'sync' || args[0] === 'update') add({ kind: 'manifest' });
  }
  return findings;
}

const NPM_PROGRAMS = new Set(['npm', 'npx', 'pnpm', 'pnpx', 'yarn', 'bun', 'bunx']);
const PYPI_PROGRAMS = new Set(['pip', 'python', 'uv', 'uvx', 'pipx', 'poetry', 'pdm']);

// When a command redirects the installer to another registry or index, its
// packages do not come from the public registry; mark them instead of reporting
// a separate finding, unless the command installs no named package.
function markCustomRegistry(findings) {
  if (!findings.some((finding) => finding.kind === 'custom-registry')) return findings;
  const packages = findings.filter((finding) => finding.kind === 'package');
  if (!packages.length) return findings;
  return findings
    .filter((finding) => finding.kind !== 'custom-registry')
    .map((finding) => (finding.kind === 'package' ? { ...finding, customRegistry: true } : finding));
}

// ---------------------------------------------------------- entry point

// Files a downloader writes: curl -o/--output, wget -O/--output-document, or a
// stdout redirection on the downloader command itself.
function downloadTargets(program, rawArgv) {
  const targets = [];
  for (let i = 1; i < rawArgv.length; i += 1) {
    const arg = rawArgv[i];
    const [flag, inline] = arg.split(/=(.*)/s);
    const takes = program === 'curl' ? ['-o', '--output'] : ['-O', '--output-document'];
    if (takes.includes(flag)) {
      const value = inline ?? rawArgv[i + 1];
      if (value && value !== '-') targets.push(value);
      if (inline === undefined) i += 1;
    } else if (program === 'curl' && /^-[A-Za-z]*o$/.test(arg) && rawArgv[i + 1]) {
      targets.push(rawArgv[i + 1]);
      i += 1;
    } else if (program === 'curl' && /^-[A-Za-z]*o.+$/.test(arg) && !arg.startsWith('--')) {
      targets.push(arg.slice(arg.indexOf('o') + 1));
    } else if (/^1?>>?$/.test(arg) && rawArgv[i + 1]) {
      targets.push(rawArgv[i + 1]);
      i += 1;
    } else if (/^1?>>?[^>&].*/.test(arg)) {
      targets.push(arg.replace(/^1?>>?/, ''));
    }
  }
  return targets.map((target) => target.replace(/^\.\//, ''));
}

function sameFile(a, b) {
  return String(a).replace(/^\.\//, '') === String(b).replace(/^\.\//, '');
}

// Does this command run one of the downloaded files as a program?
function runsDownloadedFile(program, argv, downloaded) {
  if (!downloaded.size) return false;
  const files = [...downloaded];
  if (files.some((file) => sameFile(argv[0], file) && /[\/]/.test(argv[0]))) return true;
  if (program === 'source' || program === '.') return files.some((file) => sameFile(argv[1], file));
  if (!INTERPRETERS.has(program)) return false;
  const script = argv.slice(1).find((arg) => !arg.startsWith('-'));
  return script !== undefined && files.some((file) => sameFile(script, file));
}

function analyzeText(fullText, depth, findings, downloadedFiles = new Set()) {
  const { text, bodies } = splitHeredocs(fullText);
  for (const body of bodies) {
    if (SHELLS.has(body.program) && !body.args.some((arg) => /^-[A-Za-z]*c[A-Za-z]*$/.test(arg))) {
      if (depth >= MAX_DEPTH) throw new CommandParseError('nested shell depth exceeded');
      analyzeText(body.text, depth + 1, findings, downloadedFiles);
    }
  }
  for (const rule of SUBSTITUTION_RULES) {
    if (rule.test(text)) {
      findings.push({ ecosystem: 'shell', kind: 'pipe-to-shell' });
      break;
    }
  }
  if (DECODED_SUBSTITUTION_RULES.some((rule) => rule.test(text))) {
    findings.push({ ecosystem: 'shell', kind: 'decoded-to-interpreter' });
  }

  const pipelines = toPipelines(lexShell(text));
  for (const pipeline of pipelines) {
    let downloaded = false;
    let decoded = false;
    for (const rawArgv of pipeline) {
      const argv = stripPrefixes(rawArgv);
      if (!argv.length) continue;
      const program = programName(argv[0]);
      const args = argv.slice(1);

      if (decoded && INTERPRETERS.has(program) && readsProgramFromStdin(program, args)) {
        findings.push({ ecosystem: 'shell', kind: 'decoded-to-interpreter' });
      }
      if (isDecoder(program, args)) decoded = true;

      if (downloaded && INTERPRETERS.has(program) && readsProgramFromStdin(program, args) ||
          runsDownloadedFile(program, argv, downloadedFiles)) {
        findings.push({ ecosystem: 'shell', kind: 'pipe-to-shell' });
      }
      if (DOWNLOADERS.has(program)) {
        downloaded = true;
        const rawIndex = rawArgv.findIndex((word) => programName(word) === program);
        for (const target of downloadTargets(program, rawArgv.slice(Math.max(rawIndex, 0)))) downloadedFiles.add(target);
      }

      if (SHELLS.has(program) || program === 'eval') {
        const flagIndex = args.findIndex((arg) => /^-[A-Za-z]*c[A-Za-z]*$/.test(arg));
        const script = program === 'eval' ? args.join(' ') : flagIndex >= 0 ? args[flagIndex + 1] : null;
        if (script) {
          if (depth >= MAX_DEPTH) throw new CommandParseError('nested shell depth exceeded');
          analyzeText(script, depth + 1, findings, downloadedFiles);
        }
        continue;
      }
      if (program === 'xargs' && args.length) {
        const inner = stripPrefixes(args.filter((arg) => !arg.startsWith('-')));
        if (inner.length && (NPM_PROGRAMS.has(programName(inner[0])) || PYPI_PROGRAMS.has(programName(inner[0])))) {
          findings.push({ ecosystem: 'shell', kind: 'opaque-arguments' });
        }
        continue;
      }
      if (NPM_PROGRAMS.has(program)) findings.push(...markCustomRegistry(npmFamily(program, args)));
      else if (PYPI_PROGRAMS.has(program)) findings.push(...markCustomRegistry(pypiFamily(program, args)));
    }
  }
}

export function mentionsPackageTool(text) {
  return PACKAGE_TOOL_RE.test(String(text || ''));
}

// Returns { findings, parseError }. Findings are structural; `spec` is the raw
// package argument and must go through parsePackageSpec before being displayed.
export function analyzeInstallCommand(text) {
  const findings = [];
  try {
    analyzeText(String(text || ''), 0, findings);
  } catch (error) {
    if (error instanceof CommandParseError) {
      return {
        findings: mentionsPackageTool(text) ? [{ ecosystem: 'shell', kind: 'unparseable-command' }] : [],
        parseError: true
      };
    }
    throw error;
  }
  return { findings, parseError: false };
}

// ------------------------------------------------------ spec parsing

const NPM_NAME_RE = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/i;
const EXACT_SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const LOCAL_PATH_RE = /^(?:\.{1,2}(?:[\\/]|$)|[\\/]|~[\\/]|[A-Za-z]:[\\/])/;

export function parseNpmSpec(raw) {
  let spec = String(raw || '').trim();
  if (!spec) return { type: 'invalid' };
  if (LOCAL_PATH_RE.test(spec) || /^(?:file|link|workspace|portal|patch):/i.test(spec)) return { type: 'local' };
  if (/\.(?:tgz|tar\.gz|tar)$/i.test(spec)) return { type: 'unregistered' };
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(spec) && !/^npm:/i.test(spec)) return { type: 'unregistered' };

  // Aliases: name@npm:target@range
  const alias = /^((?:@[^/@\s]+\/)?[^/@\s]+)@npm:(.+)$/i.exec(spec);
  if (alias) spec = alias[2];
  if (/^npm:/i.test(spec)) spec = spec.slice(4);

  const at = spec.indexOf('@', spec.startsWith('@') ? 1 : 0);
  const name = at < 0 ? spec : spec.slice(0, at);
  const selector = at < 0 ? '' : spec.slice(at + 1);
  if (!name.startsWith('@') && name.includes('/')) return { type: 'unregistered' };
  if (!NPM_NAME_RE.test(name) || name.length > 214) return { type: 'invalid' };
  if (/[\s\x00-\x1f\x7f]/.test(selector)) return { type: 'invalid' };
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(selector)) return { type: 'unregistered' };

  if (!selector) return { type: 'registry', name, selector: { kind: 'tag', value: 'latest' } };
  const bare = selector.replace(/^[=v]+/, '');
  if (EXACT_SEMVER_RE.test(bare)) return { type: 'registry', name, selector: { kind: 'exact', value: bare } };
  if (/^[A-Za-z][A-Za-z0-9._-]*$/.test(selector) && !/^v?\d/.test(selector) && selector !== 'x' && selector !== 'X') {
    return { type: 'registry', name, selector: { kind: 'tag', value: selector } };
  }
  return { type: 'registry', name, selector: { kind: 'range', value: selector } };
}

const PEP508_RE = /^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*(.*)$/s;

export function normalizePypiName(name) {
  return String(name).toLowerCase().replace(/[-_.]+/g, '-');
}

export function parsePypiSpec(raw, { editable = false } = {}) {
  const spec = String(raw || '').trim();
  if (!spec) return { type: 'invalid' };
  if (LOCAL_PATH_RE.test(spec) || /\.(?:whl|tar\.gz|zip|tgz)$/i.test(spec) && !/:\/\//.test(spec)) {
    return { type: 'local' };
  }
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(spec) || /^git\+/i.test(spec) || /\s@\s|^[^@\s]+@\s*[A-Za-z][A-Za-z0-9+.-]*:/.test(spec)) {
    return { type: 'unregistered' };
  }
  if (editable) return { type: 'local' };
  const match = PEP508_RE.exec(spec.split(';')[0].trim());
  if (!match) return { type: 'invalid' };
  const name = normalizePypiName(match[1]);
  const constraint = match[3].replace(/\s+/g, '');
  if (!constraint) return { type: 'registry', name, selector: { kind: 'latest' } };
  const exact = /^===?([^,*<>=!~]+)$/.exec(constraint);
  if (exact) return { type: 'registry', name, selector: { kind: 'exact', value: exact[1] } };
  if (/^>=?[^,*<>=!~]+$/.test(constraint)) return { type: 'registry', name, selector: { kind: 'latest', lowerBoundOnly: true } };
  if (/^[(\[]?[<>=!~]/.test(constraint)) return { type: 'registry', name, selector: { kind: 'range', value: constraint } };
  return { type: 'invalid' };
}
