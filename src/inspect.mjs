import { sha256Json } from './canonical.mjs';

const SECRET_KEY_RE = /(token|secret|password|passwd|api[_-]?key|credential|auth)/i;
const SHELLS = new Set(['sh', 'bash', 'zsh', 'fish', 'cmd', 'powershell', 'pwsh']);
const RUNNERS = new Set(['npx', 'pnpx', 'bunx', 'uvx']);

function executableName(command = '') {
  const name = String(command).trim().split(/[\\/]/).pop().toLowerCase();
  return name.replace(/\.(?:bat|cmd|exe)$/i, '');
}

// Runner options, per runner. Value options consume the next argument unless written as
// --flag=value. "package" options name what is installed; "extra" options add more
// packages; "source" options change where packages, configuration, or already-installed
// binaries come from; "shell" options run a shell command or inline code. An option not
// listed here makes the package identity ambiguous.
const RUNNER_OPTIONS = {
  npm: {
    package: ['-p', '--package'],
    extra: [],
    // --prefix and --workspace run binaries already installed in that project, and a
    // cache with --offline can stand in for the registry.
    source: ['--registry', '--userconfig', '--cache', '--prefix', '-w', '--workspace'],
    shell: ['-c', '--call', '--node-options'],
    value: [],
    flags: ['-y', '--yes', '--no', '-q', '--quiet', '--silent', '--no-install', '--ignore-existing', '--prefer-offline', '--prefer-online', '--offline']
  },
  uv: {
    package: ['--from'],
    extra: ['--with', '--with-editable', '--with-requirements'],
    // Configuration files, constraints, and overrides can redirect a requirement to any
    // index or URL; a keyring provider runs a helper program.
    source: ['--index', '--index-url', '--extra-index-url', '--default-index', '-i', '--find-links', '-f',
      '--config-file', '--env-file', '-c', '--constraint', '--override', '--build-constraint', '--cache-dir',
      '--keyring-provider'],
    shell: [],
    value: ['-p', '--python', '--directory', '--project', '--index-strategy', '--resolution', '--prerelease',
      '--exclude-newer', '--link-mode', '--python-preference', '--color'],
    flags: ['-q', '--quiet', '-v', '--verbose', '--isolated', '--no-cache', '-n', '--offline', '--refresh', '-U', '--upgrade',
      '--no-config', '--no-progress', '--native-tls', '--no-python-downloads', '--no-build-isolation', '--no-sources',
      '--managed-python', '--no-managed-python', '--compile-bytecode']
  }
};
const RUNNER_FAMILY = { npx: 'npm', pnpx: 'npm', bunx: 'npm', uvx: 'uv' };
// A Python request such as "3.12", "cpython@3.12", or "pypy3.10"; anything else (a path
// or a program name) selects an interpreter outside the reviewed package.
const PYTHON_REQUEST_RE = /^(?:(?:cpython|pypy|graalpy|python)[-@]?)?\d+(?:\.\d+){0,2}t?$/i;

// The executable a package option is expected to provide: the package name without a
// scope, version, or extras.
function packageCommandName(spec) {
  if (!isRegistrySpec(spec)) return null;
  const value = String(spec).replace(/^npm:/i, '');
  const unscoped = value.startsWith('@') ? value.slice(value.indexOf('/') + 1) : value;
  return unscoped.split(/[@=<>!~[\s]/)[0] || null;
}

// Returns the installed package spec plus identity signals for a runner command.
function analyzeRunner(command, args) {
  const family = RUNNER_FAMILY[executableName(command)];
  if (!family) return { spec: null, signals: [] };
  const options = RUNNER_OPTIONS[family];
  const has = (list, name) => list.includes(name);
  const values = Array.isArray(args) ? args.map(String) : [];
  const packages = [];
  const signals = new Set();
  let positional = null;
  for (let i = 0; i < values.length; i += 1) {
    const arg = values[i];
    if (arg === '--') { positional = values[i + 1] ?? null; break; }
    if (!arg.startsWith('-') || arg === '-') { positional = arg; break; }
    const eq = arg.indexOf('=');
    const name = eq > 0 ? arg.slice(0, eq) : arg;
    const takesValue = has(options.package, name) || has(options.extra, name) || has(options.source, name) ||
      has(options.shell, name) || has(options.value, name);
    let value = null;
    if (takesValue) {
      value = eq > 0 ? arg.slice(eq + 1) : values[i + 1] ?? null;
      if (eq < 0) i += 1;
    } else if (!has(options.flags, name) || eq > 0) {
      // A flag given "=value" is not a documented form: npm expands "-y=x" into "--yes x",
      // which makes x the package to run.
      signals.add('ambiguous-runner-arguments');
      continue;
    }
    if (has(options.package, name) && value !== null) packages.push(value);
    if (has(options.extra, name)) signals.add('additional-packages');
    if (has(options.source, name)) signals.add('package-source-override');
    if (has(options.shell, name)) signals.add('shell-execution');
    if (family === 'uv' && (name === '-p' || name === '--python') && !PYTHON_REQUEST_RE.test(value ?? '')) {
      signals.add('package-source-override');
    }
  }
  if (packages.length > 1) signals.add('additional-packages');
  // With a package option, the positional argument is the command to run. It is looked
  // up on PATH as well as in the package, so anything other than the package's own name
  // ("sh", "python", another tool) runs something the package identity does not describe.
  if (packages.length > 0 && (positional === null || positional !== packageCommandName(packages[0]))) {
    signals.add('runner-command-mismatch');
  }
  const spec = packages[0] ?? positional;
  return { spec: spec || null, signals: [...signals] };
}

// Environment variables that configure a package runner, the interpreter it starts, or
// where commands are found. In an MCP server's env block they can change the registry,
// the package, or the code that runs without changing the arguments.
const RUNNER_ENV_RE = /^(?:npm_config_.*|uv_.*|bun_config_.*|bun_install.*|pnpm_.*|yarn_.*|corepack_.*|pip_.*|node_options|node_path|python(?:path|startup|home|userbase|safepath)|ld_preload|ld_library_path|ld_audit|dyld_.*|path|pathext|home|userprofile|xdg_config_home|appdata)$/i;

// An exact version: a full semantic version after "@" (npm treats "1.2" or "^1.2.3" as a
// range), or a PEP 440 version without wildcards after "==".
const EXACT_SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const EXACT_PEP440_RE = /^(?:\d+!)?\d+(?:\.\d+)*(?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?\d*)?(?:[-_.]?(?:post|rev|r)[-_.]?\d*)?(?:[-_.]?dev[-_.]?\d*)?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$/i;

export function isPinnedPackage(spec) {
  if (!spec) return false;
  const value = String(spec).trim();
  const pep440 = value.match(/^[^=<>!~\s]+===?([^=]+)$/);
  if (pep440) return EXACT_PEP440_RE.test(pep440[1]);
  const at = value.lastIndexOf('@');
  if (at <= 0) return false;
  if (value.startsWith('@') && value.indexOf('/') > at) return false;
  return EXACT_SEMVER_RE.test(value.slice(at + 1));
}

function looksLikePath(value) {
  if (typeof value !== 'string') return false;
  return value.startsWith('/') || value.startsWith('~/') || value.startsWith('./') ||
    value.startsWith('../') || /^[A-Za-z]:\\/.test(value);
}

function fingerprintUrl(value) {
  try {
    const url = new URL(String(value));
    return {
      origin: `${url.protocol.toLowerCase()}//${url.host.toLowerCase()}`,
      pathname: url.pathname,
      queryKeys: [...new Set(url.searchParams.keys())].sort(),
      // A fragment selects a git ref; keep it so a changed ref changes the fingerprint.
      ...(url.hash ? { fragment: url.hash } : {})
    };
  } catch {
    return { invalid: true };
  }
}

function fingerprintArgs(args) {
  const values = Array.isArray(args) ? args.map(String) : [];
  const sanitized = [];
  let redactNext = false;

  for (const value of values) {
    if (redactNext) {
      sanitized.push('<redacted>');
      redactNext = false;
      continue;
    }

    const assignment = value.match(/^(-{1,2}[^=]+)=(.*)$/);
    if (assignment && SECRET_KEY_RE.test(assignment[1])) {
      sanitized.push(`${assignment[1]}=<redacted>`);
      continue;
    }
    if (/^-{1,2}/.test(value) && SECRET_KEY_RE.test(value)) {
      sanitized.push(argumentCredentials(value) ?? value);
      redactNext = true;
      continue;
    }
    if (value === '-H' || value === '--header') {
      sanitized.push(value);
      redactNext = true;
      continue;
    }
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
      sanitized.push(fingerprintUrl(value));
      continue;
    }

    sanitized.push(argumentCredentials(value) ?? value);
  }

  return sanitized;
}

// Package specs can embed URLs: tarballs, git remotes, "name@url", scp-like remotes, or
// uvx --from values. Userinfo, query values, and ;params can hold credentials or signed
// tokens, so they are never displayed. Scheme, host, path, and fragment are kept: a git
// ref is a version selector and must stay visible to review and snapshot drift. Only the
// shapes below are understood; anything else is reported as unparseable and blocked.
const KNOWN_SCHEMES = new Set([
  'http', 'https', 'git', 'git+http', 'git+https', 'git+ssh', 'ssh', 'file',
  'github', 'gitlab', 'bitbucket', 'gist', 'link'
]);
const SSH_SCHEMES = new Set(['ssh', 'git+ssh']);
const SPEC_PART = String.raw`[^\s\x00-\x1f\x7f:\\?#;@/]+`;
const SPEC_NAME = `(?:@${SPEC_PART}/)?${SPEC_PART}`;
const SIMPLE_SPEC_RE = new RegExp(`^${SPEC_NAME}(?:@${SPEC_PART})?$`);
const URL_PREFIX_RE = new RegExp(`^(${SPEC_NAME}(?:@| @ ))([A-Za-z][A-Za-z0-9+.-]*:[^]*)$`);
const SCHEME_RE = /^([A-Za-z][A-Za-z0-9+.-]*):/;
const UNSAFE_CHAR_RE = /[\s\x00-\x1f\x7f]/;
const LOCAL_PATH_RE = /^(?:\.{1,2}[\\/]|[\\/]|~[\\/]|[A-Za-z]:[\\/])/;
// user[:password]@host:path[#ref]; "name:tag@sha256:digest" image references are not remotes.
const SCP_RE = /^([^\s@/:\\]+)(?::([^\s@/\\]+))?@([^\s@/:\\?#;]+):([^\s@\\?#;]+)(#\S*)?$/;
// "name[:tag]@sha256:<hex>" container image references, matched exactly.
const IMAGE_DIGEST_RE = /^[^\s@:]+(?::[^\s@:]+)?@sha\d+:[0-9a-f]+$/i;
// ssh://user[:password]@host:path[#ref], which npm documents but URL parsers reject.
const SSH_SCP_URL_RE = /^([A-Za-z+]+):\/\/(?:([^\s@/:\\]+)(?::([^\s@/\\]+))?@)?([^\s@/:\\?#;]+):([^\s@\\?#;:]+)(#\S*)?$/;
export const UNPARSEABLE_PACKAGE_SPEC = '<unparseable-package-spec>';
const UNPARSEABLE = Object.freeze({ unparseable: true, display: UNPARSEABLE_PACKAGE_SPEC, credentials: false, query: false });

function parseKnownUrl(prefix, value, scheme) {
  if (UNSAFE_CHAR_RE.test(value)) return UNPARSEABLE;
  // URL parsers resolve "file:../x" to "file:///x"; show the relative path that npm uses.
  if (scheme === 'file' && !/^file:\/\//i.test(value)) {
    const relative = value.match(/^file:([^@?#;:\\]+)$/i);
    return relative ? { display: `${prefix}file:${relative[1]}`, credentials: false, query: false } : UNPARSEABLE;
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    const ssh = SSH_SCHEMES.has(scheme) ? value.match(SSH_SCP_URL_RE) : null;
    if (!ssh) return UNPARSEABLE;
    return {
      display: `${prefix}${scheme}://${ssh[2] && ssh[3] === undefined ? `${ssh[2]}@` : ''}${ssh[4]}:${ssh[5]}${ssh[6] || ''}`,
      credentials: ssh[3] !== undefined,
      query: false
    };
  }
  const authority = url.href.startsWith(`${url.protocol}//`);
  // Without an authority there is no userinfo field, so an "@" left in the path is an
  // unparsed credential (for example "git+https:/user:pw@host/x").
  if (!authority && url.pathname.includes('@')) return UNPARSEABLE;
  // "scheme:///user:pw@host/x" parses with an empty host and the userinfo in the path.
  if (authority && !url.host && scheme !== 'file') return UNPARSEABLE;
  if (authority && url.pathname.includes('@') && !url.host) return UNPARSEABLE;
  const pathname = url.pathname.replace(/;[^/]*/g, '');
  // An ssh username selects the account (and its home directory), so it stays visible;
  // it is not a credential. Every other userinfo is removed.
  const sshUser = SSH_SCHEMES.has(scheme) && url.username && !url.password ? `${url.username}@` : '';
  return {
    display: `${prefix}${url.protocol}${authority ? `//${sshUser}${url.host}` : ''}${pathname}${url.hash}`,
    credentials: Boolean(url.password) || (Boolean(url.username) && !SSH_SCHEMES.has(scheme)),
    query: Boolean(url.search) || url.pathname.includes(';')
  };
}

// Returns null when the value has no recognised URL or remote shape.
function analyzeEmbeddedUrl(value) {
  let prefix = '';
  let rest = value;
  const prefixed = value.match(URL_PREFIX_RE);
  if (prefixed && KNOWN_SCHEMES.has(prefixed[2].match(SCHEME_RE)[1].toLowerCase())) {
    prefix = prefixed[1];
    rest = prefixed[2];
  }
  const scheme = rest.match(SCHEME_RE)?.[1].toLowerCase();
  if (scheme && KNOWN_SCHEMES.has(scheme)) return parseKnownUrl(prefix, rest, scheme);
  if (IMAGE_DIGEST_RE.test(rest)) return null;
  const scp = rest.match(SCP_RE);
  if (scp) {
    const user = scp[2] === undefined ? `${scp[1]}@` : '';
    return { display: `${user}${scp[3]}:${scp[4]}${scp[5] || ''}`, credentials: scp[2] !== undefined, query: false };
  }
  return null;
}

// Classifies a package spec. Simple registry specs ("name", "@scope/name", "name@1.2.3",
// "name==1.2.3") pass through; anything else is shown only as a credential-free URL or
// remote, is never pinned, and is otherwise unparseable.
// True for registry specs whose name can be matched against a trust policy:
// "name", "@scope/name", "name@1.2.3", "name==1.2.3", and "npm:" aliases of those.
export function isRegistrySpec(spec) {
  const value = String(spec || '');
  const alias = value.match(/^npm:(.+)$/i);
  return SIMPLE_SPEC_RE.test(alias ? alias[1] : value);
}

export function analyzePackageSpec(spec) {
  const value = String(spec);
  if (SIMPLE_SPEC_RE.test(value)) {
    return { unparseable: false, display: value, credentials: false, query: false, pinned: isPinnedPackage(value) };
  }
  // npm aliases ("npm:name@1.2.3") are registry specs; pin them like the aliased spec.
  const alias = value.match(/^npm:(.+)$/i);
  if (alias && SIMPLE_SPEC_RE.test(alias[1])) {
    return { unparseable: false, display: value, credentials: false, query: false, pinned: isPinnedPackage(alias[1]) };
  }
  // Local directories and tarballs ("./pkg", "../pkg.tgz", "/opt/pkg") are shown as
  // given, as before, and are never pinned.
  if (LOCAL_PATH_RE.test(value) && !/[@?#;]/.test(value) && !UNSAFE_CHAR_RE.test(value)) {
    return { unparseable: false, display: value, credentials: false, query: false, pinned: false };
  }
  const embedded = analyzeEmbeddedUrl(value) || UNPARSEABLE;
  return { unparseable: false, ...embedded, pinned: false };
}

// Credentials in any argument, including "--flag=URL" values. Returns null when none
// are found, or the credential-free form to use in place of the argument.
function argumentCredentials(arg) {
  const assignment = arg.match(/^(-{1,2}[^=]+=)([^]*)$/);
  const flag = assignment ? assignment[1] : '';
  const value = assignment ? assignment[2] : arg;
  const embedded = analyzeEmbeddedUrl(value);
  if (embedded?.credentials) return `${flag}${embedded.display}`;
  // A recognised URL that cannot be parsed may still carry userinfo.
  if (embedded?.unparseable && value.includes('@')) return `${flag}${UNPARSEABLE_PACKAGE_SPEC}`;
  // Any "scheme://userinfo@" anywhere in the argument (jdbc:postgresql://, -ehttps://,
  // wss://token@, or a URL whose port makes the parser throw) is treated as a credential
  // unless it is an ssh username alone. Like libpq, a "user:password" part runs to the
  // last "@" before the first "/", so "?", "#", and spaces inside a password are covered;
  // without a ":" the part stops at "?" or "#" so an "@" in a query is not a credential.
  for (const match of arg.matchAll(/([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/]*)@/g)) {
    const [, scheme, authority] = match;
    const userinfo = authority.includes(':') ? authority : authority.split(/[?#\s]/)[0];
    if (!userinfo || (!authority.includes(':') && /[?#\s]/.test(authority))) continue;
    if (!userinfo.includes(':') && SSH_SCHEMES.has(scheme.toLowerCase())) continue;
    return arg.replace(/([A-Za-z][A-Za-z0-9+.-]*:\/\/)[^/]*@/g, '$1');
  }
  return null;
}

function extractRemoteEndpoint(server) {
  const candidate = server?.url || server?.endpoint;
  if (!candidate) return null;

  try {
    const url = new URL(String(candidate));
    const protocol = url.protocol.toLowerCase();
    return {
      host: url.hostname.toLowerCase(),
      origin: `${protocol}//${url.host.toLowerCase()}`,
      protocol,
      pathname: url.pathname,
      queryKeys: [...new Set(url.searchParams.keys())].sort(),
      hasEmbeddedCredentials: Boolean(url.username || url.password),
      hasQuery: Boolean(url.search)
    };
  } catch {
    return null;
  }
}

function normalizeServer(name, server = {}) {
  const command = String(server.command || '');
  const args = Array.isArray(server.args) ? server.args.map(String) : [];
  const env = server.env && typeof server.env === 'object' ? server.env : {};
  const envKeys = Object.keys(env).sort();
  const runner = analyzeRunner(command, args);
  const packageArg = runner.spec;
  const pkg = packageArg ? analyzePackageSpec(packageArg) : null;
  const packageSpec = pkg?.display || null;
  const remote = extractRemoteEndpoint(server);
  const remoteHost = remote?.host || null;
  const signals = new Set(Array.isArray(server._trustdexSignals) ? server._trustdexSignals : []);
  runner.signals.forEach((signal) => signals.add(signal));

  if (remote) signals.add('network-endpoint');
  if (remote && ['http:', 'ws:'].includes(remote.protocol)) signals.add('insecure-transport');
  if (remote?.hasEmbeddedCredentials) signals.add('embedded-credentials');
  if (remote?.hasQuery) signals.add('url-query-parameters');
  if (pkg?.credentials || args.some((arg) => argumentCredentials(arg) !== null)) signals.add('embedded-credentials');
  if (pkg?.query) signals.add('package-url-query');
  if (pkg?.unparseable) signals.add('unparseable-package-spec');
  if (SHELLS.has(executableName(command))) signals.add('shell-execution');
  if (RUNNERS.has(executableName(command))) signals.add('install-on-run');
  if (RUNNERS.has(executableName(command)) && envKeys.some((key) => RUNNER_ENV_RE.test(key))) {
    signals.add('runner-environment-override');
  }
  // Only a simple registry spec can be pinned: in a URL, "@" belongs to the URL, not a version.
  const pinned = Boolean(pkg?.pinned);
  if (packageSpec && !pinned) signals.add('unbounded-version');
  if (args.some(looksLikePath)) signals.add('filesystem-path');
  if (envKeys.some((key) => SECRET_KEY_RE.test(key))) signals.add('secret-env');

  let source = { type: 'unknown' };
  if (remote) {
    source = {
      type: 'remote',
      host: remoteHost,
      origin: remote.origin,
      protocol: remote.protocol
    };
  }
  else if (packageSpec) source = { type: 'package', runner: executableName(command), package: packageSpec, pinned };
  else if (command) source = { type: 'local', command };

  const fingerprint = sha256Json({
    command,
    args: fingerprintArgs(args),
    remoteEndpoint: remote ? {
      origin: remote.origin,
      pathname: remote.pathname,
      queryKeys: remote.queryKeys
    } : null,
    invalidEndpoint: (server.url || server.endpoint) && !remote ? true : null,
    envKeys,
    adapter: server._trustdexFingerprintData || null
  });

  return { name, source, fingerprint, signals: [...signals].sort(), envKeys };
}

export function inspectMcpConfig(config) {
  const servers = config?.mcpServers && typeof config.mcpServers === 'object'
    ? config.mcpServers
    : config?.servers && typeof config.servers === 'object'
      ? config.servers
      : config;
  if (!servers || typeof servers !== 'object' || Array.isArray(servers)) {
    throw new Error('Expected an MCP configuration object, or an object containing mcpServers/servers.');
  }
  for (const [name, value] of Object.entries(servers)) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new Error(`MCP server "${name}" must be a JSON object.`);
    }
  }
  return Object.entries(servers)
    .map(([name, server]) => normalizeServer(name, server))
    .sort((a, b) => a.name.localeCompare(b.name));
}
