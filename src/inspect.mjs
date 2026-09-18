import path from 'node:path';
import { sha256Json } from './canonical.mjs';

const SECRET_KEY_RE = /(token|secret|password|passwd|api[_-]?key|credential|auth)/i;
const SHELLS = new Set(['sh', 'bash', 'zsh', 'fish', 'cmd', 'cmd.exe', 'powershell', 'pwsh']);
const RUNNERS = new Set(['npx', 'pnpx', 'bunx', 'uvx']);

function basename(command = '') {
  return path.basename(String(command)).toLowerCase();
}

function firstPackageArg(command, args) {
  const cmd = basename(command);
  if (!RUNNERS.has(cmd)) return null;
  const values = Array.isArray(args) ? args.map(String) : [];
  for (let i = 0; i < values.length; i += 1) {
    const arg = values[i];
    if (arg === '--package' || arg === '-p') return values[i + 1] || null;
    if (arg.startsWith('-')) continue;
    return arg;
  }
  return null;
}

export function isPinnedPackage(spec) {
  if (!spec) return false;
  const value = String(spec).trim();
  if (!value || /@(latest|next|canary|beta|alpha)$/i.test(value)) return false;
  if (value.startsWith('@')) {
    const slash = value.indexOf('/');
    if (slash < 0) return false;
    return value.indexOf('@', slash) > slash;
  }
  return value.lastIndexOf('@') > 0 || /==[^=\s]+$/.test(value);
}

function looksLikePath(value) {
  if (typeof value !== 'string') return false;
  return value.startsWith('/') || value.startsWith('~/') || value.startsWith('./') ||
    value.startsWith('../') || /^[A-Za-z]:\\/.test(value);
}

function extractRemoteHost(server) {
  const candidate = server?.url || server?.endpoint;
  if (!candidate) return null;
  try { return new URL(candidate).hostname.toLowerCase(); } catch { return null; }
}

function normalizeServer(name, server = {}) {
  const command = String(server.command || '');
  const args = Array.isArray(server.args) ? server.args.map(String) : [];
  const env = server.env && typeof server.env === 'object' ? server.env : {};
  const envKeys = Object.keys(env).sort();
  const packageSpec = firstPackageArg(command, args);
  const remoteHost = extractRemoteHost(server);
  const signals = new Set(Array.isArray(server._trustdexSignals) ? server._trustdexSignals : []);

  if (remoteHost) signals.add('network-endpoint');
  if (SHELLS.has(basename(command))) signals.add('shell-execution');
  if (RUNNERS.has(basename(command))) signals.add('install-on-run');
  if (packageSpec && !isPinnedPackage(packageSpec)) signals.add('unbounded-version');
  if (args.some(looksLikePath)) signals.add('filesystem-path');
  if (envKeys.some((key) => SECRET_KEY_RE.test(key))) signals.add('secret-env');

  let source = { type: 'unknown' };
  if (remoteHost) source = { type: 'remote', host: remoteHost, url: String(server.url || server.endpoint) };
  else if (packageSpec) source = { type: 'package', runner: basename(command), package: packageSpec, pinned: isPinnedPackage(packageSpec) };
  else if (command) source = { type: 'local', command };

  const fingerprint = sha256Json({
    command,
    args,
    url: server.url || null,
    endpoint: server.endpoint || null,
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
  return Object.entries(servers)
    .filter(([, value]) => value && typeof value === 'object' && !Array.isArray(value))
    .map(([name, server]) => normalizeServer(name, server))
    .sort((a, b) => a.name.localeCompare(b.name));
}
