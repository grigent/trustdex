import { sha256Json, sha256Text } from './canonical.mjs';

const URL_RE = /https?:\/\/[^\s)>'"]+/gi;
// Heuristics for instruction text. They only raise a review signal; a miss is possible
// and a match does not prove intent.
const HOME_RE = String.raw`(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%)[\\/]`;
const SENSITIVE_PATH_RE = new RegExp(String.raw`(?:${HOME_RE}\.(?:ssh|aws|config|gnupg|kube|docker|netrc|npmrc|pypirc|git-credentials)|\bid_(?:rsa|ed25519|ecdsa)\b|\/(?:etc|var\/run\/secrets)\/|\.env(?:\b|\/)|credentials?\b)`, 'i');
const SHELL_NAMES = String.raw`(?:sh|bash|zsh|dash|ksh|fish|python3?|node|perl|ruby|iex|invoke-expression)`;
const SHELL_INSTRUCTION_RE = new RegExp(String.raw`(?:\|\s*(?:sudo\s+)?${SHELL_NAMES}\b|\b(?:sh|bash|zsh)\s+(?:-c\s+["']?\$\(|<\()|\beval\s+["'$]|\bnc\s+-e\b|\/dev\/tcp\/|\brm\s+-rf\b|\bsudo\b|\bpowershell\b|\bchmod\s+\+x\b)`, 'i');
const INSTALL_RE = /(?:\b(?:npm|pnpm|yarn|bun)\s+(?:i|install|add)\b|\b(?:npx|pnpx|bunx|uvx)\s|\b(?:pnpm|yarn)\s+dlx\b|\bpipx?\s+(?:install|run)\b|\buv\s+(?:pip|tool|add)\b|\b(?:cargo|go|gem|brew)\s+install\b|\bcurl\b|\bwget\b|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b)/i;
const TOOL_SCOPE_KEYS = new Set(['allowed-tools', 'allowed_tools', 'allowedtools', 'tools']);
const MAX_MANIFEST_DEPTH = 64;

function parseScalar(value) {
  let raw = value.trim();
  // An unquoted value ends at " #".
  if (!/^["'[]/.test(raw)) raw = raw.replace(/\s+#.*$/, '');
  else if (/^(["']).*\1\s+#/.test(raw)) raw = raw.replace(/^((["']).*?\2)\s+#.*$/, '$1');
  if (!raw) return '';
  if ((raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'"))) {
    return raw.slice(1, -1);
  }
  if (raw.startsWith('[') && raw.endsWith(']')) {
    return raw.slice(1, -1).split(',').map((item) => parseScalar(item)).filter(Boolean);
  }
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  return raw;
}

// Top-level frontmatter entries in file order. This is a small YAML subset: scalars,
// flow lists (also across lines), and block lists. A value written any other way
// (block scalar, nested map, unterminated list) is marked unsupported, not guessed.
function frontmatterEntries(text) {
  // A byte-order mark or blank lines before the opening fence must not hide the header.
  const value = String(text || '').replace(/^\uFEFF/, '').replace(/^(?:[ \t]*\r?\n)+/, '');
  if (!/^---[ \t]*\r?\n/.test(value)) return [];
  const lines = value.split(/\r?\n/);
  const entries = [];
  const end = lines.findIndex((line, index) => index > 0 && /^(?:---|\.\.\.)\s*$/.test(line));
  entries.header = lines.slice(1, end < 0 ? lines.length : end).join('\n');
  for (let i = 1; i < lines.length; i += 1) {
    if (/^(?:---|\.\.\.)\s*$/.test(lines[i])) break;
    const match = lines[i].match(/^\s*["']?([A-Za-z0-9_-]+)["']?\s*:\s*(.*)$/);
    if (!match) continue;
    let raw = match[2];
    let unsupported = /^[>|]/.test(raw.trim());
    if (raw.trim().startsWith('[')) {
      // A list continues only up to the next `key: value` line or tool-scope key (however
      // it is spaced), and an unterminated list consumes nothing, so a list cannot
      // swallow a scope that follows it.
      const start = i;
      let joined = raw;
      while (!/\]\s*(?:#.*)?$/.test(joined) && i + 1 < lines.length &&
        !/^(?:---|\.\.\.)\s*$|^\s*[A-Za-z0-9_-]+\s*:(?:\s|$)/.test(lines[i + 1]) &&
        !TOOL_SCOPE_KEYS.has((lines[i + 1].match(/^\s*["']?([A-Za-z0-9_-]+)["']?\s*:/)?.[1] || '').toLowerCase())) joined += ` ${lines[i += 1]}`;
      if (/\]\s*(?:#.*)?$/.test(joined)) raw = joined;
      else i = start;
      raw = raw.replace(/\]\s*#.*$/, ']');
      if (!raw.trim().endsWith(']')) unsupported = true;
    }
    let parsed = parseScalar(raw);
    if (parsed === '' || /^[>|]/.test(raw.trim())) {
      const items = [];
      while (i + 1 < lines.length && /^\s+\S|^-\s|^\s*$/.test(lines[i + 1]) && !/^(?:---|\.\.\.)\s*$/.test(lines[i + 1])) {
        const line = lines[i += 1];
        if (!line.trim() || /^\s*#/.test(line)) continue;
        const item = line.match(/^\s*-\s+(.*)$/);
        if (item) items.push(parseScalar(item[1]));
        else unsupported = true;
      }
      if (items.length && !unsupported) parsed = items;
    }
    entries.push({ key: match[1], value: parsed, unsupported });
  }
  return entries;
}

export function parseFrontmatter(text) {
  return Object.fromEntries(frontmatterEntries(text).map((entry) => [entry.key, entry.value]));
}

// "*" alone, or a tool with an unrestricted specifier such as "Bash(*)".
function isWildcard(tools) {
  if (Array.isArray(tools)) return tools.some((tool) => isWildcard(String(tool)));
  return typeof tools === 'string' && /(?:^|[,\s])(?:[A-Za-z0-9_-]+\(\s*\*\s*\)|\*)(?=$|[,\s])/.test(tools);
}

// Brackets, braces, or quotes left in a parsed scope mean the value was not fully read.
function hasStraySyntax(value) {
  return [value].flat().some((item) => typeof item === 'string' && /[[\]{}"']/.test(item));
}

// Every tool-scope key counts, in any letter case and however often it is repeated.
function toolScopeSignals(entries) {
  const scopes = entries.filter((entry) => TOOL_SCOPE_KEYS.has(entry.key.toLowerCase()));
  // A scope name the header mentions more often than it was read as a key sits in syntax
  // this parser does not read (a quoted or nested key, a flow map, inside another value).
  const mentioned = (entries.header || '').match(/allowed[-_]?tools/gi)?.length || 0;
  const read = scopes.filter((entry) => /^allowed[-_]?tools$/i.test(entry.key)).length;
  const uninspected = scopes.some((entry) => entry.unsupported || hasStraySyntax(entry.value)) || mentioned > read;
  // When a scope could not be read in full, a wildcard anywhere in the header counts, so
  // breaking the syntax cannot lower a wildcard finding to the weaker signal.
  const wildcard = scopes.some((entry) => isWildcard(entry.value)) ||
    (uninspected && isWildcard((entries.header || '').replace(/[[\]{}"',]/g, ' ')));
  return [
    ...(wildcard ? ['wildcard-tool-scope'] : []),
    ...(uninspected ? ['uninspected-tool-scope'] : [])
  ];
}

export function inspectSkillText(text, sourceName = 'SKILL.md') {
  const value = String(text || '');
  const entries = frontmatterEntries(value);
  const metadata = Object.fromEntries(entries.map((entry) => [entry.key, entry.value]));
  const signals = new Set(toolScopeSignals(entries));

  if (URL_RE.test(value)) signals.add('network-instructions');
  URL_RE.lastIndex = 0;
  if (SENSITIVE_PATH_RE.test(value)) signals.add('sensitive-path-instructions');
  if (SHELL_INSTRUCTION_RE.test(value)) signals.add('shell-instructions');
  if (INSTALL_RE.test(value)) signals.add('install-instructions');

  return {
    name: String(metadata.name || sourceName),
    kind: 'skill',
    source: { type: 'skill-file', path: sourceName },
    fingerprint: sha256Text(value),
    metadata: {
      name: metadata.name || null,
      description: metadata.description || null,
      allowedTools: metadata['allowed-tools'] ?? metadata.allowed_tools ?? null
    },
    signals: [...signals].sort(),
    envKeys: []
  };
}

function walk(value, path = [], out = []) {
  if (path.length > MAX_MANIFEST_DEPTH) throw new Error('Plugin manifest is nested too deeply to inspect.');
  if (Array.isArray(value)) {
    value.forEach((item, index) => walk(item, [...path, String(index)], out));
  } else if (value && typeof value === 'object') {
    Object.entries(value).forEach(([key, item]) => walk(item, [...path, key], out));
  } else {
    out.push({ path: path.join('.'), value });
  }
  return out;
}

export function inspectPluginManifest(manifest, sourceName = 'plugin.json') {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw new Error('Expected a plugin manifest JSON object.');
  }

  const signals = new Set();
  const leaves = walk(manifest);
  const textLeaves = leaves.filter((entry) => typeof entry.value === 'string');

  if (!manifest.version) signals.add('missing-version');
  if (textLeaves.some((entry) => /^https?:\/\//i.test(entry.value))) signals.add('network-reference');
  if (textLeaves.some((entry) => SENSITIVE_PATH_RE.test(entry.value))) signals.add('sensitive-path-reference');
  if (textLeaves.some((entry) => SHELL_INSTRUCTION_RE.test(entry.value))) signals.add('shell-reference');

  // Components that run a program when the plugin loads or a tool is used.
  const present = (key) => manifest[key] !== undefined && manifest[key] !== null &&
    (typeof manifest[key] !== 'object' || Object.keys(manifest[key]).length > 0);
  if (['hooks', 'mcpServers', 'lspServers', 'scripts'].some(present)) signals.add('plugin-executable-components');

  const toolish = leaves.filter((entry) => /(?:tool|permission|capabilit)/i.test(entry.path));
  if (toolish.some((entry) => isWildcard(entry.value))) {
    signals.add('wildcard-tool-scope');
  }

  return {
    name: String(manifest.name || sourceName),
    kind: 'plugin',
    source: { type: 'plugin-manifest', path: sourceName },
    fingerprint: sha256Json(manifest),
    metadata: {
      name: manifest.name || null,
      version: manifest.version || null,
      description: manifest.description || null
    },
    signals: [...signals].sort(),
    envKeys: []
  };
}
