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

// YAML double-quoted escapes this reader decodes. Any other escape is left in place, where
// the stray quote it keeps marks the scope as not read in full. An escape that decodes to a
// control character (which would reach the terminal) or to syntax this reader treats
// specially (`#`, quotes, brackets, commas) becomes U+FFFD, which also marks it unread.
const YAML_ESCAPES = { 0: '\0', a: '\x07', b: '\b', t: '\t', '\t': '\t', n: '\n', v: '\v', f: '\f', r: '\r',
  e: '\x1b', ' ': ' ', '"': '"', '/': '/', '\\': '\\', N: '\x85', _: '\xa0', L: '\u2028', P: '\u2029' };
const YAML_HEX_LENGTH = { x: 2, u: 4, U: 8 };
// Flow lists nested deeper than this are left unread instead of exhausting the stack.
const MAX_FLOW_DEPTH = 8;

const UNSAFE_DECODED_RE = /[\x00-\x08\x0a-\x1f\x7f-\x9f\u2028\u2029#"'\\[\]{},]/;

function decodeDoubleQuoted(body) {
  if (!body.includes('\\')) return body;
  let out = '';
  for (let i = 0; i < body.length; i += 1) {
    if (body[i] !== '\\') { out += body[i]; continue; }
    const code = body[i + 1];
    let decoded;
    if (Object.hasOwn(YAML_ESCAPES, code)) {
      decoded = YAML_ESCAPES[code];
      i += 1;
    } else {
      const length = YAML_HEX_LENGTH[code];
      const hex = length && body.slice(i + 2, i + 2 + length);
      if (!hex || !/^[0-9A-Fa-f]+$/.test(hex) || hex.length !== length || Number.parseInt(hex, 16) > 0x10ffff) return null;
      decoded = String.fromCodePoint(Number.parseInt(hex, 16));
      i += 1 + length;
    }
    // U+FFFD in its place keeps the words around it, joins no new ones, and marks the scope
    // unread; a line break still separates words, as YAML reads it.
    out += UNSAFE_DECODED_RE.test(decoded) ? (/\s/.test(decoded) ? '\uFFFD ' : '\uFFFD') : decoded;
  }
  return out;
}

function parseScalar(value, depth = 0) {
  let raw = value.trim();
  // An unquoted value ends at " #".
  if (!/^["'[]/.test(raw)) raw = raw.replace(/\s+#.*$/, '');
  else if (/^(["']).*\1\s+#/.test(raw)) raw = raw.replace(/^((["']).*?\2)\s+#.*$/, '$1');
  if (!raw) return '';
  if (raw.length > 1 && raw.startsWith('"') && raw.endsWith('"')) {
    // YAML decodes "\x2a" to "*", so the scope is read after the same decoding.
    return decodeDoubleQuoted(raw.slice(1, -1)) ?? raw;
  }
  if (raw.length > 1 && raw.startsWith("'") && raw.endsWith("'")) return raw.slice(1, -1).replaceAll("''", "'");
  if (raw.startsWith('[') && raw.endsWith(']')) {
    if (depth >= MAX_FLOW_DEPTH) return raw;
    return raw.slice(1, -1).split(',').map((item) => parseScalar(item, depth + 1)).filter(Boolean);
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
  // A lone carriage return is a YAML line break, so it splits lines here too.
  const value = String(text || '').replace(/^\uFEFF/, '').replace(/^(?:[ \t]*(?:\r\n?|\n))+/, '');
  if (!/^---[ \t]*(?:\r\n?|\n)/.test(value)) return [];
  const lines = value.split(/\r\n?|\n/);
  const entries = [];
  const end = lines.findIndex((line, index) => index > 0 && /^(?:---|\.\.\.)\s*$/.test(line));
  entries.header = lines.slice(1, end < 0 ? lines.length : end).join('\n');
  for (let i = 1; i < lines.length; i += 1) {
    if (/^(?:---|\.\.\.)\s*$/.test(lines[i])) break;
    const match = lines[i].match(/^\s*["']?([A-Za-z0-9_-]+)["']?\s*:\s*(.*)$/);
    if (!match) continue;
    let raw = match[2];
    // An alias, anchor, or tag makes the value something other than the text written.
    let unsupported = /^[>|]|^[*&!]\S/.test(raw.trim());
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
// Claude Code runs `!`command`` and ```! blocks in SKILL.md while rendering the skill,
// before the model sees it and without a permission prompt.
const SKILL_SHELL_INJECTION_RE = /!`[^`\r\n]+`|^[ \t]*(?:`{3,}|~{3,})!/m;
// A plain or quoted `hooks` key in a block mapping or a flow map registers session hooks.
const SKILL_HOOKS_KEY_RE = /(?:^|[{,])[ \t]*["']?hooks["']?[ \t]*:/m;
// Frontmatter this inspector cannot read as keys: any other mention of hooks, YAML explicit
// keys, aliases, tags and anchors at a key position, escaped quoted keys, and any of those
// after a flow map opens, including on later lines.
const SKILL_UNREAD_FRONTMATTER_RE =
  /hooks|^[ \t]*(?:\?(?:[ \t]|$)|\*[^\s*,{}[\]]|[!&]|"[^"\n]*\\)/im;

function hasUnreadFrontmatter(header) {
  const flow = header.indexOf('{');
  return SKILL_UNREAD_FRONTMATTER_RE.test(header) || (flow >= 0 && /[?*!&\\]/.test(header.slice(flow)));
}
const SHELL_TOOL_RE = /(?:^|[\s,[\]"'])(?:Bash|PowerShell)(?=$|[\s,(\]"'])/i;

function isWildcard(tools) {
  if (Array.isArray(tools)) return tools.some((tool) => isWildcard(String(tool)));
  return typeof tools === 'string' && /(?:^|[,\s])(?:[A-Za-z0-9_-]+\(\s*\*\s*\)|\*)(?=$|[,\s])/.test(tools);
}

// Brackets, braces, or quotes left in a parsed scope mean the value was not fully read.
function hasStraySyntax(value) {
  return [value].flat(Infinity).some((item) => typeof item === 'string' && /[[\]{}"'\uFFFD]/.test(item));
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
  // allowed-tools grants run without a permission prompt; a grant that cannot be read
  // in full counts as one, and a shell tool named anywhere in it counts as shell.
  const grants = scopes.filter((entry) => /^allowed[-_]?tools$/i.test(entry.key));
  const granted = grants.some((entry) => [entry.value].flat().some((item) => String(item ?? '').trim())) ||
    mentioned > read || grants.some((entry) => entry.unsupported);
  // A YAML comment folded into a list item is not a grant.
  const shellGrant = grants.some((entry) => SHELL_TOOL_RE.test([entry.value].flat()
    .map((item) => String(item ?? '').replace(/(?:^|\s)#.*$/, '')).join(' '))) ||
    ((mentioned > read || grants.some((entry) => entry.unsupported || hasStraySyntax(entry.value))) &&
      SHELL_TOOL_RE.test(entries.header || ''));
  return [
    ...(wildcard ? ['wildcard-tool-scope'] : []),
    ...(uninspected ? ['uninspected-tool-scope'] : []),
    ...(granted ? ['skill-auto-approved-tools'] : []),
    ...(shellGrant ? ['skill-shell-auto-approve'] : [])
  ];
}

export function inspectSkillText(text, sourceName = 'SKILL.md') {
  const value = String(text || '');
  // UTF-16 or binary text read as UTF-8 hides its frontmatter behind NUL characters.
  if (value.includes('\0')) throw new Error(`Unsupported ${String(sourceName).split(/[\\/]/).pop()}: it contains NUL characters (UTF-16 and binary files are not read).`);
  const entries = frontmatterEntries(value);
  const metadata = Object.fromEntries(entries.map((entry) => [entry.key, entry.value]));
  const signals = new Set(toolScopeSignals(entries));

  if (URL_RE.test(value)) signals.add('network-instructions');
  URL_RE.lastIndex = 0;
  if (SENSITIVE_PATH_RE.test(value)) signals.add('sensitive-path-instructions');
  if (SHELL_INSTRUCTION_RE.test(value)) signals.add('shell-instructions');
  if (INSTALL_RE.test(value)) signals.add('install-instructions');
  // Skill hooks register commands for the rest of the session, however the key is written.
  const header = entries.header || '';
  if (SKILL_HOOKS_KEY_RE.test(header)) signals.add('skill-hooks');
  else if (hasUnreadFrontmatter(header)) signals.add('skill-frontmatter-uninspected');
  if (SKILL_SHELL_INJECTION_RE.test(value)) signals.add('skill-shell-injection');

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
  const present = (value) => value !== undefined && value !== null &&
    (typeof value !== 'object' || Object.keys(value).length > 0);
  const experimental = manifest.experimental && typeof manifest.experimental === 'object' ? manifest.experimental : {};
  if (['hooks', 'mcpServers', 'lspServers', 'scripts', 'monitors', 'channels'].some((key) => present(manifest[key])) ||
    present(experimental.monitors)) signals.add('plugin-executable-components');
  // Claude Code also loads hooks/hooks.json, .mcp.json, .lsp.json, monitors/monitors.json,
  // bin/, skills, and commands from the plugin root whether or not the manifest names
  // them, so a manifest alone never shows that a plugin runs nothing.
  signals.add('plugin-components-uninspected');

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
