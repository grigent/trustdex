const URL_RE = /https?:\/\/[^\s)>'"]+/gi;
const SENSITIVE_PATH_RE = /(?:~\/\.(?:ssh|aws|config)|\/(?:etc|var\/run\/secrets)\/|\.env(?:\b|\/)|credentials?\b)/i;
const SHELL_INSTRUCTION_RE = /(?:curl\s+[^\n|]+\|\s*(?:sh|bash)|wget\s+[^\n|]+\|\s*(?:sh|bash)|\brm\s+-rf\b|\bsudo\b|\bpowershell\b|\bchmod\s+\+x\b)/i;
const INSTALL_RE = /(?:\bnpm\s+(?:i|install)\s+-g\b|\bpipx?\s+install\b|\bcargo\s+install\b|\bcurl\b|\bwget\b)/i;

function parseScalar(value) {
  const raw = value.trim();
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

export function parseFrontmatter(text) {
  const value = String(text || '');
  if (!value.startsWith('---\n') && !value.startsWith('---\r\n')) return {};
  const lines = value.split(/\r?\n/);
  const result = {};
  for (let i = 1; i < lines.length; i += 1) {
    if (lines[i].trim() === '---') break;
    const match = lines[i].match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
    if (match) result[match[1]] = parseScalar(match[2]);
  }
  return result;
}

function wildcardTools(metadata) {
  const tools = metadata['allowed-tools'] ?? metadata.allowed_tools ?? metadata.tools;
  if (tools === '*') return true;
  if (Array.isArray(tools)) return tools.some((tool) => String(tool).trim() === '*');
  return typeof tools === 'string' && /(^|[,\s])\*($|[,\s])/.test(tools);
}

export function inspectSkillText(text, sourceName = 'SKILL.md') {
  const value = String(text || '');
  const metadata = parseFrontmatter(value);
  const signals = new Set();

  if (URL_RE.test(value)) signals.add('network-instructions');
  URL_RE.lastIndex = 0;
  if (SENSITIVE_PATH_RE.test(value)) signals.add('sensitive-path-instructions');
  if (SHELL_INSTRUCTION_RE.test(value)) signals.add('shell-instructions');
  if (INSTALL_RE.test(value)) signals.add('install-instructions');
  if (wildcardTools(metadata)) signals.add('wildcard-tool-scope');

  return {
    name: String(metadata.name || sourceName),
    kind: 'skill',
    source: { type: 'skill-file', path: sourceName },
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

  const toolish = leaves.filter((entry) => /(?:tool|permission|capabilit)/i.test(entry.path));
  if (toolish.some((entry) => entry.value === '*' || (Array.isArray(entry.value) && entry.value.includes('*')))) {
    signals.add('wildcard-tool-scope');
  }

  return {
    name: String(manifest.name || sourceName),
    kind: 'plugin',
    source: { type: 'plugin-manifest', path: sourceName },
    metadata: {
      name: manifest.name || null,
      version: manifest.version || null,
      description: manifest.description || null
    },
    signals: [...signals].sort(),
    envKeys: []
  };
}
