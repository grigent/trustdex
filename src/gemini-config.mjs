import crypto from 'node:crypto';

// Fields documented for Gemini CLI `mcpServers` entries. The OAuth and Google
// credential fields (`oauth`, `authProviderType`, `targetAudience`,
// `targetServiceAccount`) are documented but have no inspection yet, so they fail
// closed instead of passing through unread.
const COMMON_KEYS = ['timeout', 'trust', 'includeTools', 'excludeTools'];
const SERVER_KEYS = {
  command: new Set(['command', 'args', 'env', 'cwd', ...COMMON_KEYS]),
  url: new Set(['url', 'headers', ...COMMON_KEYS]),
  httpUrl: new Set(['httpUrl', 'headers', ...COMMON_KEYS])
};
// Gemini expands POSIX references recursively before validating settings. Its MCP
// client also expands references in env and headers, including %NAME% on Windows.
const SETTINGS_REFERENCE = /\$(?:\w|\{)/;
const MCP_REFERENCE = /\$\{[^}]*\}|\$\{|\$\w+|%\w+%/g;
const SIMPLE_REFERENCE = /^(?:\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)|%([A-Za-z_]\w*)%)$/;

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requireKeys(value, allowed, context) {
  if (Object.keys(value).some((key) => !allowed.has(key))) {
    throw new Error(`Unsupported ${context} field. Gemini MCP inspection fails closed on unknown settings.`);
  }
}

function environmentReferences(value) {
  return Array.from(value.matchAll(MCP_REFERENCE), ([token]) => {
    const match = SIMPLE_REFERENCE.exec(token);
    if (!match) throw new Error('Unsupported Gemini MCP environment reference; use a simple variable name without operators or defaults.');
    return match[1] || match[2] || token;
  });
}

function referencesByKey(values) {
  return Object.fromEntries(Object.entries(values)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => [key, environmentReferences(value)]));
}

function digest(value) {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

// A missing tool filter is not the same as an empty one, so the digest keeps the
// difference. Tool names themselves stay out of fingerprints and reports.
function toolFilterDigest(server, key) {
  const list = server[key];
  if (list === undefined) return digest(null);
  if (!Array.isArray(list) || list.some((tool) => typeof tool !== 'string' || !tool)) {
    throw new Error(`Gemini MCP ${key} must be an array of tool names.`);
  }
  if (list.some((tool) => SETTINGS_REFERENCE.test(tool))) {
    throw new Error('Gemini MCP tool filters must not contain unresolved variable expansion.');
  }
  return digest([...new Set(list)].sort());
}

// Return inspection input only. Gating must preserve entries from the original
// configuration, never these internal adapter annotations.
export function parseGeminiMcpConfig(config) {
  if (!isRecord(config) || !isRecord(config.mcpServers)) {
    throw new Error('Expected a Gemini MCP JSON object containing an mcpServers object.');
  }
  requireKeys(config, new Set(['mcpServers']), 'Gemini MCP root');

  const entries = Object.entries(config.mcpServers).map(([name, server]) => {
    if (!/^[A-Za-z0-9_-]+$/.test(name) || ['__proto__', 'constructor', 'prototype'].includes(name)) {
      throw new Error('Unsupported Gemini MCP server name.');
    }
    if (!isRecord(server)) throw new Error('Each Gemini MCP server must be an object.');
    const kinds = Object.keys(SERVER_KEYS).filter((key) => Object.hasOwn(server, key));
    if (kinds.length !== 1) {
      throw new Error('A Gemini MCP server must have exactly one of command, url, or httpUrl.');
    }
    const [kind] = kinds;
    requireKeys(server, SERVER_KEYS[kind], 'Gemini MCP server');
    if (server.trust !== undefined && typeof server.trust !== 'boolean') {
      throw new Error('Gemini MCP trust must be a boolean.');
    }
    if (server.timeout !== undefined && !(Number.isFinite(server.timeout) && server.timeout > 0)) {
      throw new Error('Gemini MCP timeout must be a positive number.');
    }
    // `trust: true` can skip tool-call confirmation in a trusted workspace.
    const signals = server.trust === true ? ['auto-approve-tools'] : [];
    const adapter = {
      runtime: 'gemini-mcp-v1',
      transport: { command: 'stdio', url: 'sse', httpUrl: 'http' }[kind],
      trust: server.trust === true,
      includeToolsDigest: toolFilterDigest(server, 'includeTools'),
      excludeToolsDigest: toolFilterDigest(server, 'excludeTools')
    };
    const inspected = { ...server };

    if (kind === 'command') {
      if (typeof server.command !== 'string' || !server.command.trim()) {
        throw new Error('Gemini stdio MCP servers require a non-empty command.');
      }
      if (SETTINGS_REFERENCE.test(server.command)) {
        throw new Error('Gemini command variable expansion is unsupported; use an explicit executable.');
      }
      if (server.args !== undefined && (!Array.isArray(server.args) || server.args.some((arg) => typeof arg !== 'string' || SETTINGS_REFERENCE.test(arg)))) {
        throw new Error('Gemini MCP args must be strings without unresolved variable expansion.');
      }
      if (server.env !== undefined && (!isRecord(server.env) || Object.values(server.env).some((value) => typeof value !== 'string'))) {
        throw new Error('Gemini MCP env must contain string values.');
      }
      if (server.cwd !== undefined && (typeof server.cwd !== 'string' || !server.cwd.trim() || SETTINGS_REFERENCE.test(server.cwd))) {
        throw new Error('Gemini MCP cwd must be a literal directory path.');
      }
      // Reference names are safe metadata; do not fingerprint env values. The working
      // directory decides what a relative command or script resolves to, so a change
      // must alter the fingerprint, but the path itself is not retained.
      adapter.envReferences = referencesByKey(server.env || {});
      adapter.cwdDigest = digest(server.cwd ?? null);
    } else {
      const url = server[kind];
      if (typeof url !== 'string' || !url.trim() || SETTINGS_REFERENCE.test(url)) {
        throw new Error('Gemini remote MCP servers require a literal HTTP(S) URL.');
      }
      let endpoint;
      try { endpoint = new URL(url); } catch {
        throw new Error('Invalid Gemini MCP URL.');
      }
      if (!['https:', 'http:'].includes(endpoint.protocol)) {
        throw new Error('Unsupported Gemini MCP URL scheme.');
      }
      // The generic inspector fingerprints its input URL. Reject URL credentials
      // and query/fragment values before they can enter that fingerprint.
      if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
        throw new Error('Gemini MCP URL credentials, query parameters, and fragments are unsupported; use headers.');
      }
      if (server.headers !== undefined) {
        if (!isRecord(server.headers) || Object.values(server.headers).some((value) => typeof value !== 'string')) {
          throw new Error('Gemini MCP headers must contain string values.');
        }
        adapter.headerNames = Object.keys(server.headers).sort();
        // Keep existing header restrictions even when a value also references the environment.
        if (adapter.headerNames.length) signals.push('static-http-headers');
        const headerReferences = Object.fromEntries(Object.entries(referencesByKey(server.headers))
          .filter(([, references]) => references.length));
        if (Object.keys(headerReferences).length) {
          adapter.headerReferences = headerReferences;
          signals.push('env-http-headers');
        }
      }
      // The generic inspector reads the endpoint from `url`.
      delete inspected.httpUrl;
      inspected.url = url;
    }

    return [name, {
      ...inspected,
      _trustdexSignals: signals,
      _trustdexFingerprintData: adapter
    }];
  });
  return { mcpServers: Object.fromEntries(entries) };
}
