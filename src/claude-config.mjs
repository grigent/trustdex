const SERVER_KEYS = {
  stdio: new Set(['type', 'command', 'args', 'env']),
  http: new Set(['type', 'url', 'headers', 'headersHelper']),
  sse: new Set(['type', 'url', 'headers', 'headersHelper'])
};
const ENV_REFERENCE = /\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-[^}]*)?\}/g;

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requireKeys(value, allowed, context) {
  if (Object.keys(value).some((key) => !allowed.has(key))) {
    throw new Error(`Unsupported ${context} field. Claude MCP inspection fails closed on unknown settings.`);
  }
}

function environmentReferences(value) {
  return [...new Set([...value.matchAll(ENV_REFERENCE)].map((match) => match[1]))].sort();
}

// Return inspection input only. Gating must preserve entries from the original
// configuration, never these internal adapter annotations.
export function parseClaudeMcpConfig(config) {
  if (!isRecord(config) || !isRecord(config.mcpServers)) {
    throw new Error('Expected a Claude MCP JSON object containing an mcpServers object.');
  }
  requireKeys(config, new Set(['mcpServers']), 'Claude MCP root');

  const entries = Object.entries(config.mcpServers).map(([name, server]) => {
    if (!/^[A-Za-z0-9_-]+$/.test(name) || ['__proto__', 'constructor', 'prototype'].includes(name)) {
      throw new Error('Unsupported Claude MCP server name.');
    }
    if (!isRecord(server)) throw new Error('Each Claude MCP server must be an object.');
    const type = server.type === undefined ? 'stdio' : server.type;
    if (typeof type !== 'string' || !Object.hasOwn(SERVER_KEYS, type)) {
      throw new Error('Unsupported Claude MCP transport. Supported: stdio, http, sse.');
    }
    requireKeys(server, SERVER_KEYS[type], 'Claude MCP server');
    const signals = [];
    const adapter = { runtime: 'claude-mcp-v1', transport: type };

    if (type === 'stdio') {
      if (typeof server.command !== 'string' || !server.command.trim()) {
        throw new Error('Claude stdio MCP servers require a non-empty command.');
      }
      if (server.command.includes('${')) {
        throw new Error('Claude command variable expansion is unsupported; use an explicit executable.');
      }
      if (server.args !== undefined && (!Array.isArray(server.args) || server.args.some((arg) => typeof arg !== 'string' || arg.includes('${')))) {
        throw new Error('Claude MCP args must be strings without unresolved variable expansion.');
      }
      if (server.env !== undefined && (!isRecord(server.env) || Object.values(server.env).some((value) => typeof value !== 'string'))) {
        throw new Error('Claude MCP env must contain string values.');
      }
      // Reference names are safe metadata; do not fingerprint env values or defaults.
      adapter.envReferences = Object.fromEntries(Object.entries(server.env || {})
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, value]) => [key, environmentReferences(value)]));
    } else {
      if (typeof server.url !== 'string' || !server.url.trim() || server.url.includes('${')) {
        throw new Error('Claude remote MCP servers require a literal HTTP(S) URL.');
      }
      let endpoint;
      try { endpoint = new URL(server.url); } catch {
        throw new Error('Invalid Claude MCP URL.');
      }
      if (!['https:', 'http:'].includes(endpoint.protocol)) {
        throw new Error('Unsupported Claude MCP URL scheme.');
      }
      // The generic inspector fingerprints its input URL. Reject URL credentials
      // and query/fragment values before they can enter that fingerprint.
      if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
        throw new Error('Claude MCP URL credentials, query parameters, and fragments are unsupported; use headers.');
      }
      if (server.headers !== undefined) {
        if (!isRecord(server.headers) || Object.values(server.headers).some((value) => typeof value !== 'string')) {
          throw new Error('Claude MCP headers must contain string values.');
        }
        adapter.headerNames = Object.keys(server.headers).sort();
        adapter.headerReferences = Object.fromEntries(Object.entries(server.headers)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([key, value]) => [key, environmentReferences(value)]));
        if (adapter.headerNames.length) {
          const references = Object.values(adapter.headerReferences);
          if (references.some((refs) => refs.length)) signals.push('env-http-headers');
          if (references.some((refs) => !refs.length)) signals.push('static-http-headers');
        }
      }
      if (server.headersHelper !== undefined) {
        if (typeof server.headersHelper !== 'string' || !server.headersHelper.trim()) {
          throw new Error('Claude MCP headersHelper must be a non-empty string.');
        }
        signals.push('header-helper-command');
        adapter.hasHeadersHelper = true;
      }
    }

    return [name, {
      ...server,
      _trustdexSignals: signals,
      _trustdexFingerprintData: adapter
    }];
  });
  return { mcpServers: Object.fromEntries(entries) };
}
