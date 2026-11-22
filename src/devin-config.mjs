import crypto from 'node:crypto';

// Fields documented for Devin CLI `mcp_config.json` servers. OAuth client fields
// (`oauthClientId`, `oauthClientSecret`, `oauthResource`, `oauthScopes`) are documented
// but have no inspection yet, so they fail closed instead of passing through unread.
const SERVER_KEYS = {
  stdio: new Set(['command', 'args', 'env', 'disabled', 'disabledTools']),
  remote: new Set(['url', 'transport', 'headers', 'disabled', 'disabledTools'])
};
const ENV_REFERENCE = /\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}/g;

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requireKeys(value, allowed, context) {
  if (Object.keys(value).some((key) => !allowed.has(key))) {
    throw new Error(`Unsupported ${context} field. Devin MCP inspection fails closed on unknown settings.`);
  }
}

// `${file:/path}` sends a local file's contents to the server and any other `${...}`
// form is unknown, so only `${env:NAME}` is accepted, and only in env and headers.
function environmentReferences(value) {
  if (value.replace(ENV_REFERENCE, '').includes('${')) {
    throw new Error('Unsupported Devin MCP variable expansion; only ${env:NAME} is inspected.');
  }
  return [...new Set([...value.matchAll(ENV_REFERENCE)].map((match) => match[1]))].sort();
}

function referencesByKey(record) {
  return Object.fromEntries(Object.entries(record)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => [key, environmentReferences(value)]));
}

// Return inspection input only. Gating must preserve entries from the original
// configuration, never these internal adapter annotations.
export function parseDevinMcpConfig(config) {
  if (!isRecord(config) || !isRecord(config.mcpServers)) {
    throw new Error('Expected a Devin MCP JSON object containing an mcpServers object.');
  }
  requireKeys(config, new Set(['mcpServers']), 'Devin MCP root');

  const entries = Object.entries(config.mcpServers).map(([name, server]) => {
    if (!/^[A-Za-z0-9_-]+$/.test(name) || ['__proto__', 'constructor', 'prototype'].includes(name)) {
      throw new Error('Unsupported Devin MCP server name.');
    }
    if (!isRecord(server)) throw new Error('Each Devin MCP server must be an object.');
    const hasCommand = Object.hasOwn(server, 'command');
    const hasUrl = Object.hasOwn(server, 'url');
    if (hasCommand === hasUrl) {
      throw new Error('A Devin MCP server must have exactly one of command or url.');
    }
    requireKeys(server, hasCommand ? SERVER_KEYS.stdio : SERVER_KEYS.remote, 'Devin MCP server');
    if (server.disabled !== undefined && typeof server.disabled !== 'boolean') {
      throw new Error('Devin MCP disabled must be a boolean.');
    }
    if (server.disabledTools !== undefined && (!Array.isArray(server.disabledTools) ||
        server.disabledTools.some((tool) => typeof tool !== 'string' || !tool))) {
      throw new Error('Devin MCP disabledTools must be an array of tool names.');
    }
    const signals = [];
    // A disabled server is inspected like an enabled one: the flag is one edit away
    // from running it. The flag and the hidden-tool list are fingerprinted, without
    // tool names, so enabling a server or unhiding a tool changes the review.
    const adapter = {
      runtime: 'devin-mcp-v1',
      transport: hasCommand ? 'stdio' : 'http',
      disabled: server.disabled === true,
      disabledToolsDigest: crypto.createHash('sha256')
        .update(JSON.stringify([...new Set(server.disabledTools || [])].sort())).digest('hex')
    };

    if (hasCommand) {
      if (typeof server.command !== 'string' || !server.command.trim()) {
        throw new Error('Devin stdio MCP servers require a non-empty command.');
      }
      if (server.command.includes('${')) {
        throw new Error('Devin command variable expansion is unsupported; use an explicit executable.');
      }
      if (server.args !== undefined && (!Array.isArray(server.args) || server.args.some((arg) => typeof arg !== 'string' || arg.includes('${')))) {
        throw new Error('Devin MCP args must be strings without unresolved variable expansion.');
      }
      if (server.env !== undefined && (!isRecord(server.env) || Object.values(server.env).some((value) => typeof value !== 'string'))) {
        throw new Error('Devin MCP env must contain string values.');
      }
      // Reference names are safe metadata; do not fingerprint env values.
      adapter.envReferences = referencesByKey(server.env || {});
    } else {
      if (server.transport !== undefined && server.transport !== 'http' && server.transport !== 'sse') {
        throw new Error('Unsupported Devin MCP transport. Supported: http, sse.');
      }
      adapter.transport = server.transport || 'http';
      if (typeof server.url !== 'string' || !server.url.trim() || server.url.includes('${')) {
        throw new Error('Devin remote MCP servers require a literal HTTP(S) URL.');
      }
      let endpoint;
      try { endpoint = new URL(server.url); } catch {
        throw new Error('Invalid Devin MCP URL.');
      }
      if (!['https:', 'http:'].includes(endpoint.protocol)) {
        throw new Error('Unsupported Devin MCP URL scheme.');
      }
      // The generic inspector fingerprints its input URL. Reject URL credentials
      // and query/fragment values before they can enter that fingerprint.
      if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
        throw new Error('Devin MCP URL credentials, query parameters, and fragments are unsupported; use headers.');
      }
      if (server.headers !== undefined) {
        if (!isRecord(server.headers) || Object.values(server.headers).some((value) => typeof value !== 'string')) {
          throw new Error('Devin MCP headers must contain string values.');
        }
        adapter.headerNames = Object.keys(server.headers).sort();
        adapter.headerReferences = referencesByKey(server.headers);
        if (adapter.headerNames.length) {
          const references = Object.values(adapter.headerReferences);
          if (references.some((refs) => refs.length)) signals.push('env-http-headers');
          if (references.some((refs) => !refs.length)) signals.push('static-http-headers');
        }
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
