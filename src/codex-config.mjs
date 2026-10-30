import { decodeTomlValue, parseTomlStatements } from './toml-lite.mjs';

const CODEX_MCP_NESTED_SECTIONS = new Set(['env', 'http_headers', 'env_http_headers']);

// env_vars entries are names, optionally objects with a name and a source. Each
// entry is recorded with its source so moving a variable from a static value to
// forwarding from the host changes the fingerprint.
function envEntries(value) {
  if (!Array.isArray(value)) throw new Error('Codex env_vars must be an array.');
  return value.map((item) => {
    if (typeof item === 'string' && item) return { name: item, source: 'host' };
    if (item && typeof item === 'object' && !Array.isArray(item) && typeof item.name === 'string' && item.name) {
      for (const key of Object.keys(item)) {
        if (!['name', 'source'].includes(key)) throw new Error(`Unsupported Codex env_vars field "${key}".`);
      }
      if (item.source !== undefined && typeof item.source !== 'string') throw new Error('Codex env_vars source must be a string.');
      return { name: item.name, source: item.source === undefined ? 'host' : `host:${item.source}` };
    }
    throw new Error('Codex env_vars entries must be names or objects with a name.');
  });
}

// env_http_headers maps a header to the name of a host variable. The variable name is
// recorded so pointing a header at a different secret changes the fingerprint.
function recordEnvHeader(server, header, variable) {
  if (typeof variable !== 'string' || !variable) throw new Error('Codex env_http_headers values must be variable names.');
  server._trustdexFingerprintData.envHttpHeaderKeys.push(header);
  server._trustdexFingerprintData.envHttpHeaderSources[header] = variable;
}

const ENV_PLACEHOLDERS = { static: '<redacted>', 'bearer-token': '<bearer-token>' };

// A variable can be declared more than once (for example a static value and a bearer
// token variable); record every origin, sorted, so the result does not depend on order.
function recordEnv(server, name, origin) {
  const origins = server._trustdexFingerprintData.envOrigins;
  const all = new Set(origins[name] ? origins[name].split('+') : []);
  all.add(origin);
  origins[name] = [...all].sort().join('+');
  server.env[name] = all.has('static') ? ENV_PLACEHOLDERS.static : ENV_PLACEHOLDERS[origin] || '<forwarded>';
}

function applyAssignment(server, nested, key, value) {
  const signals = server._trustdexSignals;

  if (nested === 'env') {
    recordEnv(server, key, 'static');
    return;
  }
  if (nested === 'http_headers') {
    server._trustdexFingerprintData.httpHeaderKeys.push(key);
    signals.add('static-http-headers');
    return;
  }
  if (nested === 'env_http_headers') {
    recordEnvHeader(server, key, value);
    signals.add('env-http-headers');
    return;
  }

  if (nested) {
    throw new Error(`Unsupported Codex MCP subsection "${nested}".`);
  }

  if (key === 'command' && typeof value === 'string') server.command = value;
  else if (key === 'args' && Array.isArray(value)) server.args = value.map(String);
  else if (key === 'url' && typeof value === 'string') server.url = value;
  else if (key === 'cwd' && typeof value === 'string') {
    server.args ??= [];
    server._trustdexFingerprintData.cwd = value;
  } else if (key === 'env' && value && typeof value === 'object' && !Array.isArray(value)) {
    for (const envKey of Object.keys(value)) recordEnv(server, envKey, 'static');
  } else if (key === 'env_vars') {
    const entries = envEntries(value);
    for (const entry of entries) recordEnv(server, entry.name, entry.source);
    if (entries.length) signals.add('env-forwarding');
  } else if (key === 'bearer_token_env_var' && typeof value === 'string') {
    recordEnv(server, value, 'bearer-token');
    signals.add('secret-env');
  } else if (key === 'http_headers' && value && typeof value === 'object') {
    server._trustdexFingerprintData.httpHeaderKeys.push(...Object.keys(value));
    if (Object.keys(value).length) signals.add('static-http-headers');
  } else if (key === 'env_http_headers' && value && typeof value === 'object') {
    for (const [header, variable] of Object.entries(value)) recordEnvHeader(server, header, variable);
    if (Object.keys(value).length) signals.add('env-http-headers');
  } else if (key === 'http_headers_helper' && typeof value === 'string') {
    server._trustdexFingerprintData.httpHeadersHelper = value;
    signals.add('header-helper-command');
  } else if (key === 'enabled_tools' && Array.isArray(value)) {
    server._trustdexFingerprintData.enabledTools = value.map(String).sort();
    if (value.some((item) => String(item) === '*')) signals.add('wildcard-tool-scope');
  } else if (key === 'disabled_tools' && Array.isArray(value)) {
    server._trustdexFingerprintData.disabledTools = value.map(String).sort();
  } else if (key === 'default_tools_approval_mode' && typeof value === 'string') {
    server._trustdexFingerprintData.defaultToolsApprovalMode = value;
    if (value === 'approve') signals.add('auto-approve-tools');
  } else if (key === 'enabled' && typeof value === 'boolean') {
    server._trustdexFingerprintData.enabled = value;
  } else if (key === 'startup_timeout_sec' && typeof value === 'number') {
    server._trustdexFingerprintData.startupTimeoutSec = value;
  } else if (key === 'tool_timeout_sec' && typeof value === 'number') {
    server._trustdexFingerprintData.toolTimeoutSec = value;
  } else {
    throw new Error(`Unsupported or invalid Codex MCP key "${key}".`);
  }
}

function newServer() {
  return {
    env: {},
    _trustdexSignals: new Set(),
    _trustdexFingerprintData: {
      format: 'codex-toml',
      cwd: null,
      envOrigins: Object.create(null),
      httpHeaderKeys: [],
      envHttpHeaderKeys: [],
      envHttpHeaderSources: Object.create(null),
      httpHeadersHelper: null,
      enabledTools: [],
      disabledTools: [],
      defaultToolsApprovalMode: null,
      enabled: null,
      startupTimeoutSec: null,
      toolTimeoutSec: null
    }
  };
}

const FORBIDDEN_NAMES = new Set(['__proto__', 'prototype', 'constructor']);

const LAYOUT_ERROR = 'Unsupported Codex MCP layout: define each server in its own [mcp_servers.<name>] table.';

// Parse every mcp_servers definition in a Codex config.toml. Spaced or quoted headers
// resolve to the same server as plain ones. Servers defined any other way (a bare
// [mcp_servers] table, root-level dotted keys, or a whole server as an inline table)
// are rejected rather than skipped. Returns the MCP config plus the source spans that
// belong to each server, for gating.
export function parseCodexMcpTomlWithSpans(text) {
  const statements = parseTomlStatements(text);
  const servers = Object.create(null);
  const spans = [];
  const assigned = new Set();
  const declaredTables = new Set();

  for (const statement of statements) {
    const span = { start: statement.start, end: statement.end };
    if (statement.path[0] !== 'mcp_servers') continue;
    if (statement.type === 'array-table') throw new Error('Unsupported Codex MCP array of tables.');

    if (statement.type === 'table') {
      const [, name, nested, ...rest] = statement.path;
      if (name === undefined) throw new Error('Unsupported Codex MCP section "[mcp_servers]".');
      if (!name || FORBIDDEN_NAMES.has(name)) throw new Error('Unsupported Codex MCP server name.');
      if (rest.length || (nested !== undefined && !CODEX_MCP_NESTED_SECTIONS.has(nested))) {
        throw new Error(`Unsupported Codex MCP subsection "${[nested, ...rest].join('.')}".`);
      }
      const tableId = statement.path.join('\u0000');
      if (declaredTables.has(tableId)) throw new Error('Unsupported Codex TOML: a server table is defined more than once.');
      declaredTables.add(tableId);
      if (!servers[name]) servers[name] = newServer();
      spans.push({ name, header: true, ...span });
      continue;
    }

    if (statement.table.length < 2) throw new Error(LAYOUT_ERROR);
    const [, name, ...keyPath] = statement.path;
    const id = statement.path.join('\u0000');
    if (assigned.has(id)) throw new Error('Unsupported Codex TOML: a key is defined more than once.');
    assigned.add(id);
    spans.push({ name, ...span });
    const server = servers[name];
    if (keyPath.length === 1) {
      applyAssignment(server, '', keyPath[0], decodeTomlValue(statement.value));
    } else if (keyPath.length === 2 && CODEX_MCP_NESTED_SECTIONS.has(keyPath[0])) {
      const parent = statement.path.slice(0, 3).join('\u0000');
      if (assigned.has(parent)) throw new Error('Unsupported Codex TOML: a key is defined more than once.');
      applyAssignment(server, keyPath[0], keyPath[1], decodeTomlValue(statement.value));
    } else {
      throw new Error(`Unsupported Codex MCP subsection "${keyPath.slice(0, -1).join('.')}".`);
    }
  }

  for (const server of Object.values(servers)) {
    server._trustdexSignals = [...server._trustdexSignals].sort();
    const data = server._trustdexFingerprintData;
    data.httpHeaderKeys = [...new Set(data.httpHeaderKeys)].sort();
    data.envHttpHeaderKeys = [...new Set(data.envHttpHeaderKeys)].sort();
    data.envHttpHeaderSources = Object.fromEntries(Object.entries(data.envHttpHeaderSources).sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0)));
    data.envOrigins = Object.fromEntries(Object.entries(data.envOrigins).sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0)));
  }

  return { config: { mcpServers: servers }, spans, statements };
}

export function parseCodexMcpToml(text) {
  return parseCodexMcpTomlWithSpans(text).config;
}

// Remove every statement that belongs to a server that is not exposed. A header removes
// everything up to the next table header.
export function gateCodexToml(text, results, options = {}) {
  const includeAsk = Boolean(options.includeAsk);
  const decisions = new Map(results.map((result) => [result.name, result.action]));
  const keep = (name) => {
    const action = decisions.get(name);
    return action === 'allow' || (includeAsk && action === 'ask');
  };
  const source = String(text || '');
  const { spans, statements } = parseCodexMcpTomlWithSpans(source);
  const remove = [];
  const headers = statements.filter((statement) => statement.type === 'table' || statement.type === 'array-table');
  const headerStarts = headers.map((statement) => statement.start);
  const nextHeader = (start) => {
    let low = 0;
    let high = headerStarts.length;
    while (low < high) {
      const mid = (low + high) >> 1;
      if (headerStarts[mid] > start) high = mid;
      else low = mid + 1;
    }
    return low < headerStarts.length ? headerStarts[low] : source.length;
  };
  for (const span of spans) {
    if (keep(span.name)) continue;
    if (span.header) {
      remove.push([span.start, nextHeader(span.start)]);
    } else {
      remove.push([span.start, span.end]);
    }
  }
  remove.sort((a, b) => a[0] - b[0]);
  let output = '';
  let cursor = 0;
  for (const [start, end] of remove) {
    if (start > cursor) output += source.slice(cursor, start);
    cursor = Math.max(cursor, end);
  }
  output += source.slice(cursor);
  return output;
}
