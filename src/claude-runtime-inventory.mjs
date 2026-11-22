// Converts the `system/init` event that Claude Code documents for
// `--output-format stream-json` into a value-free runtime tool inventory.
// The user captures the event and passes the file; TrustDex does not start Claude,
// read session state, or contact MCP servers. Only server names and per-server tool
// counts leave this module. Tool names, paths, the model, and every other field are
// dropped. Anything that would make a count a guess is an error, not a best effort.

const MAX_EVENTS = 100_000;

function initEvents(text) {
  const source = String(text ?? '').replace(/^\uFEFF/, '');
  let documents;
  try {
    const parsed = JSON.parse(source);
    documents = Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    const lines = source.split(/\r?\n/).filter((line) => line.trim());
    if (lines.length > MAX_EVENTS) throw new Error('Claude stream has too many events.');
    documents = lines.map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        throw new Error('Claude stream contains a line that is not JSON.');
      }
    });
  }
  return documents.filter((event) => event && typeof event === 'object' && !Array.isArray(event) &&
    event.type === 'system' && event.subtype === 'init');
}

// Claude Code builds an MCP tool's callable name as mcp__<server>__<tool>, replacing
// characters outside A-Z a-z 0-9 _ - in the server name with "_".
function toolPrefix(serverName) {
  return `mcp__${serverName.replace(/[^A-Za-z0-9_-]/g, '_')}__`;
}

export function claudeInitToRuntimeInventory(text, options = {}) {
  const events = initEvents(text);
  if (events.length !== 1) {
    throw new Error(`Expected exactly one Claude system/init event, found ${events.length}.`);
  }
  const [event] = events;
  if (!Array.isArray(event.mcp_servers) || !Array.isArray(event.tools) ||
      event.tools.some((tool) => typeof tool !== 'string')) {
    throw new Error('Claude system/init event is missing mcp_servers or tools.');
  }
  const servers = event.mcp_servers.map((server) => {
    if (!server || typeof server !== 'object' || Array.isArray(server) ||
        typeof server.name !== 'string' || !server.name.trim() || typeof server.status !== 'string') {
      throw new Error('Claude system/init event has a malformed MCP server entry.');
    }
    // A pending server connects later, so its tools are not in this event yet.
    if (server.status !== 'connected' && server.status !== 'failed' &&
        server.status !== 'needs-auth' && server.status !== 'disabled') {
      throw new Error('An MCP server has not finished connecting or has an unknown status; capture the event again.');
    }
    return { name: server.name, prefix: toolPrefix(server.name), toolCount: 0 };
  });
  if (new Set(servers.map((server) => server.name)).size !== servers.length ||
      new Set(servers.map((server) => server.prefix)).size !== servers.length) {
    throw new Error('Claude system/init event has MCP server names that cannot be told apart.');
  }
  for (const tool of event.tools) {
    if (!tool.startsWith('mcp__')) continue;
    const owners = servers.filter((server) => tool.startsWith(server.prefix) && tool.length > server.prefix.length);
    if (owners.length !== 1) {
      throw new Error('An MCP tool in the Claude system/init event does not belong to exactly one listed server.');
    }
    owners[0].toolCount += 1;
  }
  return {
    schemaVersion: 1,
    kind: 'agent-runtime-tool-inventory',
    runtime: 'claude',
    capturedAt: (options.now ? new Date(options.now) : new Date()).toISOString(),
    captureMethod: 'runtime-export',
    servers: servers
      .map(({ name, toolCount }) => ({ name, toolCount }))
      .sort((left, right) => left.name.localeCompare(right.name))
  };
}
