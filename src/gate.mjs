export function gateMcpConfig(config, results, options = {}) {
  if (config && Object.hasOwn(config, 'mcpServers') && Object.hasOwn(config, 'servers')) {
    throw new Error('Ambiguous MCP configuration: both mcpServers and servers are present.');
  }
  let containerKey = null;
  let servers = config;

  if (config?.mcpServers && typeof config.mcpServers === 'object') {
    containerKey = 'mcpServers';
    servers = config.mcpServers;
  } else if (config?.servers && typeof config.servers === 'object') {
    containerKey = 'servers';
    servers = config.servers;
  }

  if (!servers || typeof servers !== 'object' || Array.isArray(servers)) {
    throw new Error('Expected an MCP configuration object, or an object containing mcpServers/servers.');
  }

  const includeAsk = Boolean(options.includeAsk);
  if (!Array.isArray(results)) throw new Error('MCP policy results must be an array.');
  const decisions = new Map();
  for (const result of results) {
    if (!result || typeof result.name !== 'string' || !Object.hasOwn(servers, result.name) ||
        !['allow', 'ask', 'block'].includes(result.action) || decisions.has(result.name)) {
      throw new Error('MCP policy results contain an invalid, duplicate, or unknown decision.');
    }
    decisions.set(result.name, result.action);
  }
  // Uninspected servers must not silently disappear from a supposedly complete
  // policy result, even though filtering them out would avoid execution.
  if (decisions.size !== Object.keys(servers).length) {
    throw new Error('MCP policy results do not cover every configured server.');
  }
  const allowed = Object.create(null);

  for (const [name, server] of Object.entries(servers)) {
    const action = decisions.get(name);
    if (action === 'allow' || (includeAsk && action === 'ask')) {
      allowed[name] = server;
    }
  }

  // Spread creates own data properties even for "__proto__" and preserves the
  // ordinary JSON-facing object shape expected by existing clients.
  const safeAllowed = { ...allowed };
  const output = containerKey ? { ...config, [containerKey]: safeAllowed } : safeAllowed;

  return {
    config: output,
    summary: {
      total: Object.keys(servers).length,
      exposed: Object.keys(allowed).length,
      blocked: results.filter((result) => result.action === 'block').map((result) => result.name),
      needsReview: results.filter((result) => result.action === 'ask').map((result) => result.name)
    }
  };
}
