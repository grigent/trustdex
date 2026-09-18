export function gateMcpConfig(config, results, options = {}) {
  const servers = config?.mcpServers && typeof config.mcpServers === 'object'
    ? config.mcpServers
    : config;
  if (!servers || typeof servers !== 'object' || Array.isArray(servers)) {
    throw new Error('Expected an MCP configuration object or an object containing mcpServers.');
  }

  const includeAsk = Boolean(options.includeAsk);
  const decisions = new Map(results.map((result) => [result.name, result.action]));
  const allowed = {};

  for (const [name, server] of Object.entries(servers)) {
    const action = decisions.get(name);
    if (action === 'allow' || (includeAsk && action === 'ask')) {
      allowed[name] = server;
    }
  }

  const output = config?.mcpServers && typeof config.mcpServers === 'object'
    ? { ...config, mcpServers: allowed }
    : allowed;

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
