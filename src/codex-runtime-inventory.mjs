// Converts captured responses to the `mcpServerStatus/list` request that Codex
// documents for `codex app-server` into a value-free runtime tool inventory.
// The user captures the response pages and passes the file; TrustDex does not start
// Codex, read session state, or contact MCP servers. Only server names and per-server
// tool counts leave this module. Tool names, schemas, origins, plugin ids, and every
// other field are dropped. Anything that would make a count a guess is an error.

const MAX_PAGES = 1_000;
// Statuses of a server that finished starting. `notStarted` and `starting` have no
// final tool catalog yet, and a missing status is not tied to a thread's runtime.
const SETTLED = new Set(['connected', 'authenticationRequired', 'failed', 'cancelled', 'disabled']);

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function pages(text) {
  const source = String(text ?? '').replace(/^\uFEFF/, '');
  let documents;
  try {
    const parsed = JSON.parse(source);
    documents = Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    const lines = source.split(/\r?\n/).filter((line) => line.trim());
    if (lines.length > MAX_PAGES) throw new Error('Codex capture has too many lines.');
    documents = lines.map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        throw new Error('Codex capture contains a line that is not JSON.');
      }
    });
  }
  if (documents.length === 0 || documents.length > MAX_PAGES) {
    throw new Error('Codex capture must hold between 1 and 1000 mcpServerStatus/list responses.');
  }
  // Every document must be a response page. Other app-server messages are refused
  // rather than skipped, so an unrelated list is never read as the inventory.
  return documents.map((document) => {
    const page = isObject(document) && isObject(document.result) ? document.result : document;
    if (!isObject(page) || !Array.isArray(page.data) ||
        !(page.nextCursor === undefined || page.nextCursor === null || typeof page.nextCursor === 'string')) {
      throw new Error('Codex capture contains something that is not an mcpServerStatus/list response.');
    }
    return page;
  });
}

export function codexMcpStatusToRuntimeInventory(text, options = {}) {
  const captured = pages(text);
  // The last page has no cursor; a page that still has one means more servers exist.
  captured.forEach((page, index) => {
    const more = typeof page.nextCursor === 'string';
    if (more !== (index < captured.length - 1)) {
      throw new Error('Codex capture is not a complete, ordered set of pages; capture every page up to the one without nextCursor.');
    }
  });
  const servers = captured.flatMap((page) => page.data).map((server) => {
    if (!isObject(server) || typeof server.name !== 'string' || !server.name.trim() ||
        !isObject(server.tools) || typeof server.authStatus !== 'string' ||
        !(server.toolsError === undefined || server.toolsError === null || typeof server.toolsError === 'string')) {
      throw new Error('Codex capture has a malformed MCP server entry.');
    }
    if (!SETTLED.has(server.runtimeStatus)) {
      throw new Error('An MCP server has no settled thread status; capture mcpServerStatus/list with a threadId after its servers finish starting.');
    }
    // Without a catalog the count is unknown. That is only acceptable for a server
    // the thread cannot use.
    if (typeof server.toolsError === 'string' && server.runtimeStatus === 'connected') {
      throw new Error('Tool discovery failed for a connected MCP server; capture the response again.');
    }
    return { name: server.name, toolCount: Object.keys(server.tools).length };
  });
  // One name can be registered by more than one environment; the inventory has one
  // entry per name, so that capture cannot be represented.
  if (new Set(servers.map((server) => server.name)).size !== servers.length) {
    throw new Error('Codex capture lists the same MCP server name more than once.');
  }
  return {
    schemaVersion: 1,
    kind: 'agent-runtime-tool-inventory',
    runtime: 'codex',
    capturedAt: (options.now ? new Date(options.now) : new Date()).toISOString(),
    captureMethod: 'runtime-export',
    servers: servers.sort((left, right) => left.name.localeCompare(right.name))
  };
}
