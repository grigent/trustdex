// Converts a captured `mcpServerStatus/list` exchange, the request Codex documents
// for `codex app-server`, into a value-free runtime tool inventory.
// The user captures each request with its response and passes the file; TrustDex does not start
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
    if (lines.length > MAX_PAGES * 2) throw new Error('Codex capture has too many lines.');
    documents = lines.map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        throw new Error('Codex capture contains a line that is not JSON.');
      }
    });
  }
  if (documents.length === 0 || documents.length % 2 !== 0 || documents.length > MAX_PAGES * 2) {
    throw new Error('Codex capture must hold each mcpServerStatus/list request followed by its response.');
  }
  // Responses alone cannot show that the first page is present or that the list was
  // not narrowed to one server, so each response is read with the request that
  // produced it. Other app-server messages are refused rather than skipped.
  const captured = [];
  let threadId;
  for (let index = 0; index < documents.length; index += 2) {
    const request = documents[index];
    const response = documents[index + 1];
    const params = isObject(request) && request.params === undefined ? {} : request?.params;
    if (!isObject(request) || request.method !== 'mcpServerStatus/list' || !isObject(params) ||
        !(typeof request.id === 'string' || typeof request.id === 'number') ||
        !isObject(response) || response.id !== request.id || !isObject(response.result) ||
        !Array.isArray(response.result.data) ||
        !(response.result.nextCursor === undefined || response.result.nextCursor === null ||
          (typeof response.result.nextCursor === 'string' && response.result.nextCursor))) {
      throw new Error('Codex capture contains something that is not an mcpServerStatus/list request followed by its response.');
    }
    if (typeof params.threadId !== 'string' || !params.threadId || (index > 0 && params.threadId !== threadId) ||
        !(params.serverName === undefined || params.serverName === null) ||
        !(params.environmentId === undefined || params.environmentId === null)) {
      throw new Error('Every mcpServerStatus/list request must name the same threadId and must not select a single server.');
    }
    threadId = params.threadId;
    // The first request starts the list; each later one continues from the cursor the
    // previous response returned. The last response has no cursor.
    const expectedCursor = index === 0 ? null : captured[captured.length - 1].nextCursor;
    const last = index === documents.length - 2;
    if ((params.cursor ?? null) !== expectedCursor || (typeof response.result.nextCursor === 'string') === last) {
      throw new Error('Codex capture is not a complete, ordered set of pages; capture every request and response from the first page to the one without nextCursor.');
    }
    captured.push({ data: response.result.data, nextCursor: response.result.nextCursor ?? null });
  }
  return captured;
}

export function codexMcpStatusToRuntimeInventory(text, options = {}) {
  const captured = pages(text);
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
