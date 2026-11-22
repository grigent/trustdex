import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { codexMcpStatusToRuntimeInventory } from '../src/codex-runtime-inventory.mjs';
import { normalizeRuntimeToolInventory } from '../src/runtime-evidence.mjs';

const cli = fileURLToPath(new URL('../bin/trustdex.mjs', import.meta.url));
const example = fileURLToPath(new URL('../examples/runtime/codex-mcp-status.exchange.jsonl', import.meta.url));
const now = '2026-11-22T00:00:00.000Z';
const server = (overrides = {}) => ({
  name: 'alpha', runtimeStatus: 'connected', tools: { one: { name: 'one' }, two: { name: 'two' } }, toolsError: null,
  resources: [], resourceTemplates: [], authStatus: 'unsupported', ...overrides
});
const request = (id = 1, params = {}) => ({ method: 'mcpServerStatus/list', id, params: { threadId: 'thread-1', ...params } });
const response = (id = 1, data = [server()], nextCursor = null) => ({ id, result: { data, nextCursor } });
// One request followed by its response.
const exchange = (data = [server()]) => [request(), response(1, data)];
const convert = (value) => codexMcpStatusToRuntimeInventory(typeof value === 'string' ? value : JSON.stringify(value), { now });

test('a captured mcpServerStatus/list exchange becomes a value-free inventory', () => {
  const inventory = codexMcpStatusToRuntimeInventory(fs.readFileSync(example, 'utf8'), { now });
  assert.deepEqual(inventory, {
    schemaVersion: 1, kind: 'agent-runtime-tool-inventory', runtime: 'codex', capturedAt: now,
    captureMethod: 'runtime-export',
    servers: [{ name: 'docs', toolCount: 1 }, { name: 'offline', toolCount: 0 }, { name: 'reviewed', toolCount: 2 }]
  });
  assert.deepEqual(normalizeRuntimeToolInventory(inventory), inventory);
  // Only names and counts: no tool name, origin, plugin id, thread id, status, or error text.
  const text = JSON.stringify(inventory);
  for (const value of ['search', 'lookup', 'example.invalid', 'example-plugin', 'thread-example', 'connected', 'oAuth', 'Fictional']) {
    assert.ok(!text.includes(value), value);
  }
  // A JSON array and JSONL are both accepted; an omitted or null cursor starts the list.
  assert.deepEqual(convert(exchange()).servers, [{ name: 'alpha', toolCount: 2 }]);
  assert.deepEqual(convert(exchange().map((message) => JSON.stringify(message)).join('\n')).servers, [{ name: 'alpha', toolCount: 2 }]);
  assert.deepEqual(convert([request(1, { cursor: null, serverName: null }), { id: 1, result: { data: [server()] } }]).servers,
    [{ name: 'alpha', toolCount: 2 }]);
  assert.deepEqual(convert([request('a'), response('a', [server()], 'c1'), request('b', { cursor: 'c1' }), response('b', [server({ name: 'beta', tools: {} })])]).servers,
    [{ name: 'alpha', toolCount: 2 }, { name: 'beta', toolCount: 0 }]);
  assert.deepEqual(convert(exchange([])).servers, []);
  // A server the thread cannot use is kept, so a configured BLOCK source still blocks.
  for (const runtimeStatus of ['authenticationRequired', 'failed', 'cancelled', 'disabled']) {
    assert.deepEqual(convert(exchange([server({ runtimeStatus, tools: {}, toolsError: 'no catalog' })])).servers, [{ name: 'alpha', toolCount: 0 }]);
  }
});

test('a capture that would make a count a guess is refused', () => {
  const beta = server({ name: 'beta' });
  const refused = {
    'request followed by its response': ['', '[]', '{}', 'null', '7',
      // Responses without the requests that produced them prove nothing about the first page.
      response(), [response()], [response(1, [server()], 'c1'), response(2, [beta])], [request()], [request(), response(), request(2, { cursor: 'x' })],
      [response(), request()], [request(), { id: 1, error: { code: -32600 } }], [request(), { id: 1, result: {} }],
      [request(), { id: 1, result: { data: {} } }], [request(), { id: 1, result: { data: [], nextCursor: 7 } }],
      [request(), { id: 1, result: { data: [], nextCursor: '' } }],
      [request(), response(2)], [request(1), response('1')], [request(null), response(null)],
      [{ method: 'model/list', id: 1, params: { threadId: 'thread-1' } }, response()],
      [{ id: 1, params: { threadId: 'thread-1' } }, response()], [{ ...request(), params: [] }, response()],
      // Another app-server message in the capture is refused, not skipped.
      [{ method: 'mcpServer/startupStatus/updated', params: {} }, response()],
      [request(1), response(1, [server()], 'c1'), { method: 'mcpServer/startupStatus/updated', params: {} }, response(2, [server({ name: 'beta' })])]],
    'not JSON': [`${JSON.stringify(request())}\nnot json`],
    'same threadId and must not select a single server': [
      [{ method: 'mcpServerStatus/list', id: 1 }, response()], [{ method: 'mcpServerStatus/list', id: 1, params: {} }, response()],
      [request(1, { threadId: '' }), response()], [request(1, { threadId: 7 }), response()],
      [request(1, { serverName: 'alpha' }), response()], [request(1, { serverName: '' }), response()],
      [request(1, { environmentId: 'env-1' }), response()],
      [request(1), response(1, [server()], 'c1'), request(2, { cursor: 'c1', threadId: 'thread-2' }), response(2, [beta])]
    ],
    'complete, ordered set of pages': [
      [request(), response(1, [server()], 'more')],
      // The first page is missing: the only request continues from a cursor.
      [request(1, { cursor: 'c1' }), response(1, [beta])],
      // A middle page is missing: the cursor does not continue the previous response.
      [request(1), response(1, [server()], 'c1'), request(2, { cursor: 'c2' }), response(2, [beta])],
      [request(1), response(1, [server()], 'c1'), request(2), response(2, [beta])],
      [request(1), response(1), request(2), response(2, [beta])],
      [request(1), response(1, [server()], 'c1'), request(2, { cursor: 'c1' }), response(2, [beta], 'c2')]
    ],
    'malformed MCP server': [exchange(['alpha']), exchange([null]), exchange([server({ name: '' })]), exchange([server({ name: 7 })]),
      exchange([server({ tools: undefined })]), exchange([server({ tools: ['one'] })]), exchange([server({ tools: null })]),
      exchange([server({ authStatus: undefined })]), exchange([server({ toolsError: { message: 'x' } })]),
      exchange([{ id: 'example-model', model: 'example-model', displayName: 'Example' }])],
    'no settled thread status': [exchange([server({ runtimeStatus: null })]), exchange([server({ runtimeStatus: undefined })]),
      exchange([server({ runtimeStatus: 'notStarted' })]), exchange([server({ runtimeStatus: 'starting' })]),
      exchange([server({ runtimeStatus: 'some-future-status' })]), exchange([server({ runtimeStatus: 'Connected' })])],
    'Tool discovery failed': [exchange([server({ tools: {}, toolsError: 'timeout' })])],
    'more than once': [exchange([server(), server()]),
      [request(1), response(1, [server()], 'c1'), request(2, { cursor: 'c1' }), response(2, [server({ environmentId: 'env-2' })])]]
  };
  for (const [message, inputs] of Object.entries(refused)) {
    assert.ok(inputs.length > 0, message);
    for (const input of inputs) assert.throws(() => convert(input), new RegExp(message), JSON.stringify(input));
  }
});

test('the command writes the inventory and errors never echo the capture', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'trustdex-codex-status-'));
  try {
    const out = path.join(directory, 'inventory.json');
    let result = spawnSync(process.execPath, [cli, 'inventory-codex-mcp-status', example, '--out', out], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Servers: 3\nMCP tools: 3/);
    assert.equal(normalizeRuntimeToolInventory(JSON.parse(fs.readFileSync(out, 'utf8'))).runtime, 'codex');

    const secret = 'PLANTED-VALUE-7f3a';
    const bad = path.join(directory, 'bad.json');
    fs.writeFileSync(bad, JSON.stringify([request(secret, { threadId: secret }), response(secret, [server({ runtimeStatus: secret, httpOrigin: `https://${secret}.invalid`, tools: { [secret]: {} } })])]));
    const badOut = path.join(directory, 'bad-out.json');
    result = spawnSync(process.execPath, [cli, 'inventory-codex-mcp-status', bad, '--out', badOut], { encoding: 'utf8' });
    assert.notEqual(result.status, 0);
    assert.ok(!`${result.stdout}${result.stderr}`.includes(secret));
    assert.ok(!fs.existsSync(badOut));

    result = spawnSync(process.execPath, [cli, 'inventory-codex-mcp-status', example], { encoding: 'utf8' });
    assert.notEqual(result.status, 0);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
