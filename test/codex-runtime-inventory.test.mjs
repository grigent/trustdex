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
const example = fileURLToPath(new URL('../examples/runtime/codex-mcp-status.responses.jsonl', import.meta.url));
const now = '2026-11-22T00:00:00.000Z';
const server = (overrides = {}) => ({
  name: 'alpha', runtimeStatus: 'connected', tools: { one: { name: 'one' }, two: { name: 'two' } }, toolsError: null,
  resources: [], resourceTemplates: [], authStatus: 'unsupported', ...overrides
});
const page = (data = [server()], nextCursor = null) => ({ id: 1, result: { data, nextCursor } });
const convert = (value) => codexMcpStatusToRuntimeInventory(typeof value === 'string' ? value : JSON.stringify(value), { now });

test('captured mcpServerStatus/list pages become a value-free inventory', () => {
  const inventory = codexMcpStatusToRuntimeInventory(fs.readFileSync(example, 'utf8'), { now });
  assert.deepEqual(inventory, {
    schemaVersion: 1, kind: 'agent-runtime-tool-inventory', runtime: 'codex', capturedAt: now,
    captureMethod: 'runtime-export',
    servers: [{ name: 'docs', toolCount: 1 }, { name: 'offline', toolCount: 0 }, { name: 'reviewed', toolCount: 2 }]
  });
  assert.deepEqual(normalizeRuntimeToolInventory(inventory), inventory);
  // Only names and counts: no tool name, origin, plugin id, status, or error text.
  const text = JSON.stringify(inventory);
  for (const value of ['search', 'lookup', 'example.invalid', 'example-plugin', 'connected', 'oAuth', 'Fictional']) {
    assert.ok(!text.includes(value), value);
  }
  // A bare result, a wrapped response, a JSON array of pages, and JSONL are all accepted.
  assert.deepEqual(convert(page()).servers, [{ name: 'alpha', toolCount: 2 }]);
  assert.deepEqual(convert(page().result).servers, [{ name: 'alpha', toolCount: 2 }]);
  assert.deepEqual(convert({ data: [server()] }).servers, [{ name: 'alpha', toolCount: 2 }]);
  assert.deepEqual(convert([page([server()], 'c1'), page([server({ name: 'beta', tools: {} })])]).servers,
    [{ name: 'alpha', toolCount: 2 }, { name: 'beta', toolCount: 0 }]);
  assert.deepEqual(convert(page([])).servers, []);
  // A server the thread cannot use is kept, so a configured BLOCK source still blocks.
  for (const runtimeStatus of ['authenticationRequired', 'failed', 'cancelled', 'disabled']) {
    assert.deepEqual(convert(page([server({ runtimeStatus, tools: {}, toolsError: 'no catalog' })])).servers, [{ name: 'alpha', toolCount: 0 }]);
  }
});

test('a capture that would make a count a guess is refused', () => {
  const refused = {
    'between 1 and 1000': ['', '[]'],
    'not JSON': [`${JSON.stringify(page())}\nnot json`],
    'not an mcpServerStatus/list response': ['{}', 'null', '7', '"text"', JSON.stringify({ method: 'mcpServer/startupStatus/updated', params: {} }),
      { id: 1, result: {} }, { id: 1, result: { data: {} } }, { id: 1, result: { data: [], nextCursor: 7 } }, { id: 1, error: { code: -32600 } },
      `${JSON.stringify({ id: 0, result: { userAgent: 'x' } })}\n${JSON.stringify(page())}`],
    'complete, ordered set of pages': [page([server()], 'more'), [page(), page([server({ name: 'beta' })])],
      [page([server()], 'c1'), page([server({ name: 'beta' })], 'c2')], [page(), page([server({ name: 'beta' })], 'c1')]],
    'malformed MCP server': [page(['alpha']), page([null]), page([server({ name: '' })]), page([server({ name: 7 })]),
      page([server({ tools: undefined })]), page([server({ tools: ['one'] })]), page([server({ tools: null })]),
      page([server({ authStatus: undefined })]), page([server({ toolsError: { message: 'x' } })]),
      // A model/list page has the same envelope and must not be read as an inventory.
      page([{ id: 'example-model', model: 'example-model', displayName: 'Example' }])],
    'no settled thread status': [page([server({ runtimeStatus: null })]), page([server({ runtimeStatus: undefined })]),
      page([server({ runtimeStatus: 'notStarted' })]), page([server({ runtimeStatus: 'starting' })]),
      page([server({ runtimeStatus: 'some-future-status' })]), page([server({ runtimeStatus: 'Connected' })])],
    'Tool discovery failed': [page([server({ tools: {}, toolsError: 'timeout' })])],
    'more than once': [page([server(), server()]), [page([server()], 'c1'), page([server({ environmentId: 'env-2' })])]]
  };
  for (const [message, inputs] of Object.entries(refused)) {
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
    fs.writeFileSync(bad, JSON.stringify(page([server({ runtimeStatus: secret, httpOrigin: `https://${secret}.invalid`, tools: { [secret]: {} } })])));
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
