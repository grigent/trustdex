import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { claudeInitToRuntimeInventory } from '../src/claude-runtime-inventory.mjs';
import { normalizeRuntimeToolInventory } from '../src/runtime-evidence.mjs';

const cli = fileURLToPath(new URL('../bin/trustdex.mjs', import.meta.url));
const example = fileURLToPath(new URL('../examples/runtime/claude-init.stream.jsonl', import.meta.url));
const now = '2026-11-22T00:00:00.000Z';
const init = (overrides = {}) => ({
  type: 'system', subtype: 'init', tools: ['Read', 'mcp__alpha__one', 'mcp__alpha__two'],
  mcp_servers: [{ name: 'alpha', status: 'connected' }], ...overrides
});
const convert = (value) => claudeInitToRuntimeInventory(typeof value === 'string' ? value : JSON.stringify(value), { now });

test('the documented system/init event becomes a value-free inventory', () => {
  const inventory = claudeInitToRuntimeInventory(fs.readFileSync(example, 'utf8'), { now });
  assert.deepEqual(inventory, {
    schemaVersion: 1, kind: 'agent-runtime-tool-inventory', runtime: 'claude', capturedAt: now,
    captureMethod: 'runtime-export',
    servers: [{ name: 'offline', toolCount: 0 }, { name: 'plugin:example-plugin:docs', toolCount: 1 }, { name: 'reviewed', toolCount: 2 }]
  });
  assert.deepEqual(normalizeRuntimeToolInventory(inventory), inventory);
  // Only names and counts: no tool name, path, model, or session identifier.
  const text = JSON.stringify(inventory);
  for (const value of ['search', 'lookup', '/workspace', 'example-model', '00000000', 'connected']) {
    assert.ok(!text.includes(value), value);
  }
  assert.deepEqual(convert(init()).servers, [{ name: 'alpha', toolCount: 2 }]);
  assert.deepEqual(convert([init()]).servers, [{ name: 'alpha', toolCount: 2 }]);
  assert.deepEqual(convert(init({ mcp_servers: [], tools: ['Read'] })).servers, []);
});

test('input that would make a count a guess is refused', () => {
  const refused = {
    'exactly one': ['', '{}', '[]', 'null', JSON.stringify({ type: 'result' }),
      `${JSON.stringify(init())}\n${JSON.stringify(init())}`, JSON.stringify([init(), init()]),
      JSON.stringify({ ...init(), subtype: 'other' })],
    'not JSON': [`${JSON.stringify(init())}\nnot json`],
    'missing mcp_servers or tools': [init({ mcp_servers: undefined }), init({ tools: undefined }), init({ tools: 'mcp__alpha__one' }),
      init({ tools: ['Read', 7] }), init({ mcp_servers: { alpha: {} } })],
    'malformed MCP server': [init({ mcp_servers: ['alpha'] }), init({ mcp_servers: [{ name: '', status: 'connected' }] }),
      init({ mcp_servers: [{ name: 'alpha' }] }), init({ mcp_servers: [{ name: 7, status: 'connected' }] }), init({ mcp_servers: [null] })],
    'not finished connecting': [init({ mcp_servers: [{ name: 'alpha', status: 'pending' }] }),
      init({ mcp_servers: [{ name: 'alpha', status: 'some-future-status' }] })],
    'cannot be told apart': [init({ mcp_servers: [{ name: 'alpha', status: 'connected' }, { name: 'alpha', status: 'connected' }] }),
      init({ mcp_servers: [{ name: 'a.b', status: 'connected' }, { name: 'a_b', status: 'connected' }], tools: [] })],
    'exactly one listed server': [
      init({ tools: ['mcp__unlisted__tool'] }),
      init({ tools: ['mcp__alpha__'] }),
      init({ mcp_servers: [{ name: 'alpha', status: 'connected' }, { name: 'alpha__beta', status: 'connected' }], tools: ['mcp__alpha__beta__tool'] })
    ]
  };
  for (const [message, inputs] of Object.entries(refused)) {
    for (const input of inputs) assert.throws(() => convert(input), new RegExp(message), JSON.stringify(input));
  }
});

test('the command writes the inventory and errors never echo the stream', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'trustdex-claude-init-'));
  try {
    const out = path.join(directory, 'inventory.json');
    let result = spawnSync(process.execPath, [cli, 'inventory-claude-init', example, '--out', out], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Servers: 3\nMCP tools: 3/);
    assert.equal(normalizeRuntimeToolInventory(JSON.parse(fs.readFileSync(out, 'utf8'))).servers.length, 3);

    const secret = 'PLANTED-VALUE-7f3a';
    const bad = path.join(directory, 'bad.jsonl');
    fs.writeFileSync(bad, JSON.stringify(init({ tools: [`mcp__${secret}__tool`], cwd: secret })));
    const badOut = path.join(directory, 'bad.json');
    result = spawnSync(process.execPath, [cli, 'inventory-claude-init', bad, '--out', badOut], { encoding: 'utf8' });
    assert.notEqual(result.status, 0);
    assert.ok(!`${result.stdout}${result.stderr}`.includes(secret));
    assert.ok(!fs.existsSync(badOut));

    result = spawnSync(process.execPath, [cli, 'inventory-claude-init', example], { encoding: 'utf8' });
    assert.notEqual(result.status, 0);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
