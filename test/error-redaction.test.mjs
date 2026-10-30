import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseCodexMcpToml } from '../src/codex-config.mjs';

const cli = fileURLToPath(new URL('../bin/trustdex.mjs', import.meta.url));
const SECRET = 'sk-live-SECRETVALUE123';

async function write(name, content) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'trustdex-redact-'));
  const file = path.join(dir, name);
  await fs.writeFile(file, content);
  return file;
}

function run(...args) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
}

function assertRedacted(result) {
  assert.equal(result.status, 2);
  assert.ok(!`${result.stdout}${result.stderr}`.includes('SECRET'), result.stderr);
  assert.ok(!`${result.stdout}${result.stderr}`.includes('sk-live'), result.stderr);
}

test('malformed JSON inputs do not echo their contents in errors', async () => {
  const bad = await write('bad.json', `{"mcpServers": {"x": {"env": {"TOKEN": ${SECRET}}}}}`);
  const good = fileURLToPath(new URL('../examples/mcp.json', import.meta.url));
  for (const args of [
    ['inspect', bad],
    ['inspect-claude', bad],
    ['inspect-plugin', bad],
    ['inspect-claude-settings', bad],
    ['inspect', good, '--policy', bad],
    ['inspect', good, '--trust-store', bad]
  ]) {
    const result = run(...args);
    assertRedacted(result);
    assert.match(result.stderr, /Invalid (JSON|Claude)/, args.join(' '));
  }
});

test('Codex TOML errors do not echo inline-table entries or bare values', async () => {
  for (const toml of [
    `[mcp_servers.x]\ncommand = "node"\nenv = { TOKEN "${SECRET}" }\n`,
    `[mcp_servers.x]\ncommand = "node"\nenv = { TOKEN = ${SECRET} }\n`,
    `[mcp_servers.x]\ncommand = ${SECRET}\n`
  ]) {
    const file = await write('config.toml', toml);
    assertRedacted(run('inspect-codex', file));
    assert.throws(() => parseCodexMcpToml(toml), (error) => !error.message.includes('SECRET'));
  }
  const settings = await write('config.toml', `approval_policy = ${SECRET}\n`);
  assertRedacted(run('inspect-codex-settings', settings));
});

test('unquoted TOML values fail closed instead of being read as strings', () => {
  assert.throws(() => parseCodexMcpToml('[mcp_servers.x]\ncommand = node\n'), /Unsupported TOML value/);
  assert.throws(() => parseCodexMcpToml('[mcp_servers.x]\ncommand = "node"\nstartup_timeout_sec = 1979-05-27\n'), /Unsupported TOML value/);
});
