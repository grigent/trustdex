import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const cli = fileURLToPath(new URL('../bin/trustdex.mjs', import.meta.url));

function run(...args) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
}

const BASE = [
  '[mcp_servers.files]',
  'command = "npx"',
  'args = ["-y", "@modelcontextprotocol/server-filesystem@1.2.3", "./workspace"]',
  'enabled_tools = ["read_file"]',
  'default_tools_approval_mode = "prompt"',
  '',
  '[mcp_servers.remote]',
  'url = "https://mcp.example.invalid/mcp"',
  'bearer_token_env_var = "MCP_BEARER_TOKEN"',
  ''
].join('\n');

function setup(toml = BASE) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'trustdex-codex-review-'));
  const config = path.join(dir, 'config.toml');
  fs.writeFileSync(config, toml);
  const keys = { priv: path.join(dir, 'private.pem'), pub: path.join(dir, 'public.pem') };
  run('keygen', '--private', keys.priv, '--public', keys.pub);
  const review = path.join(dir, 'review');
  return { dir, config, keys, review };
}

function approve({ config, keys, review }) {
  const result = run('approve-codex', config, '--private', keys.priv, '--dir', review, '--pack', 'development');
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /APPROVED/);
  return result;
}

function recheck({ config, keys, review }, ...flags) {
  return run('recheck-codex', config, '--review-dir', review, '--public', keys.pub, ...flags);
}

test('an unchanged Codex config rechecks as APPROVED', () => {
  const ctx = setup();
  approve(ctx);
  const result = recheck(ctx);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /APPROVED: current state matches the signed review/);
  for (const file of ['snapshot.json', 'trust-record.json', 'effective-policy.json']) {
    assert.ok(fs.existsSync(path.join(ctx.review, file)), file);
  }
});

test('Codex-specific changes after approval require review', () => {
  for (const [label, from, to] of [
    ['package version', 'server-filesystem@1.2.3', 'server-filesystem@1.2.4'],
    ['enabled tools', 'enabled_tools = ["read_file"]', 'enabled_tools = ["read_file", "write_file"]'],
    ['tool approval mode', 'default_tools_approval_mode = "prompt"', 'default_tools_approval_mode = "approve"'],
    ['remote endpoint', 'https://mcp.example.invalid/mcp', 'https://mcp.example.invalid/other'],
    ['bearer variable', 'MCP_BEARER_TOKEN', 'OTHER_TOKEN']
  ]) {
    const ctx = setup();
    approve(ctx);
    fs.writeFileSync(ctx.config, BASE.replace(from, to));
    const result = recheck(ctx);
    assert.equal(result.status, 1, `${label}: ${result.stdout}${result.stderr}`);
    assert.match(result.stdout, /NEEDS_REVIEW/, label);
  }
});

test('an added Codex server requires review', () => {
  const ctx = setup();
  approve(ctx);
  fs.writeFileSync(ctx.config, `${BASE}\n[mcp_servers.extra]\ncommand = "node"\nargs = ["extra.js"]\n`);
  const result = recheck(ctx, '--json');
  assert.equal(result.status, 1);
  const verdict = JSON.parse(result.stdout);
  assert.equal(verdict.status, 'needs-review');
  assert.ok(verdict.changes.some((change) => change.type === 'server-added' && change.name === 'extra'));
});

test('approve-codex refuses BLOCK decisions', () => {
  const ctx = setup(`${BASE}\n[mcp_servers.shell]\ncommand = "bash"\nargs = ["-c", "echo"]\n`);
  const result = run('approve-codex', ctx.config, '--private', ctx.keys.priv, '--dir', ctx.review);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /Refusing to approve/);
  assert.ok(!fs.existsSync(path.join(ctx.review, 'trust-record.json')));
});

test('a tampered Codex review bundle is INVALID', () => {
  const ctx = setup();
  approve(ctx);
  const policyFile = path.join(ctx.review, 'effective-policy.json');
  const policy = JSON.parse(fs.readFileSync(policyFile, 'utf8'));
  policy.unknownAction = 'allow';
  fs.writeFileSync(policyFile, JSON.stringify(policy));
  const result = recheck(ctx);
  assert.equal(result.status, 2);
  assert.match(result.stdout, /INVALID/);
});

test('a Codex review cannot be satisfied by the generic MCP adapter or the reverse', () => {
  const ctx = setup();
  approve(ctx);
  const json = path.join(ctx.dir, 'mcp.json');
  fs.writeFileSync(json, JSON.stringify({ mcpServers: {
    files: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@1.2.3', './workspace'] },
    remote: { url: 'https://mcp.example.invalid/mcp' }
  } }));
  const crossed = run('recheck', json, '--review-dir', ctx.review, '--public', ctx.keys.pub);
  assert.equal(crossed.status, 1, crossed.stdout);
});

test('snapshot-codex writes a v3 snapshot that diff compares', () => {
  const ctx = setup();
  const before = path.join(ctx.dir, 'before.json');
  const after = path.join(ctx.dir, 'after.json');
  assert.equal(run('snapshot-codex', ctx.config, '--out', before).status, 0);
  fs.writeFileSync(ctx.config, BASE.replace('server-filesystem@1.2.3', 'server-filesystem@1.3.0'));
  assert.equal(run('snapshot-codex', ctx.config, '--out', after).status, 0);
  assert.equal(JSON.parse(fs.readFileSync(before, 'utf8')).schemaVersion, 3);
  const diff = run('diff', before, after);
  assert.equal(diff.status, 1);
  assert.match(diff.stdout, /source-changed: files/);
});
