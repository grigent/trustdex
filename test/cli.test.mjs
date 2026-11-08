import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const cli = fileURLToPath(new URL('../bin/trustdex.mjs', import.meta.url));
const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

test('--version reports the package.json version', () => {
  for (const flag of ['--version', '-V']) {
    const output = execFileSync(process.execPath, [cli, flag], { encoding: 'utf8' });
    assert.equal(output.trim(), pkg.version);
  }
});

test('--help banner reports the package.json version', () => {
  const output = execFileSync(process.execPath, [cli, '--help'], { encoding: 'utf8' });
  assert.ok(output.startsWith(`TrustDex v${pkg.version}\n`));
});


function run(...args) {
  const outcome = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  if (outcome.error) throw outcome.error;
  return outcome;
}

test('inspect command exit codes stay 0 (allow/empty), 1 (ask), and 2 (block)', async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'trustdex-cli-audit-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'mcp.json');
  for (const [config, expected] of [
    [{ mcpServers: {} }, 0],
    [{ mcpServers: { local: { command: 'node', args: ['server.mjs'] } } }, 1],
    [{ mcpServers: { dangerous: { command: 'sh', args: ['-c', 'echo safe fixture'] } } }, 2]
  ]) {
    await fs.writeFile(file, JSON.stringify(config));
    const result = run('inspect', file, '--pack', 'strict');
    assert.equal(result.status, expected, result.stdout + result.stderr);
  }
});

test('CLI rejects missing, chained, and repeated value flags instead of silently falling back', async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'trustdex-cli-flags-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'mcp.json');
  await fs.writeFile(file, JSON.stringify({ mcpServers: {} }));
  for (const args of [
    ['--pack'],
    ['--pack', '--json'],
    ['--policy'],
    ['--policy', '--pack', 'strict'],
    ['--trust-store', '--json'],
    ['--pack', 'strict', '--pack', 'development']
  ]) {
    const result = run('inspect', file, ...args);
    assert.equal(result.status, 2, args.join(' ') + '\n' + result.stdout + result.stderr);
    assert.match(result.stderr, /requires a value|may be given only once/);
  }
});

test('help and version remain successful without reading configs', () => {
  for (const args of [['--help'], ['--version'], ['-V']]) {
    const result = run(...args);
    assert.equal(result.status, 0, result.stderr);
    if (args[0] === '--help') assert.ok(result.stdout.startsWith(`TrustDex v${pkg.version}\n`));
    else assert.equal(result.stdout.trim(), pkg.version);
  }
});
