import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
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
