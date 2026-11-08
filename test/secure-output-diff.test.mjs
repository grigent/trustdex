import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { inspectMcpConfig } from '../src/inspect.mjs';
import { gateMcpConfig } from '../src/gate.mjs';
import { evaluateServer } from '../src/policy.mjs';
import { createSnapshot, diffSnapshots } from '../src/snapshot.mjs';
import { assessReview } from '../src/review.mjs';
import { inspectGitHubRepository } from '../src/provenance-online.mjs';
import {
  renderSnapshotChanges, renderPermissionDiff, renderBindingDiff, renderRuntimeDiff
} from '../src/diff-view.mjs';

const cli = fileURLToPath(new URL('../bin/trustdex.mjs', import.meta.url));
const run = (args, options = {}) => spawnSync(process.execPath, [cli, ...args], {
  encoding: 'utf8', ...options
});

async function directory(t) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'trustdex-safe-output-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  return dir;
}

async function configFile(dir) {
  const config = path.join(dir, 'config.json');
  await fs.writeFile(config, JSON.stringify({
    mcpServers: { demo: { command: 'node', args: ['server.mjs'] } }
  }));
  return config;
}

test('output symlink is refused without overwriting its target', async t => {
  const dir = await directory(t);
  const config = await configFile(dir);
  const victim = path.join(dir, 'victim.txt');
  const output = path.join(dir, 'gated.json');
  await fs.writeFile(victim, 'original-content');
  try {
    await fs.symlink(victim, output);
  } catch (error) {
    if (['EPERM', 'EACCES', 'ENOTSUP'].includes(error.code)) return t.skip('symlinks unavailable');
    throw error;
  }
  const result = run(['gate', config, '--out', output]);
  assert.equal(result.status, 2, result.stdout + result.stderr);
  assert.match(result.stderr, /symlink|non-regular/i);
  assert.equal(await fs.readFile(victim, 'utf8'), 'original-content');
  assert.equal((await fs.lstat(output)).isSymbolicLink(), true);
});

test('parent directory symlinks are refused', async t => {
  const dir = await directory(t);
  const config = await configFile(dir);
  const outside = path.join(dir, 'elsewhere');
  await fs.mkdir(outside);
  const link = path.join(dir, 'redirected');
  try {
    await fs.symlink(outside, link, 'dir');
  } catch (error) {
    if (['EPERM', 'EACCES', 'ENOTSUP'].includes(error.code)) return t.skip('symlinks unavailable');
    throw error;
  }
  const result = run(['gate', config, '--out', path.join(link, 'gated.json')]);
  assert.equal(result.status, 2, result.stdout + result.stderr);
  assert.match(result.stderr, /symlink|non-directory/i);
  await assert.rejects(fs.access(path.join(outside, 'gated.json')));
});

test('hardlink output is atomically replaced without mutating linked target', async t => {
  const dir = await directory(t);
  const config = await configFile(dir);
  const victim = path.join(dir, 'victim.txt');
  const output = path.join(dir, 'gated.json');
  await fs.writeFile(victim, 'original-content');
  await fs.link(victim, output);
  const result = run(['gate', config, '--out', output]);
  // An untrusted local server is ASK under strict policy, so gate exits 1.
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.equal(await fs.readFile(victim, 'utf8'), 'original-content');
  assert.notEqual(await fs.readFile(output, 'utf8'), 'original-content');
});

test('keygen keeps the private key restricted even when replacing a file', async t => {
  if (process.platform === 'win32') return t.skip('POSIX file permission assertions');
  const dir = await directory(t);
  const privateFile = path.join(dir, 'private.pem');
  const publicFile = path.join(dir, 'public.pem');
  await fs.writeFile(privateFile, 'replace-me', { mode: 0o644 });
  await fs.chmod(privateFile, 0o644);
  const result = run(['keygen', '--private', privateFile, '--public', publicFile]);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.equal((await fs.stat(privateFile)).mode & 0o777, 0o600);
});

test('snapshot diff ignores object key order but detects source changes', () => {
  const make = (source, provenance) => createSnapshot([{
    name: 'demo', kind: 'mcp', source, provenance,
    fingerprint: 'same', signals: [], action: 'allow'
  }]);
  const first = make({ type: 'remote', host: 'example.test' },
    { status: 'verified', evidence: { kind: 'manual', reference: 'ref' } });
  const reordered = make({ host: 'example.test', type: 'remote' },
    { evidence: { reference: 'ref', kind: 'manual' }, status: 'verified' });
  assert.equal(first.digest, reordered.digest);
  assert.deepEqual(diffSnapshots(first, reordered), []);
  const changed = make({ type: 'remote', host: 'other.test' },
    { status: 'unknown' });
  const types = diffSnapshots(first, changed).map(change => change.type);
  assert.ok(types.includes('source-changed'));
  assert.ok(types.includes('provenance-changed'));
});

test('unknown source never inherits permissive policy', () => {
  const decision = evaluateServer({ name: 'missing-source', signals: [] }, {
    unknownAction: 'allow', verifiedPublisherAction: 'allow'
  });
  assert.equal(decision.action, 'block');
  assert.match(decision.reasons.join(' '), /source is missing/);
});

test('generic inspector and gate reject dual MCP containers', () => {
  const config = {
    mcpServers: { safe: { command: 'node' } },
    servers: { hidden: { command: 'node' } }
  };
  assert.throws(() => inspectMcpConfig(config), /both mcpServers and servers/);
  assert.throws(() => gateMcpConfig(config, [{ name: 'safe', action: 'allow' }]),
    /both mcpServers and servers/);
});

test('review without a signed baseline rejects without a crash', () => {
  const verdict = assessReview({
    record: null, publicKey: null, baseline: null,
    current: { digest: 'a'.repeat(64) }
  });
  assert.equal(verdict.status, 'invalid');
  assert.match(verdict.reason, /baseline/);
});

test('online provenance fetch refuses redirects and hides sensitive URLs on failure', async () => {
  const secret = 'INERT_QUERY_SECRET';
  const requests = [];
  const mockFetch = async (url, options) => {
    requests.push({ url, options });
    return { ok: false, status: 403 };
  };
  await assert.rejects(inspectGitHubRepository('example/project', { fetchImpl: mockFetch }),
    error => !error.message.includes(secret) && !error.message.includes('https://'));
  assert.equal(requests.length, 1);
  assert.equal(requests[0].options.redirect, 'error');
  assert.equal(typeof requests[0].options.signal?.addEventListener, 'function');
  assert.equal(requests[0].options.signal.aborted, false);
});

test('terminal diff renders structural changes without raw source values', () => {
  const changes = [
    { type: 'decision-changed', name: 'demo', from: 'allow', to: 'block' },
    { type: 'source-changed', name: 'demo',
      from: { url: 'https://example.test?token=INERT_SECRET_VALUE' },
      to: { url: 'https://example.test?token=OTHER_SECRET_VALUE' } }
  ];
  const colored = renderSnapshotChanges(changes, true);
  assert.match(colored, /\x1b\[31m/);
  assert.match(colored, /source-changed/);
  assert.doesNotMatch(colored, /INERT_SECRET|OTHER_SECRET/);
  assert.doesNotMatch(renderSnapshotChanges(changes, false), /\x1b/);
  for (const render of [renderPermissionDiff, renderBindingDiff, renderRuntimeDiff]) {
    const report = render({ status: 'needs-review', changes: [{
      impact: 'expansion', type: 'grant-changed', name: 'demo',
      field: 'automaticGrant', before: 'scoped', after: 'all'
    }] }, true);
    assert.match(report, /scoped/);
    assert.match(report, /all/);
    assert.match(report, /\x1b\[31m/);
  }
});

test('CLI --color and NO_COLOR control ANSI output without changing exit codes', async t => {
  const dir = await directory(t);
  const before = path.join(dir, 'before.json');
  const after = path.join(dir, 'after.json');
  const make = action => ({
    servers: [{ name: 'demo', source: { type: 'local', command: 'node' },
      signals: [], action, fingerprint: 'same' }]
  });
  await fs.writeFile(before, JSON.stringify(make('allow')));
  await fs.writeFile(after, JSON.stringify(make('block')));
  const args = ['diff', before, after, '--color'];
  const colored = run(args, { env: { ...process.env, NO_COLOR: undefined } });
  assert.equal(colored.status, 1);
  assert.match(colored.stdout, /\x1b\[/);
  const plain = run(args, { env: { ...process.env, NO_COLOR: '1' } });
  assert.equal(plain.status, 1);
  assert.doesNotMatch(plain.stdout, /\x1b\[/);
  const json = run(['diff', before, after, '--json']);
  assert.equal(json.status, 1);
  assert.ok(Array.isArray(JSON.parse(json.stdout)));
});
