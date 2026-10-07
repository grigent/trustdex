import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseClaudeMcpConfig } from '../src/claude-config.mjs';
import { inspectMcpConfig } from '../src/inspect.mjs';
import { evaluateAll } from '../src/policy.mjs';
import { getPolicyPack, mergePolicy } from '../src/policy-packs.mjs';
import { gateMcpConfig } from '../src/gate.mjs';
import { createSnapshot } from '../src/snapshot.mjs';
import { generateTrustKeyPair, createTrustRecord } from '../src/trust-record.mjs';
import { assessReview } from '../src/review.mjs';

const cli = fileURLToPath(new URL('../bin/trustdex.mjs', import.meta.url));
const policy = mergePolicy(getPolicyPack('strict'), {
  trustedPackages: ['reviewed-mcp'],
  allowedRemoteHosts: ['reviewed.invalid']
});
const remote = (extra = {}) => ({ mcpServers: { reviewed: { type: 'http', url: 'https://reviewed.invalid/mcp', ...extra } } });
const inspect = (config) => inspectMcpConfig(parseClaudeMcpConfig(config));
const evaluate = (config) => evaluateAll(inspect(config), policy);
function temporaryDirectory(t) {
  const base = path.resolve(os.tmpdir());
  const directory = fs.mkdtempSync(path.join(base, 'trustdex-claude-'));
  t.after(() => {
    assert.equal(path.dirname(path.resolve(directory)), base);
    assert.ok(path.basename(directory).startsWith('trustdex-claude-'));
    fs.rmSync(directory, { recursive: true, force: true });
  });
  return directory;
}
function run(...args) {
  const result = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  if (result.error) throw result.error;
  return result;
}

test('Claude adapter gates explicit stdio, HTTP, and SSE entries without changing input', () => {
  const config = { mcpServers: {
    stdio: { type: 'stdio', command: 'npx', args: ['-y', 'reviewed-mcp@1.2.3'] },
    http: { type: 'http', url: 'https://reviewed.invalid/mcp' },
    sse: { type: 'sse', url: 'https://reviewed.invalid/sse' },
    unknown: { type: 'http', url: 'https://unknown.invalid/mcp' },
    local: { command: 'node', args: ['./inert.mjs'] }
  } };
  const original = JSON.stringify(config);
  const results = evaluate(config);
  assert.deepEqual(Object.fromEntries(results.map(x => [x.name, x.action])), {
    http: 'allow', local: 'ask', sse: 'allow', stdio: 'allow', unknown: 'block'
  });
  const gated = gateMcpConfig(config, results);
  assert.deepEqual(Object.keys(gated.config.mcpServers).sort(), ['http', 'sse', 'stdio']);
  for (const name of Object.keys(gated.config.mcpServers)) assert.deepEqual(gated.config.mcpServers[name], config.mcpServers[name]);
  assert.equal(JSON.stringify(config), original);
  assert.ok(!JSON.stringify(gated.config).includes('_trustdex'));
});

test('Claude shell header helpers stay blocked even for an allowlisted endpoint', () => {
  const result = evaluate(remote({ headersHelper: 'INERT_HELPER_WITH_SECRET_VALUE' }))[0];
  assert.equal(result.action, 'block');
  assert.ok(result.signals.includes('header-helper-command'));
  assert.ok(!JSON.stringify(result).includes('INERT_HELPER_WITH_SECRET_VALUE'));
  assert.deepEqual(gateMcpConfig(remote({ headersHelper: 'INERT' }), [result]).config, { mcpServers: {} });
});

test('Claude static and variable-based headers require review without retaining values', () => {
  const config = remote({ headers: { Authorization: 'Bearer ${EXAMPLE_TOKEN}', 'X-Secret': 'INERT_STATIC_SECRET' } });
  const result = evaluate(config)[0];
  assert.equal(result.action, 'ask');
  assert.ok(result.signals.includes('env-http-headers'));
  assert.ok(result.signals.includes('static-http-headers'));
  assert.ok(!JSON.stringify(result).includes('INERT_STATIC_SECRET'));
  assert.ok(!JSON.stringify(createSnapshot([result])).includes('INERT_STATIC_SECRET'));
});

test('Claude credential rotations do not enter configuration fingerprints', () => {
  const before = inspect(remote({ headers: { Authorization: 'INERT_FIRST' }, headersHelper: 'INERT_HELPER_FIRST' }))[0];
  const after = inspect(remote({ headers: { Authorization: 'INERT_SECOND' }, headersHelper: 'INERT_HELPER_SECOND' }))[0];
  assert.equal(before.fingerprint, after.fingerprint);
});

test('Claude header names, references, and transport changes invalidate signed review', () => {
  const base = remote({ headers: { Authorization: 'Bearer ${FIRST_TOKEN}' } });
  const baseline = createSnapshot(evaluate(base));
  const keys = generateTrustKeyPair();
  const record = createTrustRecord(baseline, keys.privateKey, { policy });
  assert.equal(assessReview({ record, publicKey: keys.publicKey, baseline, current: baseline, policy }).status, 'approved');
  for (const config of [
    remote({ headers: { Authorization: 'Bearer ${SECOND_TOKEN}' } }),
    remote({ headers: { 'X-Authorization': 'Bearer ${FIRST_TOKEN}' } }),
    remote({ type: 'sse', headers: { Authorization: 'Bearer ${FIRST_TOKEN}' } })
  ]) {
    const verdict = assessReview({ record, publicKey: keys.publicKey, baseline, current: createSnapshot(evaluate(config)), policy });
    assert.equal(verdict.status, 'needs-review');
    assert.ok(verdict.changes.some(change => change.type === 'fingerprint-changed'));
  }
});

test('Claude adapter rejects unsupported fields, invalid entries, and internal annotation injection', () => {
  for (const config of [
    null, [], {}, { mcpServers: [] }, { mcpServers: null },
    { mcpServers: {}, preferences: {} }, { mcpServers: { bad: null } },
    remote({ type: null }), remote({ type: 'ws' }), remote({ type: 'ftp' }),
    remote({ alwaysLoad: true }), remote({ oauth: { scopes: 'read' } }),
    remote({ _trustdexSignals: [] }), remote({ _trustdexFingerprintData: {} }),
    remote({ command: 'node' }), remote({ headersHelper: 1 }),
    remote({ headers: { Authorization: 1 } }), remote({ headers: [] }),
    { mcpServers: { bad: { command: 'node', args: [1] } } },
    { mcpServers: { bad: { command: 'node', env: { TOKEN: 1 } } } },
    { mcpServers: { bad: { command: 'node', env: [] } } },
    { mcpServers: { 'bad.name': { command: 'node' } } },
    JSON.parse('{"mcpServers":{"__proto__":{"command":"node"}}}')
  ]) assert.throws(() => parseClaudeMcpConfig(config));
});

test('Claude adapter rejects unresolved command, argument, and endpoint expansion', () => {
  for (const config of [
    { mcpServers: { bad: { command: '${COMMAND}' } } },
    { mcpServers: { bad: { command: 'node', args: ['${SCRIPT}'] } } },
    remote({ url: '${MCP_URL}' }), remote({ url: 'https://${MCP_HOST}/mcp' })
  ]) assert.throws(() => parseClaudeMcpConfig(config), /expansion|literal/);
});

test('Claude secret-bearing URLs fail before they can be fingerprinted or reported', () => {
  for (const url of [
    'https://user:INERT_URL_SECRET@reviewed.invalid/mcp',
    'https://reviewed.invalid/mcp?token=INERT_URL_SECRET',
    'https://reviewed.invalid/mcp#INERT_URL_SECRET'
  ]) {
    assert.throws(() => parseClaudeMcpConfig(remote({ url })), error => {
      assert.ok(!error.message.includes('INERT_URL_SECRET'));
      return true;
    });
  }
});

test('Claude insecure HTTP stays blocked even when its host is allowlisted', () => {
  assert.equal(evaluate(remote({ url: 'http://reviewed.invalid/mcp' }))[0].action, 'block');
});

test('Claude adapter permits empty configurations and default stdio transport', () => {
  assert.deepEqual(parseClaudeMcpConfig({ mcpServers: {} }), { mcpServers: {} });
  assert.equal(inspect({ mcpServers: { local: { command: 'node', args: [] } } })[0].source.type, 'local');
});

test('Claude env reference changes alter fingerprints while secret values stay omitted', () => {
  const config = value => ({ mcpServers: { local: { command: 'node', env: { TOKEN: value } } } });
  assert.equal(inspect(config('INERT_ONE'))[0].fingerprint, inspect(config('INERT_TWO'))[0].fingerprint);
  assert.notEqual(inspect(config('${FIRST}'))[0].fingerprint, inspect(config('${SECOND}'))[0].fingerprint);
  assert.ok(!JSON.stringify(inspect(config('INERT_ONE'))).includes('INERT_ONE'));
});

test('Claude CLI inspects and gates the inert example with ALLOW-only output', t => {
  const directory = temporaryDirectory(t);
  const output = path.join(directory, 'gated.json');
  const input = fileURLToPath(new URL('../examples/claude.mcp.json', import.meta.url));
  const policyFile = fileURLToPath(new URL('../examples/claude.policy.json', import.meta.url));
  const inspection = run('inspect-claude', input, '--policy', policyFile, '--json');
  assert.equal(inspection.status, 2);
  assert.deepEqual(Object.fromEntries(JSON.parse(inspection.stdout).map(x => [x.name, x.action])), {
    helper: 'block', needsReview: 'ask', reviewed: 'allow', unknown: 'block'
  });
  assert.ok(!inspection.stdout.includes('INERT_HELPER_NOT_EXECUTED'));
  const gate = run('gate-claude', input, '--policy', policyFile, '--out', output);
  assert.equal(gate.status, 1);
  assert.deepEqual(Object.keys(JSON.parse(fs.readFileSync(output, 'utf8')).mcpServers), ['reviewed']);
});

test('Claude CLI snapshot, approval, and recheck use the Claude adapter consistently', t => {
  const directory = temporaryDirectory(t);
  const input = path.join(directory, 'mcp.json');
  const policyFile = path.join(directory, 'policy.json');
  const privateKey = path.join(directory, 'private.pem');
  const publicKey = path.join(directory, 'public.pem');
  const review = path.join(directory, 'review');
  const snapshot = path.join(directory, 'snapshot.json');
  fs.writeFileSync(input, JSON.stringify(remote()));
  fs.writeFileSync(policyFile, JSON.stringify(policy));
  assert.equal(run('keygen', '--private', privateKey, '--public', publicKey).status, 0);
  assert.equal(run('snapshot-claude', input, '--policy', policyFile, '--out', snapshot).status, 0);
  assert.equal(JSON.parse(fs.readFileSync(snapshot, 'utf8')).digest, createSnapshot(evaluate(remote())).digest);
  assert.equal(run('approve-claude', input, '--policy', policyFile, '--private', privateKey, '--dir', review).status, 0);
  assert.equal(run('recheck-claude', input, '--review-dir', review, '--public', publicKey).status, 0);
  fs.writeFileSync(input, JSON.stringify(remote({ type: 'sse' })));
  const recheck = run('recheck-claude', input, '--review-dir', review, '--public', publicKey, '--json');
  assert.equal(recheck.status, 1);
  assert.equal(JSON.parse(recheck.stdout).status, 'needs-review');
});

test('Claude CLI refuses BLOCK approval and malformed input without leaking values', t => {
  const directory = temporaryDirectory(t);
  const input = path.join(directory, 'mcp.json');
  const output = path.join(directory, 'gated.json');
  const privateKey = path.join(directory, 'private.pem');
  const publicKey = path.join(directory, 'public.pem');
  const review = path.join(directory, 'review');
  const policyFile = path.join(directory, 'policy.json');
  fs.writeFileSync(policyFile, JSON.stringify(policy));
  fs.writeFileSync(input, JSON.stringify(remote({ headersHelper: 'INERT_SECRET_HELPER' })));
  assert.equal(run('keygen', '--private', privateKey, '--public', publicKey).status, 0);
  const approval = run('approve-claude', input, '--policy', policyFile, '--private', privateKey, '--dir', review);
  assert.equal(approval.status, 2);
  assert.ok(!approval.stderr.includes('INERT_SECRET_HELPER'));
  assert.ok(!fs.existsSync(review));
  fs.writeFileSync(input, '{"mcpServers":{"bad":{"headers":{"Authorization":"INERT_SECRET_MALFORMED"} trailing}}}');
  const malformed = run('gate-claude', input, '--out', output);
  assert.equal(malformed.status, 2);
  assert.match(malformed.stderr, /Invalid Claude MCP JSON/);
  assert.ok(!malformed.stderr.includes('INERT_SECRET_MALFORMED'));
  assert.ok(!fs.existsSync(output));
});
