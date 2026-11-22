import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseDevinMcpConfig } from '../src/devin-config.mjs';
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
const remote = (extra = {}) => ({ mcpServers: { reviewed: { url: 'https://reviewed.invalid/mcp', ...extra } } });
const local = (extra = {}) => ({ mcpServers: { local: { command: 'node', ...extra } } });
const inspect = (config) => inspectMcpConfig(parseDevinMcpConfig(config));
const evaluate = (config) => evaluateAll(inspect(config), policy);
function temporaryDirectory(t) {
  const directory = fs.mkdtempSync(path.join(path.resolve(os.tmpdir()), 'trustdex-devin-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}
function run(...args) {
  const result = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  if (result.error) throw result.error;
  return result;
}

test('Devin adapter gates stdio, HTTP, and SSE entries without changing input', () => {
  const config = { mcpServers: {
    stdio: { command: 'npx', args: ['-y', 'reviewed-mcp@1.2.3'] },
    http: { url: 'https://reviewed.invalid/mcp', transport: 'http' },
    sse: { url: 'https://reviewed.invalid/sse', transport: 'sse' },
    implicit: { url: 'https://reviewed.invalid/mcp', disabledTools: ['delete_everything'] },
    unknown: { url: 'https://unknown.invalid/mcp' },
    local: { command: 'node', args: ['./inert.mjs'] }
  } };
  const original = JSON.stringify(config);
  const results = evaluate(config);
  assert.deepEqual(Object.fromEntries(results.map(x => [x.name, x.action])), {
    http: 'allow', implicit: 'allow', local: 'ask', sse: 'allow', stdio: 'allow', unknown: 'block'
  });
  const gated = gateMcpConfig(config, results);
  assert.deepEqual(Object.keys(gated.config.mcpServers).sort(), ['http', 'implicit', 'sse', 'stdio']);
  for (const name of Object.keys(gated.config.mcpServers)) assert.deepEqual(gated.config.mcpServers[name], config.mcpServers[name]);
  assert.equal(JSON.stringify(config), original);
  assert.ok(!JSON.stringify(gated.config).includes('_trustdex'));
});

test('a disabled Devin server is decided like an enabled one', () => {
  assert.equal(evaluate(remote({ url: 'https://unknown.invalid/mcp', disabled: true }))[0].action, 'block');
  assert.equal(evaluate(local({ args: ['-c', 'x'], command: 'bash', disabled: true }))[0].action, 'block');
  assert.equal(evaluate(remote({ url: 'http://reviewed.invalid/mcp', disabled: true }))[0].action, 'block');
});

test('Devin static and variable-based headers require review without retaining values', () => {
  const config = remote({ headers: { Authorization: 'Bearer ${env:EXAMPLE_TOKEN}', 'X-Secret': 'INERT_STATIC_SECRET' } });
  const result = evaluate(config)[0];
  assert.equal(result.action, 'ask');
  assert.ok(result.signals.includes('env-http-headers'));
  assert.ok(result.signals.includes('static-http-headers'));
  assert.ok(!JSON.stringify(result).includes('INERT_STATIC_SECRET'));
  assert.ok(!JSON.stringify(createSnapshot([result])).includes('INERT_STATIC_SECRET'));
  // The Claude ${NAME} form is not a Devin reference, so it counts as a static value.
  assert.deepEqual(evaluate(remote({ headers: { Authorization: 'Bearer $EXAMPLE' } }))[0].signals.filter(x => x.endsWith('-headers')), ['static-http-headers']);
});

test('Devin credential rotations do not enter fingerprints; tool names do not enter results', () => {
  const header = value => inspect(remote({ headers: { Authorization: value } }))[0];
  assert.equal(header('INERT_FIRST').fingerprint, header('INERT_SECOND').fingerprint);
  const env = value => inspect(local({ env: { TOKEN: value } }))[0];
  assert.equal(env('INERT_ONE').fingerprint, env('INERT_TWO').fingerprint);
  assert.notEqual(env('${env:FIRST}').fingerprint, env('${env:SECOND}').fingerprint);
  assert.ok(!JSON.stringify(env('INERT_ONE')).includes('INERT_ONE'));
  const hidden = evaluate(remote({ disabledTools: ['INERT_TOOL_NAME'] }));
  assert.ok(!JSON.stringify(hidden).includes('INERT_TOOL_NAME'));
  assert.ok(!JSON.stringify(createSnapshot(hidden)).includes('INERT_TOOL_NAME'));
});

test('Devin changes that widen exposure invalidate a signed review', () => {
  const base = remote({ headers: { Authorization: 'Bearer ${env:FIRST_TOKEN}' }, disabled: true, disabledTools: ['delete_page', 'create_page'] });
  const baseline = createSnapshot(evaluate(base));
  const keys = generateTrustKeyPair();
  const record = createTrustRecord(baseline, keys.privateKey, { policy });
  const assess = (config) => assessReview({ record, publicKey: keys.publicKey, baseline, current: createSnapshot(evaluate(config)), policy });
  assert.equal(assess(base).status, 'approved');
  // The order of hidden tools is not a change.
  assert.equal(assess(remote({ ...base.mcpServers.reviewed, disabledTools: ['create_page', 'delete_page', 'delete_page'] })).status, 'approved');
  const server = base.mcpServers.reviewed;
  for (const config of [
    remote({ ...server, headers: { Authorization: 'Bearer ${env:SECOND_TOKEN}' } }),
    remote({ ...server, headers: { 'X-Authorization': 'Bearer ${env:FIRST_TOKEN}' } }),
    remote({ ...server, transport: 'sse' }),
    remote({ ...server, disabled: false }),
    remote({ ...server, disabled: undefined }),
    remote({ ...server, disabledTools: ['create_page'] }),
    remote({ ...server, disabledTools: ['delete_page', 'other_page'] }),
    remote({ ...server, disabledTools: undefined })
  ]) {
    const verdict = assess(config);
    assert.equal(verdict.status, 'needs-review', JSON.stringify(config));
    assert.ok(verdict.changes.some(change => change.type === 'fingerprint-changed'));
  }
});

test('Devin adapter rejects unsupported fields, invalid entries, and internal annotation injection', () => {
  for (const config of [
    null, [], {}, { mcpServers: [] }, { mcpServers: null },
    { mcpServers: {}, permissions: {} }, { mcpServers: { bad: null } }, { mcpServers: { bad: [] } }, { mcpServers: { bad: {} } },
    remote({ command: 'node' }), remote({ transport: null }), remote({ transport: 'ws' }), remote({ transport: 'stdio' }), remote({ type: 'http' }),
    // Documented OAuth client fields have no inspection yet and must not pass unread.
    remote({ oauthClientId: 'Iv1.example' }), remote({ oauthClientSecret: '${env:SECRET}' }), remote({ oauthResource: '' }), remote({ oauthScopes: ['read'] }),
    remote({ args: [] }), remote({ env: {} }), remote({ tokenScope: 'user' }), remote({ trust: true }),
    remote({ _trustdexSignals: [] }), remote({ _trustdexFingerprintData: {} }),
    remote({ headers: { Authorization: 1 } }), remote({ headers: [] }), remote({ url: 7 }), remote({ url: '' }),
    remote({ disabled: 'false' }), remote({ disabled: 0 }), remote({ disabledTools: 'a' }), remote({ disabledTools: [1] }), remote({ disabledTools: [''] }),
    local({ command: '' }), local({ command: 7 }), local({ args: [1] }), local({ args: 'x' }), local({ env: { TOKEN: 1 } }), local({ env: [] }),
    local({ headers: {} }), local({ transport: 'http' }), local({ cwd: '/tmp' }),
    { mcpServers: { 'bad.name': { command: 'node' } } },
    JSON.parse('{"mcpServers":{"__proto__":{"command":"node"}}}')
  ]) assert.throws(() => parseDevinMcpConfig(config), JSON.stringify(config));
});

test('Devin adapter rejects expansion it does not inspect', () => {
  for (const config of [
    local({ command: '${env:COMMAND}' }), local({ args: ['${env:SCRIPT}'] }), local({ args: ['${file:/etc/passwd}'] }),
    remote({ url: '${env:MCP_URL}' }), remote({ url: 'https://${env:MCP_HOST}/mcp' }),
    // ${file:...} would send a local file to the server.
    remote({ headers: { Authorization: '${file:/home/user/.ssh/id_ed25519}' } }),
    remote({ headers: { Authorization: 'Bearer ${env:TOKEN} ${file:/x}' } }),
    remote({ headers: { Authorization: '${TOKEN}' } }), remote({ headers: { Authorization: '${env:}' } }),
    local({ env: { TOKEN: '${file:/x}' } }), local({ env: { TOKEN: '${env:A-B}' } })
  ]) assert.throws(() => parseDevinMcpConfig(config), /expansion|literal/, JSON.stringify(config));
});

test('Devin secret-bearing URLs fail before they can be fingerprinted or reported', () => {
  for (const url of [
    'https://user:INERT_URL_SECRET@reviewed.invalid/mcp',
    'https://reviewed.invalid/mcp?token=INERT_URL_SECRET',
    'https://reviewed.invalid/mcp#INERT_URL_SECRET',
    'ftp://reviewed.invalid/INERT_URL_SECRET', 'not a url INERT_URL_SECRET'
  ]) {
    assert.throws(() => parseDevinMcpConfig(remote({ url })), error => {
      assert.ok(!error.message.includes('INERT_URL_SECRET'));
      return true;
    });
  }
});

test('Devin CLI inspects and gates the inert example with ALLOW-only output', t => {
  const directory = temporaryDirectory(t);
  const output = path.join(directory, 'gated.json');
  const input = fileURLToPath(new URL('../examples/devin.mcp_config.json', import.meta.url));
  const policyFile = fileURLToPath(new URL('../examples/claude.policy.json', import.meta.url));
  const inspection = run('inspect-devin', input, '--policy', policyFile, '--json');
  assert.equal(inspection.status, 2);
  assert.deepEqual(Object.fromEntries(JSON.parse(inspection.stdout).map(x => [x.name, x.action])), {
    disabledLocal: 'ask', needsReview: 'ask', reviewed: 'allow', unknown: 'block'
  });
  const gate = run('gate-devin', input, '--policy', policyFile, '--out', output);
  assert.equal(gate.status, 1);
  assert.deepEqual(Object.keys(JSON.parse(fs.readFileSync(output, 'utf8')).mcpServers), ['reviewed']);
});

test('Devin CLI snapshot, approval, and recheck use the Devin adapter consistently', t => {
  const directory = temporaryDirectory(t);
  const file = name => path.join(directory, name);
  fs.writeFileSync(file('mcp.json'), JSON.stringify(remote({ disabled: true })));
  fs.writeFileSync(file('policy.json'), JSON.stringify(policy));
  assert.equal(run('keygen', '--private', file('private.pem'), '--public', file('public.pem')).status, 0);
  assert.equal(run('snapshot-devin', file('mcp.json'), '--policy', file('policy.json'), '--out', file('snapshot.json')).status, 0);
  assert.equal(JSON.parse(fs.readFileSync(file('snapshot.json'), 'utf8')).digest, createSnapshot(evaluate(remote({ disabled: true }))).digest);
  assert.equal(run('approve-devin', file('mcp.json'), '--policy', file('policy.json'), '--private', file('private.pem'), '--dir', file('review')).status, 0);
  assert.equal(run('recheck-devin', file('mcp.json'), '--review-dir', file('review'), '--public', file('public.pem')).status, 0);
  fs.writeFileSync(file('mcp.json'), JSON.stringify(remote()));
  const recheck = run('recheck-devin', file('mcp.json'), '--review-dir', file('review'), '--public', file('public.pem'), '--json');
  assert.equal(recheck.status, 1);
  assert.equal(JSON.parse(recheck.stdout).status, 'needs-review');
});

test('Devin CLI fails closed on unsupported or malformed input without leaking values', t => {
  const directory = temporaryDirectory(t);
  const input = path.join(directory, 'mcp.json');
  const output = path.join(directory, 'gated.json');
  for (const text of [
    JSON.stringify(remote({ oauthClientSecret: 'INERT_SECRET_VALUE' })),
    JSON.stringify(remote({ headers: { Authorization: '${file:/INERT_SECRET_VALUE}' } })),
    JSON.stringify(remote({ url: 'https://reviewed.invalid/mcp?key=INERT_SECRET_VALUE' })),
    '{"mcpServers": {"a": {"command": INERT_SECRET_VALUE}}}'
  ]) {
    fs.writeFileSync(input, text);
    for (const args of [['inspect-devin', input], ['inspect-devin', input, '--decisions'], ['gate-devin', input, '--out', output]]) {
      const result = run(...args);
      assert.notEqual(result.status, 0, args[0]);
      assert.ok(!`${result.stdout}${result.stderr}`.includes('INERT_SECRET_VALUE'), args[0]);
    }
    assert.ok(!fs.existsSync(output));
  }
});
