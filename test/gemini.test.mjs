import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseGeminiMcpConfig } from '../src/gemini-config.mjs';
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
const remote = (extra = {}) => ({ mcpServers: { reviewed: { httpUrl: 'https://reviewed.invalid/mcp', ...extra } } });
const local = (extra = {}) => ({ mcpServers: { local: { command: 'node', ...extra } } });
const inspect = (config) => inspectMcpConfig(parseGeminiMcpConfig(config));
const evaluate = (config) => evaluateAll(inspect(config), policy);
function temporaryDirectory(t) {
  const directory = fs.mkdtempSync(path.join(path.resolve(os.tmpdir()), 'trustdex-gemini-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}
function run(...args) {
  const result = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  if (result.error) throw result.error;
  return result;
}

test('Gemini adapter gates stdio, HTTP, and SSE entries without changing input', () => {
  const config = { mcpServers: {
    stdio: { command: 'npx', args: ['-y', 'reviewed-mcp@1.2.3'], timeout: 30000, trust: false },
    http: { httpUrl: 'https://reviewed.invalid/mcp', includeTools: ['search'] },
    sse: { url: 'https://reviewed.invalid/sse', excludeTools: ['delete_everything'] },
    unknown: { httpUrl: 'https://unknown.invalid/mcp' },
    local: { command: 'node', args: ['./inert.mjs'], cwd: './server' }
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

test('an httpUrl endpoint is inspected like a url endpoint', () => {
  assert.equal(evaluate(remote({ httpUrl: 'https://unknown.invalid/mcp' }))[0].action, 'block');
  assert.equal(evaluate(remote({ httpUrl: 'http://reviewed.invalid/mcp' }))[0].action, 'block');
  assert.equal(inspect(remote())[0].source.host, 'reviewed.invalid');
  assert.notEqual(inspect(remote())[0].fingerprint,
    inspect({ mcpServers: { reviewed: { url: 'https://reviewed.invalid/mcp' } } })[0].fingerprint);
});

test('Gemini trust: true never reaches ALLOW in a built-in pack', () => {
  for (const pack of ['strict', 'official-first', 'development']) {
    const packPolicy = mergePolicy(getPolicyPack(pack), { trustedPackages: ['reviewed-mcp'], allowedRemoteHosts: ['reviewed.invalid'] });
    for (const config of [remote({ trust: true }), { mcpServers: { stdio: { command: 'npx', args: ['-y', 'reviewed-mcp@1.2.3'], trust: true } } }]) {
      const [result] = evaluateAll(inspect(config), packPolicy);
      assert.ok(result.signals.includes('auto-approve-tools'), pack);
      assert.notEqual(result.action, 'allow', pack);
    }
  }
  assert.equal(evaluate(remote({ trust: false }))[0].action, 'allow');
  // trust does not rescue a blocked source.
  assert.equal(evaluate(remote({ httpUrl: 'https://unknown.invalid/mcp', trust: true }))[0].action, 'block');
});

test('Gemini headers require review without retaining values', () => {
  for (const endpoint of [{ httpUrl: 'https://reviewed.invalid/mcp' }, { url: 'https://reviewed.invalid/sse' }]) {
    const config = { mcpServers: { reviewed: {
      ...endpoint,
      headers: { Authorization: 'Bearer $INERT_ENV_NAME', 'X-Secret': 'INERT_STATIC_SECRET' }
    } } };
    const [result] = evaluate(config);
    assert.equal(result.action, 'ask');
    assert.ok(result.signals.includes('static-http-headers'));
    assert.ok(result.signals.includes('env-http-headers'));
    for (const text of [JSON.stringify(result), JSON.stringify(createSnapshot([result]))]) {
      assert.ok(!text.includes('INERT_STATIC_SECRET'));
      assert.ok(!text.includes('INERT_ENV_NAME'));
    }
  }
  assert.ok(!evaluate(remote({ headers: { Authorization: 'INERT_STATIC_SECRET' } }))[0].signals.includes('env-http-headers'));
  assert.equal(evaluate(remote({ headers: {} }))[0].action, 'allow');
});

test('Gemini signed reviews bind each header to its environment reference pattern', () => {
  const config = (value, other = 'INERT_LITERAL') => remote({ headers: { Authorization: value, 'X-Key': other } });
  const baseline = createSnapshot(evaluate(config('Bearer ${FIRST} $SECOND')));
  const keys = generateTrustKeyPair();
  const record = createTrustRecord(baseline, keys.privateKey, { policy });
  const assess = (current) => assessReview({ record, publicKey: keys.publicKey, baseline, current: createSnapshot(evaluate(current)), policy });
  assert.equal(assess(config('Bearer $FIRST ${SECOND}', 'ROTATED_LITERAL')).status, 'approved');
  for (const changed of [
    config('Bearer $THIRD $SECOND'),
    config('Bearer $SECOND $FIRST'),
    config('Bearer %FIRST% $SECOND'),
    config('Bearer $FIRST $SECOND', '$THIRD'),
    config('INERT_LITERAL', 'Bearer $FIRST $SECOND'),
    config('INERT_LITERAL')
  ]) {
    assert.equal(assess(changed).status, 'needs-review');
  }
});

test('Gemini credential rotations do not enter fingerprints; tool names and paths do not enter results', () => {
  const header = value => inspect(remote({ headers: { Authorization: value } }))[0];
  assert.equal(header('INERT_FIRST').fingerprint, header('INERT_SECOND').fingerprint);
  const env = value => inspect(local({ env: { TOKEN: value } }))[0];
  assert.equal(env('INERT_ONE').fingerprint, env('INERT_TWO').fingerprint);
  assert.notEqual(env('$FIRST').fingerprint, env('$SECOND').fingerprint);
  assert.equal(env('$FIRST').fingerprint, env('${FIRST}').fingerprint);
  assert.notEqual(env('%FIRST%').fingerprint, env('INERT_ONE').fingerprint);
  assert.notEqual(env('%FIRST%').fingerprint, env('$FIRST').fingerprint);
  assert.notEqual(env('$FIRST $SECOND').fingerprint, env('$SECOND $FIRST').fingerprint);
  assert.ok(!JSON.stringify(env('INERT_ONE')).includes('INERT_ONE'));
  const hidden = evaluate({ mcpServers: { local: { command: 'node', cwd: '/INERT_PATH', includeTools: ['INERT_TOOL_NAME'], excludeTools: ['INERT_OTHER_TOOL'] } } });
  for (const text of [JSON.stringify(hidden), JSON.stringify(createSnapshot(hidden))]) {
    for (const value of ['INERT_PATH', 'INERT_TOOL_NAME', 'INERT_OTHER_TOOL']) assert.ok(!text.includes(value), value);
  }
});

test('Gemini changes that widen exposure invalidate a signed review', () => {
  const server = { command: 'npx', args: ['-y', 'reviewed-mcp@1.2.3'], cwd: './a', env: { TOKEN: '$FIRST' }, includeTools: ['read', 'search'], excludeTools: ['delete'] };
  const config = (extra) => ({ mcpServers: { reviewed: { ...server, ...extra } } });
  const baseline = createSnapshot(evaluate(config()));
  const keys = generateTrustKeyPair();
  const record = createTrustRecord(baseline, keys.privateKey, { policy });
  const assess = (current) => assessReview({ record, publicKey: keys.publicKey, baseline, current: createSnapshot(evaluate(current)), policy });
  assert.equal(assess(config()).status, 'approved');
  // Order, duplicates, and the timeout are not changes.
  assert.equal(assess(config({ includeTools: ['search', 'read', 'read'], timeout: 5 })).status, 'approved');
  for (const extra of [
    { includeTools: ['read', 'search', 'write'] }, { includeTools: undefined }, { includeTools: [] },
    { excludeTools: [] }, { excludeTools: undefined }, { excludeTools: ['other'] },
    { cwd: './b' }, { cwd: undefined }, { env: { TOKEN: '$SECOND' } }, { trust: true }
  ]) {
    const verdict = assess(config(extra));
    assert.equal(verdict.status, 'needs-review', JSON.stringify(extra));
  }
});

test('Gemini adapter rejects unsupported fields, invalid entries, and internal annotation injection', () => {
  for (const config of [
    null, [], {}, { mcpServers: [] }, { mcpServers: null },
    // A whole settings.json is not accepted: other settings would pass uninspected.
    { mcpServers: {}, mcp: { allowed: ['a'] } }, { mcpServers: {}, tools: {} },
    { mcpServers: { bad: null } }, { mcpServers: { bad: [] } }, { mcpServers: { bad: {} } },
    remote({ command: 'node' }), remote({ url: 'https://reviewed.invalid/sse' }),
    { mcpServers: { bad: { command: 'node', url: 'https://reviewed.invalid/sse' } } },
    // Documented OAuth and Google credential fields have no inspection yet.
    remote({ oauth: { enabled: true } }), remote({ authProviderType: 'google_credentials' }),
    remote({ targetAudience: 'x' }), remote({ targetServiceAccount: 'x@example.invalid' }),
    remote({ type: 'http' }), remote({ transport: 'http' }), remote({ tcp: 'localhost:1' }), remote({ description: 'x' }),
    remote({ args: [] }), remote({ env: {} }), remote({ cwd: '.' }),
    remote({ _trustdexSignals: [] }), remote({ _trustdexFingerprintData: {} }),
    remote({ headers: { Authorization: 1 } }), remote({ headers: [] }), remote({ httpUrl: 7 }), remote({ httpUrl: '' }),
    remote({ trust: 'true' }), remote({ trust: 1 }), remote({ timeout: '30' }), remote({ timeout: 0 }), remote({ timeout: -1 }), remote({ timeout: null }),
    remote({ includeTools: 'a' }), remote({ includeTools: [1] }), remote({ excludeTools: [''] }), remote({ excludeTools: {} }),
    local({ command: '' }), local({ command: 7 }), local({ args: [1] }), local({ args: 'x' }), local({ env: { TOKEN: 1 } }), local({ env: [] }),
    local({ cwd: 7 }), local({ cwd: '' }), local({ headers: {} }),
    { mcpServers: { 'bad.name': { command: 'node' } } },
    JSON.parse('{"mcpServers":{"__proto__":{"command":"node"}}}')
  ]) assert.throws(() => parseGeminiMcpConfig(config), JSON.stringify(config));
});

test('Gemini adapter rejects unresolved expansion of the launch target or tool filters', () => {
  for (const config of [
    local({ command: '${COMMAND}' }), local({ command: '$COMMAND' }),
    local({ args: ['${SCRIPT}'] }), local({ args: ['$SCRIPT'] }),
    local({ cwd: '${HOME}/server' }), local({ cwd: '$HOME/server' }),
    remote({ httpUrl: '${MCP_URL}' }), remote({ httpUrl: 'https://${MCP_HOST}/mcp' }),
    remote({ httpUrl: 'https://reviewed.invalid/$MCP_PATH' }),
    { mcpServers: { reviewed: { url: 'https://$MCP_HOST/sse' } } },
    remote({ includeTools: ['$TOOLS'] }),
    local({ excludeTools: ['${TOOLS:-read}'] })
  ]) assert.throws(() => parseGeminiMcpConfig(config), /expansion|literal/, JSON.stringify(config));
});

test('Gemini adapter rejects uninspected credential reference syntax without echoing it', () => {
  for (const value of ['${TOKEN:-INERT_SECRET}', '${NAME:${INERT_SECRET}}', '${INERT_SECRET', '$123']) {
    for (const config of [local({ env: { TOKEN: value } }), remote({ headers: { Authorization: value } })]) {
      assert.throws(() => parseGeminiMcpConfig(config), ({ message }) => {
        assert.match(message, /Unsupported Gemini MCP environment reference/);
        assert.ok(!message.includes(value));
        assert.ok(!message.includes('INERT_SECRET'));
        return true;
      });
    }
  }
});

test('Gemini secret-bearing URLs fail before they can be fingerprinted or reported', () => {
  for (const key of ['url', 'httpUrl']) {
    for (const value of [
      'https://user:INERT_URL_SECRET@reviewed.invalid/mcp',
      'https://reviewed.invalid/mcp?token=INERT_URL_SECRET',
      'https://reviewed.invalid/mcp#INERT_URL_SECRET',
      'ftp://reviewed.invalid/INERT_URL_SECRET', 'not a url INERT_URL_SECRET'
    ]) {
      assert.throws(() => parseGeminiMcpConfig({ mcpServers: { reviewed: { [key]: value } } }), error => {
        assert.ok(!error.message.includes('INERT_URL_SECRET'));
        return true;
      });
    }
  }
});

test('Gemini CLI inspects and gates the inert example with ALLOW-only output', t => {
  const directory = temporaryDirectory(t);
  const output = path.join(directory, 'gated.json');
  const input = fileURLToPath(new URL('../examples/gemini.mcpServers.json', import.meta.url));
  const policyFile = fileURLToPath(new URL('../examples/claude.policy.json', import.meta.url));
  const inspection = run('inspect-gemini', input, '--policy', policyFile, '--json');
  assert.equal(inspection.status, 2);
  assert.deepEqual(Object.fromEntries(JSON.parse(inspection.stdout).map(x => [x.name, x.action])), {
    needsReview: 'ask', reviewed: 'allow', trusted: 'ask', unknown: 'block'
  });
  assert.ok(!inspection.stdout.includes('INERT_PLACEHOLDER'));
  const gate = run('gate-gemini', input, '--policy', policyFile, '--out', output);
  assert.equal(gate.status, 1);
  assert.deepEqual(JSON.parse(fs.readFileSync(output, 'utf8')), { mcpServers: { reviewed: { httpUrl: 'https://reviewed.invalid/mcp', includeTools: ['search'] } } });
});

test('Gemini CLI snapshot, approval, and recheck use the Gemini adapter consistently', t => {
  const directory = temporaryDirectory(t);
  const file = name => path.join(directory, name);
  fs.writeFileSync(file('mcp.json'), JSON.stringify(remote()));
  fs.writeFileSync(file('policy.json'), JSON.stringify(policy));
  assert.equal(run('keygen', '--private', file('private.pem'), '--public', file('public.pem')).status, 0);
  assert.equal(run('snapshot-gemini', file('mcp.json'), '--policy', file('policy.json'), '--out', file('snapshot.json')).status, 0);
  assert.equal(JSON.parse(fs.readFileSync(file('snapshot.json'), 'utf8')).digest, createSnapshot(evaluate(remote())).digest);
  assert.equal(run('approve-gemini', file('mcp.json'), '--policy', file('policy.json'), '--private', file('private.pem'), '--dir', file('review')).status, 0);
  assert.equal(run('recheck-gemini', file('mcp.json'), '--review-dir', file('review'), '--public', file('public.pem')).status, 0);
  fs.writeFileSync(file('mcp.json'), JSON.stringify(remote({ trust: true })));
  const recheck = run('recheck-gemini', file('mcp.json'), '--review-dir', file('review'), '--public', file('public.pem'), '--json');
  assert.equal(recheck.status, 1);
  assert.equal(JSON.parse(recheck.stdout).status, 'needs-review');
});

test('Gemini CLI fails closed on unsupported or malformed input without leaking values', t => {
  const directory = temporaryDirectory(t);
  const input = path.join(directory, 'mcp.json');
  const output = path.join(directory, 'gated.json');
  for (const text of [
    JSON.stringify(remote({ oauth: { clientSecret: 'INERT_SECRET_VALUE' } })),
    JSON.stringify({ mcpServers: {}, security: { auth: 'INERT_SECRET_VALUE' } }),
    JSON.stringify(remote({ httpUrl: 'https://reviewed.invalid/mcp?key=INERT_SECRET_VALUE' })),
    '{"mcpServers": {"a": {"command": INERT_SECRET_VALUE}}}'
  ]) {
    fs.writeFileSync(input, text);
    for (const args of [['inspect-gemini', input], ['inspect-gemini', input, '--decisions'], ['gate-gemini', input, '--out', output]]) {
      const result = run(...args);
      assert.notEqual(result.status, 0, args[0]);
      assert.ok(!`${result.stdout}${result.stderr}`.includes('INERT_SECRET_VALUE'), args[0]);
    }
    assert.ok(!fs.existsSync(output));
  }
});
