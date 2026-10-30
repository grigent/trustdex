import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { inspectMcpConfig } from '../src/inspect.mjs';
import { evaluateAll } from '../src/policy.mjs';
import { getPolicyPack } from '../src/policy-packs.mjs';
import { parseCodexMcpToml } from '../src/codex-config.mjs';

test('redacts remote URL credentials and query values from inspection output', () => {
  const [result] = inspectMcpConfig({
    mcpServers: {
      remote: {
        url: 'http://alice:super-secret@example.com:8080/private/path?token=top-secret#fragment'
      }
    }
  });

  assert.deepEqual(result.source, {
    type: 'remote',
    host: 'example.com',
    origin: 'http://example.com:8080',
    protocol: 'http:'
  });
  assert.ok(result.signals.includes('embedded-credentials'));
  assert.ok(result.signals.includes('insecure-transport'));
  assert.ok(result.signals.includes('url-query-parameters'));
  assert.equal(JSON.stringify(result).includes('super-secret'), false);
  assert.equal(JSON.stringify(result).includes('top-secret'), false);
  assert.equal(JSON.stringify(result).includes('/private/path'), false);
});

test('does not fingerprint URL secrets or sensitive command arguments', () => {
  const inspect = (secret) => inspectMcpConfig({
    mcpServers: {
      remote: {
        url: `https://alice:${secret}@example.com/mcp?token=${secret}&scope=read#${secret}`
      },
      local: {
        command: 'node',
        args: [
          'server.mjs',
          '--api-token', secret,
          `--password=${secret}`,
          '--header', `Authorization: Bearer ${secret}`,
          `https://example.com/callback?code=${secret}`
        ]
      }
    }
  });

  const first = inspect('INERT_SECRET_ONE');
  const second = inspect('INERT_SECRET_TWO');
  assert.equal(first[0].fingerprint, second[0].fingerprint);
  assert.equal(first[1].fingerprint, second[1].fingerprint);
  assert.equal(JSON.stringify(first).includes('INERT_SECRET_ONE'), false);
});

test('keeps non-secret remote endpoint changes trust-relevant', () => {
  const fingerprint = (url) => inspectMcpConfig({ mcpServers: { remote: { url } } })[0].fingerprint;

  assert.notEqual(
    fingerprint('https://example.com/mcp?token=one'),
    fingerprint('https://example.com/admin?token=one')
  );
  assert.notEqual(
    fingerprint('https://example.com/mcp?token=one'),
    fingerprint('https://example.com/mcp?credential=one')
  );
});

test('strict policy blocks an allowlisted host over insecure transport', () => {
  const [server] = inspectMcpConfig({
    mcpServers: {
      remote: { url: 'http://example.com/mcp' }
    }
  });
  const policy = getPolicyPack('strict');
  policy.allowedRemoteHosts = ['example.com'];

  const [result] = evaluateAll([server], policy);
  assert.equal(result.action, 'block');
  assert.ok(result.reasons.includes('signal policy: insecure-transport -> block'));
});

test('normalizes Windows executable paths and command wrappers', () => {
  const [packageServer, shellServer] = inspectMcpConfig({
    mcpServers: {
      package: {
        command: 'C:\\Program Files\\nodejs\\npx.cmd',
        args: ['--package=@scope/demo@1.2.3', 'demo']
      },
      shell: {
        command: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        args: ['-File', 'setup.ps1']
      }
    }
  });

  assert.equal(packageServer.source.type, 'package');
  assert.equal(packageServer.source.runner, 'npx');
  assert.equal(packageServer.source.package, '@scope/demo@1.2.3');
  assert.equal(packageServer.source.pinned, true);
  assert.ok(packageServer.signals.includes('install-on-run'));
  assert.ok(shellServer.signals.includes('shell-execution'));
});

test('Codex parser fingerprints supported execution controls', () => {
  const parsed = parseCodexMcpToml(`
[mcp_servers.demo]
command = "node"
args = ["server.mjs"]
enabled = true
startup_timeout_sec = 15
tool_timeout_sec = 60
`);

  assert.deepEqual(parsed.mcpServers.demo._trustdexFingerprintData, {
    format: 'codex-toml',
    cwd: null,
    httpHeaderKeys: [],
    envHttpHeaderKeys: [],
    httpHeadersHelper: null,
    enabledTools: [],
    disabledTools: [],
    defaultToolsApprovalMode: null,
    enabled: true,
    startupTimeoutSec: 15,
    toolTimeoutSec: 60
  });
});

test('Codex parser fails closed on unsupported MCP keys and subsections', () => {
  assert.throws(
    () => parseCodexMcpToml('[mcp_servers.demo]\ncommand = "node"\nfuture_option = true\n'),
    /Unsupported or invalid Codex MCP key/
  );
  assert.throws(
    () => parseCodexMcpToml('[mcp_servers.demo.oauth]\nclient_id = "example"\n'),
    /Unsupported Codex MCP subsection/
  );
  assert.throws(
    () => parseCodexMcpToml('[mcp_servers]\ndemo = {}\n'),
    /Unsupported Codex MCP section/
  );
  assert.throws(
    () => parseCodexMcpToml('[mcp_servers.__proto__]\ncommand = "node"\n'),
    /Unsupported or invalid Codex MCP key|Unsupported Codex MCP/
  );
});

test('package URLs drop credentials and query values, keep git refs, and are never pinned', () => {
  const results = inspectMcpConfig({ mcpServers: {
    tarball: { command: 'npx', args: ['-y', 'https://user:pw@registry.example.invalid/pkg-1.0.0.tgz?sig=x'] },
    git: { command: 'uvx', args: ['git+https://token@git.example.invalid/x/y#v1.0.0'] },
    ssh: { command: 'npx', args: ['git+ssh://git@git.example.invalid/x/y.git'] },
    alias: { command: 'npx', args: ['pkg@https://u:pw@registry.example.invalid/x.tgz'] },
    scp: { command: 'npx', args: ['deploy:pw@git.example.invalid:org/repo'] },
    from: { command: 'uvx', args: ['--from', 'pkg @ https://u:pw@files.example.invalid/x.whl', 'tool'] },
    shorthand: { command: 'npx', args: ['github:org/repo#v2'] },
    registry: { command: 'npx', args: ['-y', 'pkg@1.0.0'] }
  } });
  const by = Object.fromEntries(results.map((result) => [result.name, result]));
  assert.deepEqual(by.tarball.source, { type: 'package', runner: 'npx', package: 'https://registry.example.invalid/pkg-1.0.0.tgz', pinned: false });
  assert.ok(by.tarball.signals.includes('embedded-credentials'));
  assert.ok(by.tarball.signals.includes('package-url-query'));
  assert.ok(by.tarball.signals.includes('unbounded-version'));
  assert.equal(by.git.source.package, 'git+https://git.example.invalid/x/y#v1.0.0');
  assert.ok(by.git.signals.includes('embedded-credentials'));
  assert.equal(by.ssh.source.package, 'git+ssh://git@git.example.invalid/x/y.git');
  assert.ok(!by.ssh.signals.includes('embedded-credentials'));
  assert.equal(by.alias.source.package, 'pkg@https://registry.example.invalid/x.tgz');
  assert.equal(by.scp.source.package, 'git.example.invalid:org/repo');
  assert.equal(by.from.source.package, 'pkg @ https://files.example.invalid/x.whl');
  for (const name of ['alias', 'scp', 'from']) {
    assert.ok(by[name].signals.includes('embedded-credentials'), name);
    assert.equal(by[name].source.pinned, false, name);
  }
  assert.equal(by.shorthand.source.pinned, false);
  assert.equal(by.registry.source.pinned, true);
  assert.ok(!JSON.stringify(results).includes('pw'));
});

test('a changed git ref is still visible to snapshot drift', () => {
  const at = (ref) => inspectMcpConfig({ mcpServers: { git: { command: 'uvx', args: [`git+https://git.example.invalid/x/y#${ref}`] } } })[0];
  assert.notDeepEqual(at('v1.0.0').source, at('attacker-commit').source);
});

test('package URLs with query values cannot be allowed in any pack', () => {
  const [result] = inspectMcpConfig({ mcpServers: { t: { command: 'npx', args: ['https://registry.example.invalid/p.tgz?version=1.0.0'] } } });
  for (const pack of ['strict', 'official-first', 'development']) {
    const policy = { ...getPolicyPack(pack), trustedPackages: ['https://registry.example.invalid/p.tgz'], unpinnedAction: 'allow' };
    assert.equal(evaluateAll([result], policy)[0].action, 'block', pack);
  }
});

const PACKS = ['strict', 'official-first', 'development'];
const inspectOne = (command, args) => inspectMcpConfig({ mcpServers: { s: { command, args } } })[0];
const blockedEverywhere = (result) => PACKS.every((pack) => evaluateAll([result], getPolicyPack(pack))[0].action === 'block');

test('package spec bypass forms never print credentials, are flagged, and are never pinned', () => {
  const cases = [
    ['https://user:pa@SECRETA@registry.example.invalid/x.tgz', 'embedded-credentials'],
    ['pkg@https://user:pa@SECRETB@registry.example.invalid/x.tgz', 'embedded-credentials'],
    ['https://user:pa SECRETC@registry.example.invalid/x.tgz', 'unparseable-package-spec'],
    ['https://registry.example.invalid/x.tgz?sig=AAA SECRETD', 'unparseable-package-spec'],
    ['https:/u:SECRETE@registry.example.invalid/x.tgz', 'embedded-credentials'],
    ['https:\\\\u:SECRETF@registry.example.invalid/x.tgz', 'embedded-credentials'],
    ['https:u:SECRETG@registry.example.invalid/x.tgz', 'embedded-credentials'],
    ['https:/registry.example.invalid/x.tgz?sig=SECRETH', 'package-url-query'],
    ['git+https:/u:SECRETI@git.example.invalid/x/y', 'unparseable-package-spec'],
    ['github:u:SECRETJ@org/repo', 'unparseable-package-spec'],
    ['git:SECRETK@git.example.invalid:org/repo', 'unparseable-package-spec'],
    ['file://u:SECRETL@host.invalid/x', 'unparseable-package-spec']
  ];
  for (const [spec, signal] of cases) {
    const result = inspectOne('npx', ['-y', spec]);
    assert.ok(!/SECRET/.test(JSON.stringify(result)), spec);
    assert.ok(result.signals.includes(signal), `${spec} -> ${signal}`);
    assert.ok(result.signals.includes('unbounded-version'), spec);
    assert.equal(result.source.pinned, false, spec);
    assert.ok(blockedEverywhere(result), spec);
    const evaluated = evaluateAll([result], getPolicyPack('development'));
    assert.ok(!/SECRET/.test(JSON.stringify(evaluated)), spec);
  }
  assert.equal(inspectOne('npx', ['https://user:pa@SECRETA@registry.example.invalid/x.tgz']).source.package, 'https://registry.example.invalid/x.tgz');
  assert.equal(inspectOne('npx', ['https:u:SECRETG@registry.example.invalid/x.tgz']).source.package, 'https://registry.example.invalid/x.tgz');
  assert.equal(inspectOne('npx', ['https://user:pa SECRETC@registry.example.invalid/x.tgz']).source.package, '<unparseable-package-spec>');
});

test('specs TrustDex cannot parse are blocked in every pack, even when trusted by name', () => {
  for (const spec of ['ftp://h.invalid/x.tgz', 'pkg@', 'name:1.0@sha256:abc', 'npm:a b', './x?sig=1']) {
    const result = inspectOne('npx', [spec]);
    assert.ok(result.signals.includes('unparseable-package-spec'), spec);
    assert.equal(result.source.package, '<unparseable-package-spec>', spec);
    for (const pack of PACKS) {
      const policy = { ...getPolicyPack(pack), trustedPackages: ['<unparseable-package-spec>'], unpinnedAction: 'allow' };
      assert.equal(evaluateAll([result], policy)[0].action, 'block', `${spec} in ${pack}`);
    }
  }
});

test('package URL ;params are treated like query values', () => {
  const tarball = inspectOne('npx', ['https://registry.example.invalid/x.tgz;sig=SECRETP']);
  assert.equal(tarball.source.package, 'https://registry.example.invalid/x.tgz');
  assert.ok(tarball.signals.includes('package-url-query'));
  const shorthand = inspectOne('npx', ['github:org/repo;sig=SECRETQ#v2']);
  assert.equal(shorthand.source.package, 'github:org/repo#v2');
  assert.ok(shorthand.signals.includes('package-url-query'));
  for (const result of [tarball, shorthand]) {
    assert.ok(!/SECRET/.test(JSON.stringify(result)));
    assert.ok(blockedEverywhere(result));
  }
});

test('simple registry specs pass through unchanged', () => {
  const cases = [
    ['name', false], ['@scope/name', false], ['name@1.2.3', true], ['@scope/name@1.2.3', true],
    ['name==1.2.3', true], ['name@latest', false], ['tool>=1.0', false]
  ];
  for (const [spec, pinned] of cases) {
    const result = inspectOne(spec.includes('=') ? 'uvx' : 'npx', [spec]);
    assert.equal(result.source.package, spec);
    assert.equal(result.source.pinned, pinned, spec);
    for (const signal of ['unparseable-package-spec', 'embedded-credentials', 'package-url-query']) {
      assert.ok(!result.signals.includes(signal), `${spec} ${signal}`);
    }
  }
  assert.equal(inspectOne('npx', ['file:../local-pkg']).source.package, 'file:../local-pkg');
  assert.equal(inspectOne('npx', ['link:../local-pkg']).source.package, 'link:../local-pkg');
});

test('an ssh username alone is not a credential, but an ssh password is', () => {
  for (const spec of ['git+ssh://git@git.example.invalid/x/y.git', 'ssh://git@git.example.invalid/x/y.git', 'git@git.example.invalid:x/y.git#v1', 'git+ssh://git@git.example.invalid:x/y.git#v1']) {
    const result = inspectOne('npx', [spec]);
    assert.ok(!result.signals.includes('embedded-credentials'), spec);
    assert.ok(!result.signals.includes('unparseable-package-spec'), spec);
    assert.ok(result.source.package.includes('git@'), `${spec}: the ssh account stays visible`);
    assert.equal(result.source.pinned, false, spec);
  }
  assert.equal(inspectOne('npx', ['git+ssh://git@git.example.invalid:x/y.git#v1']).source.package, 'git+ssh://git@git.example.invalid:x/y.git#v1');
  for (const spec of ['ssh://git:SECRETS@git.example.invalid/x/y.git', 'git+ssh://git:SECRETS@git.example.invalid:x/y.git', 'git+https://SECRETS@git.example.invalid/x/y.git']) {
    const result = inspectOne('npx', [spec]);
    assert.ok(result.signals.includes('embedded-credentials'), spec);
    assert.ok(!/SECRET/.test(JSON.stringify(result)), spec);
  }
});

test('credentials in any argument are flagged and kept out of the fingerprint', () => {
  const cases = [
    ['uvx', (secret) => [`--from=https://u:${secret}@files.example.invalid/tool.whl`, 'tool==1.0.0']],
    ['uvx', (secret) => [`--from=https://u:pa@${secret}@files.example.invalid/tool.whl`, 'tool==1.0.0']],
    ['uvx', (secret) => [`--from=https://u:pa ${secret}@files.example.invalid/tool.whl`, 'tool==1.0.0']],
    ['node', (secret) => ['server.js', `postgres://u:${secret}@db.example.invalid/app`]],
    ['node', (secret) => ['server.js', `--db=postgres://u:${secret}@db.example.invalid/app`]],
    ['node', (secret) => ['server.js', `deploy:${secret}@git.example.invalid:org/repo`]]
  ];
  for (const [command, args] of cases) {
    const first = inspectOne(command, args('SECRETONE'));
    const second = inspectOne(command, args('SECRETTWO'));
    assert.ok(first.signals.includes('embedded-credentials'), args('X').join(' '));
    assert.ok(blockedEverywhere(first), args('X').join(' '));
    assert.equal(first.fingerprint, second.fingerprint, args('X').join(' '));
    assert.ok(!/SECRET/.test(JSON.stringify(first)));
  }
  const image = inspectOne('docker', ['run', '-i', 'nginx:1.25@sha256:0123abcd']);
  assert.ok(!image.signals.includes('embedded-credentials'));
});

test('argument value changes still change the fingerprint', () => {
  const at = (args) => inspectOne('uvx', args).fingerprint;
  assert.notEqual(
    at(['--from=https://files.example.invalid/tool.whl?version=1.0', 'tool==1.0.0']),
    at(['--from=https://files.example.invalid/tool.whl?version=9.9', 'tool==1.0.0'])
  );
  assert.notEqual(
    at(['--from=https://files.example.invalid/tool.whl;v=1', 'tool==1.0.0']),
    at(['--from=https://files.example.invalid/tool.whl;v=2', 'tool==1.0.0'])
  );
  assert.notEqual(at(['--from=git+https://git.example.invalid/x#v1', 'tool']), at(['--from=git+https://git.example.invalid/x#v2', 'tool']));
});

test('recheck reports a changed package URL query after approval', () => {
  const cli = fileURLToPath(new URL('../bin/trustdex.mjs', import.meta.url));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'trustdex-query-'));
  const run = (...args) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  const config = path.join(dir, 'mcp.json');
  const write = (version) => fs.writeFileSync(config, JSON.stringify({ mcpServers: {
    tool: { command: 'uvx', args: [`--from=https://files.example.invalid/tool.whl?version=${version}`, 'tool==1.0.0'] }
  } }));
  const priv = path.join(dir, 'private.pem');
  const pub = path.join(dir, 'public.pem');
  const review = path.join(dir, 'review');
  assert.equal(run('keygen', '--private', priv, '--public', pub).status, 0);
  write('1.0');
  const approved = run('approve', config, '--private', priv, '--dir', review, '--pack', 'development');
  assert.equal(approved.status, 0, approved.stderr);
  assert.equal(run('recheck', config, '--review-dir', review, '--public', pub).status, 0);
  write('9.9');
  const recheck = run('recheck', config, '--review-dir', review, '--public', pub, '--json');
  assert.equal(recheck.status, 1, recheck.stdout);
  assert.equal(JSON.parse(recheck.stdout).status, 'needs-review');
});

test('npm aliases and local package paths are not reported as unparseable', () => {
  const results = inspectMcpConfig({ mcpServers: {
    alias: { command: 'npx', args: ['-y', 'npm:real-pkg@1.2.3'] },
    floating: { command: 'npx', args: ['npm:real-pkg'] },
    local: { command: 'npx', args: ['./packages/tool'] },
    tarball: { command: 'npx', args: ['../dist/tool-1.0.0.tgz'] }
  } });
  const by = Object.fromEntries(results.map((result) => [result.name, result]));
  assert.equal(by.alias.source.package, 'npm:real-pkg@1.2.3');
  assert.equal(by.alias.source.pinned, true);
  assert.equal(by.floating.source.pinned, false);
  assert.equal(by.local.source.package, './packages/tool');
  assert.equal(by.tarball.source.pinned, false);
  for (const result of results) assert.ok(!result.signals.includes('unparseable-package-spec'), result.name);
});

test('round 3: empty-host URLs, ssh account changes, and argument credential forms', () => {
  for (const spec of ['git+https:///deploy:SECRET9@git.example.invalid/org/tool.git#v1', 'ssh:///u:SECRET9@h/x', 'pkg@git+https:///d:SECRET9@h/x', 'github:///u:SECRET9@h/x']) {
    const result = inspectOne('npx', ['-y', spec]);
    assert.ok(!JSON.stringify(result).includes('SECRET9'), spec);
    assert.ok(result.signals.includes('unparseable-package-spec'), spec);
    assert.ok(blockedEverywhere(result), spec);
  }
  const account = (user) => inspectOne('npx', [`git+ssh://${user}@git.example.invalid/~/tool.git#v1`]).source;
  assert.notDeepEqual(account('alice'), account('mallory'));
  const scpAccount = (user) => inspectOne('npx', [`${user}@git.example.invalid:tool.git`]).source;
  assert.notDeepEqual(scpAccount('alice'), scpAccount('mallory'));
  for (const arg of ['wss://TOKEN9@h.invalid/x', 'postgres://u:pw9@h.invalid:99999/db', 'jdbc:postgresql://u:pw9@h.invalid/db', '-ehttps://u:pw9@h.invalid', 'u:pw9@h.invalid:r#@sha1:x']) {
    const result = inspectOne('node', ['s.js', arg]);
    assert.ok(result.signals.includes('embedded-credentials'), arg);
  }
  assert.ok(!inspectOne('node', ['s.js', 'ghcr.io/org/img:1.0@sha256:abc123']).signals.includes('embedded-credentials'));
  const withRef = (ref) => inspectOne('uvx', ['tool==1.0.0', '--with', `git+https://git.example.invalid/x#${ref}`]).fingerprint;
  assert.notEqual(withRef('v1'), withRef('attacker'));
});

test('round 4: passwords containing "?", "#", or spaces, and look-alike ssh schemes', () => {
  for (const arg of ['--dsn=postgresql://admin:pa?SECRET@db.example.invalid/x', 'postgresql://admin:pa#SECRET@db.example.invalid/x', 'postgresql://admin:pa ss@db.example.invalid/x', 'myssh://TOKEN@h.invalid/x']) {
    const result = inspectOne('npx', ['trusted@1.0.0', arg]);
    assert.ok(result.signals.includes('embedded-credentials'), arg);
    for (const pack of PACKS) {
      assert.equal(evaluateAll([result], { ...getPolicyPack(pack), trustedPackages: ['trusted'] })[0].action, 'block', `${arg} in ${pack}`);
    }
  }
  assert.ok(!inspectOne('node', ['s.js', 'https://api.example.invalid?email=a@b.invalid']).signals.includes('embedded-credentials'));
  assert.ok(!inspectOne('node', ['s.js', 'git+ssh://git@git.example.invalid/x/y.git']).signals.includes('embedded-credentials'));
});
