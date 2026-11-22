import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { inspectNpmPackage, provenanceObservationToClaim } from '../src/provenance-online.mjs';
import { parseTrustStore } from '../src/provenance.mjs';

// Canary sweep for the output redaction contract (docs/SECURITY_RESEARCH.md).
//
// Unique markers are planted in the value positions of inspected inputs: environment
// and header values, URL credentials and query values, credentials inside package
// specs (URLs, name@url, scp-like remotes, uvx --from and --from=, and malformed forms:
// several "@", whitespace, "https:/" with one slash, ;params), sensitive command-line flags,
// Claude permission specifiers, hooks, helpers and directories, Codex writable roots,
// skill bodies, plugin manifest values, IDE extension manifest and registry
// fields, and npm build provenance attestations. Each command below then runs, including the changed-state paths of diff and
// recheck. No marker may appear, in any letter case, in stdout, stderr, or a written
// file. Gated MCP and Codex outputs are excluded because they intentionally preserve
// the original allowed entries. Policy, trust-store, and keyset files are trust inputs written
// by the operator and are out of scope.

const cli = fileURLToPath(new URL('../bin/trustdex.mjs', import.meta.url));
const MARK = /canary\d+z/gi;
let counter = 0;
const canary = () => `CANARY${counter += 1}Z`;

function workspace() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'trustdex-canary-'));
  const write = (name, content) => {
    const file = path.join(dir, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, typeof content === 'string' ? content : JSON.stringify(content, null, 2));
    return file;
  };
  return { dir, write };
}

function run(args) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
}

function leaked(text) {
  return [...new Set(String(text).match(MARK) || [])];
}

function assertNoLeak(args, result) {
  const found = leaked(`${result.stdout}${result.stderr}`);
  assert.deepEqual(found, [], `${args.join(' ')} printed ${found.join(', ')}`);
}

function assertFilesClean(dir) {
  for (const entry of fs.readdirSync(dir, { recursive: true })) {
    let text;
    try {
      text = fs.readFileSync(path.join(dir, entry), 'utf8');
    } catch (error) {
      if (error.code === 'EISDIR') continue;
      throw error;
    }
    const found = leaked(text);
    assert.deepEqual(found, [], `${entry} contains ${found.join(', ')}`);
  }
}

function mcpServers() {
  return {
    pkg: { command: 'npx', args: ['-y', 'some-pkg@1.0.0'], env: { API_TOKEN: canary(), PLAIN: canary() } },
    remote: { url: `https://mcp.example.invalid/mcp?key=${canary()}#${canary()}`, headers: { Authorization: `Bearer ${canary()}` } },
    creds: { url: `https://user:${canary()}@mcp.example.invalid/mcp` },
    local: { command: 'node', args: ['server.js'], env: { DB_PASSWORD: canary() } },
    tarball: { command: 'npx', args: ['-y', `https://user:${canary()}@registry.example.invalid/pkg.tgz?sig=${canary()}`] },
    git: { command: 'uvx', args: [`git+https://${canary()}@git.example.invalid/x/y#v1`] },
    alias: { command: 'npx', args: [`pkg@https://u:${canary()}@registry.example.invalid/x.tgz`] },
    scp: { command: 'npx', args: [`deploy:${canary()}@git.example.invalid:org/repo`] },
    from: { command: 'uvx', args: ['--from', `pkg @ https://u:${canary()}@files.example.invalid/x.whl`, 'tool'] },
    tripleSlash: { command: 'npx', args: ['-y', `git+https:///deploy:${canary()}@git.example.invalid/x.git#v1`] },
    wssToken: { command: 'node', args: ['s.js', `wss://${canary()}@h.invalid/x`] },
    jdbc: { command: 'node', args: ['s.js', `jdbc:postgresql://u:${canary()}@h.invalid/db`] },
    packageFlag: { command: 'npx', args: [`--package=https://u:${canary()}@registry.example.invalid/p.tgz`, 'tool'] },
    multiAt: { command: 'npx', args: [`https://user:pa@${canary()}@registry.example.invalid/x.tgz`] },
    spaceUserinfo: { command: 'npx', args: [`https://user:pa ${canary()}@registry.example.invalid/x.tgz`] },
    spaceQuery: { command: 'npx', args: [`https://registry.example.invalid/x.tgz?sig=AAA ${canary()}`] },
    singleSlash: { command: 'npx', args: [`https:/u:${canary()}@registry.example.invalid/x.tgz?sig=${canary()}`] },
    params: { command: 'npx', args: [`https://registry.example.invalid/x.tgz;sig=${canary()}`] },
    fromEquals: { command: 'uvx', args: [`--from=https://u:${canary()}@files.example.invalid/tool.whl?sig=${canary()}`, 'tool==1.0.0'] },
    flags: { command: 'node', args: ['s.js', `--token=${canary()}`, '--api-key', canary(), '-H', `Authorization: ${canary()}`, `https://h.invalid/?k=${canary()}`] }
  };
}

function claudeServers() {
  return {
    http: { type: 'http', url: 'https://mcp.example.invalid/mcp', headers: { Authorization: `Bearer ${canary()}`, 'X-Key': '${API_KEY}' } },
    stdio: { type: 'stdio', command: 'node', args: ['s.js', `--secret=${canary()}`], env: { TOKEN: canary() } },
    pkg: { type: 'stdio', command: 'npx', args: ['-y', `https://u:${canary()}@registry.example.invalid/p.tgz`] },
    multiAt: { type: 'stdio', command: 'npx', args: [`pkg@https://u:pa@${canary()}@registry.example.invalid/x.tgz`] }
  };
}

function devinServers() {
  return {
    remote: { url: 'https://mcp.example.invalid/mcp', transport: 'http', headers: { Authorization: `Bearer ${canary()}`, 'X-Key': '${env:API_KEY}' }, disabledTools: [canary()] },
    local: { command: 'node', args: ['server.js', `--token=${canary()}`], env: { API_TOKEN: canary(), OTHER: '${env:OTHER}' }, disabled: true, disabledTools: [canary()] }
  };
}

function geminiServers() {
  return {
    remote: { httpUrl: 'https://mcp.example.invalid/mcp', headers: { Authorization: `Bearer ${canary()}` }, includeTools: [canary()], excludeTools: [canary()], trust: true },
    sse: { url: 'https://mcp.example.invalid/sse', headers: { 'X-Key': `$${canary()}` } },
    local: { command: 'node', args: ['server.js', `--token=${canary()}`], env: { API_TOKEN: canary(), OTHER: '$OTHER' }, cwd: `/work/${canary()}`, timeout: 30000 }
  };
}

function claudeSettings() {
  return {
    permissions: {
      allow: [`Bash(curl ${canary()})`, `WebFetch(domain:${canary()}.invalid)`, `Read(/${canary()}/**)`, 'mcp__http__read'],
      ask: [`Bash(${canary()})`],
      deny: [`Read(./${canary()})`],
      defaultMode: 'default',
      additionalDirectories: [`/${canary()}`]
    },
    hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: `echo ${canary()}` }] }] },
    apiKeyHelper: `print ${canary()}`,
    awsAuthRefresh: canary(),
    awsCredentialExport: canary(),
    gcpAuthRefresh: canary(),
    otelHeadersHelper: canary(),
    statusLine: { type: 'command', command: canary() },
    fileSuggestion: { type: 'command', command: canary() },
    policyHelper: { path: canary() },
    [canary()]: canary(),
    env: { SECRET_ENV: canary() }
  };
}

function codexToml() {
  return [
    '[mcp_servers.a]', 'command = "npx"', 'args = ["-y", "pkg@1.0.0"]', `env = { API_TOKEN = "${canary()}" }`, '',
    '[mcp_servers.c]', 'command = "npx"', `args = ["-y", "https://u:${canary()}@registry.example.invalid/p.tgz"]`, '',
    '[mcp_servers.b]', `url = "https://mcp.example.invalid/mcp?token=${canary()}"`, 'bearer_token_env_var = "MY_TOKEN"',
    `http_headers = { "X-Key" = "${canary()}" }`, ''
  ].join('\n');
}

function codexSettingsToml() {
  return [
    'approval_policy = "on-request"', 'sandbox_mode = "workspace-write"', '',
    '[sandbox_workspace_write]', 'network_access = true', `writable_roots = ["/${canary()}"]`,
    `[permissions."${canary()}"]`, 'extends = ":danger-full-access"', `description = "${canary()}"`, ''
  ].join('\n');
}

function writeExtensions(write, base, version) {
  write(`${base}/acme.tool-${version}/package.json`, {
    publisher: 'acme', name: 'tool', version, displayName: canary(), description: canary(),
    contributes: { configuration: { default: canary() } }
  });
  write(`${base}/acme.tool-${version}/extension.js`, `// ${canary()}\n`);
  write(`${base}/extensions.json`, [{
    identifier: { id: 'acme.tool' }, version, relativeLocation: `acme.tool-${version}`,
    metadata: { source: 'gallery', targetPlatform: canary(), publisherDisplayName: canary() }
  }]);
  return path.join(path.dirname(write(`${base}/.keep`, '')), '');
}

test('no command prints or stores a planted value', () => {
  const { dir, write } = workspace();
  const out = path.join(dir, 'out');
  const files = {
    mcp: write('in/mcp.json', { mcpServers: mcpServers() }),
    mcpChanged: write('in/mcp-changed.json', { mcpServers: { ...mcpServers(), extra: { command: 'npx', args: [`https://u:${canary()}@registry.example.invalid/new.tgz`] } } }),
    claude: write('in/claude.mcp.json', { mcpServers: claudeServers() }),
    devin: write('in/devin.mcp_config.json', { mcpServers: devinServers() }),
    gemini: write('in/gemini.mcpServers.json', { mcpServers: geminiServers() }),
    devinSettings: write('in/devin.config.json', {
      [canary()]: canary(),
      permission_mode: 'smart',
      read_config_from: { [canary()]: true, claude: false },
      agent: { model: canary() },
      sandbox: { allowed_domains: [canary()], excluded: { allow: [`Exec(${canary()})`], [canary()]: [canary()] } },
      permissions: {
        allow: [`Exec(${canary()})`, `Read(${canary()})`, `Fetch(${canary()})`, `mcp__${canary()}__${canary()}`],
        ask: [`Write(${canary()})`], deny: [`Exec(${canary()})`], [canary()]: [canary()]
      },
      hooks: { [canary()]: [{ matcher: canary(), hooks: [{ type: 'command', command: canary() }] }] },
      mcpServers: { [canary()]: { command: canary(), env: { T: canary() } } }
    }),
    geminiSettings: write('in/gemini.settings.json', {
      [canary()]: canary(),
      general: { defaultApprovalMode: 'auto_edit', [canary()]: canary() },
      tools: {
        allowed: [`run_shell_command(${canary()})`, canary()], core: [`$${canary()}`], exclude: [canary()],
        sandbox: 'docker', sandboxAllowedPaths: [canary()], discoveryCommand: canary(), callCommand: canary()
      },
      mcp: { serverCommand: canary(), allowed: [canary()], excluded: [canary()] },
      security: { allowedExtensions: [canary()], environmentVariableRedaction: { allowed: [canary()], blocked: [canary()] } },
      hooksConfig: { disabled: [canary()] },
      hooks: { [canary()]: [{ command: canary() }] },
      policyPaths: [canary()],
      mcpServers: { [canary()]: { command: canary(), env: { T: canary() } } }
    }),
    claudeHelper: write('in/claude-helper.mcp.json', { mcpServers: { h: { type: 'http', url: 'https://mcp.example.invalid/x', headersHelper: `print-token ${canary()}` } } }),
    settings: write('in/settings.json', claudeSettings()),
    settingsLocal: write('in/settings.local.json', claudeSettings()),
    settingsManaged: write('in/managed.json', claudeSettings()),
    codex: write('in/config.toml', codexToml()),
    codexSettings: write('in/codex-settings.toml', codexSettingsToml()),
    codexSettingsProject: write('in/codex-project.toml', codexSettingsToml()),
    skill: write('in/SKILL.md', `---\nname: canary-skill\ndescription: test\n---\nUse token ${canary()} and fetch https://x.invalid/?k=${canary()}\n`),
    plugin: write('in/plugin.json', { name: 'p', version: '1.0.0', env: { K: canary() }, permissions: [canary()], homepage: `https://x.invalid/?t=${canary()}` }),
    ext: writeExtensions(write, 'in/ext', '1.0.0')
  };
  // BLOCK-free inputs so approve can write full review bundles.
  const approvable = (servers) => write(`in/approvable-${counter}.json`, { mcpServers: servers });
  files.approvable = approvable({
    gitRef: { command: 'uvx', args: [`--with=https://files.example.invalid/x.whl?sig=${canary()}`, '--with', 'git+https://git.example.invalid/x#v1', 'tool==1.0.0'] },
    remote: { url: `https://mcp.example.invalid/mcp?key=${canary()}`, headers: { Authorization: `Bearer ${canary()}` } },
    local: { command: 'node', args: ['server.js', `--password=${canary()}`], env: { DB_PASSWORD: canary() } }
  });
  files.claudeApprovable = write('in/claude-approvable.mcp.json', { mcpServers: {
    http: { type: 'http', url: 'https://mcp.example.invalid/mcp', headers: { Authorization: `Bearer ${canary()}` } },
    stdio: { type: 'stdio', command: 'node', args: ['s.js'], env: { TOKEN: canary() } }
  } });

  const priv = path.join(dir, 'keys/private.pem');
  const pub = path.join(dir, 'keys/public.pem');
  run(['keygen', '--private', priv, '--public', pub]);
  const keyset = write('keys/keyset.json', {
    schemaVersion: 1,
    kind: 'trustdex-keyset',
    keys: [{ id: run(['key-id', pub]).stdout.trim(), publicKey: fs.readFileSync(pub, 'utf8'), purposes: ['review'] }]
  });

  const claudeStack = ['--user', files.settings, '--project', files.settings, '--local', files.settingsLocal, '--managed', files.settingsManaged];
  const codexStack = ['--user', files.codexSettings, '--project', files.codexSettingsProject, '--legacy-managed', files.codexSettings];
  const inspections = [
    ['inspect', files.mcp], ['inspect-claude', files.claude], ['inspect-claude', files.claudeHelper], ['inspect-devin', files.devin], ['inspect-gemini', files.gemini], ['inspect-gemini-settings', files.geminiSettings], ['inspect-devin-settings', files.devinSettings],
    ['inspect-claude-settings', files.settings], ['inspect-codex', files.codex], ['inspect-codex-settings', files.codexSettings],
    ['inspect-skill', files.skill], ['inspect-plugin', files.plugin], ['inspect-ide-extensions', files.ext],
    ['inspect-claude-settings-stack', ...claudeStack], ['inspect-codex-settings-stack', ...codexStack]
  ];
  const o = (name) => path.join(out, name);
  const steps = [
    ...inspections.flatMap((args) => [args, [...args, '--json'], [...args, '--decisions']]),
    ['snapshot', files.mcp, '--out', o('snapshot-before.json')],
    ['snapshot', files.mcpChanged, '--out', o('snapshot-after.json')],
    ['diff', o('snapshot-before.json'), o('snapshot-after.json')],
    ['diff', o('snapshot-before.json'), o('snapshot-after.json'), '--json'],
    ['snapshot-claude', files.claude, '--out', o('snapshot-claude.json')],
    ['snapshot-devin', files.devin, '--out', o('snapshot-devin.json')],
    ['snapshot-gemini', files.gemini, '--out', o('snapshot-gemini.json')],
    ['snapshot-ide-extensions', files.ext, '--out', o('snapshot-ide.json')],
    ['snapshot-claude-settings', files.settings, '--out', o('posture-claude.json')],
    ['snapshot-codex-settings', files.codexSettings, '--out', o('posture-codex.json')],
    ['snapshot-claude-settings-stack', ...claudeStack, '--out', o('posture-claude-stack.json')],
    ['snapshot-codex-settings-stack', ...codexStack, '--out', o('posture-codex-stack.json')],
    ['diff-permissions', o('posture-claude.json'), o('posture-claude-stack.json')],
    ['diff-permissions', o('posture-codex.json'), o('posture-codex-stack.json'), '--json'],
    ['snapshot-claude-bindings', files.claude, '--settings', files.settings, '--out', o('bindings-claude.json')],
    ['snapshot-claude-bindings', files.claude, ...claudeStack, '--out', o('bindings-claude-stack.json')],
    ['snapshot-codex-bindings', files.codex, '--out', o('bindings-codex.json')],
    ['diff-bindings', o('bindings-claude.json'), o('bindings-claude-stack.json')],
    ['diff-bindings', o('bindings-claude.json'), o('bindings-claude-stack.json'), '--json'],
    ['gate', files.mcp, '--out', path.join(dir, 'gated/mcp.json'), '--pack', 'development'],
    ['gate', files.mcp, '--out', path.join(dir, 'gated/mcp2.json'), '--pack', 'development', '--json'],
    ['gate-claude', files.claude, '--out', path.join(dir, 'gated/claude.json'), '--pack', 'development'],
    ['gate-devin', files.devin, '--out', path.join(dir, 'gated/devin.json'), '--pack', 'development'],
    ['gate-gemini', files.gemini, '--out', path.join(dir, 'gated/gemini.json'), '--pack', 'development'],
    ['approve-gemini', files.gemini, '--private', priv, '--dir', o('review-gemini'), '--pack', 'development'],
    ['recheck-gemini', files.gemini, '--review-dir', o('review-gemini'), '--public', pub, '--json'],
    ['approve-devin', files.devin, '--private', priv, '--dir', o('review-devin'), '--pack', 'development'],
    ['recheck-devin', files.devin, '--review-dir', o('review-devin'), '--public', pub, '--json'],
    ['gate-codex', files.codex, '--out', path.join(dir, 'gated/config.toml'), '--pack', 'development'],
    ['approve', files.approvable, '--private', priv, '--dir', o('review'), '--pack', 'development'],
    ['recheck', files.approvable, '--review-dir', o('review'), '--public', pub],
    ['recheck', files.approvable, '--review-dir', o('review'), '--keyset', keyset, '--json'],
    ['approve-claude', files.claudeApprovable, '--private', priv, '--dir', o('review-claude'), '--pack', 'development'],
    ['recheck-claude', files.claudeApprovable, '--review-dir', o('review-claude'), '--public', pub, '--json'],
    ['approve-ide-extensions', files.ext, '--private', priv, '--dir', o('review-ide'), '--pack', 'development'],
    ['sign', o('snapshot-before.json'), '--private', priv, '--out', o('record.json')],
    ['verify', o('record.json'), '--public', pub, '--snapshot', o('snapshot-before.json')],
    ['verify', o('record.json'), '--keyset', keyset, '--snapshot', o('snapshot-before.json')],
    ['key-id', pub]
  ];
  for (const args of steps) assertNoLeak(args, run(args));

  // Claude init event: tool names, paths, and other fields must not reach the inventory.
  const initStream = write('in/claude-stream.jsonl', JSON.stringify({
    type: 'system', subtype: 'init', cwd: `/work/${canary()}`, model: canary(), session_id: canary(), apiKeySource: canary(),
    tools: ['Read', `mcp__reviewed__${canary()}`, `Bash(${canary()})`],
    mcp_servers: [{ name: 'reviewed', status: 'connected', source: canary() }],
    plugins: [{ name: canary(), path: `/plugins/${canary()}` }]
  }));
  const initArgs = ['inventory-claude-init', initStream, '--out', o('claude-inventory.json')];
  const initResult = run(initArgs);
  assert.equal(initResult.status, 0, initResult.stderr);
  assertNoLeak(initArgs, initResult);
  const badInit = write('in/claude-stream-bad.jsonl', JSON.stringify({
    type: 'system', subtype: 'init', tools: [`mcp__${canary()}__${canary()}`], mcp_servers: [{ name: 'reviewed', status: canary() }]
  }));
  const badInitArgs = ['inventory-claude-init', badInit, '--out', o('claude-inventory-bad.json')];
  assertNoLeak(badInitArgs, run(badInitArgs));

  // Codex mcpServerStatus/list capture: tool names, origins, and other fields must not reach the inventory.
  const codexServer = (extra = {}) => ({
    name: 'reviewed', runtimeStatus: 'connected', pluginId: canary(), httpOrigin: `https://${canary()}.example.invalid`,
    serverInfo: { name: canary(), version: canary() }, serverCapabilities: { [canary()]: {} }, toolListMeta: { token: canary() },
    tools: { [canary()]: { name: canary(), description: canary(), inputSchema: { default: canary() } } }, toolsError: null,
    resources: [{ uri: `file:///${canary()}` }], resourceTemplates: [], authStatus: 'bearerToken', environmentId: canary(), ...extra
  });
  const codexExchange = (id, params, result) => JSON.stringify([{ method: 'mcpServerStatus/list', id, params }, { id, result }]);
  const codexThread = canary();
  const codexStatus = write('in/codex-status.json', codexExchange(canary(), { threadId: codexThread }, { data: [codexServer()], nextCursor: null }));
  const codexStatusArgs = ['inventory-codex-mcp-status', codexStatus, '--out', o('codex-inventory.json')];
  const codexStatusResult = run(codexStatusArgs);
  assert.equal(codexStatusResult.status, 0, codexStatusResult.stderr);
  assertNoLeak(codexStatusArgs, codexStatusResult);
  for (const [name, bad] of Object.entries({
    status: codexExchange(1, { threadId: canary() }, { data: [codexServer({ runtimeStatus: canary() })] }),
    error: codexExchange(1, { threadId: canary() }, { data: [codexServer({ toolsError: canary() })] }),
    cursor: codexExchange(1, { threadId: canary(), cursor: canary() }, { data: [codexServer()], nextCursor: canary() }),
    filter: codexExchange(1, { threadId: canary(), serverName: canary() }, { data: [codexServer()] }),
    shape: JSON.stringify({ [canary()]: canary() })
  })) {
    const badArgs = ['inventory-codex-mcp-status', write(`in/codex-status-${name}.json`, bad), '--out', o(`codex-inventory-${name}.json`)];
    const badResult = run(badArgs);
    assert.notEqual(badResult.status, 0);
    assertNoLeak(badArgs, badResult);
  }

  // Changed-state paths: recheck after the reviewed input changes prints source drift.
  const changedApprovable = { mcpServers: {
    remote: { url: `https://mcp.example.invalid/other?key=${canary()}`, headers: { Authorization: `Bearer ${canary()}` } },
    local: { command: 'node', args: ['server2.js', `--password=${canary()}`], env: { DB_PASSWORD: canary(), NEW_TOKEN: canary() } },
    fromEquals: { command: 'uvx', args: [`--from=https://u:${canary()}@files.example.invalid/tool.whl`, 'tool==1.0.0'] },
    singleSlash: { command: 'npx', args: [`https:/u:${canary()}@registry.example.invalid/x.tgz`] },
    spaceUserinfo: { command: 'npx', args: [`https://user:pa ${canary()}@registry.example.invalid/x.tgz`] }
  } };
  fs.writeFileSync(files.approvable, JSON.stringify(changedApprovable));
  fs.writeFileSync(files.claudeApprovable, JSON.stringify({ mcpServers: {
    http: { type: 'http', url: 'https://mcp.example.invalid/other', headers: { Authorization: `Bearer ${canary()}` } },
    stdio: { type: 'stdio', command: 'node', args: ['s2.js', `--secret=${canary()}`], env: { TOKEN: canary(), NEW_TOKEN: canary() } },
    pkg: { type: 'stdio', command: 'npx', args: [`https://user:pa@${canary()}@registry.example.invalid/x.tgz?sig=${canary()}`] }
  } }));
  writeExtensions(write, 'in/ext', '1.0.0');
  for (const args of [
    ['recheck', files.approvable, '--review-dir', o('review'), '--public', pub],
    ['recheck', files.approvable, '--review-dir', o('review'), '--public', pub, '--json'],
    ['recheck', files.approvable, '--review-dir', o('review'), '--keyset', keyset],
    ['recheck-claude', files.claudeApprovable, '--review-dir', o('review-claude'), '--public', pub],
    ['recheck-claude', files.claudeApprovable, '--review-dir', o('review-claude'), '--public', pub, '--json'],
    ['recheck-ide-extensions', files.ext, '--review-dir', o('review-ide'), '--public', pub],
    ['recheck-ide-extensions', files.ext, '--review-dir', o('review-ide'), '--public', pub, '--json']
  ]) {
    const result = run(args);
    assert.equal(result.status, 1, `${args.join(' ')} should report NEEDS_REVIEW: ${result.stderr}`);
    assertNoLeak(args, result);
  }

  for (const file of ['snapshot-before.json', 'posture-claude-stack.json', 'bindings-claude.json', 'review/snapshot.json', 'review-claude/trust-record.json', 'review-ide/trust-record.json', 'record.json']) {
    assert.ok(fs.existsSync(o(file)), `${file} was not written`);
  }
  assertFilesClean(out);
});

test('no malformed input echoes a planted value in errors or reports', () => {
  const { write } = workspace();
  const cases = [
    ['inspect', 'json', () => ({ mcpServers: { a: { command: 'node', env: { T: 123, U: canary() } } } })],
    ['inspect', 'json', () => ({ mcpServers: { a: { url: `ftp://x.invalid/${canary()}` } } })],
    ['inspect', 'json', () => ({ mcpServers: { a: { url: `not a url ${canary()}` } } })],
    ['inspect', 'json', () => ({ mcpServers: { a: { command: 'node', env: [canary()] } } })],
    ['inspect', 'raw', () => `{"mcpServers": {"a": {"env": {"T": ${canary()}}}}}`],
    ['inspect-claude', 'json', () => ({ mcpServers: { a: { type: 'http', url: `https://x.invalid/?k=${canary()}` } } })],
    ['inspect-claude', 'json', () => ({ mcpServers: { a: { type: 'stdio', command: 'node', env: { T: canary() }, extra: canary() } } })],
    ['inspect-claude', 'json', () => ({ mcpServers: { a: { type: 'ws', url: `wss://x.invalid/${canary()}` } } })],
    ['inspect-claude', 'json', () => ({ mcpServers: { a: { type: 'http', url: 'https://x.invalid/', headers: { A: 5, B: canary() } } } })],
    ['inspect-gemini', 'json', () => ({ mcpServers: { a: { httpUrl: `https://x.invalid/?k=${canary()}` } } })],
    ['inspect-gemini', 'json', () => ({ mcpServers: { a: { command: 'node', env: { T: canary() }, extra: canary() } } })],
    ['inspect-gemini', 'json', () => ({ mcpServers: { a: { httpUrl: 'https://x.invalid/', oauth: { clientSecret: canary() } } } })],
    ['inspect-gemini', 'json', () => ({ mcpServers: { a: { url: 'https://x.invalid/', headers: { A: 5, B: canary() } } } })],
    ['inspect-gemini', 'json', () => ({ mcpServers: { a: { httpUrl: 'https://x.invalid/', headers: { A: `\${HEADER:-${canary()}}` } } } })],
    ['inspect-gemini', 'json', () => ({ mcpServers: { a: { command: 'node', cwd: [canary()] } } })],
    ['inspect-gemini', 'json', () => ({ mcpServers: { a: { command: 'node', trust: canary() } } })],
    ['inspect-gemini', 'json', () => ({ mcpServers: { a: { command: 'node', includeTools: [canary(), 5] } } })],
    ['inspect-gemini', 'json', () => ({ mcpServers: {}, security: { [canary()]: canary() } })],
    ['inspect-gemini', 'raw', () => `{"mcpServers": {"a": {"env": {"T": ${canary()}}}}}`],
    ['inspect-devin', 'json', () => ({ mcpServers: { a: { url: `https://x.invalid/?k=${canary()}` } } })],
    ['inspect-devin', 'json', () => ({ mcpServers: { a: { command: 'node', env: { T: canary() }, extra: canary() } } })],
    ['inspect-devin', 'json', () => ({ mcpServers: { a: { url: 'https://x.invalid/', oauthClientSecret: canary() } } })],
    ['inspect-devin', 'json', () => ({ mcpServers: { a: { url: 'https://x.invalid/', headers: { A: `\${file:/${canary()}}` } } } })],
    ['inspect-devin', 'json', () => ({ mcpServers: { a: { url: 'https://x.invalid/', headers: { A: 5, B: canary() } } } })],
    ['inspect-devin', 'json', () => ({ mcpServers: { a: { url: 'https://x.invalid/', transport: canary() } } })],
    ['inspect-devin', 'json', () => ({ mcpServers: { a: { command: 'node', disabledTools: [canary(), 5] } } })],
    ['inspect-devin', 'raw', () => `{"mcpServers": {"a": {"env": {"T": ${canary()}}}}}`],
    ['inspect-claude-settings', 'json', () => ({ permissions: { allow: [`Bash(${canary()}`] } })],
    ['inspect-claude-settings', 'json', () => ({ permissions: { allow: [canary(), 5] } })],
    ['inspect-claude-settings', 'json', () => ({ permissions: { defaultMode: canary() } })],
    ['inspect-claude-settings', 'json', () => ({ permissions: { additionalDirectories: canary() } })],
    ['inspect-claude-settings', 'json', () => ({ permissions: { [canary()]: canary() } })],
    ['inspect-claude-settings', 'json', () => ({ allowManagedPermissionRulesOnly: canary() })],
    ['inspect-codex', 'toml', () => `[mcp_servers.a]\ncommand = "node"\nenv = { T = "${canary()}" \n`],
    ['inspect-codex', 'toml', () => `[mcp_servers.a]\ncommand = "node"\nargs = ["${canary()}"\n`],
    ['inspect-codex', 'toml', () => `[mcp_servers.a.env]\nT = "${canary()}"\nU = ${canary()}\n`],
    ['inspect-codex', 'toml', () => `[mcp_servers.a]\ncommand = "node"\nenv = { T "${canary()}" }\n`],
    ['inspect-codex', 'toml', () => `[mcp_servers.a]\ncommand = "node"\n"${canary()}"\n`],
    ['inspect-devin-settings', 'json', () => ({ permission_mode: canary() })],
    ['inspect-devin-settings', 'json', () => ({ permissions: { allow: [canary(), `Shell(${canary()})`] } })],
    ['inspect-devin-settings', 'json', () => ({ [canary()]: canary(), hooks: { [canary()]: canary() } })],
    ['inspect-devin-settings', 'raw', () => `{"permissions": {"allow": [${canary()}]}}`],
    ['inspect-devin-settings', 'json', () => ({ sandbox: { excluded: { allow: [canary(), `Read(${canary()})`] } } })],
    ['inspect-devin-settings', 'json', () => ({ read_config_from: { claude: canary() } })],
    ['inspect-gemini-settings', 'json', () => ({ general: { defaultApprovalMode: canary() } })],
    ['inspect-gemini-settings', 'json', () => ({ tools: { allowed: [canary(), 5] } })],
    ['inspect-gemini-settings', 'json', () => ({ [canary()]: [canary()], tools: { discoveryCommand: [canary()] } })],
    ['inspect-gemini-settings', 'json', () => ({ hooks: { [canary()]: canary() } })],
    ['inspect-gemini-settings', 'json', () => ({ tools: { sandbox: canary() } })],
    ['inspect-gemini-settings', 'json', () => ({ tools: { sandbox: `${'$'}{${canary()}:-${canary()}}` } })],
    ['inspect-gemini-settings', 'json', () => ({ tools: { sandbox: `${canary()}$${canary()}` } })],
    ['inspect-gemini-settings', 'json', () => ({
      admin: { mcp: { requiredConfig: { [canary()]: { trust: canary() } } } }
    })],
    ['inspect-gemini-settings', 'raw', () => `{"tools": {"allowed": [${canary()}]}}`],
    ['inspect-codex-settings', 'toml', () => `approval_policy = "${canary()}"\n`],
    ['inspect-codex-settings', 'toml', () => `approval_policy = ${canary()}\n`],
    ['inspect-codex-settings', 'toml', () => `sandbox_mode = "workspace-write"\n[sandbox_workspace_write]\nwritable_roots = "${canary()}"\n`],
    ['inspect-plugin', 'json', () => [canary()]],
    ['inspect-plugin', 'raw', () => `{"name": "p", "token": ${canary()}}`]
  ];
  for (const [command, kind, make] of cases) {
    const content = make();
    const file = write(`case-${counter}.${kind === 'toml' ? 'toml' : 'json'}`, kind === 'json' ? JSON.stringify(content) : content);
    for (const flags of [[], ['--json'], ['--decisions']]) {
      const args = [command, file, ...flags];
      assertNoLeak(args, run(args));
    }
  }
});

test('blocking a known malicious release does not disclose a custom index URL', () => {
  const args = ['check-install', `pip install --index-url https://user:${canary()}@mirror.example.invalid/simple agent-framework==1.26.2`, '--json'];
  const result = run(args);
  assert.equal(result.status, 2);
  assert.equal(JSON.parse(result.stdout).decision, 'block');
  assert.match(result.stdout, /known-malicious-release/);
  assertNoLeak(args, result);
});

test('npm build provenance evidence does not carry planted attestation values', async () => {
  const digest = crypto.createHash('sha512').update('bytes').digest();
  const integrity = `sha512-${digest.toString('base64')}`;
  const hex = digest.toString('hex');
  const attestation = (repository, workflowPath) => ({ attestations: [{
    predicateType: 'https://slsa.dev/provenance/v1',
    bundle: { dsseEnvelope: { payloadType: 'application/vnd.in-toto+json', payload: Buffer.from(JSON.stringify({
      subject: [{ name: 'pkg:npm/agent@2.0.0', digest: { sha512: hex } }],
      predicate: { buildDefinition: { externalParameters: { workflow: { repository, path: workflowPath } } } }
    })).toString('base64') } }
  }] });
  const packument = (previousRepository) => ({
    name: 'agent',
    'dist-tags': { latest: '2.0.0' },
    time: { '1.0.0': '2026-01-01T00:00:00Z', '2.0.0': '2026-11-01T00:00:00Z' },
    versions: {
      '1.0.0': { repository: { url: previousRepository }, dist: { integrity } },
      '2.0.0': { repository: { url: 'git+https://github.com/example/agent.git' },
        dist: { integrity, attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } } }
    }
  });
  const inspect = (doc, statement) => inspectNpmPackage('agent', {
    verifyBundle: () => ({ verified: true, reason: canary() }),
    fetchImpl: async (url) => ({ ok: true, status: 200, json: async () => (url.includes('/attestations/') ? statement : doc) })
  });

  const matched = await inspect(packument('git+https://github.com/example/agent.git'),
    attestation('https://github.com/example/agent', `.github/workflows/publish.yml?token=${canary()}`));
  assert.equal(matched.evidence.buildProvenance.status, 'matched');
  const claim = provenanceObservationToClaim(matched, 'Example');
  const stored = parseTrustStore({ version: 1, claims: [claim] });

  const mismatch = await inspect(packument(`https://user:${canary()}@github.com/example/agent`),
    attestation(`https://user:${canary()}@github.com/attacker/agent`, `.github/workflows/${canary()}/x.yml`));
  assert.notEqual(mismatch.evidence.buildProvenance.status, 'matched');

  const found = leaked(JSON.stringify([matched, claim, stored, mismatch]));
  assert.deepEqual(found, [], `build provenance retained ${found.join(', ')}`);
});
