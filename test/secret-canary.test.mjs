import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Canary sweep for the output redaction contract (docs/SECURITY_RESEARCH.md).
//
// Unique markers are planted in the value positions of inspected inputs: environment
// and header values, URL credentials and query values, credentials inside package
// specs (URLs, name@url, scp-like remotes, uvx --from and --from=, and malformed forms:
// several "@", whitespace, "https:/" with one slash, ;params), sensitive command-line flags,
// Claude permission specifiers, hooks, helpers and directories, Codex writable roots,
// skill bodies, plugin manifest values, and IDE extension manifest and registry
// fields. Each command below then runs, including the changed-state paths of diff and
// recheck. No marker may appear, in any letter case, in stdout, stderr, or a written
// file. Gated MCP and Codex outputs are excluded because they intentionally preserve
// the original allowed entries. Policy and trust-store files are trust inputs written
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
    '[sandbox_workspace_write]', 'network_access = true', `writable_roots = ["/${canary()}"]`, ''
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
    gitRef: { command: 'uvx', args: [`--from=https://files.example.invalid/x.whl?sig=${canary()}`, 'tool==1.0.0', '--with', `git+https://git.example.invalid/x#v1`] },
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

  const claudeStack = ['--user', files.settings, '--project', files.settings, '--local', files.settingsLocal, '--managed', files.settingsManaged];
  const codexStack = ['--user', files.codexSettings, '--project', files.codexSettingsProject];
  const inspections = [
    ['inspect', files.mcp], ['inspect-claude', files.claude], ['inspect-claude', files.claudeHelper],
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
    ['gate-codex', files.codex, '--out', path.join(dir, 'gated/config.toml'), '--pack', 'development'],
    ['approve', files.approvable, '--private', priv, '--dir', o('review'), '--pack', 'development'],
    ['recheck', files.approvable, '--review-dir', o('review'), '--public', pub],
    ['approve-claude', files.claudeApprovable, '--private', priv, '--dir', o('review-claude'), '--pack', 'development'],
    ['recheck-claude', files.claudeApprovable, '--review-dir', o('review-claude'), '--public', pub, '--json'],
    ['approve-ide-extensions', files.ext, '--private', priv, '--dir', o('review-ide'), '--pack', 'development'],
    ['sign', o('snapshot-before.json'), '--private', priv, '--out', o('record.json')],
    ['verify', o('record.json'), '--public', pub, '--snapshot', o('snapshot-before.json')]
  ];
  for (const args of steps) assertNoLeak(args, run(args));

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
    ['inspect-claude-settings', 'json', () => ({ permissions: { allow: [`Bash(${canary()}`] } })],
    ['inspect-claude-settings', 'json', () => ({ permissions: { allow: [canary(), 5] } })],
    ['inspect-claude-settings', 'json', () => ({ permissions: { defaultMode: canary() } })],
    ['inspect-claude-settings', 'json', () => ({ permissions: { additionalDirectories: canary() } })],
    ['inspect-codex', 'toml', () => `[mcp_servers.a]\ncommand = "node"\nenv = { T = "${canary()}" \n`],
    ['inspect-codex', 'toml', () => `[mcp_servers.a]\ncommand = "node"\nargs = ["${canary()}"\n`],
    ['inspect-codex', 'toml', () => `[mcp_servers.a.env]\nT = "${canary()}"\nU = ${canary()}\n`],
    ['inspect-codex', 'toml', () => `[mcp_servers.a]\ncommand = "node"\nenv = { T "${canary()}" }\n`],
    ['inspect-codex', 'toml', () => `[mcp_servers.a]\ncommand = "node"\n"${canary()}"\n`],
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
