import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Canary sweep: plant a unique marker in every value position each input format
// accepts, run every command that reads that format, and require that no marker
// appears in stdout, stderr, or any snapshot, posture, binding, or review file.
// Names (environment variable names, setting keys, server names) may be reported;
// values may not. Values include credentials in package URLs and in sensitive
// command-line flags. Gated MCP/Codex outputs are excluded because they intentionally
// preserve the original allowed entries.

const cli = fileURLToPath(new URL('../bin/trustdex.mjs', import.meta.url));
const MARK = /CANARY\d+Z/g;
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
    const file = path.join(dir, entry);
    if (fs.statSync(file).isDirectory()) continue;
    const found = leaked(fs.readFileSync(file, 'utf8'));
    assert.deepEqual(found, [], `${entry} contains ${found.join(', ')}`);
  }
}

function inputs() {
  const { dir, write } = workspace();
  const files = {
    mcp: write('in/mcp.json', { mcpServers: {
      pkg: { command: 'npx', args: ['-y', 'some-pkg@1.0.0'], env: { API_TOKEN: canary(), PLAIN: canary() } },
      remote: { url: `https://mcp.example.invalid/mcp?key=${canary()}#${canary()}`, headers: { Authorization: `Bearer ${canary()}` } },
      creds: { url: `https://user:${canary()}@mcp.example.invalid/mcp` },
      local: { command: 'node', args: ['server.js'], env: { DB_PASSWORD: canary() } },
      tarball: { command: 'npx', args: ['-y', `https://user:${canary()}@registry.example.invalid/pkg.tgz?sig=${canary()}`] },
      git: { command: 'uvx', args: [`git+https://${canary()}@git.example.invalid/x/y#${canary()}`] },
      flags: { command: 'node', args: ['s.js', `--token=${canary()}`, '--api-key', canary(), '-H', `Authorization: ${canary()}`, `https://h.invalid/?k=${canary()}`] }
    } }),
    claude: write('in/claude.mcp.json', { mcpServers: {
      http: { type: 'http', url: 'https://mcp.example.invalid/mcp', headers: { Authorization: `Bearer ${canary()}`, 'X-Key': '${API_KEY}' } },
      stdio: { type: 'stdio', command: 'node', args: ['s.js'], env: { TOKEN: canary() } },
      pkg: { type: 'stdio', command: 'npx', args: ['-y', `https://u:${canary()}@registry.example.invalid/p.tgz`] },
      helper: { type: 'http', url: 'https://mcp.example.invalid/x', headersHelper: `print-token ${canary()}` }
    } }),
    settings: write('in/settings.json', {
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
    }),
    codex: write('in/config.toml', [
      '[mcp_servers.a]', 'command = "npx"', 'args = ["-y", "pkg@1.0.0"]', `env = { API_TOKEN = "${canary()}" }`, '',
      '[mcp_servers.c]', 'command = "npx"', `args = ["-y", "https://u:${canary()}@registry.example.invalid/p.tgz"]`, '',
      '[mcp_servers.b]', `url = "https://mcp.example.invalid/mcp?token=${canary()}"`, 'bearer_token_env_var = "MY_TOKEN"',
      `http_headers = { "X-Key" = "${canary()}" }`, ''
    ].join('\n')),
    codexSettings: write('in/codex-settings.toml', [
      'approval_policy = "on-request"', 'sandbox_mode = "workspace-write"', '',
      '[sandbox_workspace_write]', 'network_access = true', `writable_roots = ["/${canary()}"]`, ''
    ].join('\n')),
    skill: write('in/SKILL.md', `---\nname: canary-skill\ndescription: test\n---\nUse token ${canary()} and fetch https://x.invalid/?k=${canary()}\n`),
    plugin: write('in/plugin.json', { name: 'p', version: '1.0.0', env: { K: canary() }, permissions: [canary()], homepage: `https://x.invalid/?t=${canary()}` }),
    ext: path.join(dir, 'in/ext')
  };
  write('in/ext/acme.tool-1.0.0/package.json', { publisher: 'acme', name: 'tool', version: '1.0.0', description: canary(), contributes: { configuration: { default: canary() } } });
  write('in/ext/acme.tool-1.0.0/extension.js', `// ${canary()}\n`);
  write('in/ext/extensions.json', [{ identifier: { id: 'acme.tool' }, version: '1.0.0', relativeLocation: 'acme.tool-1.0.0', metadata: { source: 'gallery' } }]);
  // A BLOCK-free MCP config so approve/recheck write a full review bundle.
  files.approvable = write('in/approvable.json', { mcpServers: {
    remote: { url: `https://mcp.example.invalid/mcp?key=${canary()}`, headers: { Authorization: `Bearer ${canary()}` } },
    local: { command: 'node', args: ['server.js'], env: { DB_PASSWORD: canary() } }
  } });
  return { dir, files, out: path.join(dir, 'out') };
}

test('no command prints or stores a planted value', () => {
  const { files, out } = inputs();
  const priv = path.join(out, 'keys/private.pem');
  const pub = path.join(out, 'keys/public.pem');
  run(['keygen', '--private', priv, '--public', pub]);
  const inspections = [
    ['inspect', files.mcp], ['inspect-claude', files.claude], ['inspect-claude-settings', files.settings],
    ['inspect-codex', files.codex], ['inspect-codex-settings', files.codexSettings], ['inspect-skill', files.skill],
    ['inspect-plugin', files.plugin], ['inspect-ide-extensions', files.ext],
    ['inspect-claude-settings-stack', '--user', files.settings], ['inspect-codex-settings-stack', '--user', files.codexSettings]
  ];
  const commands = [
    ...inspections.flatMap((args) => [args, [...args, '--json'], [...args, '--decisions']]),
    ['snapshot', files.mcp, '--out', path.join(out, 'snapshot.json')],
    ['snapshot-claude', files.claude, '--out', path.join(out, 'snapshot-claude.json')],
    ['snapshot-ide-extensions', files.ext, '--out', path.join(out, 'snapshot-ide.json')],
    ['snapshot-claude-settings', files.settings, '--out', path.join(out, 'posture-claude.json')],
    ['snapshot-codex-settings', files.codexSettings, '--out', path.join(out, 'posture-codex.json')],
    ['snapshot-claude-settings-stack', '--user', files.settings, '--out', path.join(out, 'posture-claude-stack.json')],
    ['snapshot-claude-bindings', files.claude, '--settings', files.settings, '--out', path.join(out, 'bindings-claude.json')],
    ['snapshot-codex-bindings', files.codex, '--out', path.join(out, 'bindings-codex.json')],
    ['gate', files.mcp, '--out', path.join(out, '..', 'gated/mcp.json'), '--pack', 'development'],
    ['gate-claude', files.claude, '--out', path.join(out, '..', 'gated/claude.json'), '--pack', 'development'],
    ['gate-codex', files.codex, '--out', path.join(out, '..', 'gated/config.toml'), '--pack', 'development'],
    ['approve', files.approvable, '--private', priv, '--dir', path.join(out, 'review'), '--pack', 'development'],
    ['recheck', files.approvable, '--review-dir', path.join(out, 'review'), '--public', pub],
    ['recheck', files.approvable, '--review-dir', path.join(out, 'review'), '--public', pub, '--json'],
    ['approve-ide-extensions', files.ext, '--private', priv, '--dir', path.join(out, 'review-ide'), '--pack', 'development'],
    ['recheck-ide-extensions', files.ext, '--review-dir', path.join(out, 'review-ide'), '--public', pub]
  ];
  for (const args of commands) {
    const result = run(args);
    assertNoLeak(args, result);
    if (args[0] === 'approve' || args[0] === 'recheck') assert.notEqual(result.status, 2, `${args[0]}: ${result.stderr}`);
  }
  for (const file of ['snapshot.json', 'posture-claude.json', 'bindings-claude.json', 'review/snapshot.json', 'review-ide/trust-record.json']) {
    assert.ok(fs.existsSync(path.join(out, file)), `${file} was not written`);
  }
  fs.rmSync(path.join(out, 'keys'), { recursive: true });
  assertFilesClean(out);
});

test('no malformed input echoes a planted value in errors or reports', () => {
  const { write } = workspace();
  const cases = [
    ['inspect', 'json', () => ({ mcpServers: { a: { command: 'node', env: { T: 123, U: canary() } } } })],
    ['inspect', 'json', () => ({ mcpServers: { a: { url: `ftp://${canary()}.invalid/x` } } })],
    ['inspect', 'json', () => ({ mcpServers: { a: { url: `not a url ${canary()}` } } })],
    ['inspect', 'json', () => ({ mcpServers: { a: { command: 'node', env: [canary()] } } })],
    ['inspect', 'raw', () => `{"mcpServers": {"a": {"env": {"T": ${canary()}}}}}`],
    ['inspect-claude', 'json', () => ({ mcpServers: { a: { type: 'http', url: `https://x.invalid/?k=${canary()}` } } })],
    ['inspect-claude', 'json', () => ({ mcpServers: { a: { type: 'stdio', command: 'node', env: { T: canary() }, extra: canary() } } })],
    ['inspect-claude', 'json', () => ({ mcpServers: { a: { type: 'ws', url: `wss://${canary()}.invalid` } } })],
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
