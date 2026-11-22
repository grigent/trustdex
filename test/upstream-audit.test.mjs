import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { inspectSkillText, inspectPluginManifest } from '../src/extensions.mjs';
import { inspectMcpConfig } from '../src/inspect.mjs';
import { parseCodexMcpToml } from '../src/codex-config.mjs';
import { evaluateAll } from '../src/policy.mjs';
import { getPolicyPack } from '../src/policy-packs.mjs';

const allowLocal = { ...getPolicyPack('strict'), localAction: 'allow' };
const action = (record, policy = allowLocal) => evaluateAll([record], policy)[0].action;
const skill = (text) => inspectSkillText(text);

test('skill hooks and injected shell commands block even when local skills are allowed', () => {
  for (const text of [
    '---\nname: x\nhooks:\n  PreToolUse:\n    - command: "echo hi"\n---\nbody\n',
    '---\n"hooks": {PreToolUse: []}\n---\nbody\n',
    '---\n{name: x, hooks: {PreToolUse: []}}\n---\nbody\n',
    '---\nmeta: {"hooks": 1}\n---\nbody\n',
    '---\n!!str hooks: {PreToolUse: []}\n---\nbody\n',
    '---\n&h hooks: {PreToolUse: []}\n---\nbody\n',
    '---\nname: &k hooks\n*k: {PreToolUse: []}\n---\nbody\n',
    '---\n? hooks\n: {PreToolUse: []}\n---\nbody\n',
    '---\n"\\x68ooks": {PreToolUse: []}\n---\nbody\n',
    '---\nmeta:\n  ? hooks\n  : {PreToolUse: []}\n---\nbody\n',
    '---\n{name: x, ? hooks: {PreToolUse: []}}\n---\nbody\n',
    "---\n'hooks': {PreToolUse: []}\n---\nbody\n"
  ]) {
    const record = skill(text);
    assert.ok(record.signals.includes('skill-hooks'), text);
    assert.equal(action(record), 'block', text);
  }
  for (const body of ['Changes: !`git diff HEAD`\n', '```!\nls\n```\n', '  ~~~!\nls\n~~~\n']) {
    const record = skill(`---\nname: x\n---\n${body}`);
    assert.ok(record.signals.includes('skill-shell-injection'), body);
    assert.equal(action(record), 'block', body);
  }
  assert.deepEqual(skill('---\nname: x\ndescription: Explains React hooks: state and effects\n---\nbody\n').signals, []);
  assert.deepEqual(skill('---\nname: x\ndescription: Fast, *safe* and small\n---\nbody\n').signals, []);
  const started = Date.now();
  skill(`---\nname: x\ndescription: ${', "'.repeat(20000)}${'\\a'.repeat(20000)}\n---\nbody\n`);
  assert.ok(Date.now() - started < 2000, 'quoted frontmatter must not stall inspection');
  assert.deepEqual(skill('---\nname: x\ndescription:\n  **Bold** start of a long description\n---\nbody\n').signals, []);
  assert.deepEqual(skill('---\nname: x\n---\nUse hooks: carefully. Say hi!\n```js\nx\n```\n').signals, []);
});

test('allowed-tools grants need review and shell grants block', () => {
  assert.deepEqual(skill('---\nname: x\n---\nbody\n').signals, []);
  assert.equal(action(skill('---\nname: x\n---\nbody\n')), 'allow');
  const read = skill('---\nallowed-tools: Read Grep\n---\nbody\n');
  assert.deepEqual(read.signals, ['skill-auto-approved-tools']);
  assert.equal(action(read), 'ask');
  for (const header of ['allowed-tools: Bash(gh *)', 'allowed-tools: Read, Bash', 'allowed-tools:\n  - PowerShell(Get-Item *)',
    'allowed-tools: |\n  Bash(git *)']) {
    const record = skill(`---\n${header}\n---\nbody\n`);
    assert.ok(record.signals.includes('skill-shell-auto-approve'), header);
    assert.equal(action(record), 'block', header);
  }
  assert.ok(!skill('---\nallowed-tools: Read\ntools: Bash\n---\nbody\n').signals.includes('skill-shell-auto-approve'));
  const commented = skill('---\nallowed-tools: [Read, # not Bash\n  Grep]\n---\nbody\n');
  assert.ok(!commented.signals.includes('skill-shell-auto-approve'), commented.signals.join());
  assert.ok(!skill('---\nallowed-tools: BashHistoryReader\n---\nbody\n').signals.includes('skill-shell-auto-approve'));
});

test('a plugin manifest never reaches ALLOW and monitors or channels count as executable', () => {
  const plain = inspectPluginManifest({ name: 'p', version: '1.0.0' });
  assert.deepEqual(plain.signals, ['plugin-components-uninspected']);
  assert.equal(action(plain), 'ask');
  for (const extra of [
    { experimental: { monitors: [{ name: 'm', command: 'x', description: 'd' }] } },
    { experimental: { monitors: './config/monitors.json' } },
    { monitors: './monitors.json' },
    { channels: [{ server: 's' }] }
  ]) {
    const record = inspectPluginManifest({ name: 'p', version: '1.0.0', ...extra });
    assert.ok(record.signals.includes('plugin-executable-components'), JSON.stringify(extra));
  }
  assert.ok(!inspectPluginManifest({ name: 'p', version: '1.0.0', experimental: {} }).signals
    .includes('plugin-executable-components'));
});

test('generic MCP fields TrustDex does not read need review', () => {
  const [plain, typed, extra, badType] = inspectMcpConfig({
    servers: {
      a: { command: 'node', args: ['s.js'] },
      b: { type: 'stdio', command: 'node' },
      c: { command: 'node', envFile: '${workspaceFolder}/.env' },
      d: { type: 'ws', url: 'wss://h.invalid/mcp' }
    }
  });
  assert.ok(!plain.signals.includes('uninspected-server-fields'));
  assert.ok(!typed.signals.includes('uninspected-server-fields'));
  assert.ok(extra.signals.includes('uninspected-server-fields'));
  assert.ok(badType.signals.includes('uninspected-server-fields'));
  for (const server of [extra, badType]) assert.notEqual(action(server, getPolicyPack('development')), 'allow');
});

test('adapter metadata in a generic MCP file does not skip field review', async () => {
  const config = { mcpServers: { a: { command: 'node', headers: { A: 'b' }, _trustdexFingerprintData: {} } } };
  assert.ok(inspectMcpConfig(config, { generic: true })[0].signals.includes('uninspected-server-fields'));
  const { execFileSync } = await import('node:child_process');
  const fs = await import('node:fs/promises');
  const os = await import('node:os');
  const path = await import('node:path');
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'trustdex-generic-'));
  const file = path.join(dir, 'mcp.json');
  await fs.writeFile(file, JSON.stringify(config));
  let out = '';
  try {
    out = execFileSync(process.execPath, [fileURLToPath(new URL('../bin/trustdex.mjs', import.meta.url)), 'inspect', file, '--json'],
      { encoding: 'utf8' });
  } catch (error) { out = error.stdout; }
  assert.match(out, /uninspected-server-fields/);
});

test('Codex MCP values and transport fields follow upstream validation', () => {
  const parse = (body) => parseCodexMcpToml(`[mcp_servers.x]\n${body}`);
  for (const mode of ['auto', 'prompt', 'writes', 'approve']) {
    assert.equal(parse(`command = "node"\ndefault_tools_approval_mode = "${mode}"\n`).mcpServers.x
      ._trustdexFingerprintData.defaultToolsApprovalMode, mode);
  }
  assert.throws(() => parse('command = "node"\ndefault_tools_approval_mode = "always"\n'), /Unsupported or invalid/);
  assert.throws(() => parse('command = "node"\nenv_vars = [{ name = "T", source = "elsewhere" }]\n'), /"local" or "remote"/);
  parse('command = "node"\nenv_vars = [{ name = "T", source = "remote" }]\n');
  for (const body of ['bearer_token_env_var = "T"', 'http_headers_helper = "h"', 'http_headers = { A = "b" }',
    'env_http_headers = { A = "B" }']) {
    assert.throws(() => parse(`command = "node"\n${body}\n`), /not supported for the stdio transport/, body);
  }
  for (const body of ['args = ["a"]', 'env = { A = "b" }', 'env_vars = ["A"]', 'cwd = "/tmp"']) {
    assert.throws(() => parse(`url = "https://h.invalid/mcp"\n${body}\n`), /not supported for the HTTP transport/, body);
  }
  assert.throws(() => parseCodexMcpToml('[mcp_servers.x.env]\nA = "b"\n'), /must set command or url/);
  assert.throws(() => parseCodexMcpToml('[mcp_servers.x]\nenabled = true\n'), /must set command or url/);
  assert.throws(() => parse('url = "https://h.invalid/mcp"\nhttp_headers_helper = "  "\n'), /Unsupported or invalid/);
});
