import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { MAX_JSON_DEPTH, parseStrictJson } from '../src/canonical.mjs';
import { inspectSkillText } from '../src/extensions.mjs';

const cli = fileURLToPath(new URL('../bin/trustdex.mjs', import.meta.url));
const fixtures = fileURLToPath(new URL('./fixtures/adversarial-parsers/', import.meta.url));
const expected = JSON.parse(fs.readFileSync(path.join(fixtures, 'expected.json'), 'utf8'));

function run(command, file) {
  return spawnSync(process.execPath, [cli, command, file, '--pack', 'strict', '--json'], { encoding: 'utf8' });
}

function assertFailsClosed(result, message, label) {
  assert.equal(result.status, 2, `${label} exited ${result.status}: ${result.stdout}${result.stderr}`);
  assert.ok(result.stderr.includes(message), `${label} printed: ${result.stderr}`);
  assert.doesNotMatch(result.stdout, /"action":\s*"allow"/, `${label} reported ALLOW`);
}

test('every adversarial parser fixture has an expectation', () => {
  const files = fs.readdirSync(fixtures, { recursive: true })
    .map((file) => String(file).split(path.sep).join('/'))
    .filter((file) => fs.statSync(path.join(fixtures, file)).isFile() && file !== 'expected.json');
  assert.deepEqual(files.sort(), Object.keys(expected).sort());
});

for (const [file, expectation] of Object.entries(expected)) {
  test(`adversarial parser fixture ${file}`, () => {
    const result = run(expectation.command, path.join(fixtures, file));
    if (expectation.error) {
      assertFailsClosed(result, expectation.error, file);
      return;
    }
    const [report] = JSON.parse(result.stdout);
    assert.equal(report.action, expectation.action, `${file}: ${result.stdout}`);
    for (const signal of expectation.signals) assert.ok(report.signals.includes(signal), `${file} did not report ${signal}`);
  });
}

function workspace() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'trustdex-adversarial-'));
  test.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

const encodedInputs = [
  ['inspect', 'mcp.json', '{"mcpServers":{"notes":{"command":"node","args":["server.js"]}}}\n'],
  ['inspect-codex', 'config.toml', '[mcp_servers.notes]\ncommand = "node"\nargs = ["server.js"]\n'],
  ['inspect-skill', 'SKILL.md', '---\nname: example-skill\nallowed-tools: "*"\n---\nBody.\n'],
  ['inspect-plugin', 'plugin.json', '{"name":"example-plugin","version":"1.0.0"}\n']
];

test('invalid UTF-8, UTF-16, and oversized inputs fail closed for every parser', () => {
  const dir = workspace();
  for (const [command, name, text] of encodedInputs) {
    const cases = [
      // A stray 0xff byte would otherwise become U+FFFD and hide what another reader sees.
      ['invalid-utf8', Buffer.concat([Buffer.from(text.slice(0, 20)), Buffer.from([0xff]), Buffer.from(text.slice(20))]), 'is not valid UTF-8'],
      ['utf16le-bom', Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, 'utf16le')]), 'is not valid UTF-8'],
      ['utf16be-bom', Buffer.concat([Buffer.from([0xfe, 0xff]), Buffer.from(text, 'utf16le').swap16()]), 'is not valid UTF-8']
    ];
    for (const [label, bytes, message] of cases) {
      const file = path.join(dir, `${label}-${name}`);
      fs.writeFileSync(file, bytes);
      assertFailsClosed(run(command, file), message, `${command} ${label}`);
    }
    const large = path.join(dir, `large-${name}`);
    fs.writeFileSync(large, text);
    fs.truncateSync(large, 16 * 1024 * 1024 + 1);
    assertFailsClosed(run(command, large), 'is larger than 16 MiB', `${command} oversized`);
  }
});

test('UTF-16 without a byte-order mark fails closed for every parser', () => {
  const dir = workspace();
  const messages = {
    inspect: 'Invalid JSON', 'inspect-plugin': 'Invalid JSON', 'inspect-codex': 'control character', 'inspect-skill': 'NUL characters'
  };
  for (const [command, name, text] of encodedInputs) {
    const file = path.join(dir, `utf16le-${name}`);
    fs.writeFileSync(file, Buffer.from(text, 'utf16le'));
    assertFailsClosed(run(command, file), messages[command], `${command} utf16le`);
  }
});

test('a SKILL.md with lone carriage-return line breaks is read like any other', () => {
  const text = '---\rname: example-skill\rallowed-tools: Bash(*)\r---\rBody.\r';
  const report = inspectSkillText(text);
  assert.ok(report.signals.includes('skill-shell-auto-approve'), report.signals.join(', '));
  assert.ok(report.signals.includes('wildcard-tool-scope'), report.signals.join(', '));
});

test('a SKILL.md with NUL characters is rejected', () => {
  assert.throws(() => inspectSkillText('---\nallowed-tools:\0 "*"\n---\n'), /NUL characters/);
});

test('YAML double-quoted escapes in a skill scope are decoded before classification', () => {
  for (const [scope, signal] of [
    ['"\\x2a"', 'wildcard-tool-scope'],
    ['"\\u002A"', 'wildcard-tool-scope'],
    ['"\\U0000002a"', 'wildcard-tool-scope'],
    ['"Bash\\x28*)"', 'skill-shell-auto-approve'],
    ["'Bash(*)'", 'skill-shell-auto-approve']
  ]) {
    const report = inspectSkillText(`---\nallowed-tools: ${scope}\n---\n`);
    assert.ok(report.signals.includes(signal), `${scope}: ${report.signals.join(', ')}`);
  }
});

test('strict JSON keeps valid documents and rejects duplicate, prototype, and deep keys', () => {
  const valid = '{"a":{"x":1},"b":{"x":"\\"x\\":"},"c":[{"x":1},{"x":2}],"d":"{\\"a\\":1,\\"a\\":2}","e\\u0022":1}';
  assert.deepEqual(parseStrictJson(valid), JSON.parse(valid));
  assert.throws(() => parseStrictJson('{"a":1,"a":2}'), /defined more than once/);
  assert.throws(() => parseStrictJson('{"a":{"b":1},"c":[{"d":1,"d":2}]}'), /defined more than once/);
  assert.throws(() => parseStrictJson('{"\\u0061":1,"a":2}'), /defined more than once/);
  assert.throws(() => parseStrictJson('{"x":{"__proto__":{}}}'), /__proto__/);
  assert.throws(() => parseStrictJson('{'), SyntaxError);
  const deep = (depth) => '['.repeat(depth) + ']'.repeat(depth);
  assert.deepEqual(parseStrictJson(deep(MAX_JSON_DEPTH)).length, 1);
  assert.throws(() => parseStrictJson(deep(MAX_JSON_DEPTH + 1)), /nested more than/);
});
