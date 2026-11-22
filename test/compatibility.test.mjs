import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const read = (path) => fs.readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const matrix = JSON.parse(read('docs/compatibility.json'));
const pages = ['docs/COMPATIBILITY.md', 'docs/COMPATIBILITY.ko.md'].map(read);

test('the compatibility platforms are exactly the CI matrix', () => {
  const ci = [...read('.github/workflows/ci.yml')
    .matchAll(/- os: (\S+)\s+node-version: (\d+)/g)].map(([, os, node]) => `${os}/${node}`);
  assert.ok(ci.length > 0);
  assert.deepEqual(matrix.platforms.map(({ os, node }) => `${os}/${node}`).sort(), ci.sort());
  for (const page of pages) {
    for (const os of new Set(matrix.platforms.map((platform) => platform.os))) {
      const versions = matrix.platforms.filter((platform) => platform.os === os).map((platform) => platform.node);
      assert.ok(page.includes(`(\`${os}\`) | ${versions.join(', ')} |`), os);
    }
  }
});

test('every compatibility row names commands, tests, and examples that exist', () => {
  const cli = read('bin/trustdex.mjs');
  const ids = matrix.inputs.map((input) => input.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const input of matrix.inputs) {
    assert.ok(input.commands.length > 0 && input.tests.length > 0, input.id);
    for (const command of input.commands) {
      assert.ok(cli.includes(`'${command}'`), `${input.id}: ${command}`);
    }
    for (const file of input.tests) assert.ok(fs.existsSync(new URL(file, import.meta.url)), `${input.id}: ${file}`);
    if (input.example) assert.ok(fs.existsSync(new URL(`../${input.example}`, import.meta.url)), input.example);
    for (const page of pages) {
      const row = page.split('\n').find((line) => line.trimEnd().endsWith(`| \`${input.id}\` |`));
      assert.ok(row, `${input.id} is missing from a compatibility page`);
      for (const command of input.commands) assert.ok(row.includes(`\`${command}\``), `${input.id}: ${command}`);
      for (const file of input.tests) assert.ok(row.includes(`\`test/${file}\``), `${input.id}: ${file}`);
    }
  }
  for (const page of pages) {
    const rows = page.split('\n').filter((line) => /\| `[a-z0-9-]+` \|\s*$/.test(line));
    assert.equal(rows.length, matrix.inputs.length);
  }
});

test('every published schema is listed in the schema rules pages', () => {
  const schemas = fs.readdirSync(new URL('../schemas/', import.meta.url)).filter((name) => name.endsWith('.json'));
  assert.ok(schemas.length > 0);
  for (const page of ['docs/SCHEMAS.md', 'docs/SCHEMAS.ko.md'].map(read)) {
    for (const name of schemas) assert.ok(page.includes(`schemas/${name}`), name);
  }
});
