import test from 'node:test';
import assert from 'node:assert/strict';
import { findIdentityProblems, isAllowedAddress, parseLog } from '../scripts/check-commit-identity.mjs';

const BOT = '158243242+example-bot[bot]@users.noreply.github.com';
const USER = '12345+someone@users.noreply.github.com';

function commit(overrides = {}) {
  return { sha: 'a'.repeat(40), authorEmail: USER, committerEmail: 'noreply@github.com', message: 'fix: thing\n', ...overrides };
}

test('noreply addresses are accepted', () => {
  assert.ok(isAllowedAddress(USER));
  assert.ok(isAllowedAddress(BOT));
  assert.ok(isAllowedAddress('noreply@github.com'));
  assert.ok(isAllowedAddress('noreply@example.com'));
  assert.equal(isAllowedAddress('someone@example.com'), false);
  assert.equal(isAllowedAddress('noreply@localhost'), false);
  assert.equal(isAllowedAddress('x@users.noreply.github.com.evil.example'), false);
});

test('clean commits produce no problems', () => {
  const message = `fix: thing\n\nCo-authored-by: Bot <${BOT}>\nSigned-off-by: Someone <${USER}>\n`;
  assert.deepEqual(findIdentityProblems([commit({ message })]), []);
});

test('personal addresses in author, committer, and trailers are reported without the address', () => {
  const message = 'fix: thing\n\nCo-authored-by: Someone <someone@example.com>\nco-authored-by:   other@example.org\n';
  const problems = findIdentityProblems([
    commit({ authorEmail: 'someone@example.com', committerEmail: 'someone@example.com', message }),
  ]);
  assert.equal(problems.length, 4);
  for (const problem of problems) assert.doesNotMatch(problem, /example\.(com|org)/);
  assert.match(problems[2], /Co-authored-by trailer/);
});

test('parseLog splits git log records', () => {
  const raw = `${'b'.repeat(40)}\x1f${USER}\x1fnoreply@github.com\x1fone\n\nCo-authored-by: X <x@example.com>\n\x1e\n${'c'.repeat(40)}\x1f${USER}\x1f${USER}\x1ftwo\n\x1e\n`;
  const commits = parseLog(raw);
  assert.equal(commits.length, 2);
  assert.equal(findIdentityProblems(commits).length, 1);
});
