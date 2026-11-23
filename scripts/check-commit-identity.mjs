#!/usr/bin/env node
// Fails when a commit in the given range carries a personal email address in its
// author, committer, or identity trailers (Co-authored-by, Signed-off-by, ...).
// Only GitHub noreply addresses and noreply@<domain> are accepted. Addresses are
// never printed, so a failing run does not republish them in a public log.
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const NOREPLY = /^(?:[^@\s]+@users\.noreply\.github\.com|noreply@[a-z0-9.-]+\.[a-z]{2,})$/i;
const TRAILER = /^\s*([A-Za-z][A-Za-z-]*-by)\s*:\s*(.*)$/;
const EMAIL = /<([^<>]*)>|([^\s<>]+@[^\s<>]+)/g;
const FIELD_SEP = '\x1f';
const RECORD_SEP = '\x1e';

export function isAllowedAddress(address) {
  return NOREPLY.test(String(address).trim());
}

export function findIdentityProblems(commits) {
  const problems = [];
  for (const commit of commits) {
    const short = commit.sha.slice(0, 12);
    if (!isAllowedAddress(commit.authorEmail)) problems.push(`${short}: author address is not a noreply address`);
    if (!isAllowedAddress(commit.committerEmail)) problems.push(`${short}: committer address is not a noreply address`);
    for (const line of commit.message.split('\n')) {
      const trailer = TRAILER.exec(line);
      if (!trailer) continue;
      for (const match of trailer[2].matchAll(EMAIL)) {
        const address = match[1] ?? match[2];
        if (!isAllowedAddress(address)) problems.push(`${short}: ${trailer[1]} trailer is not a noreply address`);
      }
    }
  }
  return problems;
}

export function parseLog(raw) {
  return raw
    .split(RECORD_SEP)
    .map((record) => record.replace(/^\n/, ''))
    .filter((record) => record.length > 0)
    .map((record) => {
      const [sha, authorEmail, committerEmail, message = ''] = record.split(FIELD_SEP);
      return { sha, authorEmail, committerEmail, message };
    });
}

function readRange(range) {
  const raw = execFileSync(
    'git',
    ['log', '--no-merges', `--format=%H${FIELD_SEP}%ae${FIELD_SEP}%ce${FIELD_SEP}%B${RECORD_SEP}`, range],
    { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
  );
  return parseLog(raw);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const range = process.argv[2];
  if (!range || !/^[0-9a-f]{7,40}\.\.[0-9a-f]{7,40}$/i.test(range)) {
    console.error('usage: check-commit-identity.mjs <base-sha>..<head-sha>');
    process.exit(2);
  }
  const commits = readRange(range);
  const problems = findIdentityProblems(commits);
  if (problems.length > 0) {
    console.error('Commits must use GitHub noreply addresses in author, committer, and *-by trailers:');
    for (const problem of problems) console.error(`  ${problem}`);
    console.error('Rewrite the listed commits (amend or rebase) before merging.');
    process.exit(1);
  }
  console.log(`Checked ${commits.length} commit(s): all identities use noreply addresses.`);
}
