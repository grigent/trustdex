// One-time approvals for actions the hook stopped.
//
// A stopped action gets a short code. A person approves it with
// `trustdex allow-once <code>` in their own terminal; the CLI refuses to approve
// without an interactive terminal, so an agent's non-interactive shell cannot
// approve on the user's behalf, and the hook separately blocks agent commands
// that mention `trustdex allow-once` or touch this state directory.
//
// An approval is bound to the SHA-256 digest of the exact tool call, lasts 30
// minutes, and is consumed by its first use.

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const PENDING_TTL_MS = 60 * 60 * 1000;
export const APPROVAL_TTL_MS = 30 * 60 * 1000;
export const ITEM_APPROVAL_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_ENTRIES = 100;
const CODE_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
const CODE_RE = /^[2-9A-HJ-NP-Z]{8}$/;

export function defaultStateDir(home = os.homedir()) {
  return path.join(home, '.config', 'trustdex', 'state');
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(dir);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('TrustDex state directory must be a real directory.');
  if ((stat.mode & 0o077) !== 0) fs.chmodSync(dir, 0o700);
}

function readEntries(file) {
  try {
    const stat = fs.lstatSync(file);
    if (!stat.isFile()) throw new Error('TrustDex state file must be a regular file.');
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
  const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!Array.isArray(parsed)) throw new Error('TrustDex state file is invalid.');
  return parsed.filter((entry) => entry && typeof entry === 'object' && typeof entry.digest === 'string');
}

function writeEntries(file, entries) {
  const temporary = `${file}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(entries.slice(-MAX_ENTRIES), null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  fs.renameSync(temporary, file);
}

function newCode() {
  const bytes = crypto.randomBytes(8);
  return [...bytes].map((byte) => CODE_ALPHABET[byte % CODE_ALPHABET.length]).join('');
}

export function actionDigest(toolName, toolInput) {
  const canonical = (value) => {
    if (Array.isArray(value)) return value.map(canonical);
    if (value && typeof value === 'object') {
      return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
    }
    return value;
  };
  return crypto.createHash('sha256').update(JSON.stringify(canonical({ toolName, toolInput }))).digest('hex');
}

export function createApprovalStore(stateDir = defaultStateDir(), { now = () => Date.now() } = {}) {
  const pendingFile = path.join(stateDir, 'pending.json');
  const approvedFile = path.join(stateDir, 'approved.json');
  const live = (entries) => entries.filter((entry) => Number(entry.expiresAt) > now());

  return {
    stateDir,

    // Records a stopped action and returns its approval code. The summary holds
    // only item names and signals, never command text or file contents.
    // itemKeys, when given, make the approval cover those exact package versions
    // and signals for a day instead of one exact tool call.
    recordPending(digest, summary, itemKeys = null) {
      ensureDir(stateDir);
      const entries = live(readEntries(pendingFile)).filter((entry) => entry.digest !== digest);
      const code = newCode();
      const keys = Array.isArray(itemKeys) && itemKeys.length ? [...new Set(itemKeys.map(String))].sort() : null;
      entries.push({ code, digest, summary, ...(keys ? { itemKeys: keys } : {}), createdAt: now(), expiresAt: now() + PENDING_TTL_MS });
      writeEntries(pendingFile, entries);
      return code;
    },

    listPending() {
      return live(readEntries(pendingFile)).map(({ code, summary, expiresAt }) => ({ code, summary, expiresAt }));
    },

    findPending(code) {
      if (!CODE_RE.test(String(code))) return null;
      return live(readEntries(pendingFile)).find((entry) => entry.code === code) || null;
    },

    approve(code) {
      ensureDir(stateDir);
      const pending = live(readEntries(pendingFile));
      const entry = pending.find((candidate) => candidate.code === code);
      if (!entry) return null;
      const approved = live(readEntries(approvedFile)).filter((candidate) => candidate.digest !== entry.digest);
      const itemScoped = Array.isArray(entry.itemKeys) && entry.itemKeys.length > 0;
      approved.push({
        digest: entry.digest,
        summary: entry.summary,
        ...(itemScoped ? { itemKeys: entry.itemKeys } : {}),
        approvedAt: now(),
        expiresAt: now() + (itemScoped ? ITEM_APPROVAL_TTL_MS : APPROVAL_TTL_MS)
      });
      writeEntries(approvedFile, approved);
      writeEntries(pendingFile, pending.filter((candidate) => candidate !== entry));
      return entry;
    },

    // Returns true when an approval covers this action: an exact-call approval is
    // used up; package approvals stay valid for a day and cover any call whose
    // findings are all among the approved package versions and signals.
    consume(digest, itemKeys = []) {
      let approved;
      try {
        approved = live(readEntries(approvedFile));
      } catch {
        return false;
      }
      const index = approved.findIndex((entry) => entry.digest === digest && !entry.itemKeys);
      if (index >= 0) {
        approved.splice(index, 1);
        writeEntries(approvedFile, approved);
        return true;
      }
      if (!Array.isArray(itemKeys) || !itemKeys.length) return false;
      const covered = new Set(approved.flatMap((entry) => (Array.isArray(entry.itemKeys) ? entry.itemKeys : [])));
      return itemKeys.every((key) => covered.has(key));
    }
  };
}
