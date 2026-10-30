import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import { sha256Json } from './canonical.mjs';

// Static inventory of a VS Code-compatible editor extensions directory
// (for example ~/.vscode/extensions or ~/.cursor/extensions). Nothing is
// executed, nothing outside the supplied directory is read, and no network
// access is performed.

const REGISTRY_FILE = 'extensions.json';
const OBSOLETE_FILE = '.obsolete';
const STARTUP_EVENTS = new Set(['*', 'onStartupFinished']);
const NATIVE_EXTENSIONS = new Set(['.node', '.dll', '.so', '.dylib', '.exe']);
const NATIVE_MAGIC = [
  [0x7f, 0x45, 0x4c, 0x46], // ELF
  [0xfe, 0xed, 0xfa, 0xce], [0xfe, 0xed, 0xfa, 0xcf], // Mach-O
  [0xce, 0xfa, 0xed, 0xfe], [0xcf, 0xfa, 0xed, 0xfe], // Mach-O (little-endian)
  [0xca, 0xfe, 0xba, 0xbe], // Mach-O universal
  [0x4d, 0x5a] // PE ("MZ")
];
const ID_RE = /^[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9._-]*$/;

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

export function normalizeIdeExtensionId(value) {
  return String(value || '').trim().toLowerCase();
}

function isNativeHeader(bytes) {
  return NATIVE_MAGIC.some((magic) => magic.every((byte, index) => bytes[index] === byte));
}

function insideRoot(root, target) {
  const relative = path.relative(root, target);
  return relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative);
}

async function hashFile(file) {
  const handle = await fs.open(file, 'r');
  try {
    const hash = createHash('sha256');
    const header = Buffer.alloc(4);
    let headerLength = 0;
    let size = 0;
    for await (const chunk of handle.createReadStream()) {
      if (headerLength < 4) {
        const take = Math.min(4 - headerLength, chunk.length);
        chunk.copy(header, headerLength, 0, take);
        headerLength += take;
      }
      size += chunk.length;
      hash.update(chunk);
    }
    return { digest: hash.digest('hex'), size, native: headerLength >= 2 && isNativeHeader(header) };
  } finally {
    await handle.close();
  }
}

// Digest every entry in the installed extension tree. Symlinks are recorded by
// target text and never followed; other non-regular entries are recorded by type.
export async function digestExtensionTree(directory) {
  const tree = createHash('sha256');
  const signals = new Set();
  let files = 0;

  async function visit(relative) {
    const entries = await fs.readdir(path.join(directory, relative), { withFileTypes: true });
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      const rel = relative ? `${relative}/${entry.name}` : entry.name;
      const full = path.join(directory, rel);
      if (entry.isSymbolicLink()) {
        signals.add('ide-extension-non-regular-files');
        tree.update(`L\0${rel}\0${await fs.readlink(full)}\n`);
      } else if (entry.isDirectory()) {
        tree.update(`D\0${rel}\n`);
        await visit(rel);
      } else if (entry.isFile()) {
        const file = await hashFile(full);
        files += 1;
        if (file.native || NATIVE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
          signals.add('ide-extension-native-code');
        }
        tree.update(`F\0${rel}\0${file.size}\0${file.digest}\n`);
      } else {
        signals.add('ide-extension-non-regular-files');
        tree.update(`S\0${rel}\n`);
      }
    }
  }

  await visit('');
  return { digest: `sha256:${tree.digest('hex')}`, files, signals: [...signals].sort() };
}

function parseRegistry(text) {
  let value;
  try { value = JSON.parse(text); } catch {
    throw new Error(`Invalid IDE extension registry JSON (${REGISTRY_FILE}).`);
  }
  if (!Array.isArray(value)) throw new Error(`IDE extension registry (${REGISTRY_FILE}) must be a JSON array.`);
  return value.map((entry, index) => {
    if (!isObject(entry) || !isObject(entry.identifier) || typeof entry.identifier.id !== 'string') {
      throw new Error(`IDE extension registry entry #${index + 1} requires identifier.id.`);
    }
    if (typeof entry.version !== 'string' || !entry.version) {
      throw new Error(`IDE extension registry entry #${index + 1} requires a version.`);
    }
    if (entry.metadata !== undefined && entry.metadata !== null && !isObject(entry.metadata)) {
      throw new Error(`IDE extension registry entry #${index + 1} has invalid metadata.`);
    }
    return entry;
  });
}

function parseObsolete(text) {
  let value;
  try { value = JSON.parse(text); } catch {
    throw new Error(`Invalid IDE extension ${OBSOLETE_FILE} JSON.`);
  }
  if (!isObject(value)) throw new Error(`IDE extension ${OBSOLETE_FILE} must be a JSON object.`);
  return new Set(Object.entries(value).filter(([, flag]) => flag === true).map(([name]) => name));
}

async function readOptional(file) {
  try {
    return await fs.readFile(file, 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

function registryLocation(root, entry) {
  if (typeof entry.relativeLocation === 'string' && entry.relativeLocation) {
    return path.resolve(root, entry.relativeLocation);
  }
  const location = entry.location;
  if (typeof location === 'string') return path.resolve(root, location);
  if (isObject(location)) {
    const value = location.fsPath || location.path;
    if (typeof value === 'string' && value) return path.resolve(root, value);
  }
  return null;
}

function manifestSignals(manifest, expectedId, expectedVersion) {
  const signals = new Set();
  const id = normalizeIdeExtensionId(`${manifest.publisher || ''}.${manifest.name || ''}`);
  if (!manifest.publisher || !manifest.name || !ID_RE.test(id) || (expectedId && id !== expectedId)) {
    signals.add('ide-extension-manifest-mismatch');
  }
  if (typeof manifest.version !== 'string' || !manifest.version ||
    (expectedVersion && manifest.version !== expectedVersion)) {
    signals.add('ide-extension-manifest-mismatch');
  }
  const events = Array.isArray(manifest.activationEvents) ? manifest.activationEvents : [];
  if (events.some((event) => STARTUP_EVENTS.has(event))) signals.add('ide-extension-startup-activation');
  if (manifest.capabilities?.untrustedWorkspaces?.supported === true) {
    signals.add('ide-extension-untrusted-workspaces');
  }
  const bundled = [manifest.extensionPack, manifest.extensionDependencies]
    .some((list) => Array.isArray(list) && list.length > 0);
  if (bundled) signals.add('ide-extension-bundles-extensions');
  return { id, signals };
}

async function inspectInstalled(directory, registryEntry) {
  const signals = new Set();
  const expectedId = registryEntry ? normalizeIdeExtensionId(registryEntry.identifier.id) : null;
  const expectedVersion = registryEntry ? registryEntry.version : null;
  const metadata = isObject(registryEntry?.metadata) ? registryEntry.metadata : {};

  if (!registryEntry) signals.add('ide-extension-unregistered');
  else if (metadata.source !== 'gallery') signals.add('ide-extension-non-gallery-source');
  if (metadata.preRelease === true || metadata.isPreReleaseVersion === true) signals.add('ide-extension-prerelease');

  let manifest = null;
  if (!directory) {
    signals.add('ide-extension-external-location');
  } else {
    const stat = await fs.lstat(directory).catch(() => null);
    if (!stat?.isDirectory()) {
      signals.add('ide-extension-missing-manifest');
    } else {
      const text = await readOptional(path.join(directory, 'package.json'));
      try { manifest = text === null ? null : JSON.parse(text); } catch { manifest = null; }
      if (!isObject(manifest)) {
        manifest = null;
        signals.add('ide-extension-missing-manifest');
      }
    }
  }

  let id = expectedId;
  let version = expectedVersion;
  if (manifest) {
    const checked = manifestSignals(manifest, expectedId, expectedVersion);
    checked.signals.forEach((signal) => signals.add(signal));
    id = id || checked.id;
    version = version || (typeof manifest.version === 'string' ? manifest.version : null);
  }

  let fingerprint = null;
  let files = 0;
  if (directory && manifest) {
    const tree = await digestExtensionTree(directory);
    tree.signals.forEach((signal) => signals.add(signal));
    fingerprint = tree.digest;
    files = tree.files;
  }

  const name = id || `unidentified:${path.basename(directory || 'unknown')}`;
  return {
    name,
    kind: 'ide-extension',
    source: {
      type: 'ide-extension',
      id: id || null,
      version: version || null,
      installSource: registryEntry ? (typeof metadata.source === 'string' ? metadata.source : 'unknown') : 'unregistered',
      targetPlatform: typeof metadata.targetPlatform === 'string' ? metadata.targetPlatform : null
    },
    fingerprint,
    metadata: {
      displayName: typeof manifest?.displayName === 'string' ? manifest.displayName : null,
      files
    },
    signals: [...signals].sort(),
    envKeys: []
  };
}

// Inspect the extensions directory supplied by the user. Registry entries are
// read from extensions.json; extension folders on disk that the registry does not
// list are still reported (as unregistered) instead of being silently skipped.
export async function inspectIdeExtensionsDir(root) {
  const base = path.resolve(root);
  const stat = await fs.stat(base).catch(() => null);
  if (!stat?.isDirectory()) throw new Error('inspect-ide-extensions requires an extensions directory.');

  const registryText = await readOptional(path.join(base, REGISTRY_FILE));
  const registry = registryText === null ? [] : parseRegistry(registryText);
  const obsoleteText = await readOptional(path.join(base, OBSOLETE_FILE));
  const obsolete = obsoleteText === null ? new Set() : parseObsolete(obsoleteText);

  const results = [];
  const claimed = new Set();
  for (const entry of registry) {
    const location = registryLocation(base, entry);
    const inside = location && insideRoot(base, location);
    if (inside && obsolete.has(path.relative(base, location))) continue;
    if (inside) claimed.add(path.relative(base, location));
    results.push(await inspectInstalled(inside ? location : null, entry));
  }

  const entries = await fs.readdir(base, { withFileTypes: true });
  for (const entry of entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
    // Hidden folders are inspected too; only plain files (the registry, .obsolete) are skipped.
    if (claimed.has(entry.name) || obsolete.has(entry.name)) continue;
    if (!entry.isDirectory() && !entry.isSymbolicLink()) continue;
    const full = path.join(base, entry.name);
    if (entry.isSymbolicLink()) {
      results.push({
        name: `unidentified:${entry.name}`,
        kind: 'ide-extension',
        source: { type: 'ide-extension', id: null, version: null, installSource: 'unregistered', targetPlatform: null },
        fingerprint: `sha256:${sha256Json({ symlink: entry.name, target: await fs.readlink(full) })}`,
        metadata: { displayName: null, files: 0 },
        signals: ['ide-extension-missing-manifest', 'ide-extension-non-regular-files', 'ide-extension-unregistered'],
        envKeys: []
      });
      continue;
    }
    if ((await readOptional(path.join(full, 'package.json'))) === null) continue;
    results.push(await inspectInstalled(full, null));
  }

  // Keep result names unique so snapshots and diffs stay unambiguous.
  const seen = new Map();
  for (const result of results) seen.set(result.name, (seen.get(result.name) || 0) + 1);
  const named = results.map((result) => (seen.get(result.name) > 1 && result.source.version
    ? { ...result, name: `${result.name}@${result.source.version}` }
    : result));
  const names = new Set();
  for (const result of named) {
    if (names.has(result.name)) throw new Error(`IDE extension inventory lists ${result.name} more than once.`);
    names.add(result.name);
  }
  return named;
}

// Policy pins are "publisher.name@version" with an optional "#sha256:<hex>" tree digest.
// An entry without an exact version is rejected so a trusted publisher cannot
// silently ship a different build.
// Deny-list entries may use "@*" to match every version.
export function parseIdeExtensionPin(value, listName = 'trustedIdeExtensions') {
  const text = String(value || '').trim();
  const match = text.match(/^([^@#\s]+)@([^@#\s]+)(?:#(sha256:[0-9a-fA-F]{64}))?$/);
  const wildcardAllowed = listName === 'blockedIdeExtensions';
  if (!match || !ID_RE.test(normalizeIdeExtensionId(match[1])) || (match[2] === '*' && !wildcardAllowed)) {
    throw new Error(`${listName} entry "${text}" must be "publisher.name@exact-version" (optionally "#sha256:<digest>").`);
  }
  return {
    id: normalizeIdeExtensionId(match[1]),
    version: match[2],
    digest: match[3] ? match[3].toLowerCase() : null
  };
}
