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
const VERSION_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const NO_FOLLOW = fs.constants?.O_NOFOLLOW ?? 0;
const MAX_REGISTRY_BYTES = 16 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 1024 * 1024;

// Integrity signals that policy overlays may not lower below BLOCK.
export const IDE_INTEGRITY_SIGNALS = Object.freeze([
  'ide-extension-digest-mismatch',
  'ide-extension-external-location',
  'ide-extension-manifest-mismatch',
  'ide-extension-missing-manifest'
]);

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

// Read a regular file without following a final symlink. Returns null when it does
// not exist and { nonRegular: true } when it is a symlink, FIFO, device, or directory.
async function readRegularFile(file, maxBytes) {
  const stat = await fs.lstat(file).catch((error) => {
    if (error?.code === 'ENOENT') return null;
    throw error;
  });
  if (!stat) return null;
  if (!stat.isFile()) return { nonRegular: true };
  const handle = await fs.open(file, fs.constants.O_RDONLY | NO_FOLLOW);
  try {
    const opened = await handle.stat();
    if (!opened.isFile()) return { nonRegular: true };
    if (opened.size > maxBytes) throw new Error(`${path.basename(file)} exceeds the ${maxBytes}-byte inspection limit.`);
    return { text: await handle.readFile('utf8') };
  } finally {
    await handle.close();
  }
}

async function hashFile(file) {
  const handle = await fs.open(file, fs.constants.O_RDONLY | NO_FOLLOW);
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) return null;
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
    return {
      digest: hash.digest('hex'),
      size,
      executable: (stat.mode & 0o111) !== 0,
      native: headerLength >= 2 && isNativeHeader(header)
    };
  } finally {
    await handle.close();
  }
}

// Digest every entry in the installed extension tree: relative path, size, executable
// bit, and contents. Symlinks are recorded by target text and never followed; other
// non-regular entries are recorded by type.
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
        if (!file) {
          signals.add('ide-extension-non-regular-files');
          tree.update(`S\0${rel}\n`);
          continue;
        }
        files += 1;
        if (file.native || NATIVE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
          signals.add('ide-extension-native-code');
        }
        tree.update(`F\0${rel}\0${file.size}\0${file.executable ? 'x' : '-'}\0${file.digest}\n`);
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

async function readControlFile(base, name) {
  const result = await readRegularFile(path.join(base, name), MAX_REGISTRY_BYTES);
  if (result?.nonRegular) throw new Error(`IDE extension ${name} must be a regular file.`);
  return result ? result.text : null;
}

// The editor keys .obsolete by "<id>-<version>" plus "-<targetPlatform>" when one is set.
function extensionKey(id, version, targetPlatform) {
  const platform = targetPlatform && targetPlatform !== 'undefined' ? `-${targetPlatform}` : '';
  return `${id}-${version}${platform}`;
}

// Resolve a location only if it is inside the extensions directory and no path
// component (including the final one) is a symlink.
async function containedDirectory(base, realBase, location) {
  if (!location || !insideRoot(base, location)) return { directory: null };
  const real = await fs.realpath(location).catch((error) => {
    if (error?.code === 'ENOENT') return undefined;
    throw error;
  });
  if (real === undefined) return { directory: location, missing: true };
  if (real !== path.join(realBase, path.relative(base, location))) return { directory: null };
  return { directory: location };
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

async function inspectInstalled(directory, registryEntry, options = {}) {
  const signals = new Set();
  if (options.markedObsolete) signals.add('ide-extension-marked-obsolete');
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
      const file = await readRegularFile(path.join(directory, 'package.json'), MAX_MANIFEST_BYTES);
      if (file?.nonRegular) signals.add('ide-extension-non-regular-files');
      try { manifest = file?.text === undefined ? null : JSON.parse(file.text); } catch { manifest = null; }
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
  const realBase = await fs.realpath(base);

  const registryText = await readControlFile(base, REGISTRY_FILE);
  const registry = registryText === null ? [] : parseRegistry(registryText);
  const obsoleteText = await readControlFile(base, OBSOLETE_FILE);
  const obsolete = obsoleteText === null ? new Set() : parseObsolete(obsoleteText);

  const results = [];
  const claimed = new Set();
  // Registry entries are always inspected. An entry also marked obsolete is reported,
  // never dropped, so .obsolete cannot hide an extension the registry still lists.
  for (const entry of registry) {
    const location = registryLocation(base, entry);
    const { directory } = await containedDirectory(base, realBase, location);
    if (directory) claimed.add(path.relative(base, directory));
    const platform = isObject(entry.metadata) ? entry.metadata.targetPlatform : null;
    const markedObsolete = obsolete.has(extensionKey(normalizeIdeExtensionId(entry.identifier.id), entry.version, platform));
    results.push(await inspectInstalled(directory, entry, { markedObsolete }));
  }

  // Folders the registry does not list. Hidden folders are included; only a folder
  // whose own manifest identity is marked obsolete (pending deletion) is skipped.
  const entries = await fs.readdir(base, { withFileTypes: true });
  for (const entry of entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
    if (claimed.has(entry.name)) continue;
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
    const file = await readRegularFile(path.join(full, 'package.json'), MAX_MANIFEST_BYTES);
    if (file === null) continue;
    if (!file.nonRegular) {
      let manifest = null;
      try { manifest = JSON.parse(file.text); } catch { manifest = null; }
      if (isObject(manifest) && typeof manifest.version === 'string') {
        const key = extensionKey(normalizeIdeExtensionId(`${manifest.publisher || ''}.${manifest.name || ''}`), manifest.version);
        if ([...obsolete].some((name) => name === key || name.startsWith(`${key}-`))) continue;
      }
    }
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
// Versions must be exact semver strings; ranges such as "1.*" or "^1.0.0" are rejected.
// Deny-list entries may use "@*" to match every version.
export function parseIdeExtensionPin(value, listName = 'trustedIdeExtensions') {
  const text = String(value || '').trim();
  const match = text.match(/^([^@#\s]+)@([^@#\s]+)(?:#(sha256:[0-9a-fA-F]{64}))?$/);
  const wildcardAllowed = listName === 'blockedIdeExtensions';
  const versionOk = match && (VERSION_RE.test(match[2]) || (match[2] === '*' && wildcardAllowed && !match[3]));
  if (!match || !ID_RE.test(normalizeIdeExtensionId(match[1])) || !versionOk) {
    throw new Error(`${listName} entry "${text}" must be "publisher.name@exact-version" (optionally "#sha256:<digest>").`);
  }
  return {
    id: normalizeIdeExtensionId(match[1]),
    version: match[2],
    digest: match[3] ? match[3].toLowerCase() : null
  };
}
