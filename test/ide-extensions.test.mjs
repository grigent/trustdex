import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { digestExtensionTree, inspectIdeExtensionsDir, parseIdeExtensionPin } from '../src/ide-extensions.mjs';
import { evaluateAll } from '../src/policy.mjs';
import { getPolicyPack, mergePolicy } from '../src/policy-packs.mjs';
import { createSnapshot, diffSnapshots } from '../src/snapshot.mjs';

const cli = fileURLToPath(new URL('../bin/trustdex.mjs', import.meta.url));

async function tempDir() {
  return fs.mkdtemp(path.join(os.tmpdir(), 'trustdex-ide-'));
}

async function addExtension(root, folder, manifest, files = {}) {
  const dir = path.join(root, folder);
  await fs.mkdir(dir, { recursive: true });
  if (manifest !== null) {
    await fs.writeFile(path.join(dir, 'package.json'), typeof manifest === 'string' ? manifest : JSON.stringify(manifest));
  }
  await fs.writeFile(path.join(dir, 'extension.js'), 'exports.activate = () => {};\n');
  for (const [name, content] of Object.entries(files)) {
    await fs.mkdir(path.dirname(path.join(dir, name)), { recursive: true });
    await fs.writeFile(path.join(dir, name), content);
  }
  return dir;
}

function entry(id, version, folder, metadata = { source: 'gallery' }) {
  return { identifier: { id }, version, relativeLocation: folder, metadata };
}

async function writeRegistry(root, entries) {
  await fs.writeFile(path.join(root, 'extensions.json'), JSON.stringify(entries));
}

async function singleExtension({ id = 'acme.tool', version = '1.0.0', manifest = {}, metadata, files } = {}) {
  const root = await tempDir();
  const [publisher, name] = id.split('.');
  const folder = `${id}-${version}`;
  await addExtension(root, folder, { publisher, name, version, ...manifest }, files);
  await writeRegistry(root, [entry(id, version, folder, metadata)]);
  return root;
}

function strictWith(overlay) {
  return mergePolicy(getPolicyPack('strict'), overlay);
}

test('inspects registered extensions with a content fingerprint and no paths in the source', async () => {
  const root = await singleExtension();
  const [result] = await inspectIdeExtensionsDir(root);
  assert.equal(result.name, 'acme.tool');
  assert.equal(result.kind, 'ide-extension');
  assert.deepEqual(result.source, {
    type: 'ide-extension', id: 'acme.tool', version: '1.0.0', installSource: 'gallery', targetPlatform: null
  });
  assert.match(result.fingerprint, /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(result.signals, []);
  assert.ok(!JSON.stringify(result).includes(root));
});

test('reports startup activation, untrusted workspaces, bundled extensions, prerelease and non-gallery installs', async () => {
  const root = await singleExtension({
    manifest: {
      activationEvents: ['onStartupFinished'],
      capabilities: { untrustedWorkspaces: { supported: true } },
      extensionPack: ['other.ext']
    },
    metadata: { source: 'vsix', preRelease: true }
  });
  const [result] = await inspectIdeExtensionsDir(root);
  assert.deepEqual(result.signals, [
    'ide-extension-bundles-extensions',
    'ide-extension-non-gallery-source',
    'ide-extension-prerelease',
    'ide-extension-startup-activation',
    'ide-extension-untrusted-workspaces'
  ]);
});

test('wildcard activation is reported as startup activation', async () => {
  const root = await singleExtension({ manifest: { activationEvents: ['*'] } });
  const [result] = await inspectIdeExtensionsDir(root);
  assert.ok(result.signals.includes('ide-extension-startup-activation'));
});

test('registry and manifest disagreement is blocked under every pack', async () => {
  const root = await tempDir();
  await addExtension(root, 'acme.tool-2.0.0', { publisher: 'acme', name: 'tool', version: '2.0.0' });
  await writeRegistry(root, [entry('acme.tool', '1.0.0', 'acme.tool-2.0.0')]);
  const inspected = await inspectIdeExtensionsDir(root);
  assert.ok(inspected[0].signals.includes('ide-extension-manifest-mismatch'));
  for (const pack of ['strict', 'official-first', 'development']) {
    const policy = mergePolicy(getPolicyPack(pack), { trustedIdeExtensions: ['acme.tool@1.0.0'] });
    assert.equal(evaluateAll(inspected, policy)[0].action, 'block', pack);
  }
});

test('missing or unparseable manifests fail closed', async () => {
  const root = await tempDir();
  await addExtension(root, 'acme.none-1.0.0', null);
  await addExtension(root, 'acme.bad-1.0.0', '{not json');
  await writeRegistry(root, [entry('acme.none', '1.0.0', 'acme.none-1.0.0'), entry('acme.bad', '1.0.0', 'acme.bad-1.0.0')]);
  const results = evaluateAll(await inspectIdeExtensionsDir(root), strictWith({
    trustedIdeExtensions: ['acme.none@1.0.0', 'acme.bad@1.0.0']
  }));
  for (const result of results) {
    assert.ok(result.signals.includes('ide-extension-missing-manifest'));
    assert.equal(result.action, 'block');
  }
});

test('registry locations outside the supplied directory are never read and are blocked', async () => {
  const root = await tempDir();
  const outside = await tempDir();
  await addExtension(outside, 'acme.tool-1.0.0', { publisher: 'acme', name: 'tool', version: '1.0.0' });
  await writeRegistry(root, [{
    identifier: { id: 'acme.tool' },
    version: '1.0.0',
    location: { path: path.join(outside, 'acme.tool-1.0.0') },
    metadata: { source: 'gallery' }
  }]);
  const [result] = evaluateAll(await inspectIdeExtensionsDir(root), strictWith({ trustedIdeExtensions: ['acme.tool@1.0.0'] }));
  assert.ok(result.signals.includes('ide-extension-external-location'));
  assert.equal(result.fingerprint, null);
  assert.equal(result.action, 'block');
});

test('extension folders missing from the registry are reported instead of skipped', async () => {
  const root = await singleExtension();
  await addExtension(root, '.evil.hidden-9.9.9', { publisher: 'evil', name: 'hidden', version: '9.9.9' });
  await fs.mkdir(path.join(root, 'not-an-extension'));
  const results = await inspectIdeExtensionsDir(root);
  const hidden = results.find((result) => result.name === 'evil.hidden');
  assert.ok(hidden);
  assert.equal(hidden.source.installSource, 'unregistered');
  assert.ok(hidden.signals.includes('ide-extension-unregistered'));
  assert.equal(results.length, 2);
});

test('versions of the same extension get distinct names, and exact duplicates fail closed', async () => {
  const root = await tempDir();
  await addExtension(root, 'acme.tool-1.0.0', { publisher: 'acme', name: 'tool', version: '1.0.0' });
  await addExtension(root, 'acme.tool-1.0.1', { publisher: 'acme', name: 'tool', version: '1.0.1' });
  await writeRegistry(root, [entry('acme.tool', '1.0.0', 'acme.tool-1.0.0'), entry('acme.tool', '1.0.1', 'acme.tool-1.0.1')]);
  assert.deepEqual((await inspectIdeExtensionsDir(root)).map((result) => result.name), ['acme.tool@1.0.0', 'acme.tool@1.0.1']);
  await writeRegistry(root, [entry('acme.tool', '1.0.0', 'acme.tool-1.0.0'), entry('acme.tool', '1.0.0', 'acme.tool-1.0.0')]);
  await assert.rejects(inspectIdeExtensionsDir(root), /more than once/);
});

test('folders marked obsolete by the editor are excluded', async () => {
  const root = await singleExtension();
  await addExtension(root, 'acme.tool-0.9.0', { publisher: 'acme', name: 'tool', version: '0.9.0' });
  await fs.writeFile(path.join(root, '.obsolete'), JSON.stringify({ 'acme.tool-0.9.0': true }));
  const results = await inspectIdeExtensionsDir(root);
  assert.deepEqual(results.map((result) => `${result.name}@${result.source.version}`), ['acme.tool@1.0.0']);
});

test('malformed registry or obsolete files fail closed', async () => {
  const root = await singleExtension();
  await fs.writeFile(path.join(root, 'extensions.json'), '{');
  await assert.rejects(inspectIdeExtensionsDir(root), /Invalid IDE extension registry JSON/);
  await fs.writeFile(path.join(root, 'extensions.json'), JSON.stringify({ identifier: {} }));
  await assert.rejects(inspectIdeExtensionsDir(root), /must be a JSON array/);
  await fs.writeFile(path.join(root, 'extensions.json'), JSON.stringify([{ identifier: { id: 'acme.tool' } }]));
  await assert.rejects(inspectIdeExtensionsDir(root), /requires a version/);
  await writeRegistry(root, [entry('acme.tool', '1.0.0', 'acme.tool-1.0.0')]);
  await fs.writeFile(path.join(root, '.obsolete'), '[');
  await assert.rejects(inspectIdeExtensionsDir(root), /Invalid IDE extension \.obsolete JSON/);
  await assert.rejects(inspectIdeExtensionsDir(path.join(root, 'missing')), /requires an extensions directory/);
});

test('the fingerprint changes when any installed file changes, even with the same version', async () => {
  const root = await singleExtension();
  const [before] = await inspectIdeExtensionsDir(root);
  await fs.appendFile(path.join(root, 'acme.tool-1.0.0', 'extension.js'), 'require("child_process");\n');
  const [after] = await inspectIdeExtensionsDir(root);
  assert.equal(after.source.version, before.source.version);
  assert.notEqual(after.fingerprint, before.fingerprint);
});

test('native binaries and symlinks are reported, and symlinks are not followed', async () => {
  const root = await singleExtension({ files: { 'bin/helper': Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02]) } });
  const extension = path.join(root, 'acme.tool-1.0.0');
  const outside = await tempDir();
  await fs.writeFile(path.join(outside, 'secret.txt'), 'not read');
  let linked = true;
  try { await fs.symlink(outside, path.join(extension, 'link'), 'dir'); } catch { linked = false; }
  const tree = await digestExtensionTree(extension);
  assert.ok(tree.signals.includes('ide-extension-native-code'));
  if (linked) assert.ok(tree.signals.includes('ide-extension-non-regular-files'));
  await fs.writeFile(path.join(outside, 'secret.txt'), 'changed');
  assert.equal((await digestExtensionTree(extension)).digest, tree.digest);
});

test('native modules are detected by file extension', async () => {
  const root = await singleExtension({ files: { 'build/addon.node': 'x' } });
  const [result] = await inspectIdeExtensionsDir(root);
  assert.ok(result.signals.includes('ide-extension-native-code'));
});

test('strict policy blocks unpinned IDE extensions', async () => {
  const [result] = evaluateAll(await inspectIdeExtensionsDir(await singleExtension()), getPolicyPack('strict'));
  assert.equal(result.action, 'block');
  assert.ok(result.reasons.includes('IDE extension is not pinned: acme.tool@1.0.0'));
});

test('an exact version pin allows the extension', async () => {
  const [result] = evaluateAll(
    await inspectIdeExtensionsDir(await singleExtension()),
    strictWith({ trustedIdeExtensions: ['ACME.Tool@1.0.0'] })
  );
  assert.equal(result.action, 'allow');
});

test('an unreviewed update of a pinned extension is not allowed', async () => {
  const root = await singleExtension({ id: 'anthropic.claude-code', version: '2.1.313' });
  const [result] = evaluateAll(
    await inspectIdeExtensionsDir(root),
    strictWith({ trustedIdeExtensions: ['anthropic.claude-code@2.1.312'] })
  );
  assert.equal(result.action, 'block');
  assert.ok(result.reasons.some((reason) => reason.includes('2.1.313 is not a pinned version')));
  const development = evaluateAll(
    await inspectIdeExtensionsDir(root),
    mergePolicy(getPolicyPack('development'), { trustedIdeExtensions: ['anthropic.claude-code@2.1.312'] })
  );
  assert.notEqual(development[0].action, 'allow');
});

test('a digest pin blocks modified files that keep the same version', async () => {
  const root = await singleExtension();
  const [clean] = await inspectIdeExtensionsDir(root);
  const pinned = strictWith({ trustedIdeExtensions: [`acme.tool@1.0.0#${clean.fingerprint}`] });
  assert.equal(evaluateAll([clean], pinned)[0].action, 'allow');
  await fs.appendFile(path.join(root, 'acme.tool-1.0.0', 'extension.js'), '// changed\n');
  const [result] = evaluateAll(await inspectIdeExtensionsDir(root), pinned);
  assert.equal(result.action, 'block');
  assert.ok(result.signals.includes('ide-extension-digest-mismatch'));
});

test('signals still raise a pinned extension to review', async () => {
  const root = await singleExtension({ manifest: { activationEvents: ['onStartupFinished'] } });
  const [result] = evaluateAll(await inspectIdeExtensionsDir(root), strictWith({ trustedIdeExtensions: ['acme.tool@1.0.0'] }));
  assert.equal(result.action, 'ask');
});

test('deny-list entries override pins, including wildcard versions', async () => {
  const inspected = await inspectIdeExtensionsDir(await singleExtension());
  for (const blocked of ['acme.tool@1.0.0', 'acme.tool@*']) {
    const [result] = evaluateAll(inspected, strictWith({
      trustedIdeExtensions: ['acme.tool@1.0.0'],
      blockedIdeExtensions: [blocked]
    }));
    assert.equal(result.action, 'block', blocked);
  }
  const [other] = evaluateAll(inspected, strictWith({
    trustedIdeExtensions: ['acme.tool@1.0.0'],
    blockedIdeExtensions: ['acme.tool@0.9.0']
  }));
  assert.equal(other.action, 'allow');
});

test('policy overlays cannot drop base deny-list entries', () => {
  const base = mergePolicy(getPolicyPack('strict'), { blockedIdeExtensions: ['acme.tool@*'] });
  const merged = mergePolicy(base, { blockedIdeExtensions: [] });
  assert.deepEqual(merged.blockedIdeExtensions, ['acme.tool@*']);
});

test('pins without an exact version are rejected', () => {
  for (const value of ['acme.tool', 'acme.tool@*', 'acme@1.0.0', 'acme.tool@1.0.0#sha256:abc', '']) {
    assert.throws(() => parseIdeExtensionPin(value), /must be "publisher.name@exact-version"/, value);
  }
  assert.deepEqual(parseIdeExtensionPin('acme.tool@*', 'blockedIdeExtensions'), { id: 'acme.tool', version: '*', digest: null });
  assert.throws(() => evaluateAll([{
    name: 'acme.tool', source: { type: 'ide-extension', id: 'acme.tool', version: '1.0.0' }, signals: []
  }], strictWith({ trustedIdeExtensions: ['acme.tool'] })), /exact-version/);
});

test('snapshots record version and content drift', async () => {
  const policy = strictWith({ trustedIdeExtensions: ['acme.tool@1.0.0', 'acme.tool@1.0.1'] });
  const root = await singleExtension();
  const before = createSnapshot(evaluateAll(await inspectIdeExtensionsDir(root), policy));
  await fs.rm(path.join(root, 'acme.tool-1.0.0'), { recursive: true });
  await addExtension(root, 'acme.tool-1.0.1', { publisher: 'acme', name: 'tool', version: '1.0.1' }, { 'extra.js': 'x' });
  await writeRegistry(root, [entry('acme.tool', '1.0.1', 'acme.tool-1.0.1')]);
  const after = createSnapshot(evaluateAll(await inspectIdeExtensionsDir(root), policy));
  const types = diffSnapshots(before, after).map((change) => change.type);
  assert.ok(types.includes('source-changed'));
  assert.ok(types.includes('fingerprint-changed'));
});

test('CLI approve and recheck flag an extension that changed after review', async () => {
  const root = await singleExtension();
  const work = await tempDir();
  const policyPath = path.join(work, 'policy.json');
  await fs.writeFile(policyPath, JSON.stringify({ trustedIdeExtensions: ['acme.tool@1.0.0'] }));
  const priv = path.join(work, 'private.pem');
  const pub = path.join(work, 'public.pem');
  const review = path.join(work, 'review');
  execFileSync(process.execPath, [cli, 'keygen', '--private', priv, '--public', pub]);
  execFileSync(process.execPath, [cli, 'approve-ide-extensions', root, '--private', priv, '--dir', review, '--policy', policyPath]);

  const unchanged = spawnSync(process.execPath, [cli, 'recheck-ide-extensions', root, '--review-dir', review, '--public', pub], { encoding: 'utf8' });
  assert.equal(unchanged.status, 0, unchanged.stderr);
  assert.match(unchanged.stdout, /APPROVED/);

  await fs.appendFile(path.join(root, 'acme.tool-1.0.0', 'extension.js'), '// tampered\n');
  const changed = spawnSync(process.execPath, [cli, 'recheck-ide-extensions', root, '--review-dir', review, '--public', pub], { encoding: 'utf8' });
  assert.equal(changed.status, 1);
  assert.match(changed.stdout, /NEEDS_REVIEW/);
  assert.match(changed.stdout, /fingerprint-changed: acme\.tool/);
});

test('CLI refuses to approve blocked IDE extensions and rejects trust stores', async () => {
  const root = await singleExtension();
  const work = await tempDir();
  const priv = path.join(work, 'private.pem');
  execFileSync(process.execPath, [cli, 'keygen', '--private', priv, '--public', path.join(work, 'public.pem')]);
  const approve = spawnSync(process.execPath, [cli, 'approve-ide-extensions', root, '--private', priv, '--dir', path.join(work, 'r')], { encoding: 'utf8' });
  assert.equal(approve.status, 2);
  assert.match(approve.stderr, /Refusing to approve/);
  const inspect = spawnSync(process.execPath, [cli, 'inspect-ide-extensions', root, '--trust-store', 'x.json'], { encoding: 'utf8' });
  assert.equal(inspect.status, 2);
  assert.match(inspect.stderr, /do not accept --trust-store/);
});

test('bundled example inventory demonstrates pinned, updated, and sideloaded extensions', async () => {
  const examples = fileURLToPath(new URL('../examples/', import.meta.url));
  const policy = mergePolicy(getPolicyPack('strict'), JSON.parse(await fs.readFile(path.join(examples, 'ide-extensions.policy.json'), 'utf8')));
  const results = evaluateAll(await inspectIdeExtensionsDir(path.join(examples, 'ide-extensions')), policy);
  const actions = Object.fromEntries(results.map((result) => [result.name, result.action]));
  assert.deepEqual(actions, {
    'example.pinned-ext': 'allow',
    'example.updated-ext': 'block',
    'example.sideloaded-ext': 'block'
  });
});
