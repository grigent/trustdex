import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { analyzeInstallCommand, parseNpmSpec, parsePypiSpec } from '../src/install-command.mjs';
import {
  compileNpmRange,
  evaluateInstallCommand,
  parseInstallPolicy,
  resolveNpmVersion,
  similarPopularName
} from '../src/install-check.mjs';

const cli = fileURLToPath(new URL('../bin/trustdex.mjs', import.meta.url));
const NOW = Date.parse('2026-11-18T00:00:00Z');
const INTEGRITY = `sha512-${Buffer.alloc(64, 1).toString('base64')}`;
const SHA256 = 'a'.repeat(64);
const daysAgo = (days) => new Date(NOW - days * 86_400_000).toISOString();

function kinds(command) {
  return analyzeInstallCommand(command).findings.map((finding) =>
    finding.kind === 'package' ? `${finding.ecosystem}:${finding.mode}:${finding.spec}` : `${finding.ecosystem}:${finding.kind}`);
}

// ------------------------------------------------------------ parser

test('install command parser finds packages across npm-family tools', () => {
  assert.deepEqual(kinds('npm i esbuild'), ['npm:install:esbuild']);
  assert.deepEqual(kinds('npm install -D typescript@5.9.3 @types/node'), ['npm:install:typescript@5.9.3', 'npm:install:@types/node']);
  assert.deepEqual(kinds('pnpm --filter web add zod'), ['npm:install:zod']);
  assert.deepEqual(kinds('yarn global add serve'), ['npm:install:serve']);
  assert.deepEqual(kinds('bun add hono'), ['npm:install:hono']);
  assert.deepEqual(kinds('npx -y create-vite@latest app --template react'), ['npm:run:create-vite@latest']);
  assert.deepEqual(kinds('npx -p cowsay -p lolcatjs cowsay hi'), ['npm:run:cowsay', 'npm:run:lolcatjs']);
  assert.deepEqual(kinds('npm exec -- prettier --check .'), ['npm:run:prettier']);
  assert.deepEqual(kinds('pnpm dlx degit user/repo'), ['npm:run:degit']);
  assert.deepEqual(kinds('bunx eslint .'), ['npm:run:eslint']);
  assert.deepEqual(kinds('npm ci'), ['npm:manifest']);
  assert.deepEqual(kinds('npm install'), ['npm:manifest']);
  assert.deepEqual(kinds('yarn'), ['npm:manifest']);
  assert.deepEqual(kinds('npx -c "eslint ."'), []);
  assert.deepEqual(kinds('npm run build && npm test'), []);
});

test('install command parser finds packages across PyPI-family tools', () => {
  assert.deepEqual(kinds('pip install requests==2.32.3 "httpx[http2]>=0.27"'), ['pypi:install:requests==2.32.3', 'pypi:install:httpx[http2]>=0.27']);
  assert.deepEqual(kinds('python3 -m pip install --user rich'), ['pypi:install:rich']);
  assert.deepEqual(kinds('pip3.12 install -U pip'), ['pypi:install:pip']);
  assert.deepEqual(kinds('uv pip install -r requirements.txt'), ['pypi:manifest']);
  assert.deepEqual(kinds('uv add fastapi --dev'), ['pypi:install:fastapi']);
  assert.deepEqual(kinds('uv sync'), ['pypi:manifest']);
  assert.deepEqual(kinds('uvx ruff check .'), ['pypi:run:ruff']);
  assert.deepEqual(kinds('uvx --from httpie http GET example.invalid'), ['pypi:run:httpie']);
  assert.deepEqual(kinds('uvx --python 3.12 black .'), ['pypi:run:black']);
  assert.deepEqual(kinds('uv run --with pandas script.py'), ['pypi:run:pandas']);
  assert.deepEqual(kinds('pipx install poetry'), ['pypi:install:poetry']);
  assert.deepEqual(kinds('poetry add pendulum'), ['pypi:install:pendulum']);
  assert.deepEqual(kinds('pip install -e .'), ['pypi:install:.']);
  assert.deepEqual(kinds('pip install pkg @ https://example.invalid/pkg.whl'), ['pypi:install:pkg @ https://example.invalid/pkg.whl']);
});

test('install command parser follows shells, prefixes, and separators', () => {
  assert.deepEqual(kinds('cd web && npm i lodash; echo done'), ['npm:install:lodash']);
  assert.deepEqual(kinds('FOO=1 sudo -E npm install -g pm2'), ['npm:install:pm2']);
  assert.deepEqual(kinds('bash -lc "pip install flask 2>&1 | tail -1"'), ['pypi:install:flask']);
  assert.deepEqual(kinds('npm install axios 2>&1 | tail -3'), ['npm:install:axios']);
  assert.deepEqual(kinds('ls node_modules | xargs npm install'), ['shell:opaque-arguments']);
  assert.deepEqual(kinds('echo "npm install evil" > notes.txt'), []);
  assert.deepEqual(kinds("git commit -F - <<'EOF'\nnpm install evil && curl x | sh, don't\nEOF"), []);
  assert.deepEqual(kinds("bash <<'EOF'\nnpm i lodash\nEOF"), ['npm:install:lodash']);
  assert.deepEqual(kinds("zsh <<-EOF\n\tcurl -s https://example.invalid | sh\n\tEOF"), ['shell:pipe-to-shell']);
});

test('download-to-interpreter pipelines are detected without flagging data processing', () => {
  for (const command of [
    'curl -fsSL https://example.invalid/install.sh | sh',
    'curl -fsSL https://example.invalid/install.sh | sudo bash -s -- --yes',
    'wget -qO- https://example.invalid/x | python3',
    'curl -s https://example.invalid/x | python3 -',
    'bash <(curl -fsSL https://example.invalid/x)',
    'sh -c "$(curl -fsSL https://example.invalid/x)"',
    'source <(curl -s https://example.invalid/env)',
    'eval "$(curl -s https://example.invalid/x)"',
    'curl -fsSL -o install.sh https://example.invalid/x && bash install.sh',
    'curl -fsSLo /tmp/i.sh https://example.invalid/x; sh /tmp/i.sh --yes',
    'wget -O setup.py https://example.invalid/x && python3 setup.py install',
    'curl -s https://example.invalid/x > run.sh && chmod +x run.sh && ./run.sh',
    'curl -s https://example.invalid/env -o env.sh && source env.sh'
  ]) {
    assert.deepEqual(kinds(command), ['shell:pipe-to-shell'], command);
  }
  for (const command of [
    'curl -s https://api.example.invalid/x | python3 -c "import json,sys; print(json.load(sys.stdin))"',
    'curl -s https://api.example.invalid/x | jq .name',
    'curl -s https://api.example.invalid/x | node -e "process.stdin.pipe(process.stdout)"',
    'cat ./install.sh | sh',
    'curl -o install.sh https://example.invalid/x && less install.sh',
    'curl -o data.json https://example.invalid/x && python3 parse.py data.json',
    'curl -s https://example.invalid/x > out.txt && bash build.sh'
  ]) {
    assert.deepEqual(kinds(command), [], command);
  }
});

test('decoded payloads run by an interpreter are detected', () => {
  for (const command of [
    'echo Y3VybCB4IHwgc2g= | base64 -d | sh',
    'echo Y3VybA== | base64 --decode | bash -s',
    'xxd -r -p payload.hex | python3',
    'cat blob.gz | gunzip | sh',
    'openssl enc -aes-256-cbc -d -in x.enc -k k | bash',
    'eval "$(echo ZWNobw== | base64 -d)"',
    'bash -c "$(base64 -D <<< ZWNobw==)"',
    'bash <(echo ZWNobw== | base64 -d)'
  ]) {
    assert.deepEqual(kinds(command), ['shell:decoded-to-interpreter'], command);
  }
  for (const command of ['echo aGk= | base64 -d', 'base64 -d img.b64 > img.png', 'gunzip -c data.gz | jq .', 'base64 -d x | python3 parse.py']) {
    assert.deepEqual(kinds(command), [], command);
  }
});

test('unlexable commands fail toward review only when they mention a package tool', () => {
  assert.deepEqual(kinds('npm install "unterminated'), ['shell:unparseable-command']);
  assert.deepEqual(kinds('echo "unterminated'), []);
});

test('custom registries mark the packages of that command instead of looking them up', () => {
  const { findings } = analyzeInstallCommand('npm install --registry https://user:secret@example.invalid foo');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].customRegistry, true);
  assert.deepEqual(kinds('pip install --extra-index-url https://example.invalid/simple torch').length, 1);
  assert.deepEqual(kinds('npm ci --registry https://example.invalid'), ['npm:custom-registry', 'npm:manifest']);
});

test('package spec parsing distinguishes registry, local, and unregistered sources', () => {
  assert.deepEqual(parseNpmSpec('react'), { type: 'registry', name: 'react', selector: { kind: 'tag', value: 'latest', implicit: true } });
  assert.deepEqual(parseNpmSpec('@scope/pkg@^1.2.0').selector, { kind: 'range', value: '^1.2.0' });
  assert.deepEqual(parseNpmSpec('pkg@v1.2.3').selector, { kind: 'exact', value: '1.2.3' });
  assert.deepEqual(parseNpmSpec('pkg@next').selector, { kind: 'tag', value: 'next' });
  assert.equal(parseNpmSpec('alias@npm:real@1.0.0').name, 'real');
  for (const spec of ['git+https://example.invalid/x.git', 'github:user/repo', 'user/repo', 'https://example.invalid/x.tgz', 'pkg@https://example.invalid/x']) {
    assert.equal(parseNpmSpec(spec).type, 'unregistered', spec);
  }
  for (const spec of ['./local', '../pkg', '/abs/pkg', 'file:../x']) assert.equal(parseNpmSpec(spec).type, 'local', spec);
  assert.equal(parseNpmSpec('bad name').type, 'invalid');

  assert.deepEqual(parsePypiSpec('Requests_OAuthlib[rsa]==1.3.1'), { type: 'registry', name: 'requests-oauthlib', selector: { kind: 'exact', value: '1.3.1' } });
  assert.equal(parsePypiSpec('django>=4').selector.kind, 'latest');
  assert.equal(parsePypiSpec('django~=4.2').selector.kind, 'range');
  assert.equal(parsePypiSpec('django==4.*').selector.kind, 'range');
  assert.equal(parsePypiSpec('pkg @ https://example.invalid/x.whl').type, 'unregistered');
  assert.equal(parsePypiSpec('git+https://example.invalid/x.git').type, 'unregistered');
  assert.equal(parsePypiSpec('./dist/pkg-1.0-py3-none-any.whl').type, 'local');
});

test('npm range resolution follows npm selection rules for the supported subset', () => {
  const doc = {
    'dist-tags': { latest: '1.4.0', next: '2.0.0-rc.1' },
    versions: Object.fromEntries(['0.2.3', '0.2.9', '0.3.0', '1.0.0', '1.4.0', '1.5.0', '2.0.0-rc.1'].map((v) => [v, {}]))
  };
  assert.equal(resolveNpmVersion(doc, { kind: 'range', value: '^0.2.3' }), '0.2.9');
  assert.equal(resolveNpmVersion(doc, { kind: 'range', value: '^1.0.0' }), '1.4.0', 'latest wins when it satisfies');
  assert.equal(resolveNpmVersion(doc, { kind: 'range', value: '>=1.5.0' }), '1.5.0');
  assert.equal(resolveNpmVersion(doc, { kind: 'range', value: '~0.2' }), '0.2.9');
  assert.equal(resolveNpmVersion(doc, { kind: 'range', value: '0.x || 2' }), '0.3.0');
  assert.equal(resolveNpmVersion(doc, { kind: 'range', value: '1.0.0 - 1.4.0' }), '1.4.0');
  assert.equal(resolveNpmVersion(doc, { kind: 'tag', value: 'next' }), '2.0.0-rc.1');
  assert.equal(resolveNpmVersion(doc, { kind: 'range', value: '^9' }), null);
  assert.equal(resolveNpmVersion(doc, { kind: 'range', value: '>=1 <2 !weird' }), undefined);
  assert.equal(compileNpmRange('<1.0.0')('0.9.0'), true);
  assert.equal(compileNpmRange('^1.0.0')('1.2.0-beta.1'), false, 'prereleases are excluded from ranges');
});

test('npm skips a deprecated or engine-incompatible default tag the way npm-pick-manifest does', () => {
  const bare = { kind: 'tag', value: 'latest', implicit: true };
  const doc = (latest, extra = {}) => ({
    'dist-tags': { latest: '2.0.0', beta: '1.9.0-beta.1' },
    versions: { '1.0.0': {}, '1.9.0': {}, '1.9.0-beta.1': {}, '2.0.0': latest, ...extra }
  });
  const node22 = { nodeVersion: '22.0.0' };
  assert.equal(resolveNpmVersion(doc({}), bare, node22), '2.0.0');
  assert.equal(resolveNpmVersion(doc({ deprecated: 'x' }), bare, node22), '1.9.0', 'bare installs skip a deprecated latest');
  assert.equal(resolveNpmVersion(doc({ deprecated: 'x' }), { kind: 'tag', value: 'latest' }, node22), '2.0.0', 'an explicit tag is taken as-is');
  assert.equal(resolveNpmVersion(doc({ engines: { node: '>=24' } }), bare, node22), '1.9.0');
  assert.equal(resolveNpmVersion(doc({ engines: { node: '>=24' } }), { kind: 'range', value: '^2' }, node22), '2.0.0', 'an incompatible match still beats nothing');
  assert.equal(resolveNpmVersion(doc({ engines: { node: '>=20' } }), bare, node22), '2.0.0');
  assert.equal(resolveNpmVersion(doc({ engines: { npm: '>=11' } }), bare, node22), undefined, 'TrustDex cannot see the npm version');
  assert.equal(resolveNpmVersion(doc({ engines: { node: '>=20 !x' } }), bare, node22), undefined);
  assert.equal(resolveNpmVersion(doc({}, { '1.9.0': { engines: { npm: '>=11' } } }), bare, node22), '2.0.0', 'uncertainty that cannot change the pick is ignored');
  const unknownNpm = { engines: { npm: '>=11' } };
  assert.equal(resolveNpmVersion(doc({}, { '1.0.0': unknownNpm, '1.9.0': unknownNpm }), { kind: 'range', value: '^1' }, node22), undefined, 'a mix of unknown engines can change the pick');
  assert.equal(resolveNpmVersion(doc({ engines: { npm: '>=11' } }, { '1.0.0': unknownNpm, '1.9.0': unknownNpm }), bare, node22), undefined);
  assert.equal(resolveNpmVersion(doc({}, { '1.9.0': unknownNpm }), { kind: 'range', value: '^1' }, node22), undefined);
  assert.equal(resolveNpmVersion(doc({}, { '1.0.0': unknownNpm }), { kind: 'range', value: '^1' }, node22), '1.9.0');
  assert.equal(resolveNpmVersion({ 'dist-tags': { latest: '1.0.0' }, versions: { '1.0.0': unknownNpm } }, bare, node22), '1.0.0', 'a lone candidate is the pick whatever its engines');
  assert.equal(resolveNpmVersion(doc({}), bare, { ...node22, defaultTag: 'beta' }), '1.9.0-beta.1', '--tag changes the default tag');
  assert.equal(resolveNpmVersion(doc({}), { kind: 'range', value: '^1' }, { ...node22, defaultTag: 'beta' }), '1.9.0');
  assert.equal(resolveNpmVersion(doc({}), bare, { ...node22, defaultTag: 'missing' }), null);
  assert.equal(resolveNpmVersion(doc({}), bare, { ...node22, defaultTag: '' }), undefined);
  assert.equal(resolveNpmVersion(doc({}), bare, { ...node22, before: true }), undefined, '--before is not modeled');
  assert.equal(resolveNpmVersion(doc({}), { kind: 'exact', value: '1.0.0' }, { ...node22, before: true }), '1.0.0');
  assert.equal(resolveNpmVersion(doc({}), { kind: 'range', value: '>1.9.0-beta' }, node22), undefined, 'prerelease comparators are not modeled');
});

test('npm --tag and --before reach the resolver and fail safe', async () => {
  const doc = npmDoc('tagged', { version: '1.0.0' });
  doc['dist-tags'].beta = '1.0.0';
  let [item] = await evaluate('npm i tagged --before 2020-01-01', { [NPM('tagged')]: doc });
  assert.deepEqual([item.action, item.signals], ['ask', ['unresolved-version']]);
  [item] = await evaluate('npm i tagged@1.0.0 --before=2020-01-01', { [NPM('tagged')]: doc });
  assert.equal(item.signals.includes('unresolved-version'), false);
  [item] = await evaluate('npm i tagged --tag nope', { [NPM('tagged')]: doc });
  assert.deepEqual([item.action, item.signals], ['ask', ['version-not-found']]);
  [item] = await evaluate('npm i tagged --tag=beta', { [NPM('tagged')]: doc });
  assert.deepEqual([item.name, item.action], ['npm:tagged@1.0.0', 'allow']);
  [item] = await evaluate('pnpm add tagged --tag nope', { [NPM('tagged')]: doc });
  assert.deepEqual([item.name, item.action], ['npm:tagged@1.0.0', 'allow'], 'only npm takes --tag as the default tag');
});

test('look-alike names of popular packages are flagged, exact names are not', () => {
  assert.equal(similarPopularName('pypi', 'reqeusts'), 'requests');
  assert.equal(similarPopularName('npm', 'expres'), 'express');
  assert.equal(similarPopularName('npm', 'reactdom'), 'react-dom');
  assert.equal(similarPopularName('npm', '@evil/react'), 'react');
  assert.equal(similarPopularName('npm', '@types/react'), null);
  assert.equal(similarPopularName('npm', 'express'), null);
  assert.equal(similarPopularName('npm', 'completely-unrelated-name'), null);
});

// -------------------------------------------------------- evaluation

function npmDoc(name, { version = '1.0.0', published = daysAgo(400), created = daysAgo(900), meta = {}, history = [] } = {}) {
  const versions = {};
  const time = { created, modified: published };
  for (const [v, when, publisher] of history) {
    versions[v] = { name, version: v, dist: { integrity: INTEGRITY }, _npmUser: { name: publisher } };
    time[v] = when;
  }
  versions[version] = { name, version, dist: { integrity: INTEGRITY }, _npmUser: { name: 'owner' }, ...meta };
  time[version] = published;
  return { name, 'dist-tags': { latest: version }, versions, time };
}

function pypiDoc(name, { version = '1.0.0', uploaded = daysAgo(400), first = daysAgo(900), files } = {}) {
  return {
    info: { name, version },
    releases: {
      '0.1.0': [{ packagetype: 'bdist_wheel', upload_time_iso_8601: first, digests: { sha256: SHA256 } }],
      [version]: files || [{ packagetype: 'bdist_wheel', upload_time_iso_8601: uploaded, digests: { sha256: SHA256 } }]
    }
  };
}

function fakeFetch(routes, calls = []) {
  return async (url) => {
    calls.push(url);
    if (!(url in routes)) return { ok: false, status: 404, headers: new Map() };
    const body = routes[url];
    if (body instanceof Error) throw body;
    if (typeof body === 'number') return { ok: false, status: body, headers: new Map() };
    return { ok: true, status: 200, headers: new Map(), json: async () => body };
  };
}

async function evaluate(command, routes, options = {}) {
  const { items } = await evaluateInstallCommand(command, { fetchImpl: fakeFetch(routes, options.calls), now: NOW, ...options });
  return items;
}

const NPM = (name) => `https://registry.npmjs.org/${name.startsWith('@') ? `@${encodeURIComponent(name.slice(1))}` : name}`;
const PYPI = (name) => `https://pypi.org/pypi/${name}/json`;

test('established packages with no signals are allowed and only names are sent', async () => {
  const calls = [];
  const items = await evaluate('npm install left@1.0.0 && pip install sturdy', {
    [NPM('left')]: npmDoc('left'),
    [PYPI('sturdy')]: pypiDoc('sturdy')
  }, { calls });
  assert.deepEqual(items.map((item) => [item.name, item.action]), [['npm:left@1.0.0', 'allow'], ['pypi:sturdy@1.0.0', 'allow']]);
  assert.deepEqual(calls, [NPM('left'), PYPI('sturdy')]);
});

test('missing packages are blocked (hallucinated or typo names)', async () => {
  const items = await evaluate('npm i ghost-pkg && pip install ghost-py', {});
  assert.deepEqual(items.map((item) => [item.action, item.signals[0]]), [['block', 'package-not-found'], ['block', 'package-not-found']]);
});

test('recent releases and new packages need review, respecting policy thresholds', async () => {
  const routes = { [NPM('fresh')]: npmDoc('fresh', { published: daysAgo(0.5), created: daysAgo(3) }) };
  let [item] = await evaluate('npm i fresh', routes);
  assert.equal(item.action, 'ask');
  assert.deepEqual(item.signals.sort(), ['new-package', 'recent-release']);

  [item] = await evaluate('npm i fresh', routes, { policy: { minReleaseAgeHours: 1, minPackageAgeDays: 1 } });
  assert.equal(item.action, 'allow');

  [item] = await evaluate('pip install fresh', { [PYPI('fresh')]: pypiDoc('fresh', { uploaded: daysAgo(1) }) });
  assert.deepEqual(item.signals, ['recent-release']);
});

test('install scripts need review unless disabled or explicitly allowed', async () => {
  const routes = { [NPM('native')]: npmDoc('native', { meta: { scripts: { postinstall: 'node build.js' } } }) };
  let [item] = await evaluate('npm i native', routes);
  assert.deepEqual([item.action, item.signals], ['ask', ['install-scripts']]);

  [item] = await evaluate('npm i native --ignore-scripts', routes);
  assert.deepEqual([item.action, item.signals], ['allow', ['install-scripts-disabled']]);

  [item] = await evaluate('npm i native', routes, { policy: { allowInstallScripts: ['npm:native'] } });
  assert.equal(item.action, 'allow');

  [item] = await evaluate('npm i gyp', { [NPM('gyp')]: npmDoc('gyp', { meta: { gypfile: true } }) });
  assert.deepEqual(item.signals, ['install-scripts']);

  [item] = await evaluate('pip install sdist-only', {
    [PYPI('sdist-only')]: pypiDoc('sdist-only', { files: [{ packagetype: 'sdist', upload_time_iso_8601: daysAgo(400), digests: { sha256: SHA256 } }] })
  });
  assert.deepEqual(item.signals, ['source-build']);
});

test('a first-time publisher on a recent release needs review, old handovers do not', async () => {
  const history = [['0.9.0', daysAgo(500), 'owner'], ['0.9.1', daysAgo(450), 'owner']];
  const recent = npmDoc('handover', { published: daysAgo(5), history });
  recent.versions['1.0.0']._npmUser.name = 'stranger';
  let [item] = await evaluate('npm i handover@1.0.0', { [NPM('handover')]: recent }, { policy: { minReleaseAgeHours: 0 } });
  assert.deepEqual(item.signals, ['publisher-changed']);

  const old = npmDoc('handover', { published: daysAgo(120), history });
  old.versions['1.0.0']._npmUser.name = 'stranger';
  [item] = await evaluate('npm i handover', { [NPM('handover')]: old });
  assert.equal(item.action, 'allow');
});

test('a recent release without the provenance earlier releases had needs review', async () => {
  const attested = { integrity: INTEGRITY, attestations: { url: 'https://registry.npmjs.org/-/npm/v1/attestations/x', provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } };
  const build = (published, latest = {}) => {
    const doc = npmDoc('attested', { published, history: [['0.9.0', daysAgo(500), 'owner'], ['0.9.1', daysAgo(450), 'owner']] });
    doc.versions['0.9.1'].dist = { ...attested };
    doc.versions['1.0.0'].dist = { integrity: INTEGRITY, ...latest };
    return { [NPM('attested')]: doc };
  };
  const policy = { minReleaseAgeHours: 0 };
  let [item] = await evaluate('npm i attested@1.0.0', build(daysAgo(5)), { policy });
  assert.deepEqual([item.action, item.signals], ['ask', ['provenance-dropped']]);
  assert.doesNotMatch(item.reasons.join(' '), /registry\.npmjs\.org|slsa/);

  [item] = await evaluate('npm i attested@1.0.0', build(daysAgo(5)), { policy: { ...policy, allowPackages: ['npm:attested'] } });
  assert.deepEqual(item.signals, ['provenance-dropped']);

  for (const latest of [{ attestations: {} }, { attestations: { provenance: {} } }, { attestations: { provenance: 'yes' } }]) {
    [item] = await evaluate('npm i attested@1.0.0', build(daysAgo(5), latest), { policy });
    assert.deepEqual(item.signals, ['provenance-dropped']);
  }

  [item] = await evaluate('npm i attested@1.0.0', build(daysAgo(5), { attestations: attested.attestations }), { policy });
  assert.equal(item.action, 'allow');

  [item] = await evaluate('npm i attested', build(daysAgo(120)));
  assert.equal(item.action, 'allow');

  [item] = await evaluate('npm i plain@1.0.0', { [NPM('plain')]: npmDoc('plain', { published: daysAgo(5), history: [['0.9.0', daysAgo(500), 'owner']] }) }, { policy });
  assert.equal(item.action, 'allow');
});

test('broken or withdrawn registry metadata fails closed', async () => {
  const noIntegrity = npmDoc('broken');
  delete noIntegrity.versions['1.0.0'].dist.integrity;
  let [item] = await evaluate('npm i broken', { [NPM('broken')]: noIntegrity });
  assert.deepEqual([item.action, item.signals], ['block', ['invalid-registry-metadata']]);

  [item] = await evaluate('npm i other', { [NPM('other')]: npmDoc('different-name') });
  assert.equal(item.action, 'block');

  [item] = await evaluate('pip install nodigest', {
    [PYPI('nodigest')]: pypiDoc('nodigest', { files: [{ packagetype: 'bdist_wheel', upload_time_iso_8601: daysAgo(400), digests: {} }] })
  });
  assert.equal(item.action, 'block');

  [item] = await evaluate('npm i flaky', { [NPM('flaky')]: 503 });
  assert.deepEqual([item.action, item.signals], ['ask', ['lookup-failed']]);

  [item] = await evaluate('npm i offline', { [NPM('offline')]: new Error('ECONNRESET with secret-token-value') });
  assert.deepEqual([item.action, item.signals], ['ask', ['lookup-failed']]);
  assert.ok(!JSON.stringify(item).includes('secret-token-value'));
});

test('deprecated, yanked, unresolved, and missing versions need review', async () => {
  let [item] = await evaluate('npm i old', { [NPM('old')]: npmDoc('old', { meta: { deprecated: 'use new' } }) });
  assert.deepEqual(item.signals, ['deprecated']);

  [item] = await evaluate('pip install gone==1.0.0', {
    [PYPI('gone')]: pypiDoc('gone', { files: [{ packagetype: 'bdist_wheel', yanked: true, upload_time_iso_8601: daysAgo(400), digests: { sha256: SHA256 } }] })
  });
  assert.deepEqual(item.signals, ['yanked']);

  [item] = await evaluate('pip install "range~=1.0"', { [PYPI('range')]: pypiDoc('range') });
  assert.deepEqual(item.signals, ['unresolved-version']);

  [item] = await evaluate('npm i left@9.9.9', { [NPM('left')]: npmDoc('left') });
  assert.deepEqual(item.signals, ['version-not-found']);
});

test('registry drift fixtures: ownership transfer, deleted releases, and yanked releases', async () => {
  // An account handover modeled on 2026-11 hijacks: CI-published history with
  // provenance, then a recent latest from a new account without it.
  const attested = { integrity: INTEGRITY, attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } };
  const handover = npmDoc('handed-over', { version: '2.4.6', published: daysAgo(4), history: [['2.3.6', daysAgo(30), 'ci'], ['2.4.0', daysAgo(9), 'ci']] });
  for (const v of ['2.3.6', '2.4.0']) handover.versions[v].dist = { ...attested };
  handover.versions['2.4.6']._npmUser.name = 'newcomer';
  let [item] = await evaluate('npm i handed-over', { [NPM('handed-over')]: handover }, { policy: { minReleaseAgeHours: 0, allowPackages: ['npm:handed-over'] } });
  assert.deepEqual([item.action, item.signals], ['ask', ['publisher-changed', 'provenance-dropped']]);

  // npm keeps publish times of removed versions; a removed pin or tag never resolves to ALLOW.
  const removed = npmDoc('removed', { version: '2.4.0', history: [['2.4.1', daysAgo(2), 'owner']] });
  delete removed.versions['2.4.1'];
  [item] = await evaluate('npm i removed@2.4.1', { [NPM('removed')]: removed });
  assert.deepEqual([item.action, item.signals], ['ask', ['version-not-found']]);
  removed['dist-tags'].latest = '2.4.1';
  [item] = await evaluate('npm i removed', { [NPM('removed')]: removed });
  assert.deepEqual([item.action, item.signals], ['ask', ['version-not-found']]);

  // A yanked release is never suggested as the older alternative to a too-recent one.
  const file = (when, extra = {}) => [{ packagetype: 'bdist_wheel', upload_time_iso_8601: when, digests: { sha256: SHA256 }, ...extra }];
  const doc = { info: { name: 'drifted', version: '1.2.0' }, releases: {
    '1.0.0': file(daysAgo(300)), '1.1.0': file(daysAgo(30), { yanked: true }), '1.2.0': file(daysAgo(0.5))
  } };
  [item] = await evaluate('pip install drifted', { [PYPI('drifted')]: doc });
  assert.deepEqual(item.signals, ['recent-release']);
  assert.match(item.reasons[0], /drifted==1\.0\.0 instead/);
  [item] = await evaluate('pip install drifted==1.1.0', { [PYPI('drifted')]: doc });
  assert.deepEqual([item.action, item.signals], ['ask', ['yanked']]);
});

test('known malicious PyPI pins block offline, including mirrored and equivalent pins', async () => {
  const calls = [];
  const policy = {
    minReleaseAgeHours: 0,
    allowPackages: ['pypi:agent-framework'],
    allowInstallScripts: ['pypi:agent-framework']
  };
  const commands = [
    ['pip install agent-framework==1.26.1', '1.26.1'],
    ['uv pip install Agent_Framework===1.26.2', '1.26.2'],
    ['pip install --index-url https://mirror.example.invalid/simple "agent-framework[extra]==v0!01.26.2.0"', 'v0!01.26.2.0']
  ];
  for (const [command, version] of commands) {
    const [item] = await evaluate(command, {}, { calls, policy });
    assert.deepEqual([item.name, item.action, item.signals], [
      `pypi:agent-framework@${version}`, 'block', ['known-malicious-release']
    ]);
    assert.match(item.reasons[0], /GHSA-764m-3ppc-5m73/);
  }
  assert.deepEqual(calls, []);
});

test('hijacked npm releases block offline and when resolved, and are never suggested', async () => {
  const calls = [];
  const policy = { minReleaseAgeHours: 0, allowPackages: ['npm:vant'], allowInstallScripts: ['npm:vant'] };
  for (const [command, name, advisory] of [
    ['npm i vant@4.9.11', 'npm:vant@4.9.11', /youzan\/vant\/discussions\/13273/],
    ['pnpm add vant@=2.13.5', 'npm:vant@2.13.5', /youzan\/vant\/discussions\/13273/],
    ['npm i vant@4.9.12+build.7', 'npm:vant@4.9.12+build.7', /youzan\/vant\/discussions\/13273/],
    ['npm i --registry https://mirror.example.invalid/ qrcode-reader-vue3@3.1.4', 'npm:qrcode-reader-vue3@3.1.4', /GHSA-9q69-8j7m-ppmh/],
    ['npx -y @wppconnect-team/wppconnect@2.4.1', 'npm:@wppconnect-team/wppconnect@2.4.1', /GHSA-cxc9-87g6-qrj9/]
  ]) {
    const [item] = await evaluate(command, {}, { calls, policy });
    assert.deepEqual([item.name, item.action, item.signals], [name, 'block', ['known-malicious-release']], command);
    assert.match(item.reasons[0], advisory);
  }
  assert.deepEqual(calls, []);

  const latest = npmDoc('@wppconnect/server', { version: '2.10.82', published: daysAgo(1), history: [['2.10.81', daysAgo(3), 'owner']] });
  let [item] = await evaluate('npm i @wppconnect/server', { [NPM('@wppconnect/server')]: latest });
  assert.deepEqual([item.name, item.action, item.signals], ['npm:@wppconnect/server@2.10.82', 'block', ['known-malicious-release']]);

  const doc = npmDoc('vant', { version: '4.9.16', published: daysAgo(1), history: [['4.9.10', daysAgo(30), 'owner'], ['4.9.11', daysAgo(10), 'owner']] });
  [item] = await evaluate('npm i vant@^4.9.0', { [NPM('vant')]: doc });
  assert.deepEqual(item.signals, ['recent-release']);
  assert.match(item.reasons[0], /vant@4\.9\.10 instead/);

  [item] = await evaluate('npm i vant@4.9.15', { [NPM('vant')]: npmDoc('vant', { version: '4.9.15' }) });
  assert.equal(item.action, 'allow');
});

test('package-wide npm malware advisories block names, ranges, and prerelease pins offline', async () => {
  const calls = [];
  for (const [command, name, advisory] of [
    ['npm i @structureit/ir-dealapi-js', 'npm:@structureit/ir-dealapi-js', /GHSA-gq28-39q4-2fq3/],
    ['npm i @structureit/ir-dealapi-js@^9.9.0', 'npm:@structureit/ir-dealapi-js', /GHSA-gq28-39q4-2fq3/],
    ['npm i --registry https://mirror.example.invalid/ @zervonex/baileys@0.0.0-stage', 'npm:@zervonex/baileys@0.0.0-stage', /GHSA-j2m6-4cjj-vv5m/],
    ['npx -y @zervonex/baileys@latest', 'npm:@zervonex/baileys', /GHSA-j2m6-4cjj-vv5m/]
  ]) {
    const [item] = await evaluate(command, {}, { calls });
    assert.deepEqual([item.name, item.action, item.signals], [name, 'block', ['known-malicious-release']], command);
    assert.match(item.reasons[0], advisory);
  }
  assert.deepEqual(calls, []);
});

test('version-specific npm malware advisories block pins and resolved versions, not neighboring releases', async () => {
  for (const [name, version, other, fresh, advisory] of [
    ['abir-fca', '0.0.25', '0.0.24', '0.0.26', /GHSA-5rhq-849p-frrr/],
    ['obfuscation-detector', '3.0.1', '3.0.0', '3.1.1', /GHSA-2f84-r5f9-388p/],
    ['obfuscation-detector', '3.1.0', '3.0.0', '3.1.1', /GHSA-2f84-r5f9-388p/],
    ['fca-uzair-dev', '1.2.0', '1.1.0', '1.3.0', /GHSA-f84q-56c5-63xh/]
  ]) {
    const [pinned] = await evaluate(`npm i ${name}@${version}`, {});
    assert.deepEqual([pinned.name, pinned.action, pinned.signals], [`npm:${name}@${version}`, 'block', ['known-malicious-release']]);
    assert.match(pinned.reasons[0], advisory);
    const [resolved] = await evaluate(`npm i ${name}`, { [NPM(name)]: npmDoc(name, { version }) });
    assert.deepEqual(resolved, pinned);

    const doc = npmDoc(name, { version: fresh, published: daysAgo(1), history: [
      [other, daysAgo(50), 'owner'], [version, daysAgo(40), 'owner']
    ] });
    const [unaffected] = await evaluate(`npm i ${name}@${other}`, { [NPM(name)]: doc });
    assert.equal(unaffected.action, 'allow');
    const [review] = await evaluate(`npm i ${name}`, { [NPM(name)]: doc });
    assert.deepEqual(review.signals, ['recent-release']);
    assert.ok(review.reasons[0].includes(`Use ${name}@${other} instead`));
  }
});

test('PyPI advice blocks an affected registry selection and skips it in fallback recommendations', async () => {
  const name = 'agent-framework';
  const affected = pypiDoc(name, { version: '1.26.2' });
  const [blocked] = await evaluate(`pip install ${name}`, { [PYPI(name)]: affected });
  assert.deepEqual([blocked.action, blocked.signals], ['block', ['known-malicious-release']]);

  const clean = pypiDoc(name, { version: '1.26.0', uploaded: daysAgo(410) });
  const fresh = pypiDoc(name, { version: '1.26.3', uploaded: daysAgo(1) });
  fresh.releases = { ...clean.releases, ...affected.releases, ...fresh.releases };
  const routes = { [PYPI(name)]: fresh };
  const [allowed] = await evaluate(`pip install ${name}==1.26.0`, routes);
  assert.equal(allowed.action, 'allow');
  const [review] = await evaluate(`pip install ${name}`, routes);
  assert.equal(review.action, 'ask');
  assert.match(review.reasons[0], /Use agent-framework==1\.26\.0 instead/);
});

test('look-alike, unregistered, local, manifest, and local-bin installs are classified', async () => {
  let [item] = await evaluate('pip install reqeusts', { [PYPI('reqeusts')]: pypiDoc('reqeusts') });
  assert.deepEqual(item.signals, ['similar-to-popular']);

  [item] = await evaluate('pip install reqeusts', { [PYPI('reqeusts')]: pypiDoc('reqeusts') }, { policy: { allowPackages: ['pypi:reqeusts'] } });
  assert.equal(item.action, 'allow');

  [item] = await evaluate('npm i github:user/repo', {});
  assert.deepEqual([item.name, item.action], ['npm:url-or-git-source', 'ask']);

  [item] = await evaluate('pip install -e .', {});
  assert.deepEqual([item.name, item.action], ['pypi:local-path', 'allow']);

  [item] = await evaluate('npm ci', {});
  assert.deepEqual([item.action, item.signals], ['ask', ['manifest-install']]);
  [item] = await evaluate('npm ci', {}, { policy: { manifestInstall: 'allow' } });
  assert.equal(item.action, 'allow');

  [item] = await evaluate('npx tsc --noEmit', {}, { localBinExists: (name) => name === 'tsc' });
  assert.deepEqual([item.name, item.action], ['npm:local-bin:tsc', 'allow']);
  [item] = await evaluate('npx tsc@5 --noEmit', {}, { localBinExists: () => true });
  assert.equal(item.signals[0], 'package-not-found', 'an explicit version is always looked up');
});

test('reports never contain registry URLs, credentials, or raw source arguments', async () => {
  const items = await evaluate(
    'npm install --registry https://user:hunter2@registry.example.invalid/?token=abc123 left && ' +
    'pip install "pkg @ https://ghp_secretvalue@example.invalid/pkg.whl" && npm i git+https://tok3n@example.invalid/x.git',
    { [NPM('left')]: npmDoc('left') }
  );
  const text = JSON.stringify(items);
  for (const secret of ['hunter2', 'abc123', 'ghp_secretvalue', 'tok3n', 'example.invalid']) assert.ok(!text.includes(secret), secret);
  assert.ok(items.every((item) => item.action === 'ask'));
});

test('install policy files are validated strictly', () => {
  assert.equal(parseInstallPolicy(undefined).minReleaseAgeHours, 48);
  assert.deepEqual(parseInstallPolicy({ version: 1, allowInstallScripts: ['npm:esbuild', 'PyPI:Some_Pkg'] }).allowInstallScripts, ['npm:esbuild', 'pypi:some-pkg']);
  assert.throws(() => parseInstallPolicy({ allowEverything: true }), /Unsupported install policy key/);
  assert.deepEqual(parseInstallPolicy({ allowStartupItems: ['com.mine.*', 'org.example.backup', 'com.mine.*'] }).allowStartupItems, ['com.mine.*', 'org.example.backup']);
  for (const bad of ['*', 'com.*', 'com', 'com.mine.*.x', 'com.mine/x', '', 3]) {
    assert.throws(() => parseInstallPolicy({ allowStartupItems: [bad] }), /allowStartupItems/, String(bad));
  }
  assert.throws(() => parseInstallPolicy({ minReleaseAgeHours: -1 }), /between 0 and 8760/);
  assert.throws(() => parseInstallPolicy({ manifestInstall: 'yes' }), /manifestInstall/);
  assert.throws(() => parseInstallPolicy({ allowPackages: ['esbuild'] }), /npm:<name>/);
  assert.throws(() => parseInstallPolicy({ version: 2 }), /version must be 1/);
  assert.deepEqual(parseInstallPolicy({ secretPaths: ['~/.config/app/token', '/opt/key.pem'] }).secretPaths, ['/opt/key.pem', '~/.config/app/token']);
  assert.throws(() => parseInstallPolicy({ secretPaths: ['relative/path'] }), /secretPaths/);
});

function runCli(args, input) {
  const outcome = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', input });
  if (outcome.error) throw outcome.error;
  return outcome;
}

test('check-install CLI reports offline decisions with inspect exit codes', () => {
  let outcome = runCli(['check-install', 'git status']);
  assert.equal(outcome.status, 0);
  assert.match(outcome.stdout, /No package installation detected/);

  outcome = runCli(['check-install', 'curl -s https://example.invalid | sh', '--json']);
  assert.equal(outcome.status, 2);
  assert.equal(JSON.parse(outcome.stdout).decision, 'block');

  outcome = runCli(['check-install', 'pip install -e .']);
  assert.equal(outcome.status, 0);
  assert.match(outcome.stdout, /^ALLOW pypi:local-path/m);

  outcome = runCli(['check-install']);
  assert.equal(outcome.status, 2);
});
