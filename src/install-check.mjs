// Pre-install checks for package installation commands.
//
// `evaluateInstallCommand` parses a shell command offline, then looks up each
// registry package it would install in the public npm registry or PyPI and
// returns ALLOW / ASK / BLOCK items. These lookups are explicit: they happen only
// when the check-install or claude-hook commands are invoked, and only against the
// two fixed public registry hosts. Only the parsed package name is sent.
//
// What the checks mean: they compare registry metadata (publish times, install
// scripts, wheels, publishers, provenance presence, deprecation) with a local policy and check known
// malicious npm and PyPI releases against bundled advisories. An ALLOW means no signal fired.

import {
  analyzeInstallCommand,
  normalizePypiName,
  parseNpmSpec,
  parsePypiSpec
} from './install-command.mjs';
import { hasValidRegistryIntegrity } from './provenance-online.mjs';

const RANK = { allow: 0, ask: 1, block: 2 };
const FETCH_TIMEOUT_MS = 20_000;
const MAX_REGISTRY_BYTES = 64 * 1024 * 1024;
const HOUR = 3_600_000;
const DAY = 24 * HOUR;

export const SIGNAL_ACTIONS = Object.freeze({
  'pipe-to-shell': 'block',
  'obfuscated-execution': 'block',
  'package-not-found': 'block',
  'invalid-registry-metadata': 'block',
  'known-malicious-release': 'block',
  'version-not-found': 'ask',
  'recent-release': 'ask',
  'new-package': 'ask',
  'install-scripts': 'ask',
  'source-build': 'ask',
  'publisher-changed': 'ask',
  'provenance-dropped': 'ask',
  deprecated: 'ask',
  yanked: 'ask',
  'similar-to-popular': 'ask',
  'unregistered-source': 'ask',
  'custom-registry': 'ask',
  'unresolved-version': 'ask',
  'invalid-package-spec': 'ask',
  'lookup-failed': 'ask',
  'unparseable-command': 'ask',
  'opaque-arguments': 'ask',
  'manifest-install': 'ask',
  'local-source': 'allow',
  'local-bin': 'allow',
  'install-scripts-disabled': 'allow'
});

// ------------------------------------------------------------- policy

export const DEFAULT_INSTALL_POLICY = Object.freeze({
  minReleaseAgeHours: 48,
  minPackageAgeDays: 30,
  manifestInstall: 'ask',
  allowPackages: [],
  allowInstallScripts: [],
  secretPaths: [],
  allowStartupItems: []
});

// launchd labels the user created and starts or stops often, e.g.
// "com.example.backup" or "com.example.*". At least two segments must come
// before a trailing wildcard, so "*" or "com.*" cannot allow everything.
const STARTUP_LABEL_RE = /^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+(?:\.\*)?$/;

const POLICY_KEYS = new Set(['version', ...Object.keys(DEFAULT_INSTALL_POLICY)]);
const PACKAGE_REF_RE = /^(npm|pypi):((?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*)$/i;

function canonicalRef(ref) {
  const match = PACKAGE_REF_RE.exec(ref);
  if (!match) throw new Error('Install policy package references must look like npm:<name> or pypi:<name>.');
  const ecosystem = match[1].toLowerCase();
  return ecosystem === 'pypi' ? `pypi:${normalizePypiName(match[2])}` : `npm:${match[2]}`;
}

export function parseInstallPolicy(value) {
  if (value === undefined || value === null) return { ...DEFAULT_INSTALL_POLICY };
  if (typeof value !== 'object' || Array.isArray(value)) throw new Error('Install policy must be a JSON object.');
  for (const key of Object.keys(value)) {
    if (!POLICY_KEYS.has(key)) throw new Error(`Unsupported install policy key: ${key}`);
  }
  if (value.version !== undefined && value.version !== 1) throw new Error('Install policy version must be 1.');
  const policy = { ...DEFAULT_INSTALL_POLICY };
  for (const key of ['minReleaseAgeHours', 'minPackageAgeDays']) {
    if (value[key] === undefined) continue;
    if (!Number.isFinite(value[key]) || value[key] < 0 || value[key] > 24 * 365) {
      throw new Error(`Install policy ${key} must be a number between 0 and 8760.`);
    }
    policy[key] = value[key];
  }
  if (value.manifestInstall !== undefined) {
    if (!['allow', 'ask'].includes(value.manifestInstall)) throw new Error('Install policy manifestInstall must be "allow" or "ask".');
    policy.manifestInstall = value.manifestInstall;
  }
  if (value.secretPaths !== undefined) {
    if (!Array.isArray(value.secretPaths) || value.secretPaths.some((entry) => typeof entry !== 'string' || !/^(?:~\/|\/)/.test(entry))) {
      throw new Error('Install policy secretPaths must be an array of absolute or ~/ paths.');
    }
    policy.secretPaths = [...new Set(value.secretPaths)].sort();
  }
  if (value.allowStartupItems !== undefined) {
    if (!Array.isArray(value.allowStartupItems) || value.allowStartupItems.some((entry) => typeof entry !== 'string' || !STARTUP_LABEL_RE.test(entry))) {
      throw new Error('Install policy allowStartupItems must be an array of launchd labels such as "com.example.job" or "com.example.*".');
    }
    policy.allowStartupItems = [...new Set(value.allowStartupItems)].sort();
  }
  for (const key of ['allowPackages', 'allowInstallScripts']) {
    if (value[key] === undefined) continue;
    if (!Array.isArray(value[key]) || value[key].some((entry) => typeof entry !== 'string')) {
      throw new Error(`Install policy ${key} must be an array of strings.`);
    }
    policy[key] = [...new Set(value[key].map(canonicalRef))].sort();
  }
  return policy;
}

// ------------------------------------------------------------- semver

function parseVersion(value) {
  const match = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(String(value));
  if (!match) return null;
  return { major: +match[1], minor: +match[2], patch: +match[3], pre: match[4] ? match[4].split('.') : [] };
}

function compareVersions(a, b) {
  for (const key of ['major', 'minor', 'patch']) if (a[key] !== b[key]) return a[key] - b[key];
  if (!a.pre.length || !b.pre.length) return b.pre.length - a.pre.length;
  for (let i = 0; i < Math.max(a.pre.length, b.pre.length); i += 1) {
    if (a.pre[i] === undefined) return -1;
    if (b.pre[i] === undefined) return 1;
    const an = /^\d+$/.test(a.pre[i]);
    const bn = /^\d+$/.test(b.pre[i]);
    if (an && bn && +a.pre[i] !== +b.pre[i]) return +a.pre[i] - +b.pre[i];
    if (an !== bn) return an ? -1 : 1;
    if (a.pre[i] !== b.pre[i]) return a.pre[i] < b.pre[i] ? -1 : 1;
  }
  return 0;
}

const PARTIAL_RE = /^(\^|~>?|>=|<=|>|<|=)?\s*v?(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:-([0-9A-Za-z.-]+))?$/;

// Converts one comparator into predicates over parsed versions; returns null when
// the syntax is outside the supported subset.
function comparatorPredicates(text) {
  const match = PARTIAL_RE.exec(text);
  // Prerelease comparators also admit prereleases of the same version in npm; not modeled.
  if (!match || match[5] !== undefined) return null;
  const [, op = '', ma, mi, pa] = match;
  const wild = (part) => part === undefined || /^[xX*]$/.test(part);
  const nums = [ma, mi, pa].map((part) => (wild(part) ? null : +part));
  const [M, m, p] = nums;
  const v = (a, b, c) => ({ major: a, minor: b, patch: c, pre: [] });
  const ge = (bound) => (x) => compareVersions(x, bound) >= 0;
  const lt = (bound) => (x) => compareVersions(x, bound) < 0;
  if (M === null) return op === '' || op === '=' || op === '>=' ? [] : null;

  if (op === '^') {
    const lo = v(M, m ?? 0, p ?? 0);
    const hi = M > 0 || m === null ? v(M + 1, 0, 0) : m > 0 || p === null ? v(0, m + 1, 0) : v(0, 0, p + 1);
    return [ge(lo), lt(hi)];
  }
  if (op === '~' || op === '~>') {
    const lo = v(M, m ?? 0, p ?? 0);
    const hi = m === null ? v(M + 1, 0, 0) : v(M, m + 1, 0);
    return [ge(lo), lt(hi)];
  }
  if (op === '' || op === '=') {
    if (m === null) return [ge(v(M, 0, 0)), lt(v(M + 1, 0, 0))];
    if (p === null) return [ge(v(M, m, 0)), lt(v(M, m + 1, 0))];
    return [(x) => compareVersions(x, v(M, m, p)) === 0];
  }
  const full = v(M, m ?? 0, p ?? 0);
  if (op === '>=') return [ge(full)];
  if (op === '<') return [lt(full)];
  if (op === '>') {
    if (m === null) return [ge(v(M + 1, 0, 0))];
    if (p === null) return [ge(v(M, m + 1, 0))];
    return [(x) => compareVersions(x, full) > 0];
  }
  if (op === '<=') {
    if (m === null) return [lt(v(M + 1, 0, 0))];
    if (p === null) return [lt(v(M, m + 1, 0))];
    return [(x) => compareVersions(x, full) <= 0];
  }
  return null;
}

// Supports exact, x-ranges, ^, ~, comparators, space-AND, || and hyphen ranges.
// Returns a predicate, or null when the range uses unsupported syntax.
export function compileNpmRange(range) {
  const alternatives = String(range).trim().split('||');
  const sets = [];
  for (const alternative of alternatives) {
    let text = alternative.trim().replace(/(\^|~>?|>=|<=|>|<|=)\s+/g, '$1');
    const hyphen = /^(\S+)\s+-\s+(\S+)$/.exec(text);
    if (hyphen) text = `>=${hyphen[1]} <=${hyphen[2]}`;
    const predicates = [];
    for (const comparator of text ? text.split(/\s+/) : ['*']) {
      const compiled = comparatorPredicates(comparator);
      if (!compiled) return null;
      predicates.push(...compiled);
    }
    sets.push(predicates);
  }
  return (version) => {
    const parsed = parseVersion(version);
    if (!parsed || parsed.pre.length) return false;
    return sets.some((predicates) => predicates.every((predicate) => predicate(parsed)));
  };
}

// npm-install-checks checkEngine: true, false, or null when TrustDex cannot tell
// (an engines range it does not parse, or an npm version requirement).
function npmEngineOk(meta, nodeVersion) {
  const engines = meta?.engines;
  if (!engines || typeof engines !== 'object') return true;
  if (engines.node) {
    const satisfies = typeof engines.node === 'string' ? compileNpmRange(engines.node) : null;
    if (!satisfies || !nodeVersion) return null;
    if (!satisfies(nodeVersion)) return false;
  }
  return engines.npm ? null : true;
}

// npm-pick-manifest for ranges and the implicit default tag: the default tag when it
// satisfies, is not deprecated, and fits the engines; else the best-sorted match.
function pickNpmRange(doc, range, satisfies, defaultTag, engineOk) {
  const versions = doc.versions;
  const tagged = doc['dist-tags']?.[defaultTag];
  if (typeof tagged === 'string' && Object.hasOwn(versions, tagged) && (range === '*' || satisfies(tagged))) {
    const meta = versions[tagged];
    if (meta && engineOk(tagged) && !meta.deprecated) return tagged;
  }
  const entries = Object.keys(versions).filter(satisfies).map((version) => {
    const engine = engineOk(version);
    const live = !versions[version]?.deprecated;
    return { version, parsed: parseVersion(version), engine, live, best: engine && live };
  });
  entries.sort((a, b) => (b.best - a.best) || (b.engine - a.engine) || (b.live - a.live) ||
    compareVersions(b.parsed, a.parsed));
  return entries[0]?.version ?? null;
}

// Resolves a selector the way npm does; null when nothing matches, undefined when
// TrustDex cannot tell which version npm would pick.
export function resolveNpmVersion(doc, selector, options = {}) {
  const versions = Object.keys(doc.versions || {});
  if (selector.kind === 'exact') return versions.includes(selector.value) ? selector.value : null;
  if (options.before) return undefined;
  if (selector.kind === 'tag' && !selector.implicit) {
    const tagged = doc['dist-tags']?.[selector.value];
    return typeof tagged === 'string' && versions.includes(tagged) ? tagged : null;
  }
  const defaultTag = options.defaultTag ?? 'latest';
  if (!/^[A-Za-z0-9._-]+$/.test(defaultTag) || /^v?\d/.test(defaultTag)) return undefined;
  const tagged = doc['dist-tags']?.[defaultTag];
  // A missing or dangling default tag is inconsistent metadata; do not guess past it.
  if (typeof tagged !== 'string' || !versions.includes(tagged)) {
    if (selector.kind !== 'range') return null;
  }
  const range = selector.kind === 'range' ? selector.value.trim() || '*' : '*';
  const satisfies = compileNpmRange(range);
  if (!satisfies) return undefined;
  const nodeVersion = options.nodeVersion ?? process.versions.node;
  const engine = new Map(versions.map((version) => [version, npmEngineOk(doc.versions[version], nodeVersion)]));
  // Each candidate ranks on its own fields, so a pick that wins with every unknown engine
  // treated as compatible, and still wins when its own unknown engine is not, wins every case.
  const pick = pickNpmRange(doc, range, satisfies, defaultTag, (version) => engine.get(version) !== false);
  if (pick === null || engine.get(pick) !== null) return pick;
  const withoutPick = pickNpmRange(doc, range, satisfies, defaultTag,
    (version) => version !== pick && engine.get(version) !== false);
  return withoutPick === pick ? pick : undefined;
}

// ---------------------------------------------- name similarity (typosquats)

// Widely installed names used only to flag look-alike names for review. Being on
// this list is not evidence of trust and never produces an ALLOW by itself.
const POPULAR = {
  npm: `react react-dom next vue express lodash axios typescript webpack vite esbuild eslint prettier
jest vitest mocha chalk commander yargs dotenv moment dayjs date-fns uuid debug cross-env nodemon
ts-node tsx zod prisma mongoose mongodb pg mysql mysql2 sqlite3 better-sqlite3 redis ioredis
socket.io ws cors body-parser jsonwebtoken bcrypt bcryptjs passport nodemailer sharp puppeteer
playwright cheerio node-fetch got rxjs redux react-router react-router-dom tailwindcss postcss
autoprefixer sass styled-components classnames clsx framer-motion three chart.js electron svelte
nuxt rollup core-js tslib rimraf glob minimist semver fs-extra colors inquirer ora execa openai
wrangler vercel firebase stripe aws-sdk graphql ethers web3 discord.js telegraf jquery bootstrap
underscore async bluebird qs mime cookie multer helmet morgan winston pino yup joi ajv handlebars
ejs marked js-yaml yaml concurrently husky lint-staged turbo lerna nx`,
  pypi: `requests numpy pandas scipy matplotlib seaborn scikit-learn tensorflow torch torchvision keras
flask django fastapi uvicorn gunicorn pydantic sqlalchemy psycopg2 psycopg2-binary psycopg pymysql
redis celery boto3 botocore urllib3 certifi idna charset-normalizer setuptools wheel pip six
python-dateutil pytz pyyaml jinja2 markupsafe click rich typer httpx aiohttp beautifulsoup4 lxml
selenium playwright pillow opencv-python openai anthropic langchain transformers tokenizers
huggingface-hub datasets tqdm pytest black flake8 mypy ruff isort cryptography pyjwt paramiko
colorama python-dotenv jsonschema attrs protobuf grpcio google-auth pyopenssl packaging filelock
websockets ipython jupyter notebook pyarrow polars streamlit gradio scrapy pymongo
elasticsearch sentry-sdk pyinstaller virtualenv poetry pipenv tox nltk spacy xgboost lightgbm
statsmodels sympy networkx plotly openpyxl pypdf reportlab starlette alembic loguru tenacity
orjson ujson msgpack pyserial psutil docker kubernetes ansible`
};
const POPULAR_SETS = Object.fromEntries(
  Object.entries(POPULAR).map(([ecosystem, text]) => [ecosystem, new Set(text.split(/\s+/).filter(Boolean))])
);

function distance(a, b, limit) {
  if (Math.abs(a.length - b.length) > limit) return limit + 1;
  const rows = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j += 1) rows[0][j] = j;
  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      rows[i][j] = Math.min(rows[i - 1][j] + 1, rows[i][j - 1] + 1, rows[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        rows[i][j] = Math.min(rows[i][j], rows[i - 2][j - 2] + 1);
      }
    }
  }
  return rows[a.length][b.length];
}

export function similarPopularName(ecosystem, name) {
  const set = POPULAR_SETS[ecosystem];
  const plain = ecosystem === 'npm' ? name.toLowerCase().replace(/^@[^/]+\//, '') : name;
  if (!set || set.has(name.toLowerCase()) || /^@types\//i.test(name)) return null;
  const squash = (value) => value.replace(/[-_.]/g, '');
  for (const popular of set) {
    if (plain === popular && name !== popular) return popular;
    if (squash(plain) === squash(popular)) return popular;
    if (plain.length < 4) continue;
    const limit = popular.length <= 6 ? 1 : 2;
    if (distance(plain, popular, limit) <= limit) return popular;
  }
  return null;
}

// ------------------------------------------------------------ registry

async function fetchRegistryJson(url, fetchImpl) {
  if (typeof fetchImpl !== 'function') throw new Error('fetch() is unavailable; Node.js 20+ is required.');
  const response = await fetchImpl(url, {
    headers: { Accept: 'application/json', 'User-Agent': 'trustdex' },
    redirect: 'error',
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS)
  });
  if (response?.status === 404) return { notFound: true };
  if (!response?.ok) throw new Error(`Registry lookup failed (HTTP ${response?.status ?? 'unknown'}).`);
  const length = Number(response.headers?.get?.('content-length'));
  if (Number.isFinite(length) && length > MAX_REGISTRY_BYTES) throw new Error('Registry response is too large.');
  return { data: await response.json() };
}

function age(now, iso) {
  const time = Date.parse(iso);
  return Number.isFinite(time) ? now - time : null;
}

function hours(ms) {
  return Math.max(0, Math.floor(ms / HOUR));
}

async function checkNpm(item, parsed, context) {
  const { policy, fetchImpl, now } = context;
  const encoded = parsed.name.startsWith('@') ? `@${encodeURIComponent(parsed.name.slice(1))}` : encodeURIComponent(parsed.name);
  const result = await fetchRegistryJson(`https://registry.npmjs.org/${encoded}`, fetchImpl);
  if (result.notFound) return item.signal('package-not-found', 'The npm registry has no package with this name.');
  const doc = result.data;
  if (!doc || doc.name !== parsed.name || doc.time?.unpublished || !doc.versions || typeof doc.versions !== 'object') {
    return item.signal('invalid-registry-metadata', 'npm registry metadata is missing, unpublished, or does not match the name.');
  }

  const version = resolveNpmVersion(doc, parsed.selector, context.npmResolution);
  if (version === undefined) {
    item.signal('unresolved-version', 'TrustDex cannot tell which version npm would install for this range, tag, --tag, --before, or engines requirement; pin an exact version.');
    return;
  }
  if (version === null) return item.signal('version-not-found', 'No published version matches the requested version or tag.');
  if (blockKnownRelease(item, npmMalwareAdvisory(parsed.name, version), version)) return;
  item.version = version;
  const meta = doc.versions[version];
  if (!meta || meta.version && meta.version !== version || !hasValidRegistryIntegrity(meta.dist?.integrity)) {
    return item.signal('invalid-registry-metadata', 'The resolved version has no valid integrity metadata.');
  }

  const ref = `npm:${parsed.name}`;
  const released = age(now, doc.time?.[version]);
  if (released === null) item.signal('lookup-failed', 'The registry does not report when this version was published.');
  else if (released < policy.minReleaseAgeHours * HOUR) {
    const older = olderNpmRelease(doc, parsed.selector, now - policy.minReleaseAgeHours * HOUR);
    const alternative = older
      ? ` Use ${parsed.name}@${older} instead (published ${Math.floor((now - Date.parse(doc.time[older])) / DAY)} days ago), or wait.`
      : '';
    item.signal('recent-release', `Version published ${hours(released)}h ago (policy minimum ${policy.minReleaseAgeHours}h); hijacked releases are usually caught within this window.${alternative}`);
  }
  const created = age(now, doc.time?.created);
  if (created !== null && created < policy.minPackageAgeDays * DAY && !policy.allowPackages.includes(ref)) {
    item.signal('new-package', `Package first published ${Math.floor(created / DAY)} days ago (policy minimum ${policy.minPackageAgeDays} days).`);
  }

  const scripts = meta.scripts && typeof meta.scripts === 'object' ? meta.scripts : {};
  const hasScripts = ['preinstall', 'install', 'postinstall'].some((key) => typeof scripts[key] === 'string') ||
    meta.hasInstallScript === true || meta.gypfile === true;
  if (hasScripts) {
    if (item.ignoreScripts) item.signal('install-scripts-disabled', 'Install scripts exist but this command disables them.');
    else if (!policy.allowInstallScripts.includes(ref)) {
      item.signal('install-scripts', 'This version runs preinstall/install/postinstall code on your machine during installation.');
    }
  }
  if (typeof meta.deprecated === 'string' && meta.deprecated) item.signal('deprecated', 'This version is marked deprecated on npm.');

  // Publisher continuity: has the account that published this version published any
  // earlier version of the package? A first-time publisher on an established package
  // is worth a look while the release is recent (within minPackageAgeDays); an old
  // release under a new account that the ecosystem has not withdrawn is usually a
  // planned handover. Account names are not reported.
  const publisher = meta._npmUser?.name;
  const releasedAt = Date.parse(doc.time?.[version]);
  if (publisher && Number.isFinite(releasedAt) && now - releasedAt < policy.minPackageAgeDays * DAY) {
    const earlier = Object.keys(doc.versions)
      .filter((other) => other !== version && Date.parse(doc.time?.[other]) < releasedAt)
      .map((other) => doc.versions[other]?._npmUser?.name)
      .filter(Boolean);
    if (earlier.length && !earlier.includes(publisher)) {
      item.signal('publisher-changed', 'This version was published by an account that never published an earlier version of this package.');
    }
  }

  // Provenance continuity: an established package that published earlier versions
  // with npm provenance, then a recent version without it, matches releases pushed
  // with a stolen token instead of the project's CI. Only the presence of the
  // registry's provenance metadata is compared; attestations are not verified.
  if (Number.isFinite(releasedAt) && now - releasedAt < policy.minPackageAgeDays * DAY && !hasNpmProvenance(meta)) {
    const attestedEarlier = Object.keys(doc.versions)
      .some((other) => other !== version && Date.parse(doc.time?.[other]) < releasedAt && hasNpmProvenance(doc.versions[other]));
    if (attestedEarlier) {
      item.signal('provenance-dropped', 'Earlier versions of this package were published with npm provenance, but this version has none.');
    }
  }

  const similar = similarPopularName('npm', parsed.name);
  if (similar && !policy.allowPackages.includes(ref)) {
    item.signal('similar-to-popular', `Name is one or two characters away from the popular package "${similar}".`);
  }
}

function hasNpmProvenance(meta) {
  const provenance = meta?.dist?.attestations?.provenance;
  return Boolean(provenance && typeof provenance === 'object' && typeof provenance.predicateType === 'string' && provenance.predicateType);
}

// The newest stable, non-deprecated version published before `cutoff`, within the
// requested range when there is one, as a safe alternative to a too-recent release.
function olderNpmRelease(doc, selector, cutoff) {
  const satisfies = selector.kind === 'range' ? compileNpmRange(selector.value) : null;
  const candidates = Object.keys(doc.versions || {})
    .filter((version) => {
      const parsed = parseVersion(version);
      const published = Date.parse(doc.time?.[version]);
      return parsed && !parsed.pre.length && Number.isFinite(published) && published < cutoff &&
        !doc.versions[version]?.deprecated && !npmMalwareAdvisory(doc.name, version) && (!satisfies || satisfies(version));
    })
    .sort((a, b) => compareVersions(parseVersion(b), parseVersion(a)));
  return candidates[0] ?? null;
}

function pypiReleaseTime(files) {
  const times = (Array.isArray(files) ? files : [])
    .map((file) => Date.parse(file?.upload_time_iso_8601 || file?.upload_time))
    .filter(Number.isFinite);
  return times.length ? Math.min(...times) : null;
}

const GHSA = (id) => `https://github.com/advisories/${id}`;

// Public PyPI malware advisories keyed by normalized project and final release.
const PYPI_MALWARE_ADVISORIES = new Map([
  ['agent-framework', new Map([
    ['1.26.1', GHSA('GHSA-764m-3ppc-5m73')],
    ['1.26.2', GHSA('GHSA-764m-3ppc-5m73')]
  ])]
]);

const VANT_NOTICE = 'https://github.com/youzan/vant/discussions/13273';
const NPM_ALL_VERSIONS_MALWARE_ADVISORIES = new Map([
  ['@structureit/ir-dealapi-js', GHSA('GHSA-gq28-39q4-2fq3')],
  ['@zervonex/baileys', GHSA('GHSA-j2m6-4cjj-vv5m')]
]);
const NPM_MALWARE_ADVISORIES = new Map([
  ['abir-fca', new Map([['0.0.25', GHSA('GHSA-5rhq-849p-frrr')]])],
  ['fca-uzair-dev', new Map([['1.2.0', GHSA('GHSA-f84q-56c5-63xh')]])],
  ['obfuscation-detector', new Map([
    ['3.0.1', GHSA('GHSA-2f84-r5f9-388p')],
    ['3.1.0', GHSA('GHSA-2f84-r5f9-388p')]
  ])],
  ['vant', new Map(['2.13.3', '2.13.4', '2.13.5', '3.6.13', '3.6.14', '3.6.15', '4.9.11', '4.9.12', '4.9.13', '4.9.14']
    .map((version) => [version, VANT_NOTICE]))],
  ['@wppconnect-team/wppconnect', new Map([['2.4.1', GHSA('GHSA-cxc9-87g6-qrj9')]])],
  ['@wppconnect/server', new Map([['2.10.82', 'https://github.com/wppconnect-team/wppconnect-server/issues/2734']])],
  ['qrcode-reader-vue3', new Map([['3.1.4', GHSA('GHSA-9q69-8j7m-ppmh')]])]
]);

function npmMalwareAdvisory(name, version) {
  const allVersions = NPM_ALL_VERSIONS_MALWARE_ADVISORIES.get(name);
  if (allVersions) return allVersions;
  if (typeof version !== 'string') return undefined;
  // npm ignores build metadata when matching versions, so `1.2.3+x` installs 1.2.3.
  return NPM_MALWARE_ADVISORIES.get(name)?.get(version.trim().replace(/^[=v]+/i, '').replace(/\+.*$/, ''));
}

function blockKnownRelease(item, advisory, version) {
  if (!advisory) return false;
  item.version = version;
  item.signal('known-malicious-release', `This release was identified as malicious in ${advisory}.`);
  return true;
}

function pypiMalwareAdvisory(name, version) {
  const advisories = PYPI_MALWARE_ADVISORIES.get(name);
  if (!advisories || typeof version !== 'string') return undefined;
  // PEP 440 final releases can have a leading v, epoch zero, and zero padding.
  const match = /^v?(?:0+!)?(\d+(?:\.\d+)*)$/i.exec(version);
  if (!match) return undefined;
  const release = match[1].split('.').map((part) => part.replace(/^0+(?=\d)/, ''));
  while (release.length > 1 && release.at(-1) === '0') release.pop();
  return advisories.get(release.join('.'));
}

function blockKnownPypiRelease(item, name, version) {
  return blockKnownRelease(item, pypiMalwareAdvisory(name, version), version);
}

async function checkPypi(item, parsed, context) {
  const { policy, fetchImpl, now } = context;
  const result = await fetchRegistryJson(`https://pypi.org/pypi/${encodeURIComponent(parsed.name)}/json`, fetchImpl);
  if (result.notFound) return item.signal('package-not-found', 'PyPI has no project with this name.');
  const doc = result.data;
  if (!doc?.info?.name || normalizePypiName(doc.info.name) !== parsed.name || !doc.releases || typeof doc.releases !== 'object') {
    return item.signal('invalid-registry-metadata', 'PyPI metadata is missing or does not match the name.');
  }
  if (parsed.selector.kind === 'range') {
    item.signal('unresolved-version', 'The version constraint is not resolved by TrustDex; pin an exact version with ==.');
    return;
  }
  const version = parsed.selector.kind === 'exact' ? parsed.selector.value : doc.info.version;
  if (parsed.selector.kind === 'latest' && blockKnownPypiRelease(item, parsed.name, version)) return;
  const files = doc.releases[version];
  if (!Array.isArray(files)) return item.signal('version-not-found', 'No release matches the requested version.');
  item.version = version;
  if (!files.length) return item.signal('invalid-registry-metadata', 'The release has no downloadable files.');
  if (files.some((file) => !file?.digests?.sha256)) {
    return item.signal('invalid-registry-metadata', 'A release file has no SHA-256 digest.');
  }

  const ref = `pypi:${parsed.name}`;
  const releasedAt = pypiReleaseTime(files);
  if (releasedAt === null) item.signal('lookup-failed', 'PyPI does not report when this release was uploaded.');
  else if (now - releasedAt < policy.minReleaseAgeHours * HOUR) {
    const cutoff = now - policy.minReleaseAgeHours * HOUR;
    const older = Object.entries(doc.releases)
      .filter(([candidate, candidateFiles]) => /^\d+(?:\.\d+)*$/.test(candidate) && Array.isArray(candidateFiles) &&
        candidateFiles.length && !candidateFiles.every((file) => file.yanked === true) &&
        !pypiMalwareAdvisory(parsed.name, candidate) && pypiReleaseTime(candidateFiles) < cutoff)
      .sort((a, b) => pypiReleaseTime(b[1]) - pypiReleaseTime(a[1]))[0]?.[0];
    const alternative = older ? ` Use ${parsed.name}==${older} instead, or wait.` : '';
    item.signal('recent-release', `Release uploaded ${hours(now - releasedAt)}h ago (policy minimum ${policy.minReleaseAgeHours}h); hijacked releases are usually caught within this window.${alternative}`);
  }
  const firstAt = Math.min(...Object.values(doc.releases).map(pypiReleaseTime).filter((value) => value !== null));
  if (Number.isFinite(firstAt) && now - firstAt < policy.minPackageAgeDays * DAY && !policy.allowPackages.includes(ref)) {
    item.signal('new-package', `Project first uploaded ${Math.floor((now - firstAt) / DAY)} days ago (policy minimum ${policy.minPackageAgeDays} days).`);
  }
  if (files.every((file) => file.yanked === true)) item.signal('yanked', 'This release has been yanked on PyPI.');
  if (!files.some((file) => file.packagetype === 'bdist_wheel') && !policy.allowInstallScripts.includes(ref)) {
    item.signal('source-build', 'No wheel is published, so installing runs the package build code on your machine.');
  }
  const similar = similarPopularName('pypi', parsed.name);
  if (similar && !policy.allowPackages.includes(ref)) {
    item.signal('similar-to-popular', `Name is one or two characters away from the popular project "${similar}".`);
  }
}

// --------------------------------------------------------- evaluation

function makeItem(name, extra = {}) {
  const item = { name, kind: 'package-install', signals: [], reasons: [], ...extra };
  item.signal = (signal, reason) => {
    if (!item.signals.includes(signal)) item.signals.push(signal);
    if (reason) item.reasons.push(reason);
  };
  return item;
}

function finish(item) {
  delete item.signal;
  item.action = item.signals.reduce((current, signal) => {
    const action = SIGNAL_ACTIONS[signal] ?? 'ask';
    return RANK[action] > RANK[current] ? action : current;
  }, 'allow');
  if (item.version && !item.name.endsWith(`@${item.version}`)) item.name = `${item.name}@${item.version}`;
  delete item.version;
  delete item.ignoreScripts;
  return item;
}

export function overallAction(items) {
  return items.reduce((current, item) => (RANK[item.action] > RANK[current] ? item.action : current), 'allow');
}

export async function evaluateInstallCommand(command, options = {}) {
  const policy = options.policy ? parseInstallPolicy(options.policy) : { ...DEFAULT_INSTALL_POLICY };
  const context = {
    policy,
    fetchImpl: options.fetchImpl ?? globalThis.fetch,
    now: options.now ?? Date.now(),
    nodeVersion: options.nodeVersion
  };
  const localBinExists = typeof options.localBinExists === 'function' ? options.localBinExists : () => false;
  const { findings } = analyzeInstallCommand(command);
  const items = [];
  const seen = new Set();

  for (const finding of findings) {
    if (finding.kind === 'pipe-to-shell') {
      const item = makeItem('command:download-to-interpreter');
      item.signal('pipe-to-shell', 'Downloaded content is executed directly by a shell or interpreter without review.');
      items.push(item);
      continue;
    }
    if (finding.kind === 'decoded-to-interpreter') {
      const item = makeItem('command:decoded-to-interpreter');
      item.signal('obfuscated-execution', 'Decodes hidden content (base64, hex, compressed data) and runs it as a program, a common way to hide malicious commands.');
      items.push(item);
      continue;
    }
    if (finding.kind === 'unparseable-command' || finding.kind === 'opaque-arguments') {
      const item = makeItem('command:unparsed');
      item.signal(finding.kind, 'TrustDex could not determine which packages this command installs.');
      items.push(item);
      continue;
    }
    if (finding.kind === 'custom-registry') {
      const item = makeItem(`${finding.ecosystem}:custom-registry`);
      item.signal('custom-registry', 'The command points the installer at a non-default registry or index; packages from it are not checked.');
      items.push(item);
      continue;
    }
    if (finding.kind === 'manifest') {
      const item = makeItem(`${finding.ecosystem}:project-dependencies`);
      if (policy.manifestInstall === 'allow') {
        item.signal('local-source', 'Installs the project manifest or lockfile; packages are not resolved by TrustDex (manifestInstall=allow).');
      } else {
        item.signal('manifest-install', 'Installs from a project manifest or lockfile; TrustDex does not resolve those packages.');
      }
      items.push(item);
      continue;
    }

    const parsed = finding.ecosystem === 'npm'
      ? parseNpmSpec(finding.spec)
      : parsePypiSpec(finding.spec, { editable: finding.editable });
    if (parsed.type === 'local') {
      const item = makeItem(`${finding.ecosystem}:local-path`);
      item.signal('local-source', 'Installs from a local path.');
      items.push(item);
      continue;
    }
    if (parsed.type === 'unregistered') {
      const item = makeItem(`${finding.ecosystem}:url-or-git-source`);
      item.signal('unregistered-source', 'Installs from a URL, git repository, or tarball instead of the registry; it has no registry metadata to check.');
      items.push(item);
      continue;
    }
    if (parsed.type !== 'registry') {
      const item = makeItem(`${finding.ecosystem}:invalid-spec`);
      item.signal('invalid-package-spec', 'The package argument could not be parsed.');
      items.push(item);
      continue;
    }
    if (finding.localBinCandidate && !parsed.name.includes('/') && parsed.selector.kind === 'tag' &&
        parsed.selector.value === 'latest' && !finding.spec.includes('@') && localBinExists(parsed.name, finding.dir ?? null)) {
      const item = makeItem(`npm:local-bin:${parsed.name}`);
      item.signal('local-bin', 'Runs an executable already installed in the project node_modules/.bin.');
      items.push(item);
      continue;
    }

    const item = makeItem(`${finding.ecosystem}:${parsed.name}`, { ignoreScripts: Boolean(finding.ignoreScripts) });
    if (finding.ecosystem === 'npm') {
      const pinned = parsed.selector.kind === 'exact' ? parsed.selector.value : undefined;
      if (blockKnownRelease(item, npmMalwareAdvisory(parsed.name, pinned), pinned)) {
        items.push(item);
        continue;
      }
    }
    if (finding.ecosystem === 'pypi') {
      const { kind, value } = parsed.selector;
      // The generic parser leaves pins with an epoch in the unresolved range category.
      const pinned = kind === 'exact' ? value : /^===?(v?0+!\d+(?:\.\d+)*)$/i.exec(value ?? '')?.[1];
      if (blockKnownPypiRelease(item, parsed.name, pinned)) {
        items.push(item);
        continue;
      }
    }
    if (finding.customRegistry) {
      item.signal('custom-registry', 'The command installs this package from a non-default registry or index, so public registry metadata does not apply.');
      items.push(item);
      continue;
    }

    const key = `${finding.ecosystem}:${parsed.name}:${JSON.stringify(parsed.selector)}:${Boolean(finding.ignoreScripts)}:${finding.defaultTag ?? ''}:${Boolean(finding.before)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    try {
      if (finding.ecosystem === 'npm') {
        await checkNpm(item, parsed, { ...context, npmResolution: { defaultTag: finding.defaultTag, before: finding.before, nodeVersion: context.nodeVersion } });
      }
      else await checkPypi(item, parsed, context);
    } catch {
      item.signal('lookup-failed', 'The registry lookup failed, so the package could not be checked.');
    }
    items.push(item);
  }

  return { policy, items: items.map(finish) };
}
