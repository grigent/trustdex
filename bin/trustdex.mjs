#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

import { inspectMcpConfig } from '../src/inspect.mjs';
import { parseCodexMcpToml, gateCodexToml } from '../src/codex-config.mjs';
import { inspectSkillText, inspectPluginManifest } from '../src/extensions.mjs';
import { evaluateAll } from '../src/policy.mjs';
import { getPolicyPack, mergePolicy } from '../src/policy-packs.mjs';
import { parseTrustStore, attachProvenanceAll } from '../src/provenance.mjs';
import {
  inspectGitHubRepository,
  inspectNpmPackage,
  inspectGitHubReleaseSignature,
  inspectMcpRegistryServer,
  provenanceObservationToClaim,
  upsertTrustStoreClaim
} from '../src/provenance-online.mjs';
import { createSnapshot, diffSnapshots } from '../src/snapshot.mjs';
import { gateMcpConfig } from '../src/gate.mjs';
import { assessReview } from '../src/review.mjs';
import {
  generateTrustKeyPair,
  createTrustRecord,
  verifyTrustRecord
} from '../src/trust-record.mjs';

const VERSION = '0.3.0';

function usage() {
  console.log(`TrustDex v${VERSION}

Usage:
  trustdex inspect <mcp.json> [--pack strict|official-first|development]
      [--policy policy.json] [--trust-store trust-store.json] [--json]

  trustdex inspect-skill <SKILL.md> [--pack ...] [--policy policy.json] [--json]
  trustdex inspect-plugin <plugin.json> [--pack ...] [--policy policy.json] [--json]
  trustdex inspect-codex <config.toml> [--pack ...] [--policy policy.json]
      [--trust-store trust-store.json] [--json]

  trustdex gate <mcp.json> --out gated.json [--pack ...] [--policy policy.json]
      [--trust-store trust-store.json] [--include-ask] [--json]
  trustdex gate-codex <config.toml> --out gated.toml [--pack ...] [--policy policy.json]
      [--trust-store trust-store.json] [--include-ask]

  trustdex provenance github <owner/repo> [--json]
  trustdex provenance github-release <owner/repo> [--json]
  trustdex provenance npm <package> [--json]
  trustdex provenance mcp <namespace/server> [--json]
  trustdex trust-source github <owner/repo> --publisher <name> --out trust-store.json
  trustdex trust-source github-release <owner/repo> --publisher <name> --out trust-store.json
  trustdex trust-source npm <package> --publisher <name> --out trust-store.json
  trustdex trust-source mcp <namespace/server> --publisher <name> --out trust-store.json

  trustdex approve <mcp.json> --private trustdex-private.pem --dir .trustdex/review
      [--pack ...] [--policy policy.json] [--trust-store trust-store.json]
  trustdex recheck <mcp.json> --review-dir .trustdex/review --public trustdex-public.pem [--json]

  trustdex snapshot <mcp.json> --out snapshot.json [--pack ...]
      [--policy policy.json] [--trust-store trust-store.json]

  trustdex diff <before.json> <after.json> [--json]
  trustdex policy <strict|official-first|development>

  trustdex keygen --private trustdex-private.pem --public trustdex-public.pem
  trustdex sign <snapshot.json> --private trustdex-private.pem --out trust-record.json
      [--policy policy.json] [--source-ref <ref>]
  trustdex verify <trust-record.json> --public trustdex-public.pem
      [--snapshot snapshot.json] [--policy policy.json]

Most commands are local-only. The provenance and trust-source commands perform explicit
network lookups to GitHub or npm when you invoke them.`);
}

async function readJson(file) {
  return JSON.parse(await fs.readFile(file, 'utf8'));
}

async function readJsonIfExists(file, fallback = null) {
  try {
    return await readJson(file);
  } catch (error) {
    if (error?.code === 'ENOENT') return fallback;
    throw error;
  }
}

async function writeFileSafe(file, content, options = {}) {
  const directory = path.dirname(path.resolve(file));
  await fs.mkdir(directory, { recursive: true });
  await fs.writeFile(file, content, options);
}

function getFlag(args, name) {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : null;
}

function hasFlag(args, name) {
  return args.includes(name);
}

function label(action) {
  if (action === 'allow') return 'ALLOW';
  if (action === 'ask') return 'ASK';
  return 'BLOCK';
}

async function loadPolicy(args) {
  const pack = getPolicyPack(getFlag(args, '--pack') || 'strict');
  const policyPath = getFlag(args, '--policy');
  return policyPath ? mergePolicy(pack, await readJson(policyPath)) : pack;
}

async function loadTrustStore(args) {
  const file = getFlag(args, '--trust-store');
  return file ? parseTrustStore(await readJson(file)) : null;
}

function printResults(results, asJson = false) {
  if (asJson) {
    console.log(JSON.stringify(results, null, 2));
    return;
  }

  for (const result of results) {
    console.log(`${label(result.action).padEnd(5)} ${result.name}`);
    console.log(`      source: ${JSON.stringify(result.source)}`);
    if (result.fingerprint) console.log(`      fingerprint: ${result.fingerprint}`);
    if (result.provenance) console.log(`      provenance: ${JSON.stringify(result.provenance)}`);
    if (result.signals?.length) console.log(`      signals: ${result.signals.join(', ')}`);
    for (const reason of result.reasons || []) console.log(`      - ${reason}`);
  }
}

function setInspectExitCode(results) {
  if (results.some((result) => result.action === 'block')) process.exitCode = 2;
  else if (results.some((result) => result.action === 'ask')) process.exitCode = 1;
}

async function evaluateMcp(configPath, args) {
  const config = await readJson(configPath);
  const inspected = inspectMcpConfig(config);
  const store = await loadTrustStore(args);
  const withProvenance = store ? attachProvenanceAll(inspected, store) : inspected;
  const policy = await loadPolicy(args);
  return {
    config,
    policy,
    store,
    results: evaluateAll(withProvenance, policy)
  };
}

async function evaluateCodex(configPath, args) {
  const text = await fs.readFile(configPath, 'utf8');
  const config = parseCodexMcpToml(text);
  const inspected = inspectMcpConfig(config);
  const store = await loadTrustStore(args);
  const withProvenance = store ? attachProvenanceAll(inspected, store) : inspected;
  const policy = await loadPolicy(args);
  return {
    text,
    config,
    policy,
    store,
    results: evaluateAll(withProvenance, policy)
  };
}

async function inspectSingle(item, args) {
  const results = evaluateAll([item], await loadPolicy(args));
  printResults(results, hasFlag(args, '--json'));
  setInspectExitCode(results);
}

function printObservation(observation, asJson) {
  if (asJson) {
    console.log(JSON.stringify(observation, null, 2));
    return;
  }
  console.log(`${observation.adapter.toUpperCase()} ${observation.subject}`);
  console.log(`Publisher hint: ${observation.publisherHint || 'none'}`);
  console.log(`Evidence: ${observation.evidence.kind} ${observation.evidence.reference}`);
  console.log('Observation only. Nothing is trusted until you explicitly create a trust-store claim.');
}

async function lookupProvenance(adapter, subject) {
  if (adapter === 'github') return inspectGitHubRepository(subject);
  if (adapter === 'github-release') return inspectGitHubReleaseSignature(subject);
  if (adapter === 'npm') return inspectNpmPackage(subject);
  if (adapter === 'mcp') return inspectMcpRegistryServer(subject);
  throw new Error('provenance adapter must be "github", "github-release", "npm", or "mcp".');
}

function printChanges(changes) {
  for (const change of changes) {
    console.log(`${change.type}: ${change.name}${change.signals ? ` (${change.signals.join(', ')})` : ''}`);
  }
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === '-h' || command === '--help') {
    usage();
    return;
  }

  if (command === '--version' || command === '-V') {
    console.log(VERSION);
    return;
  }

  if (command === 'policy') {
    console.log(JSON.stringify(getPolicyPack(args[1] || 'strict'), null, 2));
    return;
  }

  if (command === 'inspect') {
    const configPath = args[1];
    if (!configPath) throw new Error('inspect requires a path to an MCP JSON file.');

    const { results } = await evaluateMcp(configPath, args);
    printResults(results, hasFlag(args, '--json'));
    setInspectExitCode(results);
    return;
  }

  if (command === 'inspect-skill') {
    const skillPath = args[1];
    if (!skillPath) throw new Error('inspect-skill requires a path to SKILL.md.');
    await inspectSingle(inspectSkillText(await fs.readFile(skillPath, 'utf8'), skillPath), args);
    return;
  }

  if (command === 'inspect-plugin') {
    const pluginPath = args[1];
    if (!pluginPath) throw new Error('inspect-plugin requires a path to plugin.json.');
    await inspectSingle(inspectPluginManifest(await readJson(pluginPath), pluginPath), args);
    return;
  }

  if (command === 'inspect-codex') {
    const configPath = args[1];
    if (!configPath) throw new Error('inspect-codex requires a path to Codex config.toml.');
    const { results } = await evaluateCodex(configPath, args);
    printResults(results, hasFlag(args, '--json'));
    setInspectExitCode(results);
    return;
  }

  if (command === 'gate-codex') {
    const configPath = args[1];
    const out = getFlag(args, '--out');
    if (!configPath || !out) throw new Error('gate-codex requires <config.toml> and --out <gated.toml>.');
    const { text, results } = await evaluateCodex(configPath, args);
    const gated = gateCodexToml(text, results, { includeAsk: hasFlag(args, '--include-ask') });
    await writeFileSafe(out, gated);
    console.log(`Wrote ${out}`);
    const allowed = results.filter((result) => result.action === 'allow').map((result) => result.name);
    const review = results.filter((result) => result.action === 'ask').map((result) => result.name);
    const blocked = results.filter((result) => result.action === 'block').map((result) => result.name);
    console.log(`Allowed: ${allowed.length ? allowed.join(', ') : 'none'}`);
    if (review.length) console.log(`Needs review: ${review.join(', ')}`);
    if (blocked.length) console.log(`Blocked: ${blocked.join(', ')}`);
    if (review.length && !hasFlag(args, '--include-ask')) process.exitCode = 1;
    return;
  }

  if (command === 'provenance') {
    const adapter = args[1];
    const subject = args[2];
    if (!adapter || !subject) throw new Error('provenance requires <github|github-release|npm|mcp> <subject>.');
    printObservation(await lookupProvenance(adapter, subject), hasFlag(args, '--json'));
    return;
  }

  if (command === 'trust-source') {
    const adapter = args[1];
    const subject = args[2];
    const publisher = getFlag(args, '--publisher');
    const out = getFlag(args, '--out');
    if (!adapter || !subject || !publisher || !out) {
      throw new Error('trust-source requires <github|github-release|npm|mcp> <subject>, --publisher <name>, and --out <trust-store.json>.');
    }

    const observation = await lookupProvenance(adapter, subject);
    const claim = provenanceObservationToClaim(observation, publisher);
    const existing = await readJsonIfExists(out, { version: 1, claims: [] });
    const store = upsertTrustStoreClaim(existing, claim);
    parseTrustStore(store);
    await writeFileSafe(out, `${JSON.stringify(store, null, 2)}\n`);
    console.log(`Trusted ${claim.type} ${claim.subject} as "${claim.publisher}" using ${claim.evidence.kind} evidence.`);
    console.log(`Wrote ${out}`);
    return;
  }

  if (command === 'gate') {
    const configPath = args[1];
    const out = getFlag(args, '--out');
    if (!configPath || !out) throw new Error('gate requires <mcp.json> and --out <gated.json>.');

    const { config, results } = await evaluateMcp(configPath, args);
    const gated = gateMcpConfig(config, results, { includeAsk: hasFlag(args, '--include-ask') });
    await writeFileSafe(out, `${JSON.stringify(gated.config, null, 2)}\n`);

    if (hasFlag(args, '--json')) console.log(JSON.stringify(gated.summary, null, 2));
    else {
      console.log(`Wrote ${out}`);
      console.log(`Exposed ${gated.summary.exposed}/${gated.summary.total} MCP servers.`);
      if (gated.summary.needsReview.length) console.log(`Needs review: ${gated.summary.needsReview.join(', ')}`);
      if (gated.summary.blocked.length) console.log(`Blocked: ${gated.summary.blocked.join(', ')}`);
    }

    if (gated.summary.needsReview.length && !hasFlag(args, '--include-ask')) process.exitCode = 1;
    return;
  }

  if (command === 'approve') {
    const configPath = args[1];
    const privatePath = getFlag(args, '--private');
    const reviewDir = getFlag(args, '--dir');
    if (!configPath || !privatePath || !reviewDir) {
      throw new Error('approve requires <mcp.json>, --private <key.pem>, and --dir <review-directory>.');
    }

    const { policy, store, results } = await evaluateMcp(configPath, args);
    if (results.some((result) => result.action === 'block')) {
      throw new Error('Refusing to approve a configuration containing BLOCK decisions. Fix the policy or source first.');
    }

    const snapshot = createSnapshot(results);
    const record = createTrustRecord(snapshot, await fs.readFile(privatePath, 'utf8'), {
      policy,
      sourceRef: path.resolve(configPath)
    });

    await writeFileSafe(path.join(reviewDir, 'snapshot.json'), `${JSON.stringify(snapshot, null, 2)}\n`);
    await writeFileSafe(path.join(reviewDir, 'trust-record.json'), `${JSON.stringify(record, null, 2)}\n`);
    await writeFileSafe(path.join(reviewDir, 'effective-policy.json'), `${JSON.stringify(policy, null, 2)}\n`);
    if (store) {
      await writeFileSafe(path.join(reviewDir, 'trust-store.json'), `${JSON.stringify(store, null, 2)}\n`);
    }

    console.log(`APPROVED ${configPath}`);
    console.log(`Digest: ${snapshot.digest}`);
    console.log(`Review bundle: ${reviewDir}`);
    return;
  }

  if (command === 'recheck') {
    const configPath = args[1];
    const reviewDir = getFlag(args, '--review-dir');
    const publicPath = getFlag(args, '--public');
    if (!configPath || !reviewDir || !publicPath) {
      throw new Error('recheck requires <mcp.json>, --review-dir <directory>, and --public <key.pem>.');
    }

    const baseline = await readJson(path.join(reviewDir, 'snapshot.json'));
    const record = await readJson(path.join(reviewDir, 'trust-record.json'));
    const policy = await readJson(path.join(reviewDir, 'effective-policy.json'));
    const storedTrustStore = path.join(reviewDir, 'trust-store.json');
    const trustStoreExists = await readJsonIfExists(storedTrustStore, null);

    const evalArgs = [...args, '--policy', path.join(reviewDir, 'effective-policy.json')];
    if (trustStoreExists && !getFlag(args, '--trust-store')) {
      evalArgs.push('--trust-store', storedTrustStore);
    }
    const { results } = await evaluateMcp(configPath, evalArgs);
    const current = createSnapshot(results);
    const verdict = assessReview({
      record,
      publicKey: await fs.readFile(publicPath, 'utf8'),
      baseline,
      current,
      policy
    });

    if (hasFlag(args, '--json')) {
      console.log(JSON.stringify({ ...verdict, currentDigest: current.digest, approvedDigest: baseline.digest }, null, 2));
    } else if (verdict.status === 'approved') {
      console.log('APPROVED: current state matches the signed review.');
      console.log(`Digest: ${current.digest}`);
    } else if (verdict.status === 'needs-review') {
      console.log('NEEDS_REVIEW: trust-relevant state changed.');
      printChanges(verdict.changes);
    } else {
      console.log(`INVALID: ${verdict.reason}`);
    }

    if (verdict.status === 'needs-review') process.exitCode = 1;
    if (verdict.status === 'invalid') process.exitCode = 2;
    return;
  }

  if (command === 'snapshot') {
    const configPath = args[1];
    const out = getFlag(args, '--out');
    if (!configPath || !out) throw new Error('snapshot requires <mcp.json> and --out <snapshot.json>.');

    const { results } = await evaluateMcp(configPath, args);
    const snapshot = createSnapshot(results);
    await writeFileSafe(out, `${JSON.stringify(snapshot, null, 2)}\n`);
    console.log(`Wrote ${out}\nDigest: ${snapshot.digest}`);
    return;
  }

  if (command === 'diff') {
    const beforePath = args[1];
    const afterPath = args[2];
    if (!beforePath || !afterPath) throw new Error('diff requires <before.json> <after.json>.');

    const changes = diffSnapshots(await readJson(beforePath), await readJson(afterPath));
    if (hasFlag(args, '--json')) console.log(JSON.stringify(changes, null, 2));
    else if (!changes.length) console.log('No trust-relevant changes detected.');
    else printChanges(changes);

    if (changes.some((change) =>
      ['server-added', 'signals-added', 'decision-changed', 'source-changed', 'provenance-changed', 'fingerprint-changed'].includes(change.type)
    )) process.exitCode = 1;
    return;
  }

  if (command === 'keygen') {
    const privatePath = getFlag(args, '--private');
    const publicPath = getFlag(args, '--public');
    if (!privatePath || !publicPath) throw new Error('keygen requires --private <file> and --public <file>.');

    const keys = generateTrustKeyPair();
    await writeFileSafe(privatePath, keys.privateKey, { mode: 0o600 });
    await writeFileSafe(publicPath, keys.publicKey);
    console.log(`Wrote ${privatePath} and ${publicPath}`);
    return;
  }

  if (command === 'sign') {
    const snapshotPath = args[1];
    const privatePath = getFlag(args, '--private');
    const out = getFlag(args, '--out');
    if (!snapshotPath || !privatePath || !out) {
      throw new Error('sign requires <snapshot.json>, --private <key.pem>, and --out <record.json>.');
    }

    const policyPath = getFlag(args, '--policy');
    const record = createTrustRecord(
      await readJson(snapshotPath),
      await fs.readFile(privatePath, 'utf8'),
      {
        policy: policyPath ? await readJson(policyPath) : null,
        sourceRef: getFlag(args, '--source-ref')
      }
    );
    await writeFileSafe(out, `${JSON.stringify(record, null, 2)}\n`);
    console.log(`Wrote ${out}`);
    return;
  }

  if (command === 'verify') {
    const recordPath = args[1];
    const publicPath = getFlag(args, '--public');
    if (!recordPath || !publicPath) throw new Error('verify requires <record.json> and --public <key.pem>.');

    const snapshotPath = getFlag(args, '--snapshot');
    const policyPath = getFlag(args, '--policy');
    const verdict = verifyTrustRecord(
      await readJson(recordPath),
      await fs.readFile(publicPath, 'utf8'),
      {
        snapshot: snapshotPath ? await readJson(snapshotPath) : null,
        policy: policyPath ? await readJson(policyPath) : null
      }
    );
    console.log(verdict.valid ? 'VALID' : `INVALID: ${verdict.reason}`);
    if (!verdict.valid) process.exitCode = 2;
    return;
  }

  throw new Error(`Unknown command: ${command}`);
}

main().catch((error) => {
  console.error(`trustdex: ${error.message}`);
  process.exitCode = 2;
});
