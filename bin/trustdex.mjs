#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

import { inspectMcpConfig } from '../src/inspect.mjs';
import { inspectSkillText, inspectPluginManifest } from '../src/extensions.mjs';
import { evaluateAll } from '../src/policy.mjs';
import { getPolicyPack, mergePolicy } from '../src/policy-packs.mjs';
import { parseTrustStore, attachProvenanceAll } from '../src/provenance.mjs';
import { createSnapshot, diffSnapshots } from '../src/snapshot.mjs';
import { gateMcpConfig } from '../src/gate.mjs';
import {
  generateTrustKeyPair,
  createTrustRecord,
  verifyTrustRecord
} from '../src/trust-record.mjs';

const VERSION = '0.2.0';

function usage() {
  console.log(`TrustDex v${VERSION}

Usage:
  trustdex inspect <mcp.json> [--pack strict|official-first|development]
      [--policy policy.json] [--trust-store trust-store.json] [--json]

  trustdex inspect-skill <SKILL.md> [--pack ...] [--policy policy.json] [--json]
  trustdex inspect-plugin <plugin.json> [--pack ...] [--policy policy.json] [--json]

  trustdex gate <mcp.json> --out gated.json [--pack ...] [--policy policy.json]
      [--trust-store trust-store.json] [--include-ask] [--json]

  trustdex snapshot <mcp.json> --out snapshot.json [--pack ...]
      [--policy policy.json] [--trust-store trust-store.json]

  trustdex diff <before.json> <after.json> [--json]
  trustdex policy <strict|official-first|development>

  trustdex keygen --private trustdex-private.pem --public trustdex-public.pem
  trustdex sign <snapshot.json> --private trustdex-private.pem --out trust-record.json
      [--policy policy.json] [--source-ref <ref>]
  trustdex verify <trust-record.json> --public trustdex-public.pem
      [--snapshot snapshot.json] [--policy policy.json]

TrustDex is local-first. These commands do not upload your agent configuration.`);
}

async function readJson(file) {
  return JSON.parse(await fs.readFile(file, 'utf8'));
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
  return {
    config,
    policy: await loadPolicy(args),
    results: evaluateAll(withProvenance, await loadPolicy(args))
  };
}

async function inspectSingle(item, args) {
  const results = evaluateAll([item], await loadPolicy(args));
  printResults(results, hasFlag(args, '--json'));
  setInspectExitCode(results);
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
    else for (const change of changes) {
      console.log(`${change.type}: ${change.name}${change.signals ? ` (${change.signals.join(', ')})` : ''}`);
    }

    if (changes.some((change) =>
      ['server-added', 'signals-added', 'decision-changed', 'source-changed', 'provenance-changed'].includes(change.type)
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
