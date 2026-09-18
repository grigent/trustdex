#!/usr/bin/env node
import fs from 'node:fs/promises';
import process from 'node:process';
import { inspectMcpConfig } from '../src/inspect.mjs';
import { evaluateAll } from '../src/policy.mjs';
import { createSnapshot, diffSnapshots } from '../src/snapshot.mjs';

function usage() {
  console.log(`TrustDex v0.1.0

Usage:
  trustdex inspect <mcp.json> [--policy policy.json] [--json]
  trustdex snapshot <mcp.json> --out snapshot.json [--policy policy.json]
  trustdex diff <before.json> <after.json> [--json]

TrustDex is local-first and does not upload configuration data.`);
}

async function readJson(file) {
  return JSON.parse(await fs.readFile(file, 'utf8'));
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

async function evaluate(configPath, policyPath) {
  const config = await readJson(configPath);
  const policy = policyPath ? await readJson(policyPath) : {};
  return evaluateAll(inspectMcpConfig(config), policy);
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === '-h' || command === '--help') {
    usage();
    return;
  }

  if (command === 'inspect') {
    const configPath = args[1];
    if (!configPath) throw new Error('inspect requires a path to an MCP JSON file.');

    const results = await evaluate(configPath, getFlag(args, '--policy'));
    if (hasFlag(args, '--json')) {
      console.log(JSON.stringify(results, null, 2));
    } else {
      for (const result of results) {
        console.log(`${label(result.action).padEnd(5)} ${result.name}`);
        console.log(`      source: ${JSON.stringify(result.source)}`);
        if (result.signals.length) console.log(`      signals: ${result.signals.join(', ')}`);
        for (const reason of result.reasons) console.log(`      - ${reason}`);
      }
    }

    if (results.some((result) => result.action === 'block')) process.exitCode = 2;
    else if (results.some((result) => result.action === 'ask')) process.exitCode = 1;
    return;
  }

  if (command === 'snapshot') {
    const configPath = args[1];
    const out = getFlag(args, '--out');
    if (!configPath || !out) throw new Error('snapshot requires <mcp.json> and --out <snapshot.json>.');

    const snapshot = createSnapshot(await evaluate(configPath, getFlag(args, '--policy')));
    const slash = Math.max(out.lastIndexOf('/'), out.lastIndexOf('\\'));
    if (slash > 0) await fs.mkdir(out.slice(0, slash), { recursive: true });
    await fs.writeFile(out, `${JSON.stringify(snapshot, null, 2)}\n`);
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
      ['server-added', 'signals-added', 'decision-changed', 'source-changed'].includes(change.type)
    )) process.exitCode = 1;
    return;
  }

  throw new Error(`Unknown command: ${command}`);
}

main().catch((error) => {
  console.error(`trustdex: ${error.message}`);
  process.exitCode = 2;
});
