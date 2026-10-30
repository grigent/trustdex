#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

import { inspectMcpConfig } from '../src/inspect.mjs';
import { parseCodexMcpToml, gateCodexToml } from '../src/codex-config.mjs';
import { inspectCodexSettingsStack, inspectCodexSettingsText } from '../src/codex-settings.mjs';
import { parseClaudeMcpConfig } from '../src/claude-config.mjs';
import {
  inspectClaudeMcpPermissionBindings,
  inspectClaudeSettings,
  inspectClaudeSettingsStack
} from '../src/claude-settings.mjs';
import { inspectSkillText, inspectPluginManifest } from '../src/extensions.mjs';
import { inspectIdeExtensionsDir } from '../src/ide-extensions.mjs';
import { evaluateAll } from '../src/policy.mjs';
import { getPolicyPack, mergePolicy, validatePolicyOverlay } from '../src/policy-packs.mjs';
import { parseTrustStore, attachProvenanceAll } from '../src/provenance.mjs';
import {
  inspectGitHubRepository,
  inspectNpmPackage,
  inspectGitHubReleaseSignature,
  inspectMcpRegistryServer,
  provenanceObservationToClaim,
  upsertTrustStoreClaim,
  verifyArtifactBytes
} from '../src/provenance-online.mjs';
import { createSnapshot, diffSnapshots } from '../src/snapshot.mjs';
import {
  createPermissionPostureSnapshot,
  diffPermissionPostureSnapshots
} from '../src/posture.mjs';
import {
  codexAutomaticGrantProjection,
  createToolPermissionBindingSnapshot,
  diffToolPermissionBindingSnapshots
} from '../src/bindings.mjs';
import {
  createEffectiveRuntimeEvidence,
  diffEffectiveRuntimeEvidence
} from '../src/runtime-evidence.mjs';
import {
  createRuntimeInventoryAttestation,
  verifyRuntimeInventoryAttestation
} from '../src/runtime-attestation.mjs';
import { gateMcpConfig } from '../src/gate.mjs';
import { createDecisionError, createDecisionReport } from '../src/decisions.mjs';
import { assessReview } from '../src/review.mjs';
import { parseEd25519PublicKeyPem, parseKeyset, spkiKeyId } from '../src/keyset.mjs';
import {
  generateTrustKeyPair,
  createTrustRecord,
  verifyTrustRecord
} from '../src/trust-record.mjs';

// Read the version from the package manifest so --version cannot drift from releases.
const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;

function usage() {
  console.log(`TrustDex v${VERSION}

Usage:
  trustdex inspect <mcp.json> [--pack strict|official-first|development]
      [--policy policy.json] [--trust-store trust-store.json] [--json]

  trustdex inspect-skill <SKILL.md> [--pack ...] [--policy policy.json] [--json]
  trustdex inspect-plugin <plugin.json> [--pack ...] [--policy policy.json] [--json]
  trustdex inspect-ide-extensions <extensions-dir> [--pack ...] [--policy policy.json] [--json]
  trustdex snapshot-ide-extensions <extensions-dir> --out snapshot.json [--pack ...]
  trustdex approve-ide-extensions <extensions-dir> --private key.pem --dir review [--pack ...]
  trustdex recheck-ide-extensions <extensions-dir> --review-dir review
      (--public key.pem | --keyset keyset.json) [--json]
      IDE extension commands read a VS Code-compatible extensions directory you name
      (for example ~/.vscode/extensions or ~/.cursor/extensions). Nothing is executed.
  trustdex inspect-codex <config.toml> [--pack ...] [--policy policy.json]
      [--trust-store trust-store.json] [--json]
  trustdex inspect-codex-settings <config.toml> [--pack ...] [--policy policy.json] [--json]
  trustdex snapshot-codex-settings <config.toml> --out posture.json [--pack ...]
  trustdex inspect-codex-settings-stack [--system file] [--managed file] [--user file]
      [--profile file] [--project file ...] [--cli file] [--json]
  trustdex snapshot-codex-settings-stack [same source flags] --out posture.json

  trustdex gate <mcp.json> --out gated.json [--pack ...] [--policy policy.json]
      [--trust-store trust-store.json] [--include-ask] [--json]
  trustdex gate-codex <config.toml> --out gated.toml [--pack ...] [--policy policy.json]
      [--trust-store trust-store.json] [--include-ask]
  trustdex snapshot-codex <config.toml> --out snapshot.json [--pack ...]
  trustdex approve-codex <config.toml> --private key.pem --dir review [--pack ...]
  trustdex recheck-codex <config.toml> --review-dir review
      (--public key.pem | --keyset keyset.json) [--json]

  trustdex inspect-claude <.mcp.json> [--pack ...] [--policy policy.json] [--json]
  trustdex inspect-claude-settings <settings.json> [--pack ...] [--policy policy.json] [--json]
  trustdex snapshot-claude-settings <settings.json> --out posture.json [--pack ...]
  trustdex inspect-claude-settings-stack [--user file] [--project file] [--local file]
      [--session file] [--managed file] [--json]
  trustdex snapshot-claude-settings-stack [same source flags] --out posture.json
  trustdex snapshot-claude-bindings <.mcp.json> --settings file --out bindings.json
      [--trust-store trust-store.json] [--pack ...]
  trustdex snapshot-claude-bindings <.mcp.json> [Claude stack source flags]
      --out bindings.json [--trust-store trust-store.json] [--pack ...]
  trustdex gate-claude <.mcp.json> --out gated.json [--pack ...] [--policy policy.json]
  trustdex snapshot-claude <.mcp.json> --out snapshot.json [--pack ...]
  trustdex approve-claude <.mcp.json> --private key.pem --dir review [--pack ...]
  trustdex recheck-claude <.mcp.json> --review-dir review
      (--public key.pem | --keyset keyset.json) [--json]
  Claude MCP commands accept the same policy/trust-store flags as their generic counterparts.

  trustdex provenance github <owner/repo> [--json]
  trustdex provenance github-release <owner/repo> [--json]
  trustdex provenance npm <package> [--json]
  trustdex provenance mcp <namespace/server> [--json]
  trustdex trust-source github <owner/repo> --publisher <name> --out trust-store.json
  trustdex trust-source github-release <owner/repo> --publisher <name> --out trust-store.json
  trustdex trust-source npm <package> --publisher <name> --out trust-store.json
      [--artifact downloaded-package.tgz]
  trustdex trust-source mcp <namespace/server> --publisher <name> --out trust-store.json
      [--artifact downloaded-package]

  trustdex approve <mcp.json> --private trustdex-private.pem --dir .trustdex/review
      [--pack ...] [--policy policy.json] [--trust-store trust-store.json]
  trustdex recheck <mcp.json> --review-dir .trustdex/review
      (--public trustdex-public.pem | --keyset keyset.json) [--json]

  trustdex snapshot <mcp.json> --out snapshot.json [--pack ...]
      [--policy policy.json] [--trust-store trust-store.json]

  trustdex diff <before.json> <after.json> [--json]
  trustdex diff-permissions <before.json> <after.json> [--json]
  trustdex snapshot-codex-bindings <config.toml> --out bindings.json
      [--trust-store trust-store.json] [--pack ...]
  trustdex diff-bindings <before.json> <after.json> [--json]
  trustdex snapshot-runtime-tools <bindings.json> <inventory.json> --out runtime.json
      [--attestation attestation.json (--public key.pem | --keyset keyset.json)]
      [--max-age-seconds n]
      [--require-authenticated]
  trustdex diff-runtime-tools <before.json> <after.json> [--json]
  trustdex sign-runtime-inventory <inventory.json> --private key.pem --out attestation.json
      [--ttl-seconds 300]
  trustdex verify-runtime-inventory <inventory.json> --attestation attestation.json
      (--public key.pem | --keyset keyset.json) [--max-age-seconds n] [--json]
  trustdex policy <strict|official-first|development>

  trustdex keygen --private trustdex-private.pem --public trustdex-public.pem
  trustdex sign <snapshot.json> --private trustdex-private.pem --out trust-record.json
      [--policy policy.json] [--source-ref <ref>]
  trustdex verify <trust-record.json> (--public trustdex-public.pem | --keyset keyset.json)
      [--snapshot snapshot.json] [--policy policy.json]
  trustdex key-id <public.pem>
      Print the SHA-256 key ID used in trustdex-keyset files and runtime attestations.

Verifying commands accept --keyset keyset.json instead of --public: a trustdex-keyset v1
allowlist with key purposes, validity windows, rotation, and revocations
(see docs/RUNTIME_EVIDENCE.md). Giving both flags is an error.

Inspection commands (inspect, inspect-*) accept --decisions to print the versioned
trustdex-decisions JSON contract for agents and automation (see docs/AGENT_INTEGRATION.md).

Most commands are local-only. The provenance and trust-source commands perform explicit
network lookups to GitHub or npm when you invoke them.`);
}

// JSON.parse messages can quote part of the input, which may be a credential.
class InvalidJsonError extends SyntaxError {}

async function readJson(file) {
  const text = await fs.readFile(file, 'utf8');
  try {
    return JSON.parse(text);
  } catch (error) {
    if (error instanceof SyntaxError) throw new InvalidJsonError(`Invalid JSON in ${path.basename(file)}.`);
    throw error;
  }
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

function getFlags(args, name) {
  const values = [];
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] !== name) continue;
    const value = args[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`${name} requires a file path.`);
    values.push(value);
  }
  return values;
}

function hasFlag(args, name) {
  return args.includes(name);
}

function getIntegerFlag(args, name, fallback = undefined) {
  const value = getFlag(args, name);
  if (value === null) return fallback;
  if (!/^\d+$/.test(value)) throw new Error(`${name} requires a non-negative integer.`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new Error(`${name} exceeds the supported integer range.`);
  return parsed;
}

// Verifying commands take exactly one key source: a pinned --public PEM or a validated
// --keyset allowlist. Returns null when neither is given so callers can name the command.
async function loadVerifier(args) {
  const keysetPaths = getFlags(args, '--keyset');
  const hasPublic = hasFlag(args, '--public');
  if (keysetPaths.length && hasPublic) throw new Error('Use either --public or --keyset, not both.');
  if (keysetPaths.length > 1) throw new Error('--keyset may be given only once.');
  if (keysetPaths.length) return parseKeyset(await readJson(keysetPaths[0]));
  const publicPath = getFlag(args, '--public');
  return publicPath ? fs.readFile(publicPath, 'utf8') : null;
}

function hasVerifier(verifier) {
  return verifier !== null && verifier !== undefined;
}

function label(action) {
  if (action === 'allow') return 'ALLOW';
  if (action === 'ask') return 'ASK';
  return 'BLOCK';
}

async function loadPolicy(args) {
  const pack = getPolicyPack(getFlag(args, '--pack') || 'strict');
  const policyPath = getFlag(args, '--policy');
  return policyPath ? mergePolicy(pack, validatePolicyOverlay(await readJson(policyPath))) : pack;
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

// --decisions prints the versioned agent decision contract instead of human output,
// using the same policy object that produced the results.
async function emitInspection(results, args, policy) {
  if (hasFlag(args, '--decisions')) {
    const report = createDecisionReport(results, { command: args[0], trustdexVersion: VERSION, policy });
    console.log(JSON.stringify(report, null, 2));
    process.exitCode = report.exitCode;
    return;
  }
  printResults(results, hasFlag(args, '--json'));
  setInspectExitCode(results);
}

const DECISION_COMMANDS = new Set([
  'inspect', 'inspect-claude', 'inspect-skill', 'inspect-plugin', 'inspect-codex',
  'inspect-claude-settings', 'inspect-claude-settings-stack',
  'inspect-codex-settings', 'inspect-codex-settings-stack', 'inspect-ide-extensions'
]);

function setInspectExitCode(results) {
  if (results.some((result) => result.action === 'block')) process.exitCode = 2;
  else if (results.some((result) => result.action === 'ask')) process.exitCode = 1;
}

async function evaluateMcp(configPath, args, options = {}) {
  const isClaude = options.claude === true || args[0].endsWith('-claude');
  let config;
  try { config = await readJson(configPath); } catch (error) {
    if (isClaude && error instanceof SyntaxError) throw new Error('Invalid Claude MCP JSON.');
    throw error;
  }
  const inspectionConfig = isClaude ? parseClaudeMcpConfig(config) : config;
  const inspected = inspectMcpConfig(inspectionConfig);
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

async function evaluateIdeExtensions(directory, args) {
  if (getFlag(args, '--trust-store')) {
    throw new Error('IDE extension commands do not accept --trust-store; pin exact versions with trustedIdeExtensions.');
  }
  const policy = await loadPolicy(args);
  return {
    policy,
    store: null,
    results: evaluateAll(await inspectIdeExtensionsDir(directory), policy)
  };
}

// Signed snapshot, approve, and recheck share one engine; the command suffix picks the adapter.
async function evaluateForReview(command, input, args) {
  if (command.endsWith('-ide-extensions')) return evaluateIdeExtensions(input, args);
  if (command.endsWith('-codex')) return evaluateCodex(input, args);
  return evaluateMcp(input, args);
}

async function inspectSingle(item, args) {
  const policy = await loadPolicy(args);
  const results = evaluateAll([item], policy);
  await emitInspection(results, args, policy);
}

async function evaluateClaudeSettings(settingsPath, args) {
  let settings;
  try { settings = await readJson(settingsPath); } catch (error) {
    if (error instanceof SyntaxError) throw new Error('Invalid Claude settings JSON.');
    throw error;
  }
  const policy = await loadPolicy(args);
  const [result] = evaluateAll([inspectClaudeSettings(settings, settingsPath)], policy);
  return { policy, result };
}

async function evaluateCodexSettings(configPath, args) {
  const policy = await loadPolicy(args);
  const [result] = evaluateAll([
    inspectCodexSettingsText(await fs.readFile(configPath, 'utf8'), configPath)
  ], policy);
  return { policy, result };
}

async function evaluateClaudeSettingsStack(args) {
  const layers = [];
  for (const scope of ['user', 'project', 'local', 'session', 'managed']) {
    for (const file of getFlags(args, `--${scope}`)) {
      let settings;
      try { settings = await readJson(file); } catch (error) {
        if (error instanceof SyntaxError) throw new Error(`Invalid Claude ${scope} settings JSON.`);
        throw error;
      }
      layers.push({ scope, settings });
    }
  }
  if (!layers.length) throw new Error('Claude settings stack requires at least one source flag.');
  const policy = await loadPolicy(args);
  const [result] = evaluateAll([inspectClaudeSettingsStack(layers)], policy);
  return { policy, result };
}

async function evaluateCodexSettingsStack(args) {
  const layers = [];
  for (const scope of ['system', 'managed', 'user', 'profile', 'project', 'cli']) {
    for (const file of getFlags(args, `--${scope}`)) {
      layers.push({ scope, text: await fs.readFile(file, 'utf8') });
    }
  }
  if (!layers.length) throw new Error('Codex settings stack requires at least one source flag.');
  const policy = await loadPolicy(args);
  const [result] = evaluateAll([inspectCodexSettingsStack(layers)], policy);
  return { policy, result };
}

async function loadClaudeBindingLayers(args) {
  const single = getFlags(args, '--settings');
  const stackScopes = ['user', 'project', 'local', 'session', 'managed'];
  const hasStack = stackScopes.some((scope) => getFlags(args, `--${scope}`).length);
  if (single.length > 1 || (single.length && hasStack)) {
    throw new Error('Claude bindings accept one --settings file or stack source flags, not both.');
  }
  if (single.length) {
    let settings;
    try { settings = await readJson(single[0]); } catch (error) {
      if (error instanceof SyntaxError) throw new Error('Invalid Claude settings JSON.');
      throw error;
    }
    return [{ scope: 'session', settings }];
  }

  const layers = [];
  for (const scope of stackScopes) {
    for (const file of getFlags(args, `--${scope}`)) {
      let settings;
      try { settings = await readJson(file); } catch (error) {
        if (error instanceof SyntaxError) throw new Error(`Invalid Claude ${scope} settings JSON.`);
        throw error;
      }
      layers.push({ scope, settings });
    }
  }
  if (!layers.length) throw new Error('Claude bindings require --settings or stack source flags.');
  return layers;
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

function printPermissionPostureDiff(diff) {
  if (diff.status === 'unchanged') {
    console.log('UNCHANGED: permission posture matches the baseline.');
    return;
  }
  if (diff.status === 'restricted') {
    console.log('RESTRICTED: permission posture became more restrictive.');
  } else {
    console.log('NEEDS_REVIEW: permission posture expanded or changed in an unclassified way.');
  }
  for (const change of diff.changes) {
    const details = change.items
      ? ` (${change.items.join(', ')})`
      : Object.hasOwn(change, 'before') ? ` (${String(change.before)} -> ${String(change.after)})` : '';
    console.log(`${change.impact.toUpperCase()} ${change.type}: ${change.field}${details}`);
  }
}

function printBindingDiff(diff) {
  if (diff.status === 'unchanged') {
    console.log('UNCHANGED: tool permission bindings match the baseline.');
    return;
  }
  console.log(diff.status === 'restricted'
    ? 'RESTRICTED: automatic tool permissions became more restrictive.'
    : 'NEEDS_REVIEW: tool provenance or automatic permissions changed.');
  for (const change of diff.changes) {
    const subject = change.name ? `${change.name}.` : '';
    const details = change.before !== null || change.after !== null
      ? ` (${String(change.before)} -> ${String(change.after)})`
      : '';
    console.log(`${change.impact.toUpperCase()} ${change.type}: ${subject}${change.field}${details}`);
  }
}

function printRuntimeEvidenceDiff(diff) {
  if (diff.status === 'unchanged') {
    console.log('UNCHANGED: effective runtime tool evidence matches the baseline.');
    return;
  }
  console.log(diff.status === 'restricted'
    ? 'RESTRICTED: observed runtime tool exposure became more restrictive.'
    : 'NEEDS_REVIEW: effective runtime tool evidence changed.');
  for (const change of diff.changes) {
    const subject = change.name ? `${change.name}.` : '';
    const details = change.before !== null || change.after !== null
      ? ` (${String(change.before)} -> ${String(change.after)})`
      : '';
    console.log(`${change.impact.toUpperCase()} ${change.type}: ${subject}${change.field}${details}`);
  }
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (hasFlag(args, '--decisions') && !DECISION_COMMANDS.has(command)) {
    throw new Error(`--decisions is supported only by inspection commands, not ${command || 'no command'}.`);
  }

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

  if (command === 'inspect-ide-extensions') {
    const directory = args[1];
    if (!directory) throw new Error('inspect-ide-extensions requires an extensions directory.');
    const { policy, results } = await evaluateIdeExtensions(directory, args);
    await emitInspection(results, args, policy);
    return;
  }

  if (command === 'inspect' || command === 'inspect-claude') {
    const configPath = args[1];
    if (!configPath) throw new Error('inspect requires a path to an MCP JSON file.');

    const { policy, results } = await evaluateMcp(configPath, args);
    await emitInspection(results, args, policy);
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

  if (command === 'inspect-claude-settings') {
    const settingsPath = args[1];
    if (!settingsPath) throw new Error('inspect-claude-settings requires a path to Claude settings JSON.');
    const { policy, result } = await evaluateClaudeSettings(settingsPath, args);
    await emitInspection([result], args, policy);
    return;
  }

  if (command === 'inspect-claude-settings-stack') {
    const { policy, result } = await evaluateClaudeSettingsStack(args);
    await emitInspection([result], args, policy);
    return;
  }

  if (command === 'inspect-codex') {
    const configPath = args[1];
    if (!configPath) throw new Error('inspect-codex requires a path to Codex config.toml.');
    const { policy, results } = await evaluateCodex(configPath, args);
    await emitInspection(results, args, policy);
    return;
  }

  if (command === 'inspect-codex-settings') {
    const configPath = args[1];
    if (!configPath) throw new Error('inspect-codex-settings requires a path to Codex config.toml.');
    const { policy, result } = await evaluateCodexSettings(configPath, args);
    await emitInspection([result], args, policy);
    return;
  }

  if (command === 'inspect-codex-settings-stack') {
    const { policy, result } = await evaluateCodexSettingsStack(args);
    await emitInspection([result], args, policy);
    return;
  }

  if (['snapshot-claude-settings', 'snapshot-codex-settings',
    'snapshot-claude-settings-stack', 'snapshot-codex-settings-stack'].includes(command)) {
    const isStack = command.endsWith('-stack');
    const configPath = isStack ? null : args[1];
    const out = getFlag(args, '--out');
    if ((!isStack && !configPath) || !out) {
      throw new Error(isStack
        ? `${command} requires source flags and --out <posture.json>.`
        : `${command} requires a settings path and --out <posture.json>.`);
    }
    let evaluated;
    if (command === 'snapshot-claude-settings') evaluated = await evaluateClaudeSettings(configPath, args);
    else if (command === 'snapshot-codex-settings') evaluated = await evaluateCodexSettings(configPath, args);
    else if (command === 'snapshot-claude-settings-stack') evaluated = await evaluateClaudeSettingsStack(args);
    else evaluated = await evaluateCodexSettingsStack(args);
    const { policy, result } = evaluated;
    const snapshot = createPermissionPostureSnapshot(result, policy);
    await writeFileSafe(out, `${JSON.stringify(snapshot, null, 2)}\n`);
    console.log(`Wrote ${out}\nDigest: ${snapshot.digest}`);
    return;
  }

  if (command === 'snapshot-claude-bindings') {
    const configPath = args[1];
    const out = getFlag(args, '--out');
    if (!configPath || !out) {
      throw new Error('snapshot-claude-bindings requires <.mcp.json>, settings sources, and --out <bindings.json>.');
    }
    const { policy, store, results } = await evaluateMcp(configPath, args, { claude: true });
    const projection = inspectClaudeMcpPermissionBindings(
      await loadClaudeBindingLayers(args),
      results.map((result) => result.name)
    );
    const snapshot = createToolPermissionBindingSnapshot({
      runtime: 'claude',
      results,
      grants: projection.grants,
      policy,
      trustStore: store,
      unboundAutomaticGrantCount: projection.unboundAllowRuleCount,
      ambiguousAutomaticGrantCount: projection.ambiguousAllowRuleCount
    });
    await writeFileSafe(out, `${JSON.stringify(snapshot, null, 2)}\n`);
    console.log(`Wrote ${out}\nStatus: ${snapshot.status}\nDigest: ${snapshot.digest}`);
    return;
  }

  if (command === 'snapshot-codex-bindings') {
    const configPath = args[1];
    const out = getFlag(args, '--out');
    if (!configPath || !out) {
      throw new Error('snapshot-codex-bindings requires <config.toml> and --out <bindings.json>.');
    }
    const { policy, store, results } = await evaluateCodex(configPath, args);
    const snapshot = createToolPermissionBindingSnapshot({
      runtime: 'codex',
      results,
      grants: codexAutomaticGrantProjection(results),
      policy,
      trustStore: store
    });
    await writeFileSafe(out, `${JSON.stringify(snapshot, null, 2)}\n`);
    console.log(`Wrote ${out}\nStatus: ${snapshot.status}\nDigest: ${snapshot.digest}`);
    return;
  }

  if (command === 'snapshot-runtime-tools') {
    const bindingsPath = args[1];
    const inventoryPath = args[2];
    const out = getFlag(args, '--out');
    if (!bindingsPath || !inventoryPath || !out) {
      throw new Error('snapshot-runtime-tools requires <bindings.json> <inventory.json> and --out <runtime.json>.');
    }
    const inventory = await readJson(inventoryPath);
    const attestationPath = getFlag(args, '--attestation');
    const verifier = await loadVerifier(args);
    if (Boolean(attestationPath) !== hasVerifier(verifier)) {
      throw new Error('Runtime inventory authentication requires both --attestation and --public (or --keyset).');
    }
    if (!attestationPath && getFlag(args, '--max-age-seconds') !== null) {
      throw new Error('--max-age-seconds requires --attestation and --public (or --keyset).');
    }
    let authentication = null;
    if (attestationPath && hasVerifier(verifier)) {
      const verification = verifyRuntimeInventoryAttestation(
        inventory,
        await readJson(attestationPath),
        verifier,
        { maxAgeSeconds: getIntegerFlag(args, '--max-age-seconds') }
      );
      if (!verification.valid) {
        throw new Error(`Runtime inventory attestation verification failed: ${verification.reason}`);
      }
      authentication = verification;
    } else if (hasFlag(args, '--require-authenticated')) {
      throw new Error('Authenticated runtime inventory evidence is required.');
    }
    const snapshot = createEffectiveRuntimeEvidence(
      await readJson(bindingsPath),
      inventory,
      authentication
    );
    await writeFileSafe(out, `${JSON.stringify(snapshot, null, 2)}\n`);
    console.log(`Wrote ${out}\nStatus: ${snapshot.status}\nDigest: ${snapshot.digest}`);
    return;
  }

  if (command === 'sign-runtime-inventory') {
    const inventoryPath = args[1];
    const privatePath = getFlag(args, '--private');
    const out = getFlag(args, '--out');
    if (!inventoryPath || !privatePath || !out) {
      throw new Error('sign-runtime-inventory requires <inventory.json>, --private <key.pem>, and --out <attestation.json>.');
    }
    const attestation = createRuntimeInventoryAttestation(
      await readJson(inventoryPath),
      await fs.readFile(privatePath, 'utf8'),
      { ttlSeconds: getIntegerFlag(args, '--ttl-seconds', 300) }
    );
    await writeFileSafe(out, `${JSON.stringify(attestation, null, 2)}\n`);
    console.log(`Wrote ${out}\nProducer key: ${attestation.producerKeyId}\nExpires: ${attestation.expiresAt}`);
    return;
  }

  if (command === 'verify-runtime-inventory') {
    const inventoryPath = args[1];
    const attestationPath = getFlag(args, '--attestation');
    const verifier = await loadVerifier(args);
    if (!inventoryPath || !attestationPath || !hasVerifier(verifier)) {
      throw new Error('verify-runtime-inventory requires <inventory.json>, --attestation <file>, and --public <key.pem> or --keyset <keyset.json>.');
    }
    const verification = verifyRuntimeInventoryAttestation(
      await readJson(inventoryPath),
      await readJson(attestationPath),
      verifier,
      { maxAgeSeconds: getIntegerFlag(args, '--max-age-seconds') }
    );
    if (hasFlag(args, '--json')) console.log(JSON.stringify(verification, null, 2));
    else if (verification.valid) console.log(`VERIFIED ${verification.producerKeyId}`);
    else console.log(`INVALID: ${verification.reason}`);
    if (!verification.valid) process.exitCode = 2;
    return;
  }

  if (command === 'diff-permissions') {
    const beforePath = args[1];
    const afterPath = args[2];
    if (!beforePath || !afterPath) {
      throw new Error('diff-permissions requires <before.json> <after.json>.');
    }
    const diff = diffPermissionPostureSnapshots(
      await readJson(beforePath),
      await readJson(afterPath)
    );
    if (hasFlag(args, '--json')) console.log(JSON.stringify(diff, null, 2));
    else printPermissionPostureDiff(diff);
    if (diff.status === 'needs-review') process.exitCode = 1;
    return;
  }

  if (command === 'diff-bindings') {
    const beforePath = args[1];
    const afterPath = args[2];
    if (!beforePath || !afterPath) {
      throw new Error('diff-bindings requires <before.json> <after.json>.');
    }
    const diff = diffToolPermissionBindingSnapshots(
      await readJson(beforePath),
      await readJson(afterPath)
    );
    if (hasFlag(args, '--json')) console.log(JSON.stringify(diff, null, 2));
    else printBindingDiff(diff);
    if (diff.status === 'needs-review') process.exitCode = 1;
    return;
  }

  if (command === 'diff-runtime-tools') {
    const beforePath = args[1];
    const afterPath = args[2];
    if (!beforePath || !afterPath) {
      throw new Error('diff-runtime-tools requires <before.json> <after.json>.');
    }
    const diff = diffEffectiveRuntimeEvidence(
      await readJson(beforePath),
      await readJson(afterPath)
    );
    if (hasFlag(args, '--json')) console.log(JSON.stringify(diff, null, 2));
    else printRuntimeEvidenceDiff(diff);
    if (diff.status === 'needs-review') process.exitCode = 1;
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
    const artifactPath = getFlag(args, '--artifact');
    const artifactVerification = artifactPath
      ? verifyArtifactBytes(observation, await fs.readFile(artifactPath))
      : null;
    const claim = provenanceObservationToClaim(observation, publisher, { artifactVerification });
    const existing = await readJsonIfExists(out, { version: 1, claims: [] });
    const store = upsertTrustStoreClaim(existing, claim);
    parseTrustStore(store);
    await writeFileSafe(out, `${JSON.stringify(store, null, 2)}\n`);
    console.log(`Trusted ${claim.type} ${claim.subject} as "${claim.publisher}" using ${claim.evidence.kind} evidence.`);
    if (artifactVerification) {
      console.log(`Verified artifact integrity: ${artifactVerification.algorithm} ${artifactVerification.digest}`);
    }
    console.log(`Wrote ${out}`);
    return;
  }

  if (command === 'gate' || command === 'gate-claude') {
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

  if (['approve', 'approve-claude', 'approve-codex', 'approve-ide-extensions'].includes(command)) {
    const configPath = args[1];
    const privatePath = getFlag(args, '--private');
    const reviewDir = getFlag(args, '--dir');
    if (!configPath || !privatePath || !reviewDir) {
      throw new Error('approve requires <mcp.json>, --private <key.pem>, and --dir <review-directory>.');
    }

    const { policy, store, results } = await evaluateForReview(command, configPath, args);
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

  if (['recheck', 'recheck-claude', 'recheck-codex', 'recheck-ide-extensions'].includes(command)) {
    const configPath = args[1];
    const reviewDir = getFlag(args, '--review-dir');
    const verifier = await loadVerifier(args);
    if (!configPath || !reviewDir || !hasVerifier(verifier)) {
      throw new Error('recheck requires <mcp.json>, --review-dir <directory>, and --public <key.pem> or --keyset <keyset.json>.');
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
    const { results } = await evaluateForReview(command, configPath, evalArgs);
    const current = createSnapshot(results);
    const verdict = assessReview({
      record,
      publicKey: verifier,
      baseline,
      current,
      policy
    });

    if (hasFlag(args, '--json')) {
      console.log(JSON.stringify({ ...verdict, currentDigest: current.digest, approvedDigest: baseline.digest }, null, 2));
    } else if (verdict.status === 'approved') {
      console.log('APPROVED: current state matches the signed review.');
      console.log(`Digest: ${current.digest}`);
      if (verdict.keyId) console.log(`Signing key: ${verdict.keyId}`);
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

  if (['snapshot', 'snapshot-claude', 'snapshot-codex', 'snapshot-ide-extensions'].includes(command)) {
    const configPath = args[1];
    const out = getFlag(args, '--out');
    if (!configPath || !out) throw new Error('snapshot requires <mcp.json> and --out <snapshot.json>.');

    const { results } = await evaluateForReview(command, configPath, args);
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
    const verifier = await loadVerifier(args);
    if (!recordPath || !hasVerifier(verifier)) {
      throw new Error('verify requires <record.json> and --public <key.pem> or --keyset <keyset.json>.');
    }

    const snapshotPath = getFlag(args, '--snapshot');
    const policyPath = getFlag(args, '--policy');
    const verdict = verifyTrustRecord(
      await readJson(recordPath),
      verifier,
      {
        snapshot: snapshotPath ? await readJson(snapshotPath) : null,
        policy: policyPath ? await readJson(policyPath) : null
      }
    );
    console.log(verdict.valid ? 'VALID' : `INVALID: ${verdict.reason}`);
    if (verdict.valid && verdict.keyId) console.log(`Signing key: ${verdict.keyId}`);
    if (!verdict.valid) process.exitCode = 2;
    return;
  }

  if (command === 'key-id') {
    const publicPath = args[1];
    if (!publicPath || publicPath.startsWith('--')) throw new Error('key-id requires <public.pem>.');
    const key = parseEd25519PublicKeyPem(await fs.readFile(publicPath, 'utf8'), path.basename(publicPath));
    console.log(spkiKeyId(key));
    return;
  }

  throw new Error(`Unknown command: ${command}`);
}

main().catch((error) => {
  if (process.argv.includes('--decisions')) {
    console.log(JSON.stringify(createDecisionError({ command: process.argv[2], trustdexVersion: VERSION }), null, 2));
  }
  const message = error instanceof SyntaxError && !(error instanceof InvalidJsonError)
    ? 'Invalid input syntax.'
    : error.message;
  console.error(`trustdex: ${message}`);
  process.exitCode = 2;
});
