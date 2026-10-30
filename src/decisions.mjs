import { sha256Json } from './canonical.mjs';

// A small, versioned decision contract for agents and automation. It carries only
// the decision, signal names, reasons, and fingerprints: no metadata, provenance
// evidence, environment names, or configuration values.

const RANK = { allow: 0, ask: 1, block: 2 };
const ACTIONS = Object.keys(RANK);

function overall(items) {
  return items.reduce((current, item) => (RANK[item.action] > RANK[current] ? item.action : current), 'allow');
}

export function createDecisionReport(results, { command, trustdexVersion, policy }) {
  const items = results
    .map((result) => {
      if (!ACTIONS.includes(result.action)) throw new Error(`Result "${result.name}" has no valid action.`);
      return {
        name: String(result.name),
        kind: String(result.kind || 'mcp'),
        action: result.action,
        signals: [...(result.signals || [])].map(String).sort(),
        reasons: (result.reasons || []).map(String),
        fingerprint: result.fingerprint ? String(result.fingerprint) : null
      };
    })
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const decision = overall(items);
  const counts = Object.fromEntries(ACTIONS.map((action) => [action, items.filter((item) => item.action === action).length]));
  const body = {
    schemaVersion: 1,
    kind: 'trustdex-decisions',
    command: String(command),
    trustdexVersion: String(trustdexVersion),
    policyDigest: sha256Json(policy || {}),
    decision,
    exitCode: RANK[decision],
    counts,
    items
  };
  return { ...body, digest: sha256Json(body) };
}

// Emitted instead of a report when inspection fails, so a consumer always receives
// parseable JSON whose decision is BLOCK. The message is fixed text, never input.
export function createDecisionError({ command, trustdexVersion }) {
  return {
    schemaVersion: 1,
    kind: 'trustdex-decisions',
    command: String(command || ''),
    trustdexVersion: String(trustdexVersion),
    decision: 'block',
    exitCode: 2,
    error: 'inspection failed; see stderr',
    items: []
  };
}
