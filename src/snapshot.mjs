import { sha256Json } from './canonical.mjs';

export function createSnapshot(results) {
  const normalized = results
    .map(({ name, kind = 'mcp', source, provenance = { status: 'unknown' }, fingerprint = null, signals = [], action }) => ({
      name,
      kind,
      source,
      provenance,
      fingerprint,
      signals: [...signals].sort(),
      action
    }))
    .sort((a, b) => a.name.localeCompare(b.name));

  return {
    schemaVersion: 3,
    createdAt: new Date().toISOString(),
    digest: sha256Json(normalized),
    servers: normalized
  };
}

export function diffSnapshots(before, after) {
  const left = new Map((before?.servers || []).map((server) => [server.name, server]));
  const right = new Map((after?.servers || []).map((server) => [server.name, server]));
  const changes = [];

  for (const [name, current] of right) {
    const previous = left.get(name);
    if (!previous) {
      changes.push({ type: 'server-added', name, current });
      continue;
    }

    const previousSignals = previous.signals || [];
    const currentSignals = current.signals || [];
    const addedSignals = currentSignals.filter((signal) => !previousSignals.includes(signal));
    const removedSignals = previousSignals.filter((signal) => !currentSignals.includes(signal));

    if (addedSignals.length) changes.push({ type: 'signals-added', name, signals: addedSignals });
    if (removedSignals.length) changes.push({ type: 'signals-removed', name, signals: removedSignals });

    if (previous.action !== current.action) {
      changes.push({ type: 'decision-changed', name, from: previous.action, to: current.action });
    }

    if (JSON.stringify(previous.source) !== JSON.stringify(current.source)) {
      changes.push({ type: 'source-changed', name, from: previous.source, to: current.source });
    }

    if (JSON.stringify(previous.provenance || {}) !== JSON.stringify(current.provenance || {})) {
      changes.push({
        type: 'provenance-changed',
        name,
        from: previous.provenance || { status: 'unknown' },
        to: current.provenance || { status: 'unknown' }
      });
    }

    if ((previous.fingerprint || null) !== (current.fingerprint || null)) {
      changes.push({
        type: 'fingerprint-changed',
        name,
        from: previous.fingerprint || null,
        to: current.fingerprint || null
      });
    }
  }

  for (const name of left.keys()) {
    if (!right.has(name)) changes.push({ type: 'server-removed', name });
  }

  return changes;
}
