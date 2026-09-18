import crypto from 'node:crypto';

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function createSnapshot(results) {
  const normalized = results
    .map(({ name, source, signals, action }) => ({ name, source, signals: [...signals].sort(), action }))
    .sort((a, b) => a.name.localeCompare(b.name));

  const digest = crypto.createHash('sha256').update(stableJson(normalized)).digest('hex');
  return {
    schemaVersion: 1,
    createdAt: new Date().toISOString(),
    digest,
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

    const addedSignals = current.signals.filter((signal) => !previous.signals.includes(signal));
    if (addedSignals.length) changes.push({ type: 'signals-added', name, signals: addedSignals });

    if (previous.action !== current.action) {
      changes.push({ type: 'decision-changed', name, from: previous.action, to: current.action });
    }

    if (JSON.stringify(previous.source) !== JSON.stringify(current.source)) {
      changes.push({ type: 'source-changed', name, from: previous.source, to: current.source });
    }
  }

  for (const name of left.keys()) {
    if (!right.has(name)) changes.push({ type: 'server-removed', name });
  }

  return changes;
}
