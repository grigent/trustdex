import { sha256Json } from './canonical.mjs';
import { validateToolPermissionBindingSnapshot } from './bindings.mjs';

const RUNTIMES = new Set(['claude', 'codex']);
const CAPTURE_METHODS = new Set(['runtime-export', 'runtime-adapter']);
const EVIDENCE_STATUSES = new Set(['matched', 'restricted', 'needs-review', 'block']);
const SERVER_STATUSES = new Set(['matched', 'not-observed', 'needs-review', 'blocked', 'unexpected']);
const KIND = 'agent-effective-tool-boundary';
const INVENTORY_KIND = 'agent-runtime-tool-inventory';

function requireObject(value, message) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(message);
  return value;
}

function requireExactKeys(value, expected, message) {
  const keys = Object.keys(requireObject(value, message));
  if (keys.length !== expected.size || keys.some((key) => !expected.has(key))) throw new Error(message);
  return value;
}

function requireCount(value, field) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`Invalid runtime evidence count: ${field}`);
  return value;
}

function requireDigest(value, field) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error(`Invalid runtime evidence digest: ${field}`);
  }
  return value;
}

function requireTimestamp(value, field) {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value)) ||
      new Date(value).toISOString() !== value) {
    throw new Error(`Invalid runtime evidence timestamp: ${field}`);
  }
  return value;
}

function normalizeInventory(input) {
  const inventory = requireExactKeys(input, new Set([
    'schemaVersion', 'kind', 'runtime', 'capturedAt', 'captureMethod', 'servers'
  ]), 'Invalid runtime tool inventory.');
  if (inventory.schemaVersion !== 1 || inventory.kind !== INVENTORY_KIND) {
    throw new Error('Unsupported runtime tool inventory schema.');
  }
  if (!RUNTIMES.has(inventory.runtime)) throw new Error('Invalid runtime tool inventory runtime.');
  requireTimestamp(inventory.capturedAt, 'capturedAt');
  if (!CAPTURE_METHODS.has(inventory.captureMethod)) throw new Error('Invalid runtime tool inventory capture method.');
  if (!Array.isArray(inventory.servers)) throw new Error('Runtime tool inventory is missing servers.');

  const servers = inventory.servers.map((server) => {
    requireExactKeys(server, new Set(['name', 'toolCount']), 'Invalid runtime tool inventory server.');
    if (typeof server.name !== 'string' || !server.name.trim()) {
      throw new Error('Runtime tool inventory server is missing a name.');
    }
    return { name: server.name, toolCount: requireCount(server.toolCount, 'toolCount') };
  }).sort((left, right) => left.name.localeCompare(right.name));
  if (new Set(servers.map((server) => server.name)).size !== servers.length) {
    throw new Error('Runtime tool inventory server names must be unique.');
  }
  return {
    schemaVersion: 1,
    kind: INVENTORY_KIND,
    runtime: inventory.runtime,
    capturedAt: inventory.capturedAt,
    captureMethod: inventory.captureMethod,
    servers
  };
}

function serverStatus(binding, observed) {
  if (!binding) return 'unexpected';
  if (!observed) return 'not-observed';
  if (binding.status === 'blocked' || binding.sourceDecision === 'block' ||
      binding.provenanceStatus === 'mismatch') return 'blocked';
  if (binding.status === 'needs-review' || binding.sourceDecision === 'ask') return 'needs-review';
  return 'matched';
}

function createSummary(servers) {
  const observedToolCount = servers.reduce((total, server) => total + (server.toolCount || 0), 0);
  requireCount(observedToolCount, 'observedToolCount');
  return {
    configuredServerCount: servers.filter((server) => server.configured).length,
    observedServerCount: servers.filter((server) => server.observed).length,
    observedToolCount,
    matchedCount: servers.filter((server) => server.status === 'matched').length,
    reviewCount: servers.filter((server) => server.status === 'needs-review').length,
    blockedCount: servers.filter((server) => server.status === 'blocked').length,
    unexpectedCount: servers.filter((server) => server.status === 'unexpected').length,
    notObservedCount: servers.filter((server) => server.status === 'not-observed').length
  };
}

function evidenceStatus(summary) {
  if (summary.blockedCount || summary.unexpectedCount) return 'block';
  if (summary.reviewCount) return 'needs-review';
  if (summary.notObservedCount) return 'restricted';
  return 'matched';
}

function evidenceDigest(snapshot) {
  return sha256Json({
    schemaVersion: snapshot.schemaVersion,
    kind: snapshot.kind,
    runtime: snapshot.runtime,
    capturedAt: snapshot.capturedAt,
    captureMethod: snapshot.captureMethod,
    bindingDigest: snapshot.bindingDigest,
    inventoryDigest: snapshot.inventoryDigest,
    status: snapshot.status,
    summary: snapshot.summary,
    servers: snapshot.servers
  });
}

function inventoryFromEvidence(snapshot) {
  return {
    schemaVersion: 1,
    kind: INVENTORY_KIND,
    runtime: snapshot.runtime,
    capturedAt: snapshot.capturedAt,
    captureMethod: snapshot.captureMethod,
    servers: snapshot.servers
      .filter((server) => server.observed)
      .map((server) => ({ name: server.name, toolCount: server.toolCount }))
  };
}

export function createEffectiveRuntimeEvidence(bindingInput, inventoryInput) {
  const bindings = validateToolPermissionBindingSnapshot(bindingInput);
  const inventory = normalizeInventory(inventoryInput);
  if (bindings.runtime !== inventory.runtime) {
    throw new Error('Runtime inventory does not match the binding runtime.');
  }

  const configured = new Map(bindings.bindings.map((binding) => [binding.name, binding]));
  const observed = new Map(inventory.servers.map((server) => [server.name, server]));
  const names = [...new Set([...configured.keys(), ...observed.keys()])].sort();
  const servers = names.map((name) => {
    const binding = configured.get(name) || null;
    const runtimeServer = observed.get(name) || null;
    return {
      name,
      configured: binding !== null,
      observed: runtimeServer !== null,
      toolCount: runtimeServer ? runtimeServer.toolCount : null,
      sourceDecision: binding ? binding.sourceDecision : null,
      provenanceStatus: binding ? binding.provenanceStatus : null,
      automaticGrant: binding ? binding.automaticGrant : null,
      bindingStatus: binding ? binding.status : null,
      status: serverStatus(binding, runtimeServer)
    };
  });
  const summary = createSummary(servers);
  const snapshot = {
    schemaVersion: 1,
    kind: KIND,
    createdAt: new Date().toISOString(),
    runtime: inventory.runtime,
    capturedAt: inventory.capturedAt,
    captureMethod: inventory.captureMethod,
    bindingDigest: bindings.digest,
    inventoryDigest: sha256Json(inventory),
    status: evidenceStatus(summary),
    summary,
    servers
  };
  return { ...snapshot, digest: evidenceDigest(snapshot) };
}

function validateServer(server) {
  requireExactKeys(server, new Set([
    'name', 'configured', 'observed', 'toolCount', 'sourceDecision', 'provenanceStatus',
    'automaticGrant', 'bindingStatus', 'status'
  ]), 'Invalid effective runtime server evidence.');
  if (typeof server.name !== 'string' || !server.name) throw new Error('Runtime server evidence is missing a name.');
  if (typeof server.configured !== 'boolean' || typeof server.observed !== 'boolean') {
    throw new Error('Invalid runtime server configured/observed state.');
  }
  if (server.observed) requireCount(server.toolCount, 'toolCount');
  else if (server.toolCount !== null) throw new Error('Unobserved runtime server must have a null tool count.');
  if (!server.configured) {
    for (const field of ['sourceDecision', 'provenanceStatus', 'automaticGrant', 'bindingStatus']) {
      if (server[field] !== null) throw new Error('Unexpected runtime server has binding metadata.');
    }
  } else {
    if (!['allow', 'ask', 'block'].includes(server.sourceDecision) ||
        !['unknown', 'verified', 'mismatch'].includes(server.provenanceStatus) ||
        !['none', 'scoped', 'all'].includes(server.automaticGrant) ||
        !['not-granted', 'bound', 'needs-review', 'blocked'].includes(server.bindingStatus)) {
      throw new Error('Invalid configured runtime server binding metadata.');
    }
  }
  if (!SERVER_STATUSES.has(server.status) || server.status !== serverStatus(
    server.configured ? {
      status: server.bindingStatus,
      sourceDecision: server.sourceDecision,
      provenanceStatus: server.provenanceStatus
    } : null,
    server.observed ? server : null
  )) throw new Error('Invalid effective runtime server status.');
  return server;
}

function validateEvidence(snapshot) {
  requireExactKeys(snapshot, new Set([
    'schemaVersion', 'kind', 'createdAt', 'runtime', 'capturedAt', 'captureMethod',
    'bindingDigest', 'inventoryDigest', 'status', 'summary', 'servers', 'digest'
  ]), 'Invalid effective runtime evidence snapshot.');
  if (snapshot.schemaVersion !== 1 || snapshot.kind !== KIND) {
    throw new Error('Unsupported effective runtime evidence schema.');
  }
  if (!RUNTIMES.has(snapshot.runtime)) throw new Error('Invalid effective runtime evidence runtime.');
  requireTimestamp(snapshot.createdAt, 'createdAt');
  requireTimestamp(snapshot.capturedAt, 'capturedAt');
  if (!CAPTURE_METHODS.has(snapshot.captureMethod)) throw new Error('Invalid effective runtime capture method.');
  requireDigest(snapshot.bindingDigest, 'bindingDigest');
  requireDigest(snapshot.inventoryDigest, 'inventoryDigest');
  requireDigest(snapshot.digest, 'digest');
  if (!EVIDENCE_STATUSES.has(snapshot.status)) throw new Error('Invalid effective runtime evidence status.');
  if (!Array.isArray(snapshot.servers)) throw new Error('Effective runtime evidence is missing servers.');
  for (const server of snapshot.servers) validateServer(server);
  const names = snapshot.servers.map((server) => server.name);
  if (new Set(names).size !== names.length || [...names].sort().join('\0') !== names.join('\0')) {
    throw new Error('Effective runtime server evidence is not canonical.');
  }
  const summaryFields = [
    'configuredServerCount', 'observedServerCount', 'observedToolCount', 'matchedCount',
    'reviewCount', 'blockedCount', 'unexpectedCount', 'notObservedCount'
  ];
  requireExactKeys(snapshot.summary, new Set(summaryFields), 'Invalid effective runtime evidence summary.');
  for (const field of summaryFields) requireCount(snapshot.summary[field], field);
  const summary = createSummary(snapshot.servers);
  if (sha256Json(summary) !== sha256Json(snapshot.summary)) throw new Error('Effective runtime evidence summary mismatch.');
  if (snapshot.inventoryDigest !== sha256Json(inventoryFromEvidence(snapshot))) {
    throw new Error('Effective runtime inventory digest mismatch.');
  }
  if (snapshot.status !== evidenceStatus(summary)) throw new Error('Effective runtime evidence status mismatch.');
  if (snapshot.digest !== evidenceDigest(snapshot)) throw new Error('Effective runtime evidence digest mismatch.');
  return snapshot;
}

export function validateEffectiveRuntimeEvidence(snapshot) {
  return validateEvidence(snapshot);
}

function addChange(changes, impact, type, name, field, before, after) {
  changes.push({ impact, type, name, field, before, after });
}

export function diffEffectiveRuntimeEvidence(beforeInput, afterInput) {
  const before = validateEvidence(beforeInput);
  const after = validateEvidence(afterInput);
  if (before.runtime !== after.runtime) throw new Error('Cannot compare different runtime evidence types.');
  const changes = [];
  if (before.bindingDigest !== after.bindingDigest) {
    addChange(changes, 'review', 'bindings-changed', null, 'bindingDigest', null, null);
  }
  if (before.captureMethod !== after.captureMethod) {
    addChange(changes, 'review', 'capture-method-changed', null, 'captureMethod', before.captureMethod, after.captureMethod);
  }

  const left = new Map(before.servers.map((server) => [server.name, server]));
  const right = new Map(after.servers.map((server) => [server.name, server]));
  const risk = { 'not-observed': 0, matched: 1, 'needs-review': 2, blocked: 3, unexpected: 3 };
  for (const [name, current] of right) {
    const previous = left.get(name);
    if (!previous) {
      addChange(changes, current.observed ? 'expansion' : 'review', 'server-added', name, 'server', null, current.status);
      continue;
    }
    if (previous.observed !== current.observed) {
      addChange(changes, current.observed ? 'expansion' : 'restriction', 'observation-changed', name, 'observed', previous.observed, current.observed);
    }
    const beforeCount = previous.toolCount || 0;
    const afterCount = current.toolCount || 0;
    if (beforeCount !== afterCount) {
      addChange(changes, afterCount > beforeCount ? 'expansion' : 'restriction', 'tool-count-changed', name, 'toolCount', previous.toolCount, current.toolCount);
    }
    for (const field of ['configured', 'sourceDecision', 'provenanceStatus', 'automaticGrant', 'bindingStatus']) {
      if (previous[field] !== current[field]) {
        addChange(changes, 'review', 'binding-state-changed', name, field, previous[field], current[field]);
      }
    }
    if (previous.status !== current.status) {
      addChange(
        changes,
        risk[current.status] > risk[previous.status] ? 'expansion' :
          risk[current.status] < risk[previous.status] ? 'restriction' : 'review',
        'server-status-changed', name, 'status', previous.status, current.status
      );
    }
  }
  for (const [name, previous] of left) {
    if (!right.has(name)) {
      addChange(changes, previous.observed ? 'restriction' : 'review', 'server-removed', name, 'server', previous.status, null);
    }
  }
  const summary = {
    expansions: changes.filter((change) => change.impact === 'expansion').length,
    restrictions: changes.filter((change) => change.impact === 'restriction').length,
    reviews: changes.filter((change) => change.impact === 'review').length
  };
  return {
    schemaVersion: 1,
    runtime: before.runtime,
    status: summary.expansions || summary.reviews ? 'needs-review' :
      summary.restrictions ? 'restricted' : 'unchanged',
    baselineDigest: before.digest,
    currentDigest: after.digest,
    summary,
    changes
  };
}
