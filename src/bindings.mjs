import { sha256Json } from './canonical.mjs';

const ACTIONS = new Set(['allow', 'ask', 'block']);
const GRANTS = new Set(['none', 'scoped', 'all']);
const PROVENANCE = new Set(['unknown', 'verified', 'mismatch']);
const BINDING_STATUSES = new Set(['not-granted', 'bound', 'needs-review', 'blocked']);
const RUNTIMES = new Set(['claude', 'codex']);
const SNAPSHOT_KIND = 'agent-tool-permission-bindings';
const SNAPSHOT_VERSION = 1;

function requireObject(value, message) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(message);
  return value;
}

function requireExactKeys(value, expected, message) {
  const keys = Object.keys(requireObject(value, message));
  if (keys.length !== expected.size || keys.some((key) => !expected.has(key))) {
    throw new Error(message);
  }
  return value;
}

function requireCount(value, field) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`Invalid binding count: ${field}`);
  return value;
}

function requireDigest(value, field, nullable = false) {
  if (nullable && value === null) return null;
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error(`Invalid binding digest: ${field}`);
  }
  return value;
}

function normalizeGrant(grant) {
  requireObject(grant, 'Invalid tool permission grant.');
  if (typeof grant.name !== 'string' || !grant.name) throw new Error('Tool permission grant is missing a name.');
  if (!GRANTS.has(grant.automaticGrant)) throw new Error('Unsupported automatic tool grant mode.');
  if (typeof grant.toolScopeWildcard !== 'boolean') throw new Error('Invalid tool permission wildcard state.');
  return {
    name: grant.name,
    automaticGrant: grant.automaticGrant,
    grantRuleCount: requireCount(grant.grantRuleCount, 'grantRuleCount'),
    toolScopeWildcard: grant.toolScopeWildcard
  };
}

function bindingStatus(sourceDecision, provenanceStatus, grant) {
  if (grant.automaticGrant === 'none') return 'not-granted';
  if (sourceDecision === 'block' || provenanceStatus === 'mismatch') return 'blocked';
  if (sourceDecision === 'ask' || grant.automaticGrant === 'all' || grant.toolScopeWildcard) {
    return 'needs-review';
  }
  return 'bound';
}

function snapshotDigest(snapshot) {
  return sha256Json({
    schemaVersion: snapshot.schemaVersion,
    kind: snapshot.kind,
    runtime: snapshot.runtime,
    policyDigest: snapshot.policyDigest,
    trustStoreDigest: snapshot.trustStoreDigest,
    summary: snapshot.summary,
    bindings: snapshot.bindings
  });
}

export function createToolPermissionBindingSnapshot({
  runtime,
  results,
  grants,
  policy,
  trustStore = null,
  unboundAutomaticGrantCount = 0,
  ambiguousAutomaticGrantCount = 0
}) {
  if (!RUNTIMES.has(runtime)) throw new Error('Unsupported tool permission binding runtime.');
  if (!Array.isArray(results) || !Array.isArray(grants)) {
    throw new Error('Tool permission bindings require result and grant arrays.');
  }

  const resultMap = new Map();
  for (const result of results) {
    if (!result || typeof result.name !== 'string' || resultMap.has(result.name)) {
      throw new Error('Tool permission binding results require unique names.');
    }
    if (!ACTIONS.has(result.action)) throw new Error('Tool permission binding result has an invalid action.');
    resultMap.set(result.name, result);
  }

  const grantMap = new Map();
  for (const input of grants) {
    const grant = normalizeGrant(input);
    if (grantMap.has(grant.name)) throw new Error('Tool permission grants require unique names.');
    grantMap.set(grant.name, grant);
  }
  if (resultMap.size !== grantMap.size || [...resultMap.keys()].some((name) => !grantMap.has(name))) {
    throw new Error('Tool permission grants do not match inspected MCP servers.');
  }

  const bindings = [...resultMap.entries()].map(([name, result]) => {
    const grant = grantMap.get(name);
    const provenanceStatus = result.provenance?.status || 'unknown';
    if (!PROVENANCE.has(provenanceStatus)) throw new Error('Unsupported tool provenance status.');
    return {
      name,
      sourceDecision: result.action,
      provenanceStatus,
      integrityVerified: result.provenance?.integrityVerified === true,
      automaticGrant: grant.automaticGrant,
      grantRuleCount: grant.grantRuleCount,
      toolScopeWildcard: grant.toolScopeWildcard,
      status: bindingStatus(result.action, provenanceStatus, grant)
    };
  }).sort((left, right) => left.name.localeCompare(right.name));

  const unbound = requireCount(unboundAutomaticGrantCount, 'unboundAutomaticGrantCount');
  const ambiguous = requireCount(ambiguousAutomaticGrantCount, 'ambiguousAutomaticGrantCount');
  const summary = {
    serverCount: bindings.length,
    automaticGrantCount: bindings.filter((binding) => binding.automaticGrant !== 'none').length,
    boundCount: bindings.filter((binding) => binding.status === 'bound').length,
    reviewCount: bindings.filter((binding) => binding.status === 'needs-review').length,
    blockedCount: bindings.filter((binding) => binding.status === 'blocked').length,
    unboundAutomaticGrantCount: unbound,
    ambiguousAutomaticGrantCount: ambiguous
  };
  const status = summary.blockedCount
    ? 'block'
    : summary.reviewCount || unbound || ambiguous
      ? 'needs-review'
      : summary.boundCount ? 'bound' : 'clear';
  const snapshot = {
    schemaVersion: SNAPSHOT_VERSION,
    kind: SNAPSHOT_KIND,
    createdAt: new Date().toISOString(),
    runtime,
    policyDigest: sha256Json(policy || {}),
    trustStoreDigest: trustStore ? sha256Json(trustStore) : null,
    status,
    summary,
    bindings
  };
  return { ...snapshot, digest: snapshotDigest(snapshot) };
}

function validateBinding(binding) {
  requireExactKeys(binding, new Set([
    'name', 'sourceDecision', 'provenanceStatus', 'integrityVerified', 'automaticGrant',
    'grantRuleCount', 'toolScopeWildcard', 'status'
  ]), 'Invalid tool permission binding.');
  if (typeof binding.name !== 'string' || !binding.name) throw new Error('Tool permission binding is missing a name.');
  if (!ACTIONS.has(binding.sourceDecision)) throw new Error('Invalid binding source decision.');
  if (!PROVENANCE.has(binding.provenanceStatus)) throw new Error('Invalid binding provenance status.');
  if (typeof binding.integrityVerified !== 'boolean') throw new Error('Invalid binding integrity state.');
  if (!GRANTS.has(binding.automaticGrant)) throw new Error('Invalid binding grant mode.');
  requireCount(binding.grantRuleCount, 'grantRuleCount');
  if (typeof binding.toolScopeWildcard !== 'boolean') throw new Error('Invalid binding wildcard state.');
  if (!BINDING_STATUSES.has(binding.status)) throw new Error('Invalid tool permission binding status.');
  if (binding.status !== bindingStatus(binding.sourceDecision, binding.provenanceStatus, binding)) {
    throw new Error('Tool permission binding status is inconsistent.');
  }
  return binding;
}

function validateSnapshot(snapshot) {
  requireExactKeys(snapshot, new Set([
    'schemaVersion', 'kind', 'createdAt', 'runtime', 'policyDigest', 'trustStoreDigest',
    'status', 'summary', 'bindings', 'digest'
  ]), 'Invalid tool permission binding snapshot.');
  if (snapshot.schemaVersion !== SNAPSHOT_VERSION || snapshot.kind !== SNAPSHOT_KIND) {
    throw new Error('Unsupported tool permission binding snapshot schema.');
  }
  if (!RUNTIMES.has(snapshot.runtime)) throw new Error('Invalid tool permission binding runtime.');
  if (typeof snapshot.createdAt !== 'string' ||
      Number.isNaN(Date.parse(snapshot.createdAt)) ||
      new Date(snapshot.createdAt).toISOString() !== snapshot.createdAt) {
    throw new Error('Invalid tool permission binding creation time.');
  }
  requireDigest(snapshot.policyDigest, 'policyDigest');
  requireDigest(snapshot.trustStoreDigest, 'trustStoreDigest', true);
  requireDigest(snapshot.digest, 'digest');
  if (!['clear', 'bound', 'needs-review', 'block'].includes(snapshot.status)) {
    throw new Error('Invalid tool permission binding snapshot status.');
  }
  if (!Array.isArray(snapshot.bindings)) throw new Error('Tool permission binding snapshot is missing bindings.');
  for (const binding of snapshot.bindings) validateBinding(binding);
  const names = snapshot.bindings.map((binding) => binding.name);
  if (new Set(names).size !== names.length || [...names].sort().join('\0') !== names.join('\0')) {
    throw new Error('Tool permission bindings are not canonical.');
  }
  const summaryFields = [
    'serverCount', 'automaticGrantCount', 'boundCount', 'reviewCount', 'blockedCount',
    'unboundAutomaticGrantCount', 'ambiguousAutomaticGrantCount'
  ];
  const summary = requireExactKeys(
    snapshot.summary,
    new Set(summaryFields),
    'Tool permission binding snapshot has invalid summary fields.'
  );
  for (const field of summaryFields) requireCount(summary[field], field);
  const expected = createSummary(snapshot.bindings, summary);
  if (sha256Json(expected) !== sha256Json(summary)) throw new Error('Tool permission binding summary mismatch.');
  const expectedStatus = expected.blockedCount
    ? 'block'
    : expected.reviewCount || expected.unboundAutomaticGrantCount || expected.ambiguousAutomaticGrantCount
      ? 'needs-review'
      : expected.boundCount ? 'bound' : 'clear';
  if (snapshot.status !== expectedStatus) throw new Error('Tool permission binding snapshot status mismatch.');
  if (snapshot.digest !== snapshotDigest(snapshot)) throw new Error('Tool permission binding snapshot digest mismatch.');
  return snapshot;
}

export function validateToolPermissionBindingSnapshot(snapshot) {
  return validateSnapshot(snapshot);
}

function createSummary(bindings, input) {
  return {
    serverCount: bindings.length,
    automaticGrantCount: bindings.filter((binding) => binding.automaticGrant !== 'none').length,
    boundCount: bindings.filter((binding) => binding.status === 'bound').length,
    reviewCount: bindings.filter((binding) => binding.status === 'needs-review').length,
    blockedCount: bindings.filter((binding) => binding.status === 'blocked').length,
    unboundAutomaticGrantCount: input.unboundAutomaticGrantCount,
    ambiguousAutomaticGrantCount: input.ambiguousAutomaticGrantCount
  };
}

function addChange(changes, impact, type, name, field, before, after) {
  changes.push({ impact, type, name, field, before, after });
}

export function diffToolPermissionBindingSnapshots(beforeInput, afterInput) {
  const before = validateSnapshot(beforeInput);
  const after = validateSnapshot(afterInput);
  if (before.runtime !== after.runtime) throw new Error('Cannot compare different binding runtimes.');

  const changes = [];
  if (before.policyDigest !== after.policyDigest) {
    addChange(changes, 'review', 'policy-changed', null, 'policyDigest', null, null);
  }
  if (before.trustStoreDigest !== after.trustStoreDigest) {
    addChange(changes, 'review', 'trust-store-changed', null, 'trustStoreDigest', null, null);
  }
  for (const field of ['unboundAutomaticGrantCount', 'ambiguousAutomaticGrantCount']) {
    const previous = before.summary[field];
    const current = after.summary[field];
    if (previous !== current) {
      addChange(changes, current > previous ? 'expansion' : 'restriction', 'count-changed', null, field, previous, current);
    }
  }

  const left = new Map(before.bindings.map((binding) => [binding.name, binding]));
  const right = new Map(after.bindings.map((binding) => [binding.name, binding]));
  const grantRank = { none: 0, scoped: 1, all: 2 };

  for (const [name, current] of right) {
    const previous = left.get(name);
    if (!previous) {
      addChange(
        changes,
        current.automaticGrant === 'none' ? 'review' : 'expansion',
        'binding-added',
        name,
        'binding',
        null,
        current.status
      );
      continue;
    }
    if (previous.sourceDecision !== current.sourceDecision) {
      addChange(changes, 'review', 'source-decision-changed', name, 'sourceDecision', previous.sourceDecision, current.sourceDecision);
    }
    for (const field of ['provenanceStatus', 'integrityVerified']) {
      if (previous[field] !== current[field]) {
        addChange(changes, 'review', 'provenance-changed', name, field, previous[field], current[field]);
      }
    }
    if (previous.automaticGrant !== current.automaticGrant) {
      addChange(
        changes,
        grantRank[current.automaticGrant] > grantRank[previous.automaticGrant] ? 'expansion' : 'restriction',
        'grant-changed',
        name,
        'automaticGrant',
        previous.automaticGrant,
        current.automaticGrant
      );
    }
    if (previous.grantRuleCount !== current.grantRuleCount) {
      addChange(
        changes,
        current.grantRuleCount > previous.grantRuleCount ? 'expansion' : 'restriction',
        'count-changed',
        name,
        'grantRuleCount',
        previous.grantRuleCount,
        current.grantRuleCount
      );
    }
    if (previous.toolScopeWildcard !== current.toolScopeWildcard) {
      addChange(
        changes,
        current.toolScopeWildcard ? 'expansion' : 'restriction',
        'wildcard-changed',
        name,
        'toolScopeWildcard',
        previous.toolScopeWildcard,
        current.toolScopeWildcard
      );
    }
  }
  for (const [name, previous] of left) {
    if (!right.has(name)) {
      addChange(
        changes,
        previous.automaticGrant === 'none' ? 'review' : 'restriction',
        'binding-removed',
        name,
        'binding',
        previous.status,
        null
      );
    }
  }

  const summary = {
    expansions: changes.filter((change) => change.impact === 'expansion').length,
    restrictions: changes.filter((change) => change.impact === 'restriction').length,
    reviews: changes.filter((change) => change.impact === 'review').length
  };
  const status = summary.expansions || summary.reviews
    ? 'needs-review'
    : summary.restrictions ? 'restricted' : 'unchanged';
  return {
    schemaVersion: 1,
    runtime: before.runtime,
    status,
    baselineDigest: before.digest,
    currentDigest: after.digest,
    summary,
    changes
  };
}

export function codexAutomaticGrantProjection(results) {
  return results.map((result) => ({
    name: result.name,
    automaticGrant: result.signals?.includes('auto-approve-tools') ? 'all' : 'none',
    grantRuleCount: result.signals?.includes('auto-approve-tools') ? 1 : 0,
    toolScopeWildcard: result.signals?.includes('wildcard-tool-scope') || false
  }));
}

