import { sha256Json } from './canonical.mjs';

const ACTION_RANK = Object.freeze({ allow: 0, ask: 1, block: 2 });
const SNAPSHOT_KIND = 'agent-permission-posture';
const SINGLE_SNAPSHOT_VERSION = 1;
const STACK_SNAPSHOT_VERSION = 2;

const CLAUDE_MODES = new Set([
  null,
  'default',
  'manual',
  'acceptEdits',
  'plan',
  'dontAsk',
  'bypassPermissions',
  'auto'
]);
const CLAUDE_CATEGORIES = new Set(['filesystem', 'mcp', 'network', 'other', 'shell', 'subagent']);
const CODEX_APPROVALS = new Set([null, 'on-request', 'never', 'granular']);
const CODEX_REVIEWERS = new Set([null, 'user', 'auto_review']);
const CODEX_SANDBOXES = new Set([null, 'read-only', 'workspace-write', 'danger-full-access']);
const CODEX_PERMISSIONS = new Set([null, ':read-only', ':workspace', ':danger-full-access', 'custom']);
const CODEX_SEARCH = new Set([null, 'disabled', 'cached', 'indexed', 'live']);
const CODEX_PROMPTS = new Set([
  'mcp_elicitations',
  'request_permissions',
  'rules',
  'sandbox_approval',
  'skill_approval'
]);
const RUNTIME_SIGNALS = Object.freeze({
  claude: new Set([
    'claude-auto-approve',
    'claude-broad-auto-approve',
    'claude-shell-auto-approve',
    'claude-filesystem-auto-approve',
    'claude-network-auto-approve',
    'claude-subagent-auto-approve',
    'claude-mcp-auto-approve',
    'claude-mcp-wildcard',
    'claude-bypass-permissions',
    'claude-auto-mode',
    'claude-additional-directories',
    'claude-outside-read-access',
    'claude-hooks',
    'claude-credential-helper',
    'claude-environment',
    'claude-sandbox-settings',
    'claude-extension-loading',
    'uninspected-claude-settings',
    'secret-env'
  ]),
  codex: new Set([
    'codex-no-approvals',
    'codex-auto-review',
    'codex-workspace-write',
    'codex-full-access',
    'codex-network-access',
    'codex-additional-writable-roots',
    'codex-temp-write-access',
    'codex-live-web-search',
    'codex-custom-permissions',
    'codex-subagents-enabled',
    'codex-subagent-settings',
    'codex-extension-settings',
    'uninspected-codex-settings',
    'uninspected-codex-sections'
  ])
});
const SOURCE_SCOPES = Object.freeze({
  claude: Object.freeze(['user', 'project', 'local', 'session', 'managed']),
  codex: Object.freeze(['system', 'managed', 'user', 'profile', 'project', 'cli'])
});

function requireObject(value, message) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(message);
  return value;
}

function requireCount(value, field) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`Invalid permission posture count: ${field}`);
  return value;
}

function requireBoolean(value, field) {
  if (typeof value !== 'boolean') throw new Error(`Invalid permission posture boolean: ${field}`);
  return value;
}

function requireEnum(value, allowed, field) {
  if (!allowed.has(value)) throw new Error(`Invalid permission posture value: ${field}`);
  return value;
}

function requireStringArray(value, allowed, field) {
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string' || !allowed.has(item))) {
    throw new Error(`Invalid permission posture list: ${field}`);
  }
  return [...new Set(value)].sort();
}

function assertMetadataKeys(metadata, expected) {
  for (const key of Object.keys(metadata)) {
    if (!expected.has(key)) throw new Error(`Unsupported permission posture metadata: ${key}`);
  }
}

function normalizeClaudeMetadata(metadata) {
  const expected = new Set([
    'defaultMode',
    'allowRuleCount',
    'askRuleCount',
    'denyRuleCount',
    'allowCategories',
    'additionalDirectoryCount',
    'bypassDisabled',
    'autoModeDisabled',
    'outsideReadsBlocked',
    'uninspectedRootKeys'
  ]);
  assertMetadataKeys(metadata, expected);
  if (!Array.isArray(metadata.uninspectedRootKeys) ||
      metadata.uninspectedRootKeys.some((item) => typeof item !== 'string')) {
    throw new Error('Invalid Claude uninspected root key metadata.');
  }
  return {
    defaultMode: requireEnum(metadata.defaultMode, CLAUDE_MODES, 'defaultMode'),
    allowRuleCount: requireCount(metadata.allowRuleCount, 'allowRuleCount'),
    askRuleCount: requireCount(metadata.askRuleCount, 'askRuleCount'),
    denyRuleCount: requireCount(metadata.denyRuleCount, 'denyRuleCount'),
    allowCategories: requireStringArray(metadata.allowCategories, CLAUDE_CATEGORIES, 'allowCategories'),
    additionalDirectoryCount: requireCount(metadata.additionalDirectoryCount, 'additionalDirectoryCount'),
    bypassDisabled: requireBoolean(metadata.bypassDisabled, 'bypassDisabled'),
    autoModeDisabled: requireBoolean(metadata.autoModeDisabled, 'autoModeDisabled'),
    outsideReadsBlocked: requireBoolean(metadata.outsideReadsBlocked, 'outsideReadsBlocked'),
    uninspectedRootKeyCount: metadata.uninspectedRootKeys.length
  };
}

function normalizeCodexMetadata(metadata) {
  const expected = new Set([
    'approvalPolicy',
    'granularPromptCategories',
    'approvalsReviewer',
    'sandboxMode',
    'defaultPermissionsKind',
    'webSearch',
    'networkAccess',
    'additionalWritableRootCount',
    'tempRootsExcluded',
    'subagentsEnabled',
    'uninspectedAgentKeys',
    'uninspectedRootKeys',
    'uninspectedSectionKinds'
  ]);
  assertMetadataKeys(metadata, expected);
  for (const field of ['uninspectedAgentKeys', 'uninspectedRootKeys', 'uninspectedSectionKinds']) {
    if (!Array.isArray(metadata[field]) || metadata[field].some((item) => typeof item !== 'string')) {
      throw new Error(`Invalid Codex ${field} metadata.`);
    }
  }
  return {
    approvalPolicy: requireEnum(metadata.approvalPolicy, CODEX_APPROVALS, 'approvalPolicy'),
    granularPromptCategories: requireStringArray(
      metadata.granularPromptCategories,
      CODEX_PROMPTS,
      'granularPromptCategories'
    ),
    approvalsReviewer: requireEnum(metadata.approvalsReviewer, CODEX_REVIEWERS, 'approvalsReviewer'),
    sandboxMode: requireEnum(metadata.sandboxMode, CODEX_SANDBOXES, 'sandboxMode'),
    defaultPermissionsKind: requireEnum(
      metadata.defaultPermissionsKind,
      CODEX_PERMISSIONS,
      'defaultPermissionsKind'
    ),
    webSearch: requireEnum(metadata.webSearch, CODEX_SEARCH, 'webSearch'),
    networkAccess: requireBoolean(metadata.networkAccess, 'networkAccess'),
    additionalWritableRootCount: requireCount(
      metadata.additionalWritableRootCount,
      'additionalWritableRootCount'
    ),
    tempRootsExcluded: requireBoolean(metadata.tempRootsExcluded, 'tempRootsExcluded'),
    subagentsEnabled: requireBoolean(metadata.subagentsEnabled, 'subagentsEnabled'),
    uninspectedAgentKeyCount: metadata.uninspectedAgentKeys.length,
    uninspectedRootKeyCount: metadata.uninspectedRootKeys.length,
    uninspectedSectionKindCount: metadata.uninspectedSectionKinds.length
  };
}

function projectAction(value) {
  return Object.hasOwn(ACTION_RANK, value) ? value : value == null ? null : 'invalid';
}

function projectPolicy(policy, runtime) {
  const relevantSignals = RUNTIME_SIGNALS[runtime];
  const signalActions = Object.fromEntries(
    Object.entries(policy?.signalActions || {})
      .filter(([signal]) => relevantSignals.has(signal))
      .map(([signal, action]) => [signal, projectAction(action)])
      .sort(([left], [right]) => left.localeCompare(right))
  );
  return {
    unknownAction: projectAction(policy?.unknownAction),
    localAction: projectAction(policy?.localAction),
    sensitiveAction: projectAction(policy?.sensitiveAction),
    signalActions
  };
}

function normalizeSettingsContext(context, runtime) {
  requireObject(context, 'Permission posture settings context is missing.');
  assertMetadataKeys(context, new Set(['sourceCount', 'activeSourceCount', 'sourceCounts']));
  const sourceCount = requireCount(context.sourceCount, 'sourceCount');
  const activeSourceCount = requireCount(context.activeSourceCount, 'activeSourceCount');
  if (activeSourceCount > sourceCount) {
    throw new Error('Permission posture active source count exceeds total source count.');
  }
  const inputCounts = requireObject(context.sourceCounts, 'Permission posture source counts are missing.');
  const scopes = SOURCE_SCOPES[runtime];
  assertMetadataKeys(inputCounts, new Set(scopes));
  const sourceCounts = Object.fromEntries(
    scopes.map((scope) => [scope, requireCount(inputCounts[scope], `sourceCounts.${scope}`)])
  );
  if (Object.values(sourceCounts).reduce((total, count) => total + count, 0) !== sourceCount) {
    throw new Error('Permission posture source counts do not match the total source count.');
  }
  return { sourceCount, activeSourceCount, sourceCounts };
}

function snapshotDigest(snapshot) {
  const projected = {
    schemaVersion: snapshot.schemaVersion,
    kind: snapshot.kind,
    runtime: snapshot.runtime,
    policyDigest: snapshot.policyDigest,
    posture: snapshot.posture
  };
  if (snapshot.schemaVersion === STACK_SNAPSHOT_VERSION) projected.sources = snapshot.sources;
  return sha256Json(projected);
}

export function createPermissionPostureSnapshot(result, policy = {}) {
  requireObject(result, 'Permission posture requires one evaluated settings result.');
  if (!Object.hasOwn(ACTION_RANK, result.action)) throw new Error('Permission posture result has an invalid action.');
  if (!Array.isArray(result.signals) || result.signals.some((item) => typeof item !== 'string')) {
    throw new Error('Permission posture result has invalid signals.');
  }
  const runtime = ['claude-settings', 'claude-settings-stack'].includes(result.kind)
    ? 'claude'
    : ['codex-settings', 'codex-settings-stack'].includes(result.kind) ? 'codex' : null;
  if (!runtime) throw new Error('Permission posture supports Claude or Codex settings results only.');
  if (result.signals.some((signal) => !RUNTIME_SIGNALS[runtime].has(signal))) {
    throw new Error('Permission posture result contains an unsupported signal.');
  }

  const metadata = requireObject(result.metadata, 'Permission posture result is missing metadata.');
  const posture = {
    action: result.action,
    signals: [...new Set(result.signals)].sort(),
    metadata: runtime === 'claude'
      ? normalizeClaudeMetadata(metadata)
      : normalizeCodexMetadata(metadata)
  };
  const isStack = result.kind.endsWith('-stack');
  const snapshot = {
    schemaVersion: isStack ? STACK_SNAPSHOT_VERSION : SINGLE_SNAPSHOT_VERSION,
    kind: SNAPSHOT_KIND,
    createdAt: new Date().toISOString(),
    runtime,
    policyDigest: sha256Json(projectPolicy(policy, runtime)),
    posture
  };
  if (isStack) snapshot.sources = normalizeSettingsContext(result.settingsContext, runtime);
  return { ...snapshot, digest: snapshotDigest(snapshot) };
}

function validateSnapshot(snapshot) {
  requireObject(snapshot, 'Invalid permission posture snapshot.');
  if (![SINGLE_SNAPSHOT_VERSION, STACK_SNAPSHOT_VERSION].includes(snapshot.schemaVersion) ||
      snapshot.kind !== SNAPSHOT_KIND) {
    throw new Error('Unsupported permission posture snapshot schema.');
  }
  if (!['claude', 'codex'].includes(snapshot.runtime)) throw new Error('Invalid permission posture runtime.');
  if (typeof snapshot.policyDigest !== 'string' || !/^[a-f0-9]{64}$/.test(snapshot.policyDigest)) {
    throw new Error('Invalid permission posture policy digest.');
  }
  requireObject(snapshot.posture, 'Permission posture snapshot is missing posture data.');
  if (!Object.hasOwn(ACTION_RANK, snapshot.posture.action)) throw new Error('Invalid permission posture action.');
  if (!Array.isArray(snapshot.posture.signals) ||
      snapshot.posture.signals.some((item) => typeof item !== 'string')) {
    throw new Error('Invalid permission posture signals.');
  }
  const normalizedSignals = [...new Set(snapshot.posture.signals)].sort();
  if (sha256Json(normalizedSignals) !== sha256Json(snapshot.posture.signals)) {
    throw new Error('Non-canonical permission posture signals.');
  }
  const metadata = requireObject(snapshot.posture.metadata, 'Permission posture snapshot is missing metadata.');
  if (snapshot.runtime === 'claude') {
    const normalized = normalizeClaudeSnapshotMetadata(metadata);
    if (sha256Json(normalized) !== sha256Json(metadata)) throw new Error('Non-canonical Claude posture metadata.');
  } else {
    const normalized = normalizeCodexSnapshotMetadata(metadata);
    if (sha256Json(normalized) !== sha256Json(metadata)) throw new Error('Non-canonical Codex posture metadata.');
  }
  if (snapshot.schemaVersion === STACK_SNAPSHOT_VERSION) {
    const normalized = normalizeSettingsContext(snapshot.sources, snapshot.runtime);
    if (sha256Json(normalized) !== sha256Json(snapshot.sources)) {
      throw new Error('Non-canonical permission posture source metadata.');
    }
  } else if (snapshot.sources !== undefined) {
    throw new Error('Permission posture v1 does not support source metadata.');
  }
  if (snapshot.digest !== snapshotDigest(snapshot)) throw new Error('Permission posture snapshot digest mismatch.');
  return snapshot;
}

function normalizeClaudeSnapshotMetadata(metadata) {
  const expected = new Set([
    'defaultMode', 'allowRuleCount', 'askRuleCount', 'denyRuleCount', 'allowCategories',
    'additionalDirectoryCount', 'bypassDisabled', 'autoModeDisabled', 'outsideReadsBlocked',
    'uninspectedRootKeyCount'
  ]);
  assertMetadataKeys(metadata, expected);
  return {
    defaultMode: requireEnum(metadata.defaultMode, CLAUDE_MODES, 'defaultMode'),
    allowRuleCount: requireCount(metadata.allowRuleCount, 'allowRuleCount'),
    askRuleCount: requireCount(metadata.askRuleCount, 'askRuleCount'),
    denyRuleCount: requireCount(metadata.denyRuleCount, 'denyRuleCount'),
    allowCategories: requireStringArray(metadata.allowCategories, CLAUDE_CATEGORIES, 'allowCategories'),
    additionalDirectoryCount: requireCount(metadata.additionalDirectoryCount, 'additionalDirectoryCount'),
    bypassDisabled: requireBoolean(metadata.bypassDisabled, 'bypassDisabled'),
    autoModeDisabled: requireBoolean(metadata.autoModeDisabled, 'autoModeDisabled'),
    outsideReadsBlocked: requireBoolean(metadata.outsideReadsBlocked, 'outsideReadsBlocked'),
    uninspectedRootKeyCount: requireCount(metadata.uninspectedRootKeyCount, 'uninspectedRootKeyCount')
  };
}

function normalizeCodexSnapshotMetadata(metadata) {
  const expected = new Set([
    'approvalPolicy', 'granularPromptCategories', 'approvalsReviewer', 'sandboxMode',
    'defaultPermissionsKind', 'webSearch', 'networkAccess', 'additionalWritableRootCount',
    'tempRootsExcluded', 'subagentsEnabled', 'uninspectedAgentKeyCount',
    'uninspectedRootKeyCount', 'uninspectedSectionKindCount'
  ]);
  assertMetadataKeys(metadata, expected);
  return {
    approvalPolicy: requireEnum(metadata.approvalPolicy, CODEX_APPROVALS, 'approvalPolicy'),
    granularPromptCategories: requireStringArray(
      metadata.granularPromptCategories,
      CODEX_PROMPTS,
      'granularPromptCategories'
    ),
    approvalsReviewer: requireEnum(metadata.approvalsReviewer, CODEX_REVIEWERS, 'approvalsReviewer'),
    sandboxMode: requireEnum(metadata.sandboxMode, CODEX_SANDBOXES, 'sandboxMode'),
    defaultPermissionsKind: requireEnum(
      metadata.defaultPermissionsKind,
      CODEX_PERMISSIONS,
      'defaultPermissionsKind'
    ),
    webSearch: requireEnum(metadata.webSearch, CODEX_SEARCH, 'webSearch'),
    networkAccess: requireBoolean(metadata.networkAccess, 'networkAccess'),
    additionalWritableRootCount: requireCount(
      metadata.additionalWritableRootCount,
      'additionalWritableRootCount'
    ),
    tempRootsExcluded: requireBoolean(metadata.tempRootsExcluded, 'tempRootsExcluded'),
    subagentsEnabled: requireBoolean(metadata.subagentsEnabled, 'subagentsEnabled'),
    uninspectedAgentKeyCount: requireCount(metadata.uninspectedAgentKeyCount, 'uninspectedAgentKeyCount'),
    uninspectedRootKeyCount: requireCount(metadata.uninspectedRootKeyCount, 'uninspectedRootKeyCount'),
    uninspectedSectionKindCount: requireCount(
      metadata.uninspectedSectionKindCount,
      'uninspectedSectionKindCount'
    )
  };
}

function addChange(changes, impact, type, field, before, after) {
  changes.push({ impact, type, field, before, after });
}

function compareCount(changes, field, before, after, riskIncreasing = true) {
  if (before === after) return;
  const increased = after > before;
  const impact = increased === riskIncreasing ? 'expansion' : 'restriction';
  addChange(changes, impact, 'count-changed', field, before, after);
}

function compareBoolean(changes, field, before, after, trueIsRisk) {
  if (before === after) return;
  const impact = after === trueIsRisk ? 'expansion' : 'restriction';
  addChange(changes, impact, 'boolean-changed', field, before, after);
}

function compareArray(changes, field, before, after, additionsAreRisk = true) {
  const added = after.filter((item) => !before.includes(item));
  const removed = before.filter((item) => !after.includes(item));
  if (added.length) {
    changes.push({
      impact: additionsAreRisk ? 'expansion' : 'restriction',
      type: 'items-added',
      field,
      items: added
    });
  }
  if (removed.length) {
    changes.push({
      impact: additionsAreRisk ? 'restriction' : 'expansion',
      type: 'items-removed',
      field,
      items: removed
    });
  }
}

function compareRanked(changes, field, before, after, ranks) {
  if (before === after) return;
  if (!Object.hasOwn(ranks, before) || !Object.hasOwn(ranks, after) || ranks[before] === ranks[after]) {
    addChange(changes, 'review', 'value-changed', field, before, after);
    return;
  }
  addChange(
    changes,
    ranks[after] > ranks[before] ? 'expansion' : 'restriction',
    'value-changed',
    field,
    before,
    after
  );
}

function compareClaudeMetadata(changes, before, after) {
  compareRanked(changes, 'defaultMode', before.defaultMode, after.defaultMode, {
    plan: 0,
    manual: 0,
    default: 1,
    acceptEdits: 2,
    dontAsk: 3,
    auto: 4,
    bypassPermissions: 5
  });
  compareCount(changes, 'allowRuleCount', before.allowRuleCount, after.allowRuleCount, true);
  compareCount(changes, 'askRuleCount', before.askRuleCount, after.askRuleCount, false);
  compareCount(changes, 'denyRuleCount', before.denyRuleCount, after.denyRuleCount, false);
  compareArray(changes, 'allowCategories', before.allowCategories, after.allowCategories, true);
  compareCount(
    changes,
    'additionalDirectoryCount',
    before.additionalDirectoryCount,
    after.additionalDirectoryCount,
    true
  );
  compareBoolean(changes, 'bypassDisabled', before.bypassDisabled, after.bypassDisabled, false);
  compareBoolean(changes, 'autoModeDisabled', before.autoModeDisabled, after.autoModeDisabled, false);
  compareBoolean(changes, 'outsideReadsBlocked', before.outsideReadsBlocked, after.outsideReadsBlocked, false);
  compareCount(
    changes,
    'uninspectedRootKeyCount',
    before.uninspectedRootKeyCount,
    after.uninspectedRootKeyCount,
    true
  );
}

function compareCodexMetadata(changes, before, after) {
  compareRanked(changes, 'approvalPolicy', before.approvalPolicy, after.approvalPolicy, {
    'on-request': 0,
    granular: 0,
    never: 2
  });
  compareArray(
    changes,
    'granularPromptCategories',
    before.granularPromptCategories,
    after.granularPromptCategories,
    false
  );
  compareRanked(changes, 'approvalsReviewer', before.approvalsReviewer, after.approvalsReviewer, {
    user: 0,
    auto_review: 1
  });
  compareRanked(changes, 'sandboxMode', before.sandboxMode, after.sandboxMode, {
    'read-only': 0,
    'workspace-write': 1,
    'danger-full-access': 2
  });
  compareRanked(changes, 'defaultPermissionsKind', before.defaultPermissionsKind, after.defaultPermissionsKind, {
    ':read-only': 0,
    ':workspace': 1,
    custom: 2,
    ':danger-full-access': 3
  });
  compareRanked(changes, 'webSearch', before.webSearch, after.webSearch, {
    disabled: 0,
    cached: 1,
    indexed: 1,
    live: 2
  });
  compareBoolean(changes, 'networkAccess', before.networkAccess, after.networkAccess, true);
  compareCount(
    changes,
    'additionalWritableRootCount',
    before.additionalWritableRootCount,
    after.additionalWritableRootCount,
    true
  );
  compareBoolean(changes, 'tempRootsExcluded', before.tempRootsExcluded, after.tempRootsExcluded, false);
  compareBoolean(changes, 'subagentsEnabled', before.subagentsEnabled, after.subagentsEnabled, true);
  compareCount(
    changes,
    'uninspectedAgentKeyCount',
    before.uninspectedAgentKeyCount,
    after.uninspectedAgentKeyCount,
    true
  );
  compareCount(
    changes,
    'uninspectedRootKeyCount',
    before.uninspectedRootKeyCount,
    after.uninspectedRootKeyCount,
    true
  );
  compareCount(
    changes,
    'uninspectedSectionKindCount',
    before.uninspectedSectionKindCount,
    after.uninspectedSectionKindCount,
    true
  );
}

export function diffPermissionPostureSnapshots(beforeInput, afterInput) {
  const before = validateSnapshot(beforeInput);
  const after = validateSnapshot(afterInput);
  if (before.runtime !== after.runtime) throw new Error('Cannot compare different permission posture runtimes.');

  const changes = [];
  if (before.schemaVersion !== after.schemaVersion) {
    addChange(
      changes,
      'review',
      'value-changed',
      'schemaVersion',
      before.schemaVersion,
      after.schemaVersion
    );
  } else if (before.schemaVersion === STACK_SNAPSHOT_VERSION) {
    for (const field of ['sourceCount', 'activeSourceCount']) {
      if (before.sources[field] !== after.sources[field]) {
        addChange(changes, 'review', 'count-changed', `sources.${field}`, before.sources[field], after.sources[field]);
      }
    }
    for (const scope of SOURCE_SCOPES[before.runtime]) {
      const previous = before.sources.sourceCounts[scope];
      const current = after.sources.sourceCounts[scope];
      if (previous !== current) {
        addChange(changes, 'review', 'count-changed', `sources.${scope}`, previous, current);
      }
    }
  }
  if (before.policyDigest !== after.policyDigest) {
    changes.push({ impact: 'review', type: 'policy-changed', field: 'policyDigest' });
  }

  compareArray(changes, 'signals', before.posture.signals, after.posture.signals, true);
  if (before.posture.action !== after.posture.action) {
    addChange(
      changes,
      ACTION_RANK[after.posture.action] > ACTION_RANK[before.posture.action]
        ? 'expansion'
        : 'restriction',
      'decision-changed',
      'action',
      before.posture.action,
      after.posture.action
    );
  }

  if (before.runtime === 'claude') {
    compareClaudeMetadata(changes, before.posture.metadata, after.posture.metadata);
  } else {
    compareCodexMetadata(changes, before.posture.metadata, after.posture.metadata);
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
    schemaVersion: Math.max(before.schemaVersion, after.schemaVersion),
    runtime: before.runtime,
    status,
    baselineDigest: before.digest,
    currentDigest: after.digest,
    summary,
    changes
  };
}
