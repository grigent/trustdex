import { decodeTomlValue, parseTomlStatements } from './toml-lite.mjs';

const APPROVAL_POLICIES = new Set(['on-request', 'never']);
const APPROVAL_REVIEWERS = new Set(['user', 'auto_review']);
const SANDBOX_MODES = new Set(['read-only', 'workspace-write', 'danger-full-access']);
const BUILTIN_PERMISSIONS = new Set([':read-only', ':workspace', ':danger-full-access']);
const WEB_SEARCH_MODES = new Set(['disabled', 'cached', 'indexed', 'live']);
const GRANULAR_KEYS = new Set([
  'sandbox_approval',
  'rules',
  'mcp_elicitations',
  'request_permissions',
  'skill_approval'
]);
const SANDBOX_KEYS = new Set([
  'network_access',
  'writable_roots',
  'exclude_slash_tmp',
  'exclude_tmpdir_env_var'
]);
const INSPECTED_ROOT_KEYS = new Set([
  'approval_policy',
  'approvals_reviewer',
  'sandbox_mode',
  'default_permissions',
  'web_search'
]);
const CODEX_SCOPE_RANK = Object.freeze({
  system: 0,
  managed: 1,
  user: 2,
  profile: 3,
  project: 4,
  cli: 5
});

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function requireBoolean(value, key) {
  if (typeof value !== 'boolean') throw new Error(`Codex ${key} must be a boolean.`);
  return value;
}

function requireStringArray(value, key) {
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string' || !item.trim())) {
    throw new Error(`Codex ${key} must be an array of non-empty strings.`);
  }
  return value;
}

function parseApprovalPolicy(value) {
  if (typeof value === 'string') {
    if (!APPROVAL_POLICIES.has(value)) throw new Error('Unsupported Codex approval_policy value.');
    return { mode: value, promptCategories: [] };
  }
  if (!isObject(value) || !isObject(value.granular) || Object.keys(value).some((key) => key !== 'granular')) {
    throw new Error('Codex approval_policy must be "on-request", "never", or a granular policy.');
  }
  for (const [key, enabled] of Object.entries(value.granular)) {
    if (!GRANULAR_KEYS.has(key) || typeof enabled !== 'boolean') {
      throw new Error(`Unsupported Codex granular approval setting: ${key}`);
    }
  }
  return {
    mode: 'granular',
    promptCategories: Object.entries(value.granular)
      .filter(([, enabled]) => enabled)
      .map(([key]) => key)
      .sort()
  };
}

function parseTomlAssignments(text) {
  const root = Object.create(null);
  const sandbox = Object.create(null);
  const agents = Object.create(null);
  const approvalGranular = Object.create(null);
  const sections = new Set();
  let granularDeclared = false;
  const put = (target, key, value, label) => {
    if (Object.hasOwn(target, key)) throw new Error(`Duplicate Codex ${label} setting: ${key}`);
    target[key] = value;
  };

  // Every statement is resolved by its full key path, so a quoted or spaced header,
  // a dotted key, or an inline table reaches the same setting as the plain form.
  const assign = (path, node, inTable) => {
    const [head, second, third, ...rest] = path;
    if (head === 'sandbox_workspace_write') {
      if (second === undefined) {
        if (node.kind !== 'table') throw new Error('Unsupported Codex sandbox_workspace_write value.');
        for (const entry of node.value) assign([head, ...entry.path], entry.value, inTable);
        return;
      }
      if (third !== undefined) throw new Error(`Unsupported Codex sandbox key: ${path.slice(1).join('.')}`);
      put(sandbox, second, decodeTomlValue(node), 'sandbox');
      return;
    }
    if (head === 'approval_policy' && second !== undefined) {
      if (second !== 'granular') throw new Error(`Unsupported Codex security section: ${path.slice(0, 2).join('.')}`);
      if (third === undefined) {
        if (node.kind !== 'table') throw new Error('Unsupported Codex approval_policy.granular value.');
        granularDeclared = true;
        for (const entry of node.value) assign([head, second, ...entry.path], entry.value, inTable);
        return;
      }
      if (rest.length) throw new Error(`Unsupported Codex approval setting: ${path.join('.')}`);
      put(approvalGranular, third, decodeTomlValue(node), 'approval');
      return;
    }
    if (head === 'agents') {
      if (second === undefined) {
        if (node.kind !== 'table') throw new Error('Unsupported Codex agents value.');
        for (const entry of node.value) assign([head, ...entry.path], entry.value, inTable);
        return;
      }
      put(agents, path.slice(1).join('.'), decodeTomlValue(node), 'agents');
      return;
    }
    if (inTable) return;
    put(root, path.join('.'), decodeTomlValue(node), 'root');
  };

  for (const statement of parseTomlStatements(text)) {
    if (statement.type !== 'value') {
      const section = statement.path.join('.');
      if (statement.path[0] === 'sandbox_workspace_write' && statement.path.length > 1) {
        throw new Error(`Unsupported Codex security section: ${section}`);
      }
      if (statement.path[0] === 'approval_policy' &&
          !(statement.path.length === 2 && statement.path[1] === 'granular')) {
        throw new Error(`Unsupported Codex security section: ${section}`);
      }
      if (statement.type === 'array-table' && ['sandbox_workspace_write', 'approval_policy', 'agents'].includes(statement.path[0])) {
        throw new Error(`Unsupported Codex security section: ${section}`);
      }
      if (section === 'approval_policy.granular') granularDeclared = true;
      sections.add(section);
      continue;
    }
    const inspected = ['sandbox_workspace_write', 'approval_policy', 'agents'].includes(statement.path[0]);
    if (statement.table.length && !inspected) continue;
    assign(statement.path, statement.value, statement.table.length > 0);
  }

  if (granularDeclared || Object.keys(approvalGranular).length) {
    if (root.approval_policy !== undefined) {
      throw new Error('Codex approval_policy cannot be declared in more than one form.');
    }
    root.approval_policy = { granular: approvalGranular };
  }

  return { root, sandbox, agents, sections: [...sections].sort() };
}

function validateSandbox(sandbox) {
  for (const key of Object.keys(sandbox)) {
    if (!SANDBOX_KEYS.has(key)) throw new Error(`Unsupported Codex sandbox_workspace_write setting: ${key}`);
  }
  if (sandbox.network_access !== undefined) requireBoolean(sandbox.network_access, 'sandbox network_access');
  if (sandbox.writable_roots !== undefined) requireStringArray(sandbox.writable_roots, 'sandbox writable_roots');
  if (sandbox.exclude_slash_tmp !== undefined) requireBoolean(sandbox.exclude_slash_tmp, 'sandbox exclude_slash_tmp');
  if (sandbox.exclude_tmpdir_env_var !== undefined) {
    requireBoolean(sandbox.exclude_tmpdir_env_var, 'sandbox exclude_tmpdir_env_var');
  }
}

function inspectParsedCodexSettings({ root, sandbox, agents, sections }, sourceName, kind) {
  validateSandbox(sandbox);

  const signals = new Set();
  let approval = { mode: null, promptCategories: [] };
  if (root.approval_policy !== undefined) {
    approval = parseApprovalPolicy(root.approval_policy);
    if (approval.mode === 'never') signals.add('codex-no-approvals');
  }

  if (root.approvals_reviewer !== undefined) {
    if (!APPROVAL_REVIEWERS.has(root.approvals_reviewer)) {
      throw new Error('Unsupported Codex approvals_reviewer value.');
    }
    if (root.approvals_reviewer === 'auto_review') signals.add('codex-auto-review');
  }

  if (root.sandbox_mode !== undefined) {
    if (!SANDBOX_MODES.has(root.sandbox_mode)) throw new Error('Unsupported Codex sandbox_mode value.');
    if (root.sandbox_mode === 'workspace-write') signals.add('codex-workspace-write');
    if (root.sandbox_mode === 'danger-full-access') signals.add('codex-full-access');
  }

  if (root.default_permissions !== undefined) {
    if (typeof root.default_permissions !== 'string' || !root.default_permissions.trim()) {
      throw new Error('Codex default_permissions must be a non-empty string.');
    }
    if (root.sandbox_mode !== undefined || sections.includes('sandbox_workspace_write') || Object.keys(sandbox).length) {
      throw new Error('Codex default_permissions cannot be combined with sandbox_mode or sandbox_workspace_write.');
    }
    if (root.default_permissions === ':workspace') signals.add('codex-workspace-write');
    else if (root.default_permissions === ':danger-full-access') signals.add('codex-full-access');
    else if (!BUILTIN_PERMISSIONS.has(root.default_permissions)) signals.add('codex-custom-permissions');
  }

  if (root.web_search !== undefined) {
    if (!WEB_SEARCH_MODES.has(root.web_search)) throw new Error('Unsupported Codex web_search value.');
    if (root.web_search === 'live') signals.add('codex-live-web-search');
  }

  if (sandbox.network_access === true) signals.add('codex-network-access');
  const writableRoots = sandbox.writable_roots || [];
  if (writableRoots.length) signals.add('codex-additional-writable-roots');
  if (sandbox.exclude_slash_tmp === false || sandbox.exclude_tmpdir_env_var === false) {
    signals.add('codex-temp-write-access');
  }
  if (agents.enabled !== undefined) {
    requireBoolean(agents.enabled, 'agents.enabled');
    if (agents.enabled) signals.add('codex-subagents-enabled');
  }
  const uninspectedAgentKeys = Object.keys(agents).filter((key) => key !== 'enabled').sort();
  if (uninspectedAgentKeys.length) signals.add('codex-subagent-settings');

  const uninspectedRootKeys = Object.keys(root).filter((key) => !INSPECTED_ROOT_KEYS.has(key)).sort();
  if (uninspectedRootKeys.length) signals.add('uninspected-codex-settings');

  const sectionKinds = new Set(sections.map((section) => section.split('.')[0]));
  sectionKinds.delete('sandbox_workspace_write');
  sectionKinds.delete('approval_policy');
  sectionKinds.delete('mcp_servers');
  if (!uninspectedAgentKeys.length) sectionKinds.delete('agents');
  if (sectionKinds.has('permissions')) signals.add('codex-custom-permissions');
  if (sectionKinds.has('apps') || sectionKinds.has('plugins')) signals.add('codex-extension-settings');
  if (sectionKinds.size) signals.add('uninspected-codex-sections');

  return {
    name: sourceName,
    kind,
    source: { type: 'local', format: 'codex-settings', path: sourceName },
    metadata: {
      approvalPolicy: approval.mode,
      granularPromptCategories: approval.promptCategories,
      approvalsReviewer: root.approvals_reviewer || null,
      sandboxMode: root.sandbox_mode || null,
      defaultPermissionsKind: BUILTIN_PERMISSIONS.has(root.default_permissions)
        ? root.default_permissions
        : root.default_permissions ? 'custom' : null,
      webSearch: root.web_search || null,
      networkAccess: sandbox.network_access === true,
      additionalWritableRootCount: writableRoots.length,
      tempRootsExcluded: sandbox.exclude_slash_tmp === true && sandbox.exclude_tmpdir_env_var === true,
      subagentsEnabled: agents.enabled === true,
      uninspectedAgentKeys,
      uninspectedRootKeys,
      uninspectedSectionKinds: [...sectionKinds].sort()
    },
    signals: [...signals].sort(),
    envKeys: []
  };
}

export function inspectCodexSettingsText(text, sourceName = 'config.toml') {
  return inspectParsedCodexSettings(
    parseTomlAssignments(text),
    sourceName,
    'codex-settings'
  );
}

function normalizeCodexLayers(layers) {
  if (!Array.isArray(layers) || !layers.length) {
    throw new Error('Codex settings stack requires at least one config source.');
  }
  const seen = new Set();
  return layers.map((layer, index) => {
    if (!isObject(layer) || !Object.hasOwn(CODEX_SCOPE_RANK, layer.scope)) {
      throw new Error('Unsupported Codex config source scope.');
    }
    if (layer.scope !== 'project' && seen.has(layer.scope)) {
      throw new Error(`Codex settings stack accepts only one ${layer.scope} source.`);
    }
    seen.add(layer.scope);
    if (typeof layer.text !== 'string') throw new Error('Codex config source must contain TOML text.');
    const parsed = parseTomlAssignments(layer.text);
    inspectParsedCodexSettings(parsed, 'Codex settings source', 'codex-settings');
    return { ...layer, parsed, index };
  }).sort((left, right) =>
    CODEX_SCOPE_RANK[left.scope] - CODEX_SCOPE_RANK[right.scope] || left.index - right.index
  );
}

export function inspectCodexSettingsStack(layers) {
  const normalized = normalizeCodexLayers(layers);
  const merged = {
    root: Object.create(null),
    sandbox: Object.create(null),
    agents: Object.create(null),
    sections: []
  };
  const sections = new Set();
  const sourceCounts = Object.fromEntries(Object.keys(CODEX_SCOPE_RANK).map((scope) => [scope, 0]));
  let activeSourceCount = 0;

  for (const layer of normalized) {
    sourceCounts[layer.scope] += 1;
    Object.assign(merged.root, layer.parsed.root);
    Object.assign(merged.sandbox, layer.parsed.sandbox);
    Object.assign(merged.agents, layer.parsed.agents);
    for (const section of layer.parsed.sections) sections.add(section);
    if (Object.keys(layer.parsed.root).length || Object.keys(layer.parsed.sandbox).length ||
        Object.keys(layer.parsed.agents).length || layer.parsed.sections.length) {
      activeSourceCount += 1;
    }
  }
  merged.sections = [...sections].sort();

  const result = inspectParsedCodexSettings(
    merged,
    'merged Codex settings',
    'codex-settings-stack'
  );
  return {
    ...result,
    source: { type: 'local', format: 'codex-settings-stack', scopes: sourceCounts },
    settingsContext: {
      sourceCount: normalized.length,
      activeSourceCount,
      sourceCounts
    }
  };
}
