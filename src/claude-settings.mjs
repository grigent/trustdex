const SECRET_KEY_RE = /(token|secret|password|passwd|api[_-]?key|credential|auth)/i;
const PERMISSION_KEYS = new Set([
  'allow',
  'ask',
  'deny',
  'defaultMode',
  'additionalDirectories',
  'disableBypassPermissionsMode',
  'disableAutoMode',
  'blockReadsOutsideWorkingDirectories',
  'blockWritesOutsideWorkingDirectories',
  'denyInsteadOfPrompting'
]);
const STICKY_PERMISSION_FLAGS = new Set([
  'blockReadsOutsideWorkingDirectories', 'blockWritesOutsideWorkingDirectories', 'denyInsteadOfPrompting'
]);
const MODES = new Set([
  'default',
  'manual',
  'acceptEdits',
  'plan',
  'dontAsk',
  'bypassPermissions',
  'auto'
]);
const CREDENTIAL_HELPERS = ['apiKeyHelper', 'awsAuthRefresh', 'awsCredentialExport', 'gcpAuthRefresh', 'otelHeadersHelper'];
const INSPECTED_ROOT_KEYS = new Set([
  '$schema', 'permissions', 'disableAutoMode', 'env', 'hooks', 'disableAllHooks', 'allowManagedHooksOnly',
  'allowManagedPermissionRulesOnly', 'statusLine', 'fileSuggestion', 'policyHelper', 'sandbox',
  'enabledPlugins', 'extraKnownMarketplaces', ...CREDENTIAL_HELPERS
]);
const CLAUDE_SCOPE_RANK = Object.freeze({
  user: 0,
  project: 1,
  local: 2,
  session: 3,
  managed: 4
});
const MERGED_PERMISSION_LISTS = new Set(['allow', 'ask', 'deny', 'additionalDirectories']);

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function requireStringArray(value, field) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string' || !item.trim())) {
    throw new Error(`Claude permissions.${field} must be an array of non-empty strings.`);
  }
  return value;
}

function parseRule(rule, list) {
  const value = rule.trim();
  const match = value.match(/^([A-Za-z0-9_*.-]+)(?:\(([\s\S]*)\))?$/);
  if (!match) throw new Error(`Invalid Claude permissions.${list} rule syntax.`);

  const tool = match[1];
  const specifier = match[2] === undefined ? null : match[2];
  if (specifier !== null && !specifier.trim()) {
    throw new Error(`Invalid empty specifier in Claude permissions.${list}.`);
  }
  const isMcp = tool.startsWith('mcp__');
  if (isMcp && specifier !== null) {
    throw new Error('Claude skips MCP permission rules with parenthesized specifiers.');
  }
  if (list === 'allow' && tool.includes('*')) {
    const separator = tool.indexOf('__', 5);
    if (!isMcp || separator <= 5 || tool.slice(5, separator).includes('*')) {
      throw new Error('Claude ignores unanchored wildcard allow rules; use a literal MCP server prefix.');
    }
  }

  return {
    tool,
    matchesAll: specifier === null || specifier.trim() === '*' || specifier.trim() === 'domain:*',
    mcpWildcard: isMcp && (tool.includes('*') || !tool.includes('__', 5))
  };
}

// Categorization is deliberately case-insensitive even when a client's rule
// parser may be stricter. An unusual spelling must never lower a risk signal.
function toolCategory(tool) {
  const normalized = String(tool || '').toLowerCase();
  if (normalized === 'bash' || normalized === 'powershell') return 'shell';
  if (['read', 'edit', 'write', 'glob', 'grep', 'notebookedit'].includes(normalized)) return 'filesystem';
  if (normalized === 'webfetch' || normalized === 'websearch') return 'network';
  if (normalized === 'agent') return 'subagent';
  if (normalized.startsWith('mcp__')) return 'mcp';
  return 'other';
}

function validateDisable(value, field) {
  if (value !== undefined && value !== 'disable') {
    throw new Error(`Claude ${field} must be "disable" when present.`);
  }
}

function validateBoolean(value, field) {
  if (value !== undefined && typeof value !== 'boolean') {
    throw new Error(`Claude ${field} must be a boolean.`);
  }
}

function validatePermissions(value) {
  if (value === undefined) return { permissions: {}, rules: { allow: [], ask: [], deny: [] } };
  if (!isObject(value)) throw new Error('Claude settings permissions must be a JSON object.');

  for (const key of Object.keys(value)) {
    if (!PERMISSION_KEYS.has(key)) throw new Error('Unsupported Claude permission setting.');
  }

  const defaultMode = value.defaultMode;
  if (defaultMode !== undefined && (!MODES.has(defaultMode) || typeof defaultMode !== 'string')) {
    throw new Error('Unsupported Claude permissions.defaultMode value.');
  }
  const additionalDirectories = requireStringArray(value.additionalDirectories, 'additionalDirectories');
  for (const key of STICKY_PERMISSION_FLAGS) validateBoolean(value[key], `permissions.${key}`);
  validateDisable(value.disableBypassPermissionsMode, 'permissions.disableBypassPermissionsMode');
  validateDisable(value.disableAutoMode, 'permissions.disableAutoMode');

  const rules = {};
  for (const list of ['allow', 'ask', 'deny']) {
    rules[list] = requireStringArray(value[list], list).map((rule) => parseRule(rule, list));
  }
  return { permissions: { ...value, additionalDirectories }, rules };
}

function inspectAllowRules(rules, signals) {
  for (const rule of rules) {
    signals.add('claude-auto-approve');
    const category = toolCategory(rule.tool);
    if (category === 'shell') signals.add('claude-shell-auto-approve');
    if (category === 'filesystem') signals.add('claude-filesystem-auto-approve');
    if (category === 'network') signals.add('claude-network-auto-approve');
    if (category === 'subagent') signals.add('claude-subagent-auto-approve');
    if (category === 'mcp') signals.add('claude-mcp-auto-approve');
    if (rule.matchesAll && ['shell', 'filesystem', 'network', 'subagent'].includes(category)) {
      signals.add('claude-broad-auto-approve');
    }
    if (rule.mcpWildcard) signals.add('claude-mcp-wildcard');
  }
}

export function inspectClaudeSettings(settings, sourceName = 'settings.json') {
  if (!isObject(settings)) throw new Error('Expected a Claude settings JSON object.');

  const { permissions, rules } = validatePermissions(settings.permissions);
  validateDisable(settings.disableAutoMode, 'settings.disableAutoMode');
  const signals = new Set();
  inspectAllowRules(rules.allow, signals);

  if (permissions.defaultMode === 'bypassPermissions') signals.add('claude-bypass-permissions');
  if (permissions.defaultMode === 'auto') signals.add('claude-auto-mode');
  if (permissions.defaultMode === 'acceptEdits') signals.add('claude-filesystem-auto-approve');
  if (permissions.additionalDirectories?.length) signals.add('claude-additional-directories');
  if (permissions.blockReadsOutsideWorkingDirectories === false) signals.add('claude-outside-read-access');

  let envKeys = [];
  if (settings.env !== undefined) {
    if (!isObject(settings.env)) throw new Error('Claude settings env must be a JSON object.');
    if (Object.values(settings.env).some((value) => typeof value !== 'string')) {
      throw new Error('Claude settings env must contain string values.');
    }
    envKeys = Object.keys(settings.env).sort();
    signals.add('claude-environment');
    if (envKeys.some((key) => SECRET_KEY_RE.test(key))) signals.add('secret-env');
  }
  for (const key of ['disableAllHooks', 'allowManagedHooksOnly', 'allowManagedPermissionRulesOnly']) {
    validateBoolean(settings[key], `settings.${key}`);
  }
  if (['hooks', 'statusLine', 'fileSuggestion', 'policyHelper'].some((key) => settings[key] !== undefined)) {
    signals.add('claude-hooks');
  }
  // Both controls can suppress a guard installed in non-managed settings.
  if (settings.disableAllHooks === true || settings.allowManagedHooksOnly === true) {
    signals.add('claude-hooks-disabled');
  }
  if (CREDENTIAL_HELPERS.some((key) => settings[key] !== undefined)) signals.add('claude-credential-helper');
  if (settings.sandbox !== undefined) signals.add('claude-sandbox-settings');
  if (settings.enabledPlugins !== undefined || settings.extraKnownMarketplaces !== undefined) {
    signals.add('claude-extension-loading');
  }

  const uninspectedRootKeyCount = Object.keys(settings).filter((key) => !INSPECTED_ROOT_KEYS.has(key)).length;
  if (uninspectedRootKeyCount) signals.add('uninspected-claude-settings');

  const allowCategories = [...new Set(rules.allow.map((rule) => toolCategory(rule.tool)))].sort();
  return {
    name: sourceName,
    kind: 'claude-settings',
    source: { type: 'local', format: 'claude-settings', path: sourceName },
    metadata: {
      defaultMode: permissions.defaultMode || null,
      allowRuleCount: rules.allow.length,
      askRuleCount: rules.ask.length,
      denyRuleCount: rules.deny.length,
      allowCategories,
      additionalDirectoryCount: permissions.additionalDirectories?.length || 0,
      bypassDisabled: permissions.disableBypassPermissionsMode === 'disable',
      autoModeDisabled: settings.disableAutoMode === 'disable' || permissions.disableAutoMode === 'disable',
      outsideReadsBlocked: permissions.blockReadsOutsideWorkingDirectories === true,
      outsideWritesBlocked: permissions.blockWritesOutsideWorkingDirectories === true,
      denyInsteadOfPrompting: permissions.denyInsteadOfPrompting === true,
      managedPermissionRulesOnly: settings.allowManagedPermissionRulesOnly === true,
      uninspectedRootKeyCount
    },
    signals: [...signals].sort(),
    envKeys
  };
}

function normalizeClaudeLayers(layers) {
  if (!Array.isArray(layers) || !layers.length) {
    throw new Error('Claude settings stack requires at least one settings source.');
  }
  const seen = new Set();
  return layers.map((layer, index) => {
    if (!isObject(layer) || typeof layer.scope !== 'string' || !Object.hasOwn(CLAUDE_SCOPE_RANK, layer.scope)) {
      throw new Error('Unsupported Claude settings source scope.');
    }
    if (seen.has(layer.scope)) {
      throw new Error(`Claude settings stack accepts only one ${layer.scope} source.`);
    }
    seen.add(layer.scope);
    if (!isObject(layer.settings)) throw new Error('Claude settings source must contain a JSON object.');
    inspectClaudeSettings(layer.settings, 'Claude settings source');
    return { ...layer, index };
  }).sort((left, right) =>
    CLAUDE_SCOPE_RANK[left.scope] - CLAUDE_SCOPE_RANK[right.scope] || left.index - right.index
  );
}

function mergeClaudeSettings(layers) {
  const merged = Object.create(null);
  const permissions = {};
  const managed = layers.find(({ scope }) => scope === 'managed')?.settings;
  const managedRulesOnly = managed?.allowManagedPermissionRulesOnly === true && managed.policyHelper === undefined;

  for (const { scope, settings } of layers) {
    for (const [key, value] of Object.entries(settings)) {
      if (key === 'permissions') continue;
      if (['allowManagedPermissionRulesOnly', 'allowManagedHooksOnly'].includes(key) && scope !== 'managed') continue;
      if (key === 'env') merged.env = { ...merged.env, ...value };
      else if (Array.isArray(value) && Array.isArray(merged[key])) merged[key] = [...merged[key], ...value];
      else merged[key] = value;
    }

    const current = settings.permissions || {};
    for (const [key, value] of Object.entries(current)) {
      if (MERGED_PERMISSION_LISTS.has(key)) {
        if (managedRulesOnly && scope !== 'managed' && key !== 'additionalDirectories') continue;
        permissions[key] = [...(permissions[key] || []), ...value];
        continue;
      }
      if (STICKY_PERMISSION_FLAGS.has(key)) {
        if (key === 'denyInsteadOfPrompting' && ['project', 'local'].includes(scope)) continue;
        permissions[key] = permissions[key] === true || value;
        continue;
      }
      if (key === 'defaultMode' && ['project', 'local'].includes(scope) &&
          ['auto', 'bypassPermissions'].includes(value)) {
        continue;
      }
      permissions[key] = value;
    }
  }

  if (managed?.policyHelper !== undefined) delete merged.allowManagedPermissionRulesOnly;
  if (Object.keys(permissions).length) merged.permissions = permissions;
  return merged;
}

export function inspectClaudeSettingsStack(layers) {
  const normalized = normalizeClaudeLayers(layers);
  const merged = mergeClaudeSettings(normalized);
  const result = inspectClaudeSettings(merged, 'merged Claude settings');
  const sourceCounts = Object.fromEntries(Object.keys(CLAUDE_SCOPE_RANK).map((scope) => [scope, 0]));
  let activeSourceCount = 0;
  for (const layer of normalized) {
    sourceCounts[layer.scope] += 1;
    if (Object.keys(layer.settings).length) activeSourceCount += 1;
  }
  return {
    ...result,
    name: 'merged Claude settings',
    kind: 'claude-settings-stack',
    source: { type: 'local', format: 'claude-settings-stack', scopes: sourceCounts },
    settingsContext: {
      sourceCount: normalized.length,
      activeSourceCount,
      sourceCounts
    }
  };
}

export function inspectClaudeMcpPermissionBindings(layers, serverNames) {
  const normalized = normalizeClaudeLayers(layers);
  if (!Array.isArray(serverNames) ||
      serverNames.some((name) => typeof name !== 'string' || !name.trim()) ||
      new Set(serverNames).size !== serverNames.length) {
    throw new Error('Claude MCP permission bindings require unique non-empty server names.');
  }

  const merged = mergeClaudeSettings(normalized);
  const { rules } = validatePermissions(merged.permissions);
  const grants = new Map(serverNames.map((name) => [name, {
    name,
    automaticGrant: 'none',
    grantRuleCount: 0,
    toolScopeWildcard: false
  }]));
  let unboundAllowRuleCount = 0;
  let ambiguousAllowRuleCount = 0;

  for (const rule of rules.allow.filter((entry) => entry.tool.startsWith('mcp__'))) {
    const matches = serverNames.filter((name) =>
      rule.tool === `mcp__${name}` || rule.tool.startsWith(`mcp__${name}__`)
    );
    if (matches.length !== 1) {
      if (matches.length > 1) ambiguousAllowRuleCount += 1;
      else unboundAllowRuleCount += 1;
      continue;
    }

    const name = matches[0];
    const grant = grants.get(name);
    const prefix = `mcp__${name}`;
    const tool = rule.tool === prefix ? '*' : rule.tool.slice(`${prefix}__`.length);
    grant.grantRuleCount += 1;
    if (tool.includes('*') || !tool) grant.toolScopeWildcard = true;
    if (tool === '*' || !tool) {
      grant.automaticGrant = 'all';
    } else if (grant.automaticGrant === 'none') {
      grant.automaticGrant = 'scoped';
    }
  }

  return {
    grants: [...grants.values()].sort((left, right) => left.name.localeCompare(right.name)),
    unboundAllowRuleCount,
    ambiguousAllowRuleCount
  };
}
