const SECRET_KEY_RE = /(token|secret|password|passwd|api[_-]?key|credential|auth)/i;
const PERMISSION_KEYS = new Set([
  'allow',
  'ask',
  'deny',
  'defaultMode',
  'additionalDirectories',
  'disableBypassPermissionsMode',
  'disableAutoMode',
  'blockReadsOutsideWorkingDirectories'
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
const NON_PERMISSION_ROOT_KEYS = new Set(['$schema', 'permissions']);

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
  if (list === 'allow' && (tool === '*' || tool === 'mcp__*' || (!tool.startsWith('mcp__') && tool.includes('*')))) {
    throw new Error('Claude ignores unanchored wildcard allow rules; use an explicit tool or MCP server rule.');
  }
  if (tool.startsWith('mcp__') && specifier !== null) {
    throw new Error('Claude skips MCP permission rules with parenthesized specifiers.');
  }

  return {
    tool,
    hasSpecifier: specifier !== null,
    matchesAll: specifier === null || specifier.trim() === '*' || specifier.trim() === 'domain:*',
    mcpWildcard: tool.startsWith('mcp__') && (tool.endsWith('__*') || !tool.includes('__', 5))
  };
}

function toolCategory(tool) {
  if (tool === 'Bash' || tool === 'PowerShell') return 'shell';
  if (['Read', 'Edit', 'Write', 'Glob', 'Grep', 'NotebookEdit'].includes(tool)) return 'filesystem';
  if (tool === 'WebFetch' || tool === 'WebSearch') return 'network';
  if (tool === 'Agent') return 'subagent';
  if (tool.startsWith('mcp__')) return 'mcp';
  return 'other';
}

function validateDisable(value, field) {
  if (value !== undefined && value !== 'disable') {
    throw new Error(`Claude permissions.${field} must be "disable" when present.`);
  }
}

function validatePermissions(value) {
  if (value === undefined) return { permissions: {}, rules: { allow: [], ask: [], deny: [] } };
  if (!isObject(value)) throw new Error('Claude settings permissions must be a JSON object.');

  for (const key of Object.keys(value)) {
    if (!PERMISSION_KEYS.has(key)) throw new Error(`Unsupported Claude permission setting: ${key}`);
  }

  const defaultMode = value.defaultMode;
  if (defaultMode !== undefined && (!MODES.has(defaultMode) || typeof defaultMode !== 'string')) {
    throw new Error('Unsupported Claude permissions.defaultMode value.');
  }
  const additionalDirectories = requireStringArray(value.additionalDirectories, 'additionalDirectories');
  if (value.blockReadsOutsideWorkingDirectories !== undefined &&
      typeof value.blockReadsOutsideWorkingDirectories !== 'boolean') {
    throw new Error('Claude permissions.blockReadsOutsideWorkingDirectories must be a boolean.');
  }
  validateDisable(value.disableBypassPermissionsMode, 'disableBypassPermissionsMode');
  validateDisable(value.disableAutoMode, 'disableAutoMode');

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
    envKeys = Object.keys(settings.env).sort();
    signals.add('claude-environment');
    if (envKeys.some((key) => SECRET_KEY_RE.test(key))) signals.add('secret-env');
  }
  if (settings.hooks !== undefined) signals.add('claude-hooks');
  if (settings.apiKeyHelper !== undefined) signals.add('claude-credential-helper');
  if (settings.sandbox !== undefined) signals.add('claude-sandbox-settings');
  if (settings.enabledPlugins !== undefined || settings.extraKnownMarketplaces !== undefined) {
    signals.add('claude-extension-loading');
  }

  const inspectedAdjacentKeys = new Set([
    'env', 'hooks', 'apiKeyHelper', 'sandbox', 'enabledPlugins', 'extraKnownMarketplaces'
  ]);
  const uninspectedRootKeys = Object.keys(settings)
    .filter((key) => !NON_PERMISSION_ROOT_KEYS.has(key) && !inspectedAdjacentKeys.has(key))
    .sort();
  if (uninspectedRootKeys.length) signals.add('uninspected-claude-settings');

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
      autoModeDisabled: permissions.disableAutoMode === 'disable',
      outsideReadsBlocked: permissions.blockReadsOutsideWorkingDirectories === true,
      uninspectedRootKeys
    },
    signals: [...signals].sort(),
    envKeys
  };
}
