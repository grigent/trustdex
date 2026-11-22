// Devin CLI config.json permission inspection. Only structural evidence is kept: the
// permission-mode enum, booleans, and counts. Rule scopes (commands, paths, URLs), MCP
// server and tool names, hook bodies, and the names of settings TrustDex does not know
// are never retained.

const PERMISSION_MODES = new Set(['normal', 'accept-edits', 'smart', 'dangerous']);
const RULE_LISTS = ['allow', 'ask', 'deny'];
const SCOPE_RULE = /^(Read|Write|Exec|Fetch)\(.+\)$/s;
const TOOL_RULES = new Map([['read', 'Read'], ['grep', 'Read'], ['glob', 'Read'], ['edit', 'Write'], ['exec', 'Exec']]);
const MCP_RULE = /^mcp__(?:\*|[^*\s]+__(?:\*|[^*\s]+))$/;
// Documented settings that grant the agent no autonomy. Their values are not read.
const NEUTRAL_ROOT_KEYS = new Set([
  'agent', 'theme_mode', 'show_path', 'unicode_mode', 'show_hints', 'include_gitignored_files',
  'respect_gitignore', 'attribution', 'subagents_enabled', 'keymap', 'auto_update', 'notify',
  'sandbox'
]);
const INSPECTED_ROOT_KEYS = new Set([
  'permissions', 'permission_mode', 'hooks', 'mcpServers', 'local_tools_bypass_permissions', 'read_config_from'
]);

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function ruleCategory(rule) {
  const scope = SCOPE_RULE.exec(rule);
  if (scope) return scope[1];
  if (TOOL_RULES.has(rule)) return TOOL_RULES.get(rule);
  if (MCP_RULE.test(rule)) return 'Mcp';
  throw new Error('Unsupported Devin permission rule.');
}

function rules(permissions, key) {
  if (!Object.hasOwn(permissions, key)) return [];
  const value = permissions[key];
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    throw new Error(`Devin permissions.${key} must be an array of strings.`);
  }
  return value.map(ruleCategory);
}

export function inspectDevinSettings(settings, sourceName = 'config.json') {
  if (!isObject(settings)) throw new Error('Devin config must be a JSON object.');

  const signals = new Set();
  let uninspectedSettingCount = Object.keys(settings)
    .filter((key) => !INSPECTED_ROOT_KEYS.has(key) && !NEUTRAL_ROOT_KEYS.has(key)).length;

  const mode = Object.hasOwn(settings, 'permission_mode') ? settings.permission_mode : null;
  if (mode !== null && !PERMISSION_MODES.has(mode)) throw new Error('Unsupported Devin permission_mode value.');
  if (mode === 'dangerous') signals.add('devin-permission-mode-bypass');
  if (mode === 'accept-edits' || mode === 'smart') signals.add('devin-permission-mode-auto');

  const permissions = Object.hasOwn(settings, 'permissions') ? settings.permissions : {};
  if (!isObject(permissions)) throw new Error('Devin permissions must be an object.');
  uninspectedSettingCount += Object.keys(permissions).filter((key) => !RULE_LISTS.includes(key)).length;
  const allow = rules(permissions, 'allow');
  const ask = rules(permissions, 'ask');
  const deny = rules(permissions, 'deny');
  const allowed = (category) => allow.filter((item) => item === category).length;
  if (allow.length) signals.add('devin-auto-approved-tools');
  if (allowed('Exec')) signals.add('devin-auto-approved-exec');

  // Hooks run shell commands or prompts on lifecycle events.
  let hookCount = 0;
  if (Object.hasOwn(settings, 'hooks')) {
    if (!isObject(settings.hooks)) throw new Error('Devin hooks must be an object.');
    for (const entries of Object.values(settings.hooks)) {
      if (!Array.isArray(entries)) throw new Error('Devin hooks events must be arrays.');
      hookCount += entries.length;
    }
  }
  if (hookCount) signals.add('devin-hooks');

  // Older Devin CLI versions read MCP servers from this key; inspect them with inspect-devin.
  let mcpServerCount = 0;
  if (Object.hasOwn(settings, 'mcpServers')) {
    if (!isObject(settings.mcpServers)) throw new Error('Devin mcpServers must be an object.');
    mcpServerCount = Object.keys(settings.mcpServers).length;
  }
  if (mcpServerCount) signals.add('devin-mcp-servers');

  const localBypass = Object.hasOwn(settings, 'local_tools_bypass_permissions')
    ? settings.local_tools_bypass_permissions : false;
  if (typeof localBypass !== 'boolean') throw new Error('Devin local_tools_bypass_permissions must be a boolean.');
  if (localBypass) signals.add('devin-local-tools-bypass');

  // read_config_from turns on providers whose rules, skills, hooks, and MCP servers Devin CLI
  // imports. Only the number of enabled providers is kept; the imported files are not read.
  let externalConfigProviderCount = 0;
  if (Object.hasOwn(settings, 'read_config_from')) {
    const providers = settings.read_config_from;
    if (!isObject(providers) || Object.values(providers).some((value) => typeof value !== 'boolean')) {
      throw new Error('Devin read_config_from must be an object of booleans.');
    }
    externalConfigProviderCount = Object.values(providers).filter(Boolean).length;
  }
  if (externalConfigProviderCount) signals.add('devin-external-config');

  if (uninspectedSettingCount) signals.add('uninspected-devin-settings');

  return {
    name: sourceName,
    kind: 'devin-settings',
    source: { type: 'local', format: 'devin-settings', path: sourceName },
    metadata: {
      permissionMode: mode,
      allowRuleCount: allow.length,
      askRuleCount: ask.length,
      denyRuleCount: deny.length,
      autoApprovedExecCount: allowed('Exec'),
      autoApprovedWriteCount: allowed('Write'),
      autoApprovedReadCount: allowed('Read'),
      autoApprovedFetchCount: allowed('Fetch'),
      autoApprovedMcpCount: allowed('Mcp'),
      hookCount,
      mcpServerCount,
      localToolsBypassPermissions: localBypass,
      externalConfigProviderCount,
      uninspectedSettingCount
    },
    signals: [...signals].sort(),
    envKeys: []
  };
}
