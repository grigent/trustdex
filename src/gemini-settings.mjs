// Gemini CLI settings.json permission inspection. Only structural evidence is kept:
// enums, booleans, and counts. Tool names, commands, paths, hook bodies, variable names,
// and the names of settings TrustDex does not know are never retained.

const SANDBOX_OFF = new Set([false, 'false', '0']);
// The values Gemini CLI's sandboxConfig.ts accepts; any other string is a fatal config error there.
const SANDBOX_ON = new Set([true, 'true', '1', 'docker', 'podman', 'sandbox-exec', 'runsc', 'lxc', 'windows-native']);
// Gemini CLI expands $VAR, ${VAR}, and ${VAR:-DEFAULT} in settings before validating them.
// TrustDex does not read the environment, so a value with such a reference is unresolved.
const ENV_REFERENCE = /\$(?:\w+|\{[^}]+\})/;
const APPROVAL_MODES = new Set(['default', 'auto_edit', 'plan']);
const SECTION_KEYS = Object.freeze({
  general: new Set(['defaultApprovalMode']),
  tools: new Set([
    'sandbox', 'sandboxAllowedPaths', 'sandboxNetworkAccess', 'core', 'allowed',
    'confirmationRequired', 'exclude', 'discoveryCommand', 'callCommand'
  ]),
  mcp: new Set(['serverCommand', 'allowed', 'excluded', 'autoAllowInHeadless']),
  security: new Set([
    'toolSandboxing', 'disableYoloMode', 'disableAlwaysAllow', 'enablePermanentToolApproval',
    'autoAddToPolicyByDefault', 'blockGitExtensions', 'allowedExtensions', 'folderTrust',
    'environmentVariableRedaction'
  ]),
  hooksConfig: new Set(['enabled', 'disabled', 'notifications']),
  admin: new Set(['secureModeEnabled', 'extensions', 'mcp', 'skills'])
});
const INSPECTED_ROOT_KEYS = new Set([
  ...Object.keys(SECTION_KEYS), 'hooks', 'mcpServers', 'policyPaths', 'adminPolicyPaths'
]);
const SHELL_GRANT = /^(?:run_shell_command|ShellTool)(?:\(|$)/;

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function section(root, key, label = key) {
  if (!Object.hasOwn(root, key)) return {};
  if (!isObject(root[key])) throw new Error(`Gemini ${label} must be an object.`);
  return root[key];
}

function own(object, key) {
  return Object.hasOwn(object, key) ? object[key] : undefined;
}

function boolean(object, key, label) {
  const value = own(object, key);
  if (value !== undefined && typeof value !== 'boolean') throw new Error(`Gemini ${label} must be a boolean.`);
  return value;
}

function strings(object, key, label) {
  const value = own(object, key);
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string' || !item.trim())) {
    throw new Error(`Gemini ${label} must be an array of non-empty strings.`);
  }
  return value;
}

function command(object, key, label) {
  const value = own(object, key);
  if (value === undefined) return false;
  if (typeof value !== 'string' || !value.trim()) throw new Error(`Gemini ${label} must be a non-empty string.`);
  return true;
}

function mcpServerTrust(object, key, label) {
  return Object.values(section(object, key, label)).map((server) => {
    if (!isObject(server)) throw new Error(`Gemini ${label} entries must be objects.`);
    return boolean(server, 'trust', `${label} entry trust`);
  });
}

export function inspectGeminiSettings(settings, sourceName = 'settings.json') {
  if (!isObject(settings)) throw new Error('Gemini settings must be a JSON object.');

  const signals = new Set();
  let uninspectedSettingCount = Object.keys(settings).filter((key) => !INSPECTED_ROOT_KEYS.has(key)).length;
  const sections = {};
  for (const [name, keys] of Object.entries(SECTION_KEYS)) {
    sections[name] = section(settings, name);
    uninspectedSettingCount += Object.keys(sections[name]).filter((key) => !keys.has(key)).length;
  }
  const { general, tools, mcp, security, hooksConfig, admin } = sections;

  const approvalMode = own(general, 'defaultApprovalMode');
  if (approvalMode !== undefined && !APPROVAL_MODES.has(approvalMode)) {
    throw new Error('Unsupported Gemini general.defaultApprovalMode value.');
  }
  if (approvalMode === 'auto_edit') signals.add('gemini-auto-edit');

  const grants = [
    ...strings(tools, 'allowed', 'tools.allowed'),
    ...strings(tools, 'core', 'tools.core')
  ];
  const shellGrants = grants.filter((entry) => SHELL_GRANT.test(entry.trim()) || entry.includes('*'));
  if (grants.length) signals.add('gemini-auto-approved-tools');
  if (shellGrants.length) signals.add('gemini-auto-approved-shell');
  if (grants.some((entry) => ENV_REFERENCE.test(entry))) signals.add('gemini-unresolved-tool-grants');
  strings(tools, 'confirmationRequired', 'tools.confirmationRequired');
  strings(tools, 'exclude', 'tools.exclude');

  const sandbox = own(tools, 'sandbox');
  const sandboxUnresolved = typeof sandbox === 'string' && ENV_REFERENCE.test(sandbox);
  // Gemini CLI also treats an empty string as off; TrustDex rejects it like any other
  // unsupported value rather than guessing which meaning the author intended.
  if (sandbox !== undefined && !sandboxUnresolved && !SANDBOX_OFF.has(sandbox) && !SANDBOX_ON.has(sandbox)) {
    throw new Error('Gemini tools.sandbox must be a boolean, "true", "false", "1", "0", an environment variable reference, or a sandbox command Gemini CLI supports (docker, podman, sandbox-exec, runsc, lxc, windows-native).');
  }
  // Gemini CLI treats false, "false", and "0" as off. This is the value in this file only;
  // another settings layer, GEMINI_SANDBOX, or --sandbox can change what applies at runtime.
  let sandboxSetting = 'enabled';
  if (sandbox === undefined) sandboxSetting = 'omitted';
  else if (sandboxUnresolved) sandboxSetting = 'unresolved';
  else if (SANDBOX_OFF.has(sandbox)) sandboxSetting = 'disabled';
  if (sandboxSetting === 'disabled') signals.add('gemini-sandbox-disabled');
  if (sandboxSetting === 'unresolved') signals.add('gemini-sandbox-unresolved');
  const sandboxPaths = strings(tools, 'sandboxAllowedPaths', 'tools.sandboxAllowedPaths');
  const sandboxNetwork = boolean(tools, 'sandboxNetworkAccess', 'tools.sandboxNetworkAccess') === true;
  if (sandboxPaths.length || sandboxNetwork) signals.add('gemini-sandbox-relaxed');

  const commandSettings = [
    command(tools, 'discoveryCommand', 'tools.discoveryCommand'),
    command(tools, 'callCommand', 'tools.callCommand'),
    command(mcp, 'serverCommand', 'mcp.serverCommand')
  ].filter(Boolean).length;
  if (commandSettings) signals.add('gemini-tool-commands');
  const allowedMcp = strings(mcp, 'allowed', 'mcp.allowed');
  const autoAllowInHeadless = boolean(mcp, 'autoAllowInHeadless', 'mcp.autoAllowInHeadless') === true;
  strings(mcp, 'excluded', 'mcp.excluded');

  boolean(security, 'toolSandboxing', 'security.toolSandboxing');
  boolean(security, 'blockGitExtensions', 'security.blockGitExtensions');
  strings(security, 'allowedExtensions', 'security.allowedExtensions');
  const permanentApproval = boolean(security, 'enablePermanentToolApproval', 'security.enablePermanentToolApproval') === true;
  const autoAddToPolicy = boolean(security, 'autoAddToPolicyByDefault', 'security.autoAddToPolicyByDefault') === true;
  if (permanentApproval || autoAddToPolicy) signals.add('gemini-persistent-approvals');

  const folderTrust = section(security, 'folderTrust');
  uninspectedSettingCount += Object.keys(folderTrust).filter((key) => key !== 'enabled').length;
  const folderTrustDisabled = boolean(folderTrust, 'enabled', 'security.folderTrust.enabled') === false;
  if (folderTrustDisabled) signals.add('gemini-folder-trust-disabled');

  const redaction = section(security, 'environmentVariableRedaction');
  uninspectedSettingCount += Object.keys(redaction).filter((key) => !['allowed', 'blocked', 'enabled'].includes(key)).length;
  boolean(redaction, 'enabled', 'security.environmentVariableRedaction.enabled');
  strings(redaction, 'blocked', 'security.environmentVariableRedaction.blocked');
  const unredacted = strings(redaction, 'allowed', 'security.environmentVariableRedaction.allowed');
  if (unredacted.length) signals.add('gemini-env-redaction-bypass');

  // Hooks are counted whether or not hooksConfig.enabled is false here: another settings
  // layer can turn the hooks system back on.
  boolean(hooksConfig, 'enabled', 'hooksConfig.enabled');
  boolean(hooksConfig, 'notifications', 'hooksConfig.notifications');
  strings(hooksConfig, 'disabled', 'hooksConfig.disabled');
  let hookCount = 0;
  for (const entries of Object.values(section(settings, 'hooks'))) {
    if (!Array.isArray(entries)) throw new Error('Gemini hooks events must be arrays.');
    hookCount += entries.length;
  }
  if (hookCount) signals.add('gemini-hooks');

  const policyPathCount = strings(settings, 'policyPaths', 'policyPaths').length +
    strings(settings, 'adminPolicyPaths', 'adminPolicyPaths').length;
  if (policyPathCount) signals.add('gemini-policy-paths');

  const secureModeEnabled = boolean(admin, 'secureModeEnabled', 'admin.secureModeEnabled') === true;
  for (const key of ['extensions', 'skills']) {
    const part = section(admin, key);
    uninspectedSettingCount += Object.keys(part).filter((name) => name !== 'enabled').length;
    boolean(part, 'enabled', `admin.${key}.enabled`);
  }
  const adminMcp = section(admin, 'mcp');
  uninspectedSettingCount += Object.keys(adminMcp).filter((key) => !['enabled', 'config', 'requiredConfig'].includes(key)).length;
  boolean(adminMcp, 'enabled', 'admin.mcp.enabled');
  const mcpTrust = mcpServerTrust(settings, 'mcpServers', 'mcpServers');
  const adminMcpTrust = mcpServerTrust(adminMcp, 'config', 'admin.mcp.config');
  const requiredMcpTrust = mcpServerTrust(adminMcp, 'requiredConfig', 'admin.mcp.requiredConfig');
  const mcpServerCount = mcpTrust.length + adminMcpTrust.length + requiredMcpTrust.length;
  if (mcpServerCount) signals.add('gemini-mcp-servers');
  // Gemini defaults injected admin-required servers to trusted.
  if (allowedMcp.length || autoAllowInHeadless ||
      [...mcpTrust, ...adminMcpTrust].includes(true) || requiredMcpTrust.some((trust) => trust !== false)) {
    signals.add('gemini-auto-approved-mcp');
  }

  if (uninspectedSettingCount) signals.add('uninspected-gemini-settings');

  return {
    name: sourceName,
    kind: 'gemini-settings',
    source: { type: 'local', format: 'gemini-settings', path: sourceName },
    metadata: {
      defaultApprovalMode: approvalMode ?? null,
      autoApprovedToolCount: grants.length,
      autoApprovedShellCount: shellGrants.length,
      sandboxConfigured: sandboxSetting === 'enabled',
      sandboxSetting,
      sandboxAllowedPathCount: sandboxPaths.length,
      sandboxNetworkAccess: sandboxNetwork,
      commandSettingCount: commandSettings,
      hookCount,
      policyPathCount,
      mcpServerCount,
      permanentToolApproval: permanentApproval,
      autoAddToPolicyByDefault: autoAddToPolicy,
      folderTrustDisabled,
      unredactedEnvironmentVariableCount: unredacted.length,
      yoloModeDisabled: boolean(security, 'disableYoloMode', 'security.disableYoloMode') === true || secureModeEnabled,
      alwaysAllowDisabled: boolean(security, 'disableAlwaysAllow', 'security.disableAlwaysAllow') === true || secureModeEnabled,
      uninspectedSettingCount
    },
    signals: [...signals].sort(),
    envKeys: []
  };
}
