import { parseIdeExtensionPin } from './ide-extensions.mjs';

const BASE_SIGNALS = {
  'shell-execution': 'block',
  'secret-env': 'ask',
  'wildcard-tool-scope': 'ask',
  'sensitive-path-instructions': 'ask',
  'shell-instructions': 'ask',
  'install-instructions': 'ask',
  'missing-version': 'ask',
  'header-helper-command': 'block',
  'static-http-headers': 'ask',
  'env-http-headers': 'ask',
  'env-forwarding': 'ask',
  'auto-approve-tools': 'ask',
  'embedded-credentials': 'block',
  'insecure-transport': 'block',
  'url-query-parameters': 'ask',
  'artifact-version-mismatch': 'block',
  'claude-auto-approve': 'ask',
  'claude-broad-auto-approve': 'block',
  'claude-shell-auto-approve': 'block',
  'claude-filesystem-auto-approve': 'ask',
  'claude-network-auto-approve': 'ask',
  'claude-subagent-auto-approve': 'ask',
  'claude-mcp-auto-approve': 'ask',
  'claude-mcp-wildcard': 'ask',
  'claude-bypass-permissions': 'block',
  'claude-auto-mode': 'ask',
  'claude-additional-directories': 'ask',
  'claude-outside-read-access': 'ask',
  'claude-hooks': 'block',
  'claude-credential-helper': 'block',
  'claude-environment': 'ask',
  'claude-sandbox-settings': 'ask',
  'claude-extension-loading': 'ask',
  'uninspected-claude-settings': 'ask',
  'codex-no-approvals': 'ask',
  'codex-auto-review': 'ask',
  'codex-workspace-write': 'ask',
  'codex-full-access': 'block',
  'codex-network-access': 'ask',
  'codex-additional-writable-roots': 'ask',
  'codex-temp-write-access': 'ask',
  'codex-live-web-search': 'ask',
  'codex-custom-permissions': 'ask',
  'codex-subagents-enabled': 'ask',
  'codex-subagent-settings': 'ask',
  'codex-extension-settings': 'ask',
  'uninspected-codex-settings': 'ask',
  'uninspected-codex-sections': 'ask',
  'ide-extension-missing-manifest': 'block',
  'ide-extension-manifest-mismatch': 'block',
  'ide-extension-digest-mismatch': 'block',
  'ide-extension-external-location': 'block',
  'ide-extension-unregistered': 'ask',
  'ide-extension-marked-obsolete': 'ask',
  'ide-extension-non-gallery-source': 'ask',
  'ide-extension-prerelease': 'ask',
  'ide-extension-startup-activation': 'ask',
  'ide-extension-untrusted-workspaces': 'ask',
  'ide-extension-native-code': 'ask',
  'ide-extension-bundles-extensions': 'ask',
  'ide-extension-non-regular-files': 'ask'
};

// Signals that are emitted but use a pack's default handling instead of a signalActions entry.
const DEFAULT_HANDLED_SIGNALS = [
  'filesystem-path', 'install-on-run', 'network-endpoint', 'network-instructions',
  'network-reference', 'sensitive-path-reference', 'shell-reference', 'unbounded-version'
];

export const KNOWN_SIGNALS = Object.freeze(new Set([...Object.keys(BASE_SIGNALS), ...DEFAULT_HANDLED_SIGNALS]));

export const POLICY_PACKS = Object.freeze({
  strict: Object.freeze({
    version: 1,
    unknownAction: 'block',
    localAction: 'ask',
    verifiedPublisherAction: 'allow',
    sensitiveAction: 'ask',
    unpinnedAction: 'block',
    shellAction: 'block',
    trustedPackages: [],
    trustedRepositories: [],
    allowedRemoteHosts: [],
    trustedIdeExtensions: [],
    blockedIdeExtensions: [],
    signalActions: BASE_SIGNALS
  }),
  'official-first': Object.freeze({
    version: 1,
    unknownAction: 'block',
    localAction: 'ask',
    verifiedPublisherAction: 'allow',
    sensitiveAction: 'ask',
    unpinnedAction: 'ask',
    shellAction: 'block',
    trustedPackages: [],
    trustedRepositories: [],
    allowedRemoteHosts: [],
    trustedIdeExtensions: [],
    blockedIdeExtensions: [],
    signalActions: BASE_SIGNALS,
    note: 'ALLOW verified provenance assertions, ASK for local extensions, and BLOCK unknown third-party sources by default.'
  }),
  development: Object.freeze({
    version: 1,
    unknownAction: 'ask',
    localAction: 'ask',
    verifiedPublisherAction: 'allow',
    sensitiveAction: 'ask',
    unpinnedAction: 'ask',
    shellAction: 'ask',
    trustedPackages: [],
    trustedRepositories: [],
    allowedRemoteHosts: ['localhost', '127.0.0.1', '::1'],
    trustedIdeExtensions: [],
    blockedIdeExtensions: [],
    signalActions: {
      ...BASE_SIGNALS,
      'shell-execution': 'ask',
      'insecure-transport': 'ask',
      'claude-broad-auto-approve': 'ask',
      'claude-shell-auto-approve': 'ask',
      'claude-hooks': 'ask',
      'claude-credential-helper': 'ask'
    }
  })
});

export function getPolicyPack(name = 'strict') {
  const pack = POLICY_PACKS[name];
  if (!pack) {
    throw new Error(`Unknown policy pack "${name}". Available: ${Object.keys(POLICY_PACKS).join(', ')}`);
  }
  return JSON.parse(JSON.stringify(pack));
}

export function mergePolicy(base, overlay = {}) {
  return {
    ...base,
    ...overlay,
    signalActions: {
      ...(base.signalActions || {}),
      ...(overlay.signalActions || {})
    },
    trustedPackages: overlay.trustedPackages ?? base.trustedPackages ?? [],
    trustedRepositories: overlay.trustedRepositories ?? base.trustedRepositories ?? [],
    allowedRemoteHosts: overlay.allowedRemoteHosts ?? base.allowedRemoteHosts ?? [],
    trustedIdeExtensions: overlay.trustedIdeExtensions ?? base.trustedIdeExtensions ?? [],
    // Deny entries accumulate so an overlay can never silently drop a base block.
    blockedIdeExtensions: [...new Set([...(base.blockedIdeExtensions || []), ...(overlay.blockedIdeExtensions || [])])]
  };
}

const POLICY_ACTIONS = new Set(['allow', 'ask', 'block']);
const ACTION_FIELDS = ['unknownAction', 'localAction', 'verifiedPublisherAction', 'sensitiveAction', 'unpinnedAction', 'shellAction'];
const LIST_FIELDS = ['trustedPackages', 'trustedRepositories', 'allowedRemoteHosts', 'trustedIdeExtensions', 'blockedIdeExtensions'];
const POLICY_FIELDS = new Set(['$schema', 'version', 'note', 'signalActions', ...ACTION_FIELDS, ...LIST_FIELDS]);

// Validate a user policy file before merging. Unknown fields and invalid values are
// rejected instead of silently falling back, so a typo cannot quietly change policy.
export function validatePolicyOverlay(overlay) {
  if (!overlay || typeof overlay !== 'object' || Array.isArray(overlay)) {
    throw new Error('Policy must be a JSON object.');
  }
  for (const key of Object.keys(overlay)) {
    if (!POLICY_FIELDS.has(key)) throw new Error(`Unknown policy field "${key}".`);
  }
  if (overlay.version !== undefined && overlay.version !== 1) throw new Error('Unsupported policy version. Expected version 1.');
  if (overlay.note !== undefined && typeof overlay.note !== 'string') throw new Error('Policy note must be a string.');
  if (overlay.$schema !== undefined && typeof overlay.$schema !== 'string') throw new Error('Policy $schema must be a string.');
  for (const field of ACTION_FIELDS) {
    if (overlay[field] !== undefined && !POLICY_ACTIONS.has(overlay[field])) {
      throw new Error(`Policy ${field} must be "allow", "ask", or "block".`);
    }
  }
  for (const field of LIST_FIELDS) {
    const value = overlay[field];
    if (value === undefined) continue;
    if (!Array.isArray(value) || value.some((item) => typeof item !== 'string' || !item.trim())) {
      throw new Error(`Policy ${field} must be an array of non-empty strings.`);
    }
    if (field.endsWith('IdeExtensions')) value.forEach((entry) => parseIdeExtensionPin(entry, field));
  }
  if (overlay.signalActions !== undefined) {
    const actions = overlay.signalActions;
    if (!actions || typeof actions !== 'object' || Array.isArray(actions)) {
      throw new Error('Policy signalActions must be an object.');
    }
    for (const [signal, action] of Object.entries(actions)) {
      if (!KNOWN_SIGNALS.has(signal)) throw new Error(`Unknown signal "${signal}" in policy signalActions.`);
      if (!POLICY_ACTIONS.has(action)) throw new Error(`Policy signalActions.${signal} must be "allow", "ask", or "block".`);
    }
  }
  return overlay;
}
