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
  'ide-extension-non-gallery-source': 'ask',
  'ide-extension-prerelease': 'ask',
  'ide-extension-startup-activation': 'ask',
  'ide-extension-untrusted-workspaces': 'ask',
  'ide-extension-native-code': 'ask',
  'ide-extension-bundles-extensions': 'ask',
  'ide-extension-non-regular-files': 'ask'
};

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
