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
  'auto-approve-tools': 'ask'
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
    signalActions: {
      ...BASE_SIGNALS,
      'shell-execution': 'ask'
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
    allowedRemoteHosts: overlay.allowedRemoteHosts ?? base.allowedRemoteHosts ?? []
  };
}
