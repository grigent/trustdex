import { IDE_INTEGRITY_SIGNALS, normalizeIdeExtensionId, parseIdeExtensionPin } from './ide-extensions.mjs';

const IDE_HARD_BLOCK = new Set(IDE_INTEGRITY_SIGNALS);

const ACTIONS = new Set(['allow', 'ask', 'block']);

function normalizeAction(value, fallback) {
  const action = String(value || fallback).toLowerCase();
  return ACTIONS.has(action) ? action : fallback;
}

function packageName(spec = '') {
  const value = String(spec);
  if (value.startsWith('@')) {
    const slash = value.indexOf('/');
    if (slash < 0) return value;
    const versionAt = value.indexOf('@', slash);
    return versionAt > slash ? value.slice(0, versionAt) : value;
  }
  const versionAt = value.lastIndexOf('@');
  return versionAt > 0 ? value.slice(0, versionAt) : value.replace(/==[^=\s]+$/, '');
}

function raise(current, next) {
  const rank = { allow: 0, ask: 1, block: 2 };
  return rank[next] > rank[current] ? next : current;
}

function signalAction(policy, signal, fallback = null) {
  const configured = policy?.signalActions?.[signal];
  if (!configured) return fallback;
  return normalizeAction(configured, fallback || 'ask');
}

export function evaluateServer(server, policy = {}) {
  const unknownAction = normalizeAction(policy.unknownAction, 'block');
  const localAction = normalizeAction(policy.localAction, 'ask');
  const sensitiveAction = normalizeAction(policy.sensitiveAction, 'ask');
  const unpinnedAction = normalizeAction(policy.unpinnedAction, 'ask');
  const shellAction = normalizeAction(policy.shellAction, 'block');
  const verifiedPublisherAction = normalizeAction(policy.verifiedPublisherAction, 'allow');

  const trustedPackages = new Set(policy.trustedPackages || []);
  const trustedRepositories = new Set((policy.trustedRepositories || []).map((x) => String(x).toLowerCase()));
  const allowedRemoteHosts = new Set((policy.allowedRemoteHosts || []).map((x) => String(x).toLowerCase()));

  // Validate IDE extension lists on every evaluation so a malformed entry fails closed
  // even when no IDE extension is being inspected.
  const idePins = (policy.trustedIdeExtensions || []).map((entry) => parseIdeExtensionPin(entry, 'trustedIdeExtensions'));
  const ideBlocked = (policy.blockedIdeExtensions || []).map((entry) => parseIdeExtensionPin(entry, 'blockedIdeExtensions'));

  let action = unknownAction;
  const reasons = [];
  const signals = [...(server.signals || [])];

  if (server.provenance?.status === 'verified') {
    action = verifiedPublisherAction;
    reasons.push(`verified provenance assertion: ${server.provenance.publisher}`);
  }

  if (server.source.type === 'package') {
    const pkg = packageName(server.source.package);
    if (trustedPackages.has(pkg)) {
      action = 'allow';
      reasons.push(`trusted package: ${pkg}`);
    } else if (server.provenance?.status !== 'verified') {
      reasons.push(`package is not trusted: ${pkg}`);
    }
    if (!server.source.pinned) {
      action = raise(action, unpinnedAction);
      reasons.push('package version is not pinned');
    }
  } else if (server.source.type === 'remote') {
    if (allowedRemoteHosts.has(server.source.host)) {
      action = 'allow';
      reasons.push(`allowed remote host: ${server.source.host}`);
    } else if (server.provenance?.status !== 'verified') {
      reasons.push(`remote host is not allowlisted: ${server.source.host}`);
    }
  } else if (server.source.type === 'repository') {
    const repository = String(server.source.repository || '').toLowerCase();
    if (trustedRepositories.has(repository)) {
      action = 'allow';
      reasons.push(`trusted repository: ${server.source.repository}`);
    } else if (server.provenance?.status !== 'verified') {
      reasons.push(`repository is not trusted: ${server.source.repository || 'unknown'}`);
    }
  } else if (server.source.type === 'ide-extension') {
    const id = normalizeIdeExtensionId(server.source.id);
    const version = server.source.version;
    const pins = idePins;
    const blocked = ideBlocked;
    // Only an exact pin can ALLOW an IDE extension, whatever unknownAction says.
    action = raise(unknownAction, 'ask');
    const pin = id && version ? pins.find((entry) => entry.id === id && entry.version === version) : null;
    if (!id || !version) {
      reasons.push('IDE extension could not be identified');
    } else if (pin && pin.digest && pin.digest !== server.fingerprint) {
      if (!signals.includes('ide-extension-digest-mismatch')) signals.push('ide-extension-digest-mismatch');
      reasons.push(`installed files do not match the pinned digest for ${id}@${version}`);
    } else if (pin) {
      action = 'allow';
      reasons.push(`pinned IDE extension: ${id}@${version}${pin.digest ? ' (digest matched)' : ''}`);
    } else {
      const other = pins.filter((entry) => entry.id === id).map((entry) => entry.version);
      reasons.push(other.length
        ? `installed version ${version} is not a pinned version of ${id} (pinned: ${other.join(', ')})`
        : `IDE extension is not pinned: ${id}@${version}`);
    }
    const denied = blocked.find((entry) => entry.id === id && (entry.version === '*' || entry.version === version));
    if (id && denied) {
      action = 'block';
      reasons.push(`blocked IDE extension: ${id}@${denied.version}`);
    }
  } else if (['local', 'skill-file', 'plugin-manifest'].includes(server.source.type)) {
    if (server.provenance?.status !== 'verified') action = localAction;
    reasons.push('local extension requires local trust policy');
  } else if (server.provenance?.status !== 'verified') {
    reasons.push('source could not be identified');
  }

  for (const signal of signals) {
    let next = signalAction(policy, signal);

    if (!next && signal === 'secret-env') next = sensitiveAction;
    if (!next && signal === 'shell-execution') next = shellAction;
    if (IDE_HARD_BLOCK.has(signal)) next = 'block';

    if (next) {
      action = raise(action, next);
      reasons.push(`signal policy: ${signal} -> ${next}`);
    }
  }

  return { ...server, ...(signals.length !== (server.signals || []).length ? { signals: signals.sort() } : {}), action, reasons };
}

export function evaluateAll(servers, policy = {}) {
  return servers.map((server) => evaluateServer(server, policy));
}
