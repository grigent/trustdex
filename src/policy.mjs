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

export function evaluateServer(server, policy = {}) {
  const unknownAction = normalizeAction(policy.unknownAction, 'block');
  const localAction = normalizeAction(policy.localAction, 'ask');
  const sensitiveAction = normalizeAction(policy.sensitiveAction, 'ask');
  const unpinnedAction = normalizeAction(policy.unpinnedAction, 'ask');
  const shellAction = normalizeAction(policy.shellAction, 'block');

  const trustedPackages = new Set(policy.trustedPackages || []);
  const allowedRemoteHosts = new Set((policy.allowedRemoteHosts || []).map((x) => String(x).toLowerCase()));

  let action = unknownAction;
  const reasons = [];

  if (server.source.type === 'package') {
    const pkg = packageName(server.source.package);
    if (trustedPackages.has(pkg)) {
      action = 'allow';
      reasons.push(`trusted package: ${pkg}`);
    } else {
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
    } else {
      reasons.push(`remote host is not allowlisted: ${server.source.host}`);
    }
  } else if (server.source.type === 'local') {
    action = localAction;
    reasons.push('local executable requires local trust policy');
  } else {
    reasons.push('source could not be identified');
  }

  if (server.signals.includes('secret-env')) {
    action = raise(action, sensitiveAction);
    reasons.push('configuration exposes secret-like environment variable names');
  }

  if (server.signals.includes('shell-execution')) {
    action = raise(action, shellAction);
    reasons.push('server launches through a shell');
  }

  return { ...server, action, reasons };
}

export function evaluateAll(servers, policy = {}) {
  return servers.map((server) => evaluateServer(server, policy));
}
