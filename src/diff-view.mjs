// Human-readable diff output. Never print raw configuration, source objects,
// provenance evidence, paths, tokens, or runtime tool names.
const COLORS = Object.freeze({ expansion: '\x1b[31m', restriction: '\x1b[32m', review: '\x1b[33m' });
const RANK = Object.freeze({ allow: 0, ask: 1, block: 2 });

function safeLabel(value) {
  return String(value ?? 'unknown')
    .replace(/[\x00-\x1f\x7f-\x9f]/g, '?')
    .slice(0, 120);
}

function line(value, impact, color) {
  const text = safeLabel(value).slice(0, 300);
  return color && COLORS[impact] ? `${COLORS[impact]}${text}\x1b[0m` : text;
}

function safeScalar(value) {
  if (value === null || value === undefined) return '(none)';
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (typeof value === 'string') return safeLabel(value);
  return '(redacted)';
}

export function renderSnapshotChanges(changes, color = false) {
  const lines = [];
  for (const change of changes) {
    const name = safeLabel(change.name);
    switch (change.type) {
      case 'server-added':
        lines.push(line(`+ server-added: ${name}`, 'expansion', color));
        break;
      case 'server-removed':
        lines.push(line(`- server-removed: ${name}`, 'restriction', color));
        break;
      case 'signals-added':
      case 'signals-removed': {
        const added = change.type === 'signals-added';
        for (const signal of change.signals || []) {
          lines.push(line(`${added ? '+' : '-'} ${change.type}: ${name} (${safeLabel(signal)})`,
            added ? 'expansion' : 'restriction', color));
        }
        break;
      }
      case 'decision-changed': {
        const impact = (RANK[change.to] ?? 2) > (RANK[change.from] ?? 2)
          ? 'expansion' : 'restriction';
        lines.push(line(`~ decision-changed: ${name} (${safeScalar(change.from)} -> ${safeScalar(change.to)})`, impact, color));
        break;
      }
      case 'source-changed':
      case 'provenance-changed':
      case 'fingerprint-changed':
        lines.push(line(`~ ${change.type}: ${name} (raw values omitted)`, 'review', color));
        break;
      default:
        lines.push(line(`~ ${safeLabel(change.type)}: ${name} (review required)`, 'review', color));
    }
  }
  return lines.join('\n');
}

// These diffs contain only value-free, schema-validated structural fields.
// Do not extend this to raw sources or permission rule strings.
function renderStructuralDiff(diff, messages, color) {
  if (diff.status === 'unchanged') return messages.unchanged;
  const lines = [line(diff.status === 'restricted' ? messages.restricted : messages.review,
    diff.status === 'restricted' ? 'restriction' : 'review', color)];
  for (const change of diff.changes) {
    const impact = COLORS[change.impact] ? change.impact : 'review';
    const target = change.name ? `${safeLabel(change.name)}.` : '';
    lines.push(line(`${impact.toUpperCase()} ${safeLabel(change.type)}: ${target}${safeLabel(change.field)}`, impact, color));
    if (Array.isArray(change.items)) {
      for (const item of change.items) {
        const removed = change.type === 'items-removed';
        lines.push(line(`  ${removed ? '-' : '+'} ${safeLabel(item)}`, impact, color));
      }
    } else if (Object.hasOwn(change, 'before') &&
               (change.before !== null || change.after !== null)) {
      lines.push(line(`  - ${safeScalar(change.before)}`, 'restriction', color));
      lines.push(line(`  + ${safeScalar(change.after)}`, impact, color));
    } else {
      lines.push(line('  (structural digest changed; values omitted)', impact, color));
    }
  }
  return lines.join('\n');
}

export function renderPermissionDiff(diff, color = false) {
  return renderStructuralDiff(diff, {
    unchanged: 'UNCHANGED: permission posture matches the baseline.',
    restricted: 'RESTRICTED: permission posture became more restrictive.',
    review: 'NEEDS_REVIEW: permission posture expanded or changed.'
  }, color);
}

export function renderBindingDiff(diff, color = false) {
  return renderStructuralDiff(diff, {
    unchanged: 'UNCHANGED: tool permission bindings match the baseline.',
    restricted: 'RESTRICTED: automatic tool permissions became more restrictive.',
    review: 'NEEDS_REVIEW: tool provenance or automatic permissions changed.'
  }, color);
}

export function renderRuntimeDiff(diff, color = false) {
  return renderStructuralDiff(diff, {
    unchanged: 'UNCHANGED: effective runtime tool evidence matches the baseline.',
    restricted: 'RESTRICTED: observed runtime tool exposure became more restrictive.',
    review: 'NEEDS_REVIEW: effective runtime tool evidence changed.'
  }, color);
}
