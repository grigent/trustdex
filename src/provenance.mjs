function normalizeHost(value) {
  return String(value || '').trim().toLowerCase().replace(/\.$/, '');
}

function normalizePackage(value) {
  const spec = String(value || '').trim();
  if (spec.startsWith('@')) {
    const slash = spec.indexOf('/');
    if (slash < 0) return spec;
    const versionAt = spec.indexOf('@', slash);
    return versionAt > slash ? spec.slice(0, versionAt) : spec;
  }
  const versionAt = spec.lastIndexOf('@');
  return versionAt > 0 ? spec.slice(0, versionAt) : spec.replace(/==[^=\s]+$/, '');
}

function validateClaim(claim, index) {
  if (!claim || typeof claim !== 'object' || Array.isArray(claim)) {
    throw new Error(`Trust-store claim #${index + 1} must be an object.`);
  }
  if (!['package', 'remote', 'repository'].includes(claim.type)) {
    throw new Error(`Trust-store claim #${index + 1} has unsupported type "${claim.type}".`);
  }
  if (!claim.subject || !claim.publisher) {
    throw new Error(`Trust-store claim #${index + 1} requires subject and publisher.`);
  }
  if (claim.status !== 'verified') {
    throw new Error(`Trust-store claim #${index + 1} must explicitly use status "verified".`);
  }
  if (!claim.evidence || typeof claim.evidence !== 'object') {
    throw new Error(`Trust-store claim #${index + 1} requires evidence metadata.`);
  }
  if (!claim.evidence.kind || !claim.evidence.reference) {
    throw new Error(`Trust-store claim #${index + 1} evidence requires kind and reference.`);
  }
}

export function parseTrustStore(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Trust store must be a JSON object.');
  }
  if (value.version !== 1) throw new Error('Unsupported trust-store version. Expected version 1.');
  const claims = Array.isArray(value.claims) ? value.claims : [];
  claims.forEach(validateClaim);
  return {
    version: 1,
    claims: claims.map((claim) => ({
      type: claim.type,
      subject: claim.type === 'remote' ? normalizeHost(claim.subject) : String(claim.subject),
      publisher: String(claim.publisher),
      status: 'verified',
      evidence: {
        kind: String(claim.evidence.kind),
        reference: String(claim.evidence.reference),
        checkedAt: claim.evidence.checkedAt ? String(claim.evidence.checkedAt) : null
      }
    }))
  };
}

function claimForSource(source, store) {
  if (!store?.claims?.length || !source) return null;

  if (source.type === 'package') {
    const subject = normalizePackage(source.package);
    return store.claims.find((claim) => claim.type === 'package' && normalizePackage(claim.subject) === subject) || null;
  }

  if (source.type === 'remote') {
    const subject = normalizeHost(source.host);
    return store.claims.find((claim) => claim.type === 'remote' && normalizeHost(claim.subject) === subject) || null;
  }

  if (source.type === 'repository' && source.repository) {
    return store.claims.find((claim) =>
      claim.type === 'repository' &&
      String(claim.subject).toLowerCase() === String(source.repository).toLowerCase()
    ) || null;
  }

  return null;
}

export function attachProvenance(item, trustStore) {
  const claim = claimForSource(item.source, trustStore);
  if (!claim) return { ...item, provenance: { status: 'unknown' } };
  return {
    ...item,
    provenance: {
      status: 'verified',
      publisher: claim.publisher,
      evidence: claim.evidence
    }
  };
}

export function attachProvenanceAll(items, trustStore) {
  return items.map((item) => attachProvenance(item, trustStore));
}
