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

function packageVersion(value) {
  const spec = String(value || '').trim();
  if (spec.startsWith('@')) {
    const slash = spec.indexOf('/');
    const versionAt = slash >= 0 ? spec.indexOf('@', slash) : -1;
    return versionAt > slash ? spec.slice(versionAt + 1) : null;
  }
  const versionAt = spec.lastIndexOf('@');
  if (versionAt > 0) return spec.slice(versionAt + 1);
  const equals = spec.match(/==([^=\s]+)$/);
  return equals ? equals[1] : null;
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

  const artifact = claim.evidence.artifact;
  const verification = claim.evidence.artifactVerification;
  if (Boolean(artifact) !== Boolean(verification)) {
    throw new Error(`Trust-store claim #${index + 1} requires artifact and artifactVerification together.`);
  }
  if (verification) {
    if (verification.verified !== true || !verification.algorithm || !verification.digest || !verification.verifiedAt) {
      throw new Error(`Trust-store claim #${index + 1} has incomplete artifact verification.`);
    }
    if (!artifact.version || !artifact.identifier) {
      throw new Error(`Trust-store claim #${index + 1} artifact requires identifier and version.`);
    }
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
        checkedAt: claim.evidence.checkedAt ? String(claim.evidence.checkedAt) : null,
        ...(claim.evidence.artifact ? {
          artifact: {
            registryType: claim.evidence.artifact.registryType ? String(claim.evidence.artifact.registryType) : null,
            identifier: String(claim.evidence.artifact.identifier),
            version: String(claim.evidence.artifact.version),
            integrity: claim.evidence.artifact.integrity ? String(claim.evidence.artifact.integrity) : null,
            shasum: claim.evidence.artifact.shasum ? String(claim.evidence.artifact.shasum) : null,
            algorithm: claim.evidence.artifact.algorithm ? String(claim.evidence.artifact.algorithm) : null,
            digest: claim.evidence.artifact.digest ? String(claim.evidence.artifact.digest).toLowerCase() : null
          },
          artifactVerification: {
            verified: true,
            algorithm: String(claim.evidence.artifactVerification.algorithm),
            digest: String(claim.evidence.artifactVerification.digest),
            encoding: String(claim.evidence.artifactVerification.encoding || 'hex'),
            version: claim.evidence.artifactVerification.version
              ? String(claim.evidence.artifactVerification.version)
              : null,
            identifier: claim.evidence.artifactVerification.identifier
              ? String(claim.evidence.artifactVerification.identifier)
              : null,
            verifiedAt: String(claim.evidence.artifactVerification.verifiedAt)
          }
        } : {})
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

  const verifiedArtifact = claim.evidence?.artifactVerification?.verified === true
    ? claim.evidence.artifact
    : null;
  const configuredVersion = item.source?.type === 'package'
    ? packageVersion(item.source.package)
    : null;
  if (verifiedArtifact?.version && configuredVersion && verifiedArtifact.version !== configuredVersion) {
    return {
      ...item,
      signals: [...new Set([...(item.signals || []), 'artifact-version-mismatch'])].sort(),
      provenance: {
        status: 'mismatch',
        publisher: claim.publisher,
        expectedVersion: verifiedArtifact.version,
        configuredVersion,
        evidence: claim.evidence
      }
    };
  }

  return {
    ...item,
    provenance: {
      status: 'verified',
      publisher: claim.publisher,
      integrityVerified: Boolean(verifiedArtifact),
      evidence: claim.evidence
    }
  };
}

export function attachProvenanceAll(items, trustStore) {
  return items.map((item) => attachProvenance(item, trustStore));
}
