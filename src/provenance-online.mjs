function assertFetch(fetchImpl) {
  if (typeof fetchImpl !== 'function') {
    throw new Error('This Node.js runtime does not provide fetch(). Node.js 20+ is required.');
  }
}

async function fetchJson(url, options = {}, fetchImpl = globalThis.fetch) {
  assertFetch(fetchImpl);
  const response = await fetchImpl(url, options);
  if (!response?.ok) {
    throw new Error(`Provenance lookup failed (${response?.status || 'unknown'}): ${url}`);
  }
  return response.json();
}

function normalizeRepoSlug(value) {
  const slug = String(value || '').trim().replace(/^https?:\/\/github\.com\//i, '').replace(/\.git$/, '').replace(/^\/+|\/+$/g, '');
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(slug)) {
    throw new Error('GitHub repository must be in owner/repo form.');
  }
  return slug;
}

export async function inspectGitHubRepository(repository, options = {}) {
  const slug = normalizeRepoSlug(repository);
  const url = `https://api.github.com/repos/${slug}`;
  const data = await fetchJson(url, {
    headers: {
      Accept: 'application/vnd.github+json',
      'User-Agent': 'trustdex'
    }
  }, options.fetchImpl);

  if (!data?.full_name || String(data.full_name).toLowerCase() !== slug.toLowerCase()) {
    throw new Error('GitHub API response did not match the requested repository.');
  }

  return {
    adapter: 'github',
    type: 'repository',
    subject: data.full_name,
    publisherHint: data.owner?.login || null,
    observedAt: new Date().toISOString(),
    evidence: {
      kind: 'github-api',
      reference: data.html_url || `https://github.com/${data.full_name}`,
      repositoryId: data.id ?? null,
      ownerLogin: data.owner?.login || null,
      ownerType: data.owner?.type || null,
      archived: Boolean(data.archived),
      disabled: Boolean(data.disabled),
      visibility: data.visibility || (data.private ? 'private' : 'public'),
      defaultBranch: data.default_branch || null,
      pushedAt: data.pushed_at || null
    }
  };
}

function normalizeNpmPackage(value) {
  const name = String(value || '').trim();
  if (!name || /\s/.test(name) || name.includes('://')) throw new Error('Invalid npm package name.');
  return name;
}

export async function inspectNpmPackage(packageName, options = {}) {
  const name = normalizeNpmPackage(packageName);
  const url = `https://registry.npmjs.org/${encodeURIComponent(name)}`;
  const data = await fetchJson(url, {
    headers: {
      Accept: 'application/json',
      'User-Agent': 'trustdex'
    }
  }, options.fetchImpl);

  if (!data?.name || data.name !== name) {
    throw new Error('npm registry response did not match the requested package.');
  }

  const latest = data['dist-tags']?.latest || null;
  const latestMeta = latest && data.versions?.[latest] ? data.versions[latest] : null;
  const repository = typeof data.repository === 'string'
    ? data.repository
    : data.repository?.url || latestMeta?.repository?.url || null;

  return {
    adapter: 'npm',
    type: 'package',
    subject: data.name,
    publisherHint: Array.isArray(data.maintainers) && data.maintainers.length === 1
      ? data.maintainers[0]?.name || null
      : null,
    observedAt: new Date().toISOString(),
    evidence: {
      kind: 'npm-registry',
      reference: `https://www.npmjs.com/package/${name}`,
      latestVersion: latest,
      repository,
      maintainers: Array.isArray(data.maintainers)
        ? data.maintainers.map((item) => item?.name).filter(Boolean).sort()
        : []
    }
  };
}

export function provenanceObservationToClaim(observation, publisher) {
  if (!observation?.type || !observation?.subject || !observation?.evidence) {
    throw new Error('Invalid provenance observation.');
  }
  const publisherName = String(publisher || '').trim();
  if (!publisherName) throw new Error('A publisher name is required for explicit approval.');

  return {
    type: observation.type,
    subject: observation.subject,
    publisher: publisherName,
    status: 'verified',
    evidence: {
      kind: observation.evidence.kind,
      reference: observation.evidence.reference,
      checkedAt: observation.observedAt || new Date().toISOString()
    }
  };
}

export function upsertTrustStoreClaim(store, claim) {
  const current = store && typeof store === 'object' ? store : { version: 1, claims: [] };
  if (current.version !== 1) throw new Error('Unsupported trust-store version. Expected version 1.');
  const claims = Array.isArray(current.claims) ? [...current.claims] : [];
  const index = claims.findIndex((item) =>
    item?.type === claim.type &&
    String(item?.subject || '').toLowerCase() === String(claim.subject).toLowerCase()
  );
  if (index >= 0) claims[index] = claim;
  else claims.push(claim);
  return { version: 1, claims };
}
