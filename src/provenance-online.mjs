import crypto from 'node:crypto';

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

export async function inspectGitHubReleaseSignature(repository, options = {}) {
  const slug = normalizeRepoSlug(repository);
  const repoUrl = `https://api.github.com/repos/${slug}`;
  const repoData = await fetchJson(repoUrl, {
    headers: {
      Accept: 'application/vnd.github+json',
      'User-Agent': 'trustdex'
    }
  }, options.fetchImpl);

  if (!repoData?.full_name || String(repoData.full_name).toLowerCase() !== slug.toLowerCase()) {
    throw new Error('GitHub API response did not match the requested repository.');
  }

  const release = await fetchJson(`${repoUrl}/releases/latest`, {
    headers: {
      Accept: 'application/vnd.github+json',
      'User-Agent': 'trustdex'
    }
  }, options.fetchImpl);

  if (!release?.tag_name) throw new Error('Latest GitHub release does not expose a tag name.');

  const ref = await fetchJson(
    `${repoUrl}/git/ref/tags/${encodeURIComponent(release.tag_name)}`,
    {
      headers: {
        Accept: 'application/vnd.github+json',
        'User-Agent': 'trustdex'
      }
    },
    options.fetchImpl
  );

  const objectType = ref?.object?.type;
  const objectSha = ref?.object?.sha;
  if (!objectType || !objectSha) throw new Error('GitHub tag reference is incomplete.');

  let verification = null;
  if (objectType === 'tag') {
    const tag = await fetchJson(`${repoUrl}/git/tags/${objectSha}`, {
      headers: {
        Accept: 'application/vnd.github+json',
        'User-Agent': 'trustdex'
      }
    }, options.fetchImpl);
    verification = tag?.verification || null;
  } else if (objectType === 'commit') {
    const commit = await fetchJson(`${repoUrl}/commits/${objectSha}`, {
      headers: {
        Accept: 'application/vnd.github+json',
        'User-Agent': 'trustdex'
      }
    }, options.fetchImpl);
    verification = commit?.commit?.verification || commit?.verification || null;
  } else {
    throw new Error(`Unsupported GitHub tag object type: ${objectType}`);
  }

  return {
    adapter: 'github-release',
    type: 'repository',
    subject: repoData.full_name,
    publisherHint: repoData.owner?.login || null,
    observedAt: new Date().toISOString(),
    evidence: {
      kind: 'github-release-signature',
      reference: release.html_url || `https://github.com/${repoData.full_name}/releases/tag/${release.tag_name}`,
      tag: release.tag_name,
      objectType,
      objectSha,
      signatureVerified: Boolean(verification?.verified),
      signatureReason: verification?.reason || null,
      signer: verification?.signer?.login || null
    }
  };
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
      artifact: latest && latestMeta?.dist?.integrity ? {
        registryType: 'npm',
        identifier: data.name,
        version: latest,
        integrity: String(latestMeta.dist.integrity),
        shasum: latestMeta.dist.shasum ? String(latestMeta.dist.shasum) : null
      } : null,
      repository,
      maintainers: Array.isArray(data.maintainers)
        ? data.maintainers.map((item) => item?.name).filter(Boolean).sort()
        : []
    }
  };
}

function normalizeMcpServerName(value) {
  const name = String(value || '').trim();
  if (!name || !name.includes('/') || /\s/.test(name)) {
    throw new Error('MCP Registry server name must be a namespace-qualified name such as io.github.user/server.');
  }
  return name;
}

export async function inspectMcpRegistryServer(serverName, options = {}) {
  const name = normalizeMcpServerName(serverName);
  const baseUrl = options.baseUrl || 'https://registry.modelcontextprotocol.io';
  if (!/^https:\/\//i.test(baseUrl)) throw new Error('MCP Registry base URL must use HTTPS.');
  const url = `${baseUrl.replace(/\/$/, '')}/v0.1/servers/${encodeURIComponent(name)}/versions/latest`;
  const data = await fetchJson(url, {
    headers: {
      Accept: 'application/json',
      'User-Agent': 'trustdex'
    }
  }, options.fetchImpl);

  const server = data?.server || data;
  if (!server?.name || server.name !== name) {
    throw new Error('MCP Registry response did not match the requested server.');
  }

  const packages = Array.isArray(server.packages) ? server.packages : [];
  const remotes = Array.isArray(server.remotes) ? server.remotes : [];
  let type = 'registry';
  let subject = server.name;

  if (packages.length === 1 && packages[0]?.identifier) {
    type = 'package';
    subject = String(packages[0].identifier);
  } else if (packages.length === 0 && remotes.length === 1 && remotes[0]?.url) {
    try {
      type = 'remote';
      subject = new URL(remotes[0].url).hostname.toLowerCase();
    } catch {
      type = 'registry';
      subject = server.name;
    }
  }

  return {
    adapter: 'mcp',
    type,
    subject,
    registryName: server.name,
    publisherHint: null,
    observedAt: new Date().toISOString(),
    evidence: {
      kind: 'mcp-official-registry',
      reference: url,
      serverName: server.name,
      version: server.version || null,
      artifact: packages.length === 1 && packages[0]?.identifier && packages[0]?.version && packages[0]?.fileSha256
        ? {
            registryType: packages[0].registryType || null,
            identifier: String(packages[0].identifier),
            version: String(packages[0].version),
            algorithm: 'sha256',
            digest: String(packages[0].fileSha256).toLowerCase()
          }
        : null,
      repository: server.repository?.url || null,
      repositorySource: server.repository?.source || null,
      packages: packages.map((pkg) => ({
        registryType: pkg?.registryType || null,
        identifier: pkg?.identifier || null,
        version: pkg?.version || null,
        fileSha256: pkg?.fileSha256 || null
      })),
      remotes: remotes.map((remote) => ({
        type: remote?.type || null,
        url: remote?.url || null
      }))
    }
  };
}

function digestMatches(actual, expected) {
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

export function verifyArtifactBytes(observation, content) {
  const artifact = observation?.evidence?.artifact;
  if (!artifact) throw new Error('The provenance observation does not provide verifiable artifact integrity.');

  const bytes = Buffer.isBuffer(content) ? content : Buffer.from(content);
  const version = artifact.version ? String(artifact.version) : null;
  const identifier = artifact.identifier ? String(artifact.identifier) : String(observation.subject || '');

  if (artifact.integrity) {
    const candidates = String(artifact.integrity).trim().split(/\s+/);
    let supported = 0;
    for (const candidate of candidates) {
      const match = candidate.match(/^(sha(?:256|384|512))-([A-Za-z0-9+/=]+)(?:\?.*)?$/i);
      if (!match) continue;
      supported += 1;
      const algorithm = match[1].toLowerCase();
      const expected = Buffer.from(match[2], 'base64');
      const actual = crypto.createHash(algorithm).update(bytes).digest();
      if (digestMatches(actual, expected)) {
        return {
          verified: true,
          algorithm,
          digest: actual.toString('base64'),
          encoding: 'base64',
          version,
          identifier,
          verifiedAt: new Date().toISOString()
        };
      }
    }
    if (!supported) throw new Error('Artifact integrity does not contain a supported SHA-256, SHA-384, or SHA-512 digest.');
    throw new Error('Artifact bytes do not match the registry integrity metadata.');
  }

  if (artifact.algorithm && artifact.digest) {
    const algorithm = String(artifact.algorithm).toLowerCase();
    if (!['sha256', 'sha384', 'sha512'].includes(algorithm)) {
      throw new Error(`Unsupported artifact digest algorithm: ${algorithm}`);
    }
    const expectedHex = String(artifact.digest).toLowerCase();
    if (!/^[a-f0-9]+$/.test(expectedHex) || expectedHex.length !== crypto.createHash(algorithm).digest().length * 2) {
      throw new Error('Artifact digest has an invalid hexadecimal format.');
    }
    const actual = crypto.createHash(algorithm).update(bytes).digest();
    const expected = Buffer.from(expectedHex, 'hex');
    if (!digestMatches(actual, expected)) {
      throw new Error('Artifact bytes do not match the registry digest.');
    }
    return {
      verified: true,
      algorithm,
      digest: actual.toString('hex'),
      encoding: 'hex',
      version,
      identifier,
      verifiedAt: new Date().toISOString()
    };
  }

  throw new Error('The provenance observation does not provide a supported cryptographic digest.');
}

export function provenanceObservationToClaim(observation, publisher, options = {}) {
  if (!observation?.type || !observation?.subject || !observation?.evidence) {
    throw new Error('Invalid provenance observation.');
  }
  if (!['package', 'remote', 'repository'].includes(observation.type)) {
    throw new Error('This observation does not map to a single trustable source. Review it manually instead.');
  }
  if (observation.adapter === 'github-release' && !observation.evidence?.signatureVerified) {
    throw new Error('Refusing to trust a GitHub release without a verified signature.');
  }

  const publisherName = String(publisher || '').trim();
  if (!publisherName) throw new Error('A publisher name is required for explicit approval.');

  const evidence = {
    kind: observation.evidence.kind,
    reference: observation.evidence.reference,
    checkedAt: observation.observedAt || new Date().toISOString()
  };

  if (options.artifactVerification) {
    if (!options.artifactVerification.verified || !observation.evidence.artifact) {
      throw new Error('Artifact verification is incomplete.');
    }
    evidence.artifact = JSON.parse(JSON.stringify(observation.evidence.artifact));
    evidence.artifactVerification = {
      verified: true,
      algorithm: String(options.artifactVerification.algorithm),
      digest: String(options.artifactVerification.digest),
      encoding: String(options.artifactVerification.encoding),
      version: options.artifactVerification.version ? String(options.artifactVerification.version) : null,
      identifier: options.artifactVerification.identifier ? String(options.artifactVerification.identifier) : null,
      verifiedAt: String(options.artifactVerification.verifiedAt)
    };
  }

  return {
    type: observation.type,
    subject: observation.subject,
    publisher: publisherName,
    status: 'verified',
    evidence
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
