import crypto from 'node:crypto';
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  githubRepositorySlug,
  inspectNpmPackage,
  inspectMcpRegistryServer,
  provenanceObservationToClaim,
  verifyArtifactBytes
} from '../src/provenance-online.mjs';
import { parseTrustStore, attachProvenanceAll } from '../src/provenance.mjs';
import { evaluateAll } from '../src/policy.mjs';
import { getPolicyPack } from '../src/policy-packs.mjs';

function response(json, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() { return json; }
  };
}

test('verifies npm SRI bytes before recording integrity-backed trust', async () => {
  const bytes = Buffer.from('reviewed npm package bytes');
  const integrity = `sha512-${crypto.createHash('sha512').update(bytes).digest('base64')}`;
  const observation = await inspectNpmPackage('@example/server', {
    fetchImpl: async () => response({
      name: '@example/server',
      'dist-tags': { latest: '1.2.3' },
      versions: {
        '1.2.3': {
          dist: {
            integrity,
            shasum: crypto.createHash('sha1').update(bytes).digest('hex')
          }
        }
      },
      maintainers: [{ name: 'alice' }]
    })
  });

  const verification = verifyArtifactBytes(observation, bytes);
  assert.equal(verification.verified, true);
  assert.equal(verification.algorithm, 'sha512');
  assert.equal(verification.version, '1.2.3');

  const claim = provenanceObservationToClaim(observation, 'Example Publisher', {
    artifactVerification: verification
  });
  const store = parseTrustStore({ version: 1, claims: [claim] });
  assert.equal(store.claims[0].evidence.artifact.version, '1.2.3');
  assert.equal(store.claims[0].evidence.artifactVerification.verified, true);

  assert.throws(
    () => verifyArtifactBytes(observation, Buffer.from('substituted bytes')),
    /do not match/
  );
});

test('verifies MCP Registry SHA-256 bytes', async () => {
  const bytes = Buffer.from('reviewed MCP artifact');
  const digest = crypto.createHash('sha256').update(bytes).digest('hex');
  const observation = await inspectMcpRegistryServer('io.github.example/server', {
    fetchImpl: async () => response({
      server: {
        name: 'io.github.example/server',
        version: '2.0.0',
        packages: [{
          registryType: 'npm',
          identifier: '@example/server',
          version: '2.0.0',
          fileSha256: digest
        }]
      }
    })
  });

  const verification = verifyArtifactBytes(observation, bytes);
  assert.equal(verification.algorithm, 'sha256');
  assert.equal(verification.digest, digest);
});

test('blocks a configured package version that differs from verified artifact evidence', async () => {
  const bytes = Buffer.from('reviewed npm package bytes');
  const integrity = `sha512-${crypto.createHash('sha512').update(bytes).digest('base64')}`;
  const observation = await inspectNpmPackage('demo-server', {
    fetchImpl: async () => response({
      name: 'demo-server',
      'dist-tags': { latest: '1.2.3' },
      versions: {
        '1.2.3': { dist: { integrity } }
      },
      maintainers: []
    })
  });
  const claim = provenanceObservationToClaim(observation, 'Example Publisher', {
    artifactVerification: verifyArtifactBytes(observation, bytes)
  });
  const store = parseTrustStore({ version: 1, claims: [claim] });
  const [attached] = attachProvenanceAll([{
    name: 'demo',
    source: { type: 'package', runner: 'npx', package: 'demo-server@2.0.0', pinned: true },
    signals: []
  }], store);

  assert.equal(attached.provenance.status, 'mismatch');
  assert.ok(attached.signals.includes('artifact-version-mismatch'));

  const [result] = evaluateAll([attached], getPolicyPack('official-first'));
  assert.equal(result.action, 'block');
});

test('keeps matching integrity-backed package evidence eligible for policy evaluation', async () => {
  const bytes = Buffer.from('reviewed npm package bytes');
  const integrity = `sha512-${crypto.createHash('sha512').update(bytes).digest('base64')}`;
  const observation = await inspectNpmPackage('demo-server', {
    fetchImpl: async () => response({
      name: 'demo-server',
      'dist-tags': { latest: '1.2.3' },
      versions: {
        '1.2.3': { dist: { integrity } }
      },
      maintainers: []
    })
  });
  const claim = provenanceObservationToClaim(observation, 'Example Publisher', {
    artifactVerification: verifyArtifactBytes(observation, bytes)
  });
  const store = parseTrustStore({ version: 1, claims: [claim] });
  const [attached] = attachProvenanceAll([{
    name: 'demo',
    source: { type: 'package', runner: 'npx', package: 'demo-server@1.2.3', pinned: true },
    signals: []
  }], store);

  assert.equal(attached.provenance.status, 'verified');
  assert.equal(attached.provenance.integrityVerified, true);

  const [result] = evaluateAll([attached], getPolicyPack('official-first'));
  assert.equal(result.action, 'allow');
});

test('rejects internally inconsistent artifact evidence', () => {
  const base = {
    version: 1,
    claims: [{
      type: 'package',
      subject: 'demo-server',
      publisher: 'Example Publisher',
      status: 'verified',
      evidence: {
        kind: 'npm-registry',
        reference: 'https://www.npmjs.com/package/demo-server',
        artifact: {
          registryType: 'npm',
          identifier: 'demo-server',
          version: '1.2.3',
          integrity: 'sha512-ZXhwZWN0ZWQ='
        },
        artifactVerification: {
          verified: true,
          algorithm: 'sha512',
          digest: 'ZGlmZmVyZW50',
          encoding: 'base64',
          version: '1.2.3',
          identifier: 'demo-server',
          verifiedAt: '2026-09-19T00:00:00Z'
        }
      }
    }]
  };

  assert.throws(() => parseTrustStore(base), /integrity does not match/);

  const wrongVersion = structuredClone(base);
  wrongVersion.claims[0].evidence.artifactVerification.digest = 'ZXhwZWN0ZWQ=';
  wrongVersion.claims[0].evidence.artifactVerification.version = '2.0.0';
  assert.throws(() => parseTrustStore(wrongVersion), /version does not match/);
});

test('npm build provenance must come from the repository the package declares', async () => {
  const bytes = Buffer.from('attested package bytes');
  const integrity = `sha512-${crypto.createHash('sha512').update(bytes).digest('base64')}`;
  const hex = crypto.createHash('sha512').update(bytes).digest('hex');
  const statement = (repository, overrides = {}) => ({
    attestations: [{
      predicateType: 'https://slsa.dev/provenance/v1',
      bundle: { dsseEnvelope: {
        payloadType: 'application/vnd.in-toto+json',
        payload: Buffer.from(JSON.stringify({
          subject: [{ name: 'pkg:npm/%40example/agent@2.0.0', digest: { sha512: hex } }],
          predicate: { buildDefinition: { externalParameters: { workflow: { repository, path: '.github/workflows/publish.yml' } } } },
          ...overrides
        })).toString('base64')
      } }
    }]
  });
  const packument = (declared, previous = declared, attested = true, previousAttested = false) => ({
    name: '@example/agent',
    'dist-tags': { latest: '2.0.0' },
    time: { '1.0.0': '2026-01-01T00:00:00Z', '2.0.0': '2026-11-01T00:00:00Z' },
    versions: {
      '1.0.0': { repository: { url: `git+https://github.com/${previous}.git` }, dist: { integrity, ...(previousAttested ? { attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } } : {}) } },
      '2.0.0': { repository: { url: `git+https://github.com/${declared}.git` }, dist: { integrity, ...(attested ? { attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } } : {}) } }
    },
    maintainers: [{ name: 'alice' }]
  });
  const ATTEST = 'https://registry.npmjs.org/-/npm/v1/attestations/%40example%2Fagent@2.0.0';
  const lookup = (doc, attestation) => inspectNpmPackage('@example/agent', {
    fetchImpl: async (url) => url === ATTEST
      ? (attestation === undefined ? response({}, 404) : response(attestation))
      : response(doc)
  });

  for (const [value, slug] of [
    ['git+https://github.com/Example/Agent.git/', 'example/agent'], ['github:example/agent', 'example/agent'],
    ['git@github.com:example/agent.git', 'example/agent'], ['https://gitlab.com/example/agent', null]
  ]) assert.equal(githubRepositorySlug(value), slug, value);

  let observation = await lookup(packument('Example/Agent'), statement('https://github.com/example/agent'));
  assert.equal(observation.evidence.buildProvenance.status, 'matched');
  const claim = provenanceObservationToClaim(observation, 'Example Publisher');
  assert.deepEqual(claim.evidence.buildProvenance, {
    source: 'npm-registry-attestation', version: '2.0.0', sourceRepository: 'example/agent',
    workflowPath: '.github/workflows/publish.yml', signatureVerified: false
  });
  assert.deepEqual(parseTrustStore({ version: 1, claims: [claim] }).claims[0].evidence.buildProvenance, claim.evidence.buildProvenance);

  const refused = [
    [packument('attacker/agent', 'example/agent'), statement('https://github.com/attacker/agent'), 'mismatch'],
    [packument('example/agent'), statement('https://github.com/attacker/agent'), 'mismatch'],
    [packument('example/agent', 'example/agent', false, true), undefined, 'dropped'],
    [packument('example/agent'), undefined, 'unverifiable'],
    [packument('example/agent'), statement('https://github.com/example/agent', { subject: [{ name: 'pkg:npm/%40example/agent@2.0.0', digest: { sha512: '00' } }] }), 'unverifiable'],
    [packument('example/agent'), { attestations: [{ predicateType: 'https://slsa.dev/provenance/v1', bundle: { dsseEnvelope: { payloadType: 'text/plain', payload: '' } } }] }, 'unverifiable']
  ];
  for (const [doc, attestation, status] of refused) {
    observation = await lookup(doc, attestation);
    assert.equal(observation.evidence.buildProvenance.status, status);
    assert.throws(() => provenanceObservationToClaim(observation, 'Example Publisher'), /Refusing to trust an npm package/);
  }

  const untimed = packument('example/agent', 'example/agent', false, true);
  untimed.versions['0.9.0'] = { ...untimed.versions['1.0.0'], version: '0.9.0' };
  delete untimed.time;
  observation = await lookup(untimed, undefined);
  assert.equal(observation.evidence.buildProvenance.status, 'dropped');

  observation = await lookup(packument('example/agent', 'example/agent', false), undefined);
  assert.equal(observation.evidence.buildProvenance.status, 'absent');
  assert.equal(provenanceObservationToClaim(observation, 'Example Publisher').evidence.buildProvenance, undefined);
});
