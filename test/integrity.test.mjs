import crypto from 'node:crypto';
import test from 'node:test';
import assert from 'node:assert/strict';

import {
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
    source: { type: 'package', package: 'demo-server@2.0.0', pinned: true },
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
    source: { type: 'package', package: 'demo-server@1.2.3', pinned: true },
    signals: []
  }], store);

  assert.equal(attached.provenance.status, 'verified');
  assert.equal(attached.provenance.integrityVerified, true);

  const [result] = evaluateAll([attached], getPolicyPack('official-first'));
  assert.equal(result.action, 'allow');
});
