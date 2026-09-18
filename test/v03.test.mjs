import test from 'node:test';
import assert from 'node:assert/strict';

import { inspectMcpConfig } from '../src/inspect.mjs';
import { inspectSkillText } from '../src/extensions.mjs';
import { createSnapshot, diffSnapshots } from '../src/snapshot.mjs';
import { generateTrustKeyPair, createTrustRecord } from '../src/trust-record.mjs';
import { assessReview } from '../src/review.mjs';
import {
  inspectGitHubRepository,
  inspectNpmPackage,
  inspectGitHubReleaseSignature,
  inspectMcpRegistryServer,
  provenanceObservationToClaim,
  upsertTrustStoreClaim
} from '../src/provenance-online.mjs';

function response(json, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() { return json; }
  };
}

test('MCP fingerprint changes when arguments change without exposing env values', () => {
  const first = inspectMcpConfig({
    mcpServers: {
      demo: { command: 'node', args: ['server.mjs', './a'], env: { API_TOKEN: 'secret-one' } }
    }
  })[0];

  const second = inspectMcpConfig({
    mcpServers: {
      demo: { command: 'node', args: ['server.mjs', './b'], env: { API_TOKEN: 'secret-two' } }
    }
  })[0];

  assert.notEqual(first.fingerprint, second.fingerprint);
  assert.deepEqual(first.envKeys, ['API_TOKEN']);
  assert.equal(JSON.stringify(first).includes('secret-one'), false);
});

test('skill fingerprint changes when content changes', () => {
  const a = inspectSkillText('---\nname: demo\n---\nHello');
  const b = inspectSkillText('---\nname: demo\n---\nHello world');
  assert.notEqual(a.fingerprint, b.fingerprint);
});

test('snapshot diff reports fingerprint drift', () => {
  const before = createSnapshot([{
    name: 'demo',
    source: { type: 'local', command: 'node' },
    fingerprint: 'a',
    signals: [],
    action: 'ask'
  }]);
  const after = createSnapshot([{
    name: 'demo',
    source: { type: 'local', command: 'node' },
    fingerprint: 'b',
    signals: [],
    action: 'ask'
  }]);

  const changes = diffSnapshots(before, after);
  assert.ok(changes.some((change) => change.type === 'fingerprint-changed'));
});

test('signed review is approved only for unchanged snapshot', () => {
  const keys = generateTrustKeyPair();
  const policy = { version: 1, unknownAction: 'block' };
  const baseline = createSnapshot([{
    name: 'demo',
    source: { type: 'package', package: 'demo@1.0.0', pinned: true },
    fingerprint: 'one',
    signals: [],
    action: 'allow'
  }]);
  const record = createTrustRecord(baseline, keys.privateKey, { policy });

  const unchanged = assessReview({
    record,
    publicKey: keys.publicKey,
    baseline,
    current: baseline,
    policy
  });
  assert.equal(unchanged.status, 'approved');

  const current = createSnapshot([{
    name: 'demo',
    source: { type: 'package', package: 'demo@1.0.0', pinned: true },
    fingerprint: 'two',
    signals: [],
    action: 'allow'
  }]);
  const changed = assessReview({
    record,
    publicKey: keys.publicKey,
    baseline,
    current,
    policy
  });
  assert.equal(changed.status, 'needs-review');
  assert.ok(changed.changes.some((item) => item.type === 'fingerprint-changed'));
});

test('GitHub provenance adapter validates repository identity', async () => {
  const seen = [];
  const observation = await inspectGitHubRepository('openai/example', {
    fetchImpl: async (url, options) => {
      seen.push({ url, options });
      return response({
        id: 123,
        full_name: 'openai/example',
        html_url: 'https://github.com/openai/example',
        owner: { login: 'openai', type: 'Organization' },
        archived: false,
        disabled: false,
        visibility: 'public',
        default_branch: 'main',
        pushed_at: '2026-09-19T00:00:00Z'
      });
    }
  });

  assert.equal(observation.type, 'repository');
  assert.equal(observation.subject, 'openai/example');
  assert.equal(observation.publisherHint, 'openai');
  assert.equal(seen[0].url, 'https://api.github.com/repos/openai/example');
});

test('npm provenance adapter returns registry evidence without auto-trusting it', async () => {
  const observation = await inspectNpmPackage('@scope/demo', {
    fetchImpl: async () => response({
      name: '@scope/demo',
      'dist-tags': { latest: '2.0.0' },
      versions: {
        '2.0.0': { repository: { url: 'git+https://github.com/example/demo.git' } }
      },
      maintainers: [{ name: 'alice' }]
    })
  });

  assert.equal(observation.type, 'package');
  assert.equal(observation.evidence.latestVersion, '2.0.0');
  assert.equal(observation.publisherHint, 'alice');

  const claim = provenanceObservationToClaim(observation, 'Example Publisher');
  const store = upsertTrustStoreClaim({ version: 1, claims: [] }, claim);
  assert.equal(store.claims[0].status, 'verified');
  assert.equal(store.claims[0].publisher, 'Example Publisher');
});

test('provenance adapter rejects mismatched GitHub API response', async () => {
  await assert.rejects(
    inspectGitHubRepository('owner/repo', {
      fetchImpl: async () => response({ full_name: 'attacker/repo' })
    }),
    /did not match/
  );
});


test('MCP Registry adapter maps a single package to package provenance', async () => {
  const observation = await inspectMcpRegistryServer('io.github.example/demo', {
    fetchImpl: async (url) => {
      assert.equal(
        url,
        'https://registry.modelcontextprotocol.io/v0.1/servers/io.github.example%2Fdemo/versions/latest'
      );
      return response({
        server: {
          name: 'io.github.example/demo',
          version: '1.2.3',
          repository: {
            url: 'https://github.com/example/demo',
            source: 'github'
          },
          packages: [{
            registryType: 'npm',
            identifier: '@example/demo',
            version: '1.2.3',
            fileSha256: 'a'.repeat(64)
          }]
        }
      });
    }
  });

  assert.equal(observation.adapter, 'mcp');
  assert.equal(observation.type, 'package');
  assert.equal(observation.subject, '@example/demo');
  assert.equal(observation.evidence.kind, 'mcp-official-registry');
});

test('GitHub release provenance accepts verified signed tag evidence', async () => {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    if (url.endsWith('/repos/example/demo')) {
      return response({
        full_name: 'example/demo',
        owner: { login: 'example' }
      });
    }
    if (url.endsWith('/releases/latest')) {
      return response({
        tag_name: 'v1.0.0',
        html_url: 'https://github.com/example/demo/releases/tag/v1.0.0'
      });
    }
    if (url.includes('/git/ref/tags/')) {
      return response({ object: { type: 'tag', sha: 'abc123' } });
    }
    if (url.endsWith('/git/tags/abc123')) {
      return response({
        verification: {
          verified: true,
          reason: 'valid',
          signer: { login: 'example' }
        }
      });
    }
    return response({}, 404);
  };

  const observation = await inspectGitHubReleaseSignature('example/demo', { fetchImpl });
  assert.equal(observation.evidence.signatureVerified, true);
  assert.equal(observation.evidence.tag, 'v1.0.0');
  const claim = provenanceObservationToClaim(observation, 'Example Publisher');
  assert.equal(claim.type, 'repository');
  assert.equal(claim.status, 'verified');
  assert.ok(calls.length >= 4);
});

test('GitHub release provenance refuses unsigned release as trust claim', async () => {
  const fetchImpl = async (url) => {
    if (url.endsWith('/repos/example/demo')) {
      return response({
        full_name: 'example/demo',
        owner: { login: 'example' }
      });
    }
    if (url.endsWith('/releases/latest')) {
      return response({ tag_name: 'v1.0.0' });
    }
    if (url.includes('/git/ref/tags/')) {
      return response({ object: { type: 'commit', sha: 'deadbeef' } });
    }
    if (url.endsWith('/commits/deadbeef')) {
      return response({ commit: { verification: { verified: false, reason: 'unsigned' } } });
    }
    return response({}, 404);
  };

  const observation = await inspectGitHubReleaseSignature('example/demo', { fetchImpl });
  assert.equal(observation.evidence.signatureVerified, false);
  assert.throws(
    () => provenanceObservationToClaim(observation, 'Example Publisher'),
    /without a verified signature/
  );
});

test('inspect supports generic servers container shape', () => {
  const result = inspectMcpConfig({
    servers: {
      demo: { command: 'node', args: ['server.mjs'] }
    }
  });
  assert.equal(result.length, 1);
  assert.equal(result[0].name, 'demo');
});
