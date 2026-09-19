import test from 'node:test';
import assert from 'node:assert/strict';

import { inspectMcpConfig } from '../src/inspect.mjs';
import { evaluateAll } from '../src/policy.mjs';
import { getPolicyPack } from '../src/policy-packs.mjs';
import { parseCodexMcpToml } from '../src/codex-config.mjs';

test('redacts remote URL credentials and query values from inspection output', () => {
  const [result] = inspectMcpConfig({
    mcpServers: {
      remote: {
        url: 'http://alice:super-secret@example.com:8080/private/path?token=top-secret#fragment'
      }
    }
  });

  assert.deepEqual(result.source, {
    type: 'remote',
    host: 'example.com',
    origin: 'http://example.com:8080',
    protocol: 'http:'
  });
  assert.ok(result.signals.includes('embedded-credentials'));
  assert.ok(result.signals.includes('insecure-transport'));
  assert.ok(result.signals.includes('url-query-parameters'));
  assert.equal(JSON.stringify(result).includes('super-secret'), false);
  assert.equal(JSON.stringify(result).includes('top-secret'), false);
  assert.equal(JSON.stringify(result).includes('/private/path'), false);
});

test('strict policy blocks an allowlisted host over insecure transport', () => {
  const [server] = inspectMcpConfig({
    mcpServers: {
      remote: { url: 'http://example.com/mcp' }
    }
  });
  const policy = getPolicyPack('strict');
  policy.allowedRemoteHosts = ['example.com'];

  const [result] = evaluateAll([server], policy);
  assert.equal(result.action, 'block');
  assert.ok(result.reasons.includes('signal policy: insecure-transport -> block'));
});

test('normalizes Windows executable paths and command wrappers', () => {
  const [packageServer, shellServer] = inspectMcpConfig({
    mcpServers: {
      package: {
        command: 'C:\\Program Files\\nodejs\\npx.cmd',
        args: ['--package=@scope/demo@1.2.3', 'demo']
      },
      shell: {
        command: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        args: ['-File', 'setup.ps1']
      }
    }
  });

  assert.equal(packageServer.source.type, 'package');
  assert.equal(packageServer.source.runner, 'npx');
  assert.equal(packageServer.source.package, '@scope/demo@1.2.3');
  assert.equal(packageServer.source.pinned, true);
  assert.ok(packageServer.signals.includes('install-on-run'));
  assert.ok(shellServer.signals.includes('shell-execution'));
});

test('Codex parser fingerprints supported execution controls', () => {
  const parsed = parseCodexMcpToml(`
[mcp_servers.demo]
command = "node"
args = ["server.mjs"]
enabled = true
startup_timeout_sec = 15
tool_timeout_sec = 60
`);

  assert.deepEqual(parsed.mcpServers.demo._trustdexFingerprintData, {
    format: 'codex-toml',
    cwd: null,
    httpHeaderKeys: [],
    envHttpHeaderKeys: [],
    httpHeadersHelper: null,
    enabledTools: [],
    disabledTools: [],
    defaultToolsApprovalMode: null,
    enabled: true,
    startupTimeoutSec: 15,
    toolTimeoutSec: 60
  });
});

test('Codex parser fails closed on unsupported MCP keys and subsections', () => {
  assert.throws(
    () => parseCodexMcpToml('[mcp_servers.demo]\ncommand = "node"\nfuture_option = true\n'),
    /Unsupported or invalid Codex MCP key/
  );
  assert.throws(
    () => parseCodexMcpToml('[mcp_servers.demo.oauth]\nclient_id = "example"\n'),
    /Unsupported Codex MCP subsection/
  );
  assert.throws(
    () => parseCodexMcpToml('[mcp_servers]\ndemo = {}\n'),
    /Unsupported Codex MCP section/
  );
});
