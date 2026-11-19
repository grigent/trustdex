import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { createApprovalStore } from '../src/approvals.mjs';
import { APPROVE, REJECT, createSlackApprover, messageText, parseApproverConfig, readToken, terminalOnly } from '../src/slack-approver.mjs';

const cli = fileURLToPath(new URL('../bin/trustdex.mjs', import.meta.url));
const CONFIG = parseApproverConfig({ tokenFile: '/tmp/token', teamId: 'T0TEAM0001', botUserId: 'U0BOT00001', ownerUserId: 'U0OWNER001', language: 'ko' });

function tempDir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'trustdex-slack-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

// A Slack stand-in that records calls and serves reactions set by the test.
function fakeSlack({ team = 'T0TEAM0001', bot = 'U0BOT00001' } = {}) {
  const calls = [];
  const reactions = new Map();
  let ts = 1000;
  return {
    calls,
    react(messageTs, name, user) {
      const list = reactions.get(messageTs) || [];
      const found = list.find((reaction) => reaction.name === name);
      if (found) found.users.push(user); else list.push({ name, users: [user] });
      reactions.set(messageTs, list);
    },
    async call(method, params = {}) {
      calls.push({ method, ...params });
      if (method === 'auth.test') return { ok: true, team_id: team, user_id: bot };
      if (method === 'conversations.open') return { ok: true, channel: { id: 'D0DM000001' } };
      if (method === 'chat.postMessage') return { ok: true, ts: `${(ts += 1)}.000100` };
      if (method === 'reactions.get') return { ok: true, message: { reactions: reactions.get(params.timestamp) || [] } };
      return { ok: true };
    }
  };
}

const SECRET = [{ name: 'command:credential-store', signals: ['secret-access'], reasons: ['Reads a credential store.'] }];
const TAMPER = [{ name: 'command:agent-or-gate-config', signals: ['guard-tamper'], reasons: ['Changes agent settings.'] }];

async function setup(t, slack = fakeSlack()) {
  const dir = tempDir(t);
  const store = createApprovalStore(path.join(dir, 'state'));
  const approver = createSlackApprover({ store, slack, config: CONFIG, stateDir: store.stateDir });
  await approver.start();
  return { dir, store, slack, approver };
}

const posted = (slack) => slack.calls.filter((call) => call.method === 'chat.postMessage');

test('config must name real Slack ids, an absolute token file, and an owner who is not the bot', () => {
  assert.throws(() => parseApproverConfig({ ...CONFIG, ownerUserId: CONFIG.botUserId }), /owner cannot be the bot/);
  assert.throws(() => parseApproverConfig({ ...CONFIG, teamId: 'nope' }), /teamId/);
  assert.throws(() => parseApproverConfig({ ...CONFIG, tokenFile: 'token' }), /absolute/);
  assert.throws(() => parseApproverConfig({ ...CONFIG, approveEveryone: true }), /Unsupported/);
  assert.throws(() => parseApproverConfig({ ...CONFIG, pollSeconds: 1 }), /pollSeconds/);
});

test('the token file must be private and hold a bot token', (t) => {
  const file = path.join(tempDir(t), 'token');
  fs.writeFileSync(file, 'xoxb-1-2-3\n', { mode: 0o644 });
  if (process.platform !== 'win32') assert.throws(() => readToken(file), /mode 600/);
  fs.chmodSync(file, 0o600);
  assert.equal(readToken(file), 'xoxb-1-2-3');
  fs.writeFileSync(file, 'xoxp-user-token');
  assert.throws(() => readToken(file), /bot token/);
});

test('it refuses a different workspace or bot', async (t) => {
  await assert.rejects(setup(t, fakeSlack({ bot: 'U0OTHER001' })), /does not match/);
});

test('only the owner’s ✅ approves; the bot’s or anyone else’s does not', async (t) => {
  const { store, slack, approver } = await setup(t);
  const code = store.recordPending('d1', SECRET);
  await approver.tick();
  const [message] = posted(slack);
  assert.equal(message.channel, 'D0DM000001');
  assert.match(message.text, new RegExp(code));
  assert.match(message.text, /비밀값·인증 정보 읽기/);
  assert.deepEqual(slack.calls.filter((c) => c.method === 'reactions.add').map((c) => c.name), [APPROVE, REJECT]);

  const ts = slack.calls.find((c) => c.method === 'chat.postMessage').ts ?? '1001.000100';
  slack.react('1001.000100', APPROVE, CONFIG.botUserId);
  slack.react('1001.000100', APPROVE, 'U0STRANGER1');
  await approver.tick();
  assert.equal(store.consume('d1'), false, 'no approval from the bot or a stranger');
  assert.ok(ts);

  slack.react('1001.000100', APPROVE, CONFIG.ownerUserId);
  await approver.tick();
  assert.equal(store.consume('d1'), true, 'the owner approved it');
  assert.ok(slack.calls.some((c) => c.method === 'chat.update' && /허용했어요/.test(c.text)));
  await approver.tick();
  assert.equal(posted(slack).length, 1, 'no second message for the same code');
});

test('❌ refuses, and expired or terminal-approved actions are closed', async (t) => {
  const { store, slack, approver } = await setup(t);
  store.recordPending('d1', SECRET);
  const second = store.recordPending('d2', SECRET);
  await approver.tick();
  slack.react('1001.000100', REJECT, CONFIG.ownerUserId);
  slack.react('1001.000100', APPROVE, CONFIG.ownerUserId);
  store.approve(second); // decided in the terminal instead
  await approver.tick();
  assert.equal(store.consume('d1'), false, 'a refusal wins over an approval');
  const updates = slack.calls.filter((c) => c.method === 'chat.update').map((c) => c.text);
  assert.ok(updates.some((text) => /거절했어요/.test(text)));
  assert.ok(updates.some((text) => /더 기다리지 않아요/.test(text)));
});

test('changes to agent settings or TrustDex itself are never approvable from Slack', async (t) => {
  const { store, slack, approver } = await setup(t);
  store.recordPending('d1', TAMPER);
  await approver.tick();
  assert.match(posted(slack)[0].text, /터미널에서만/);
  assert.equal(slack.calls.filter((c) => c.method === 'reactions.add').length, 0);
  slack.react('1001.000100', APPROVE, CONFIG.ownerUserId);
  await approver.tick();
  assert.equal(store.consume('d1'), false);
  assert.equal(terminalOnly({ summary: TAMPER }), true);
});

test('it sends at most the configured number of messages an hour', async (t) => {
  const dir = tempDir(t);
  const store = createApprovalStore(path.join(dir, 'state'));
  const slack = fakeSlack();
  const approver = createSlackApprover({ store, slack, config: { ...CONFIG, maxMessagesPerHour: 2 }, stateDir: store.stateDir });
  await approver.start();
  for (let i = 0; i < 5; i += 1) store.recordPending(`d${i}`, SECRET);
  await approver.tick();
  await approver.tick();
  const texts = posted(slack).map((c) => c.text);
  assert.equal(texts.filter((text) => /코드/.test(text)).length, 2);
  assert.equal(texts.filter((text) => /알림 수를 넘었어요/.test(text)).length, 1, 'one warning, not one per tick');
});

test('messages escape Slack markup and name the approval scope', () => {
  const text = messageText({ code: 'K7M2QX9P', summary: [{ name: '<!channel>', signals: ['persistence-change'], reasons: ['<@U1> x'] }], itemKeys: ['signal:persistence-change'] }, 'en');
  assert.match(text, /&lt;!channel&gt;/);
  assert.match(text, /&lt;@U1&gt;/);
  assert.match(text, /this kind of work for 1 hour/);
});

test('the hook protects slack-approver.json next to the install policy', (t) => {
  const dir = tempDir(t);
  const policy = path.join(dir, 'install-policy.json');
  fs.writeFileSync(policy, '{"version":1}');
  const input = JSON.stringify({ tool_name: 'Write', tool_input: { file_path: path.join(dir, 'slack-approver.json'), content: '{}' } });
  const out = spawnSync(process.execPath, [cli, 'claude-hook', '--install-policy', policy, '--state-dir', path.join(dir, 'state')], { input, encoding: 'utf8' });
  assert.equal(JSON.parse(out.stdout).hookSpecificOutput.permissionDecision, 'deny');
});
