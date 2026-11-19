// Approve stopped actions from Slack, for people who are away from their terminal.
//
// `trustdex slack-approver --config <file>` runs on the user's computer (for example
// as a launch agent). For each action the hook stopped, it sends the configured
// owner a direct message with what was stopped and why, and adds ✅ and ❌
// reactions. When the owner — and only the owner, by Slack user id — reacts with
// ✅, it records the same one-time approval `trustdex allow-once <code>` would.
//
// What it will not do:
// - approve changes to agent settings or TrustDex itself (guard-tamper) or
//   commands that could not be parsed near protected files: those stay terminal-only;
// - accept reactions from anyone but the owner, including its own bot user;
// - send more than a fixed number of messages per hour.
//
// Its message state lives in the approval state directory, which the hook already
// protects from agent writes, so an agent cannot point it at an older message.
// Anyone who can react as the owner in Slack can approve, so keep Slack behind
// two-factor sign-in and do not give agents a Slack connection that acts as you.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export const APPROVE = 'white_check_mark';
export const REJECT = 'x';
const TERMINAL_ONLY = new Set(['guard-tamper', 'unparseable-guarded-command']);
const ID_RE = /^[A-Z][A-Z0-9]{6,20}$/;
const STATE_FILE = 'slack-approver.json';

const TEXT = {
  en: {
    head: (code) => `TrustDex stopped an action (code ${code})`,
    approve: 'React with ✅ to allow it, ❌ to refuse. Only approve what you asked for yourself.',
    terminal: 'This kind of action can only be allowed in your own terminal: trustdex allow-once',
    scope: { exact: 'Covers this exact action once, within an hour.', packages: 'Covers these exact package versions for 24 hours.', signal: 'Covers this kind of work for 1 hour.' },
    approved: 'Allowed ✅ — ask the agent to run it again.',
    rejected: 'Refused ❌',
    closed: 'No longer waiting (expired or decided elsewhere).',
    tooMany: 'TrustDex stopped more actions than it will message about in an hour. Check `trustdex allow-once --list` on the computer.',
    signals: {}
  },
  ko: {
    head: (code) => `TrustDex가 작업을 멈췄어요 (코드 ${code})`,
    approve: '✅를 누르면 이 작업을 허용하고, ❌는 거절해요. 직접 시킨 일이 아니면 누르지 마세요.',
    terminal: '이 종류는 컴퓨터 터미널에서만 허용할 수 있어요: trustdex allow-once',
    scope: { exact: '이 작업 한 번만, 1시간 안에 허용돼요.', packages: '이 패키지 버전을 24시간 허용해요.', signal: '이 종류의 작업을 1시간 허용해요.' },
    approved: '허용했어요 ✅ 에이전트에게 다시 실행하라고 말해 주세요.',
    rejected: '거절했어요 ❌',
    closed: '더 기다리지 않아요(만료됐거나 다른 곳에서 정해짐).',
    tooMany: '한 시간에 보내는 알림 수를 넘었어요. 컴퓨터에서 `trustdex allow-once --list`로 확인해 주세요.',
    signals: {
      'guard-tamper': '에이전트·트러스트덱스 설정 변경',
      'secret-access': '비밀값·인증 정보 읽기',
      'agent-permission-bypass': '안전장치를 끈 AI 실행',
      'obfuscated-execution': '숨긴 내용을 풀어서 실행',
      'persistence-change': '자동 실행·예약 작업 변경',
      'remote-secret-access': '서버의 비밀값 읽기',
      'remote-config-change': '서버 설정 변경',
      'unparseable-guarded-command': '보호 파일 근처의 해석 못 한 명령'
    }
  }
};

export function parseApproverConfig(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Slack approver config must be a JSON object.');
  const allowed = new Set(['tokenFile', 'teamId', 'botUserId', 'ownerUserId', 'pollSeconds', 'maxMessagesPerHour', 'language']);
  for (const key of Object.keys(value)) if (!allowed.has(key)) throw new Error(`Unsupported Slack approver key: ${key}`);
  for (const key of ['teamId', 'botUserId', 'ownerUserId']) {
    if (!ID_RE.test(String(value[key] || ''))) throw new Error(`Slack approver ${key} must be a Slack id.`);
  }
  if (value.ownerUserId === value.botUserId) throw new Error('The owner cannot be the bot.');
  if (typeof value.tokenFile !== 'string' || !path.isAbsolute(value.tokenFile)) throw new Error('Slack approver tokenFile must be an absolute path.');
  const pollSeconds = value.pollSeconds ?? 5;
  const maxMessagesPerHour = value.maxMessagesPerHour ?? 20;
  if (!Number.isInteger(pollSeconds) || pollSeconds < 2 || pollSeconds > 60) throw new Error('pollSeconds must be 2 to 60.');
  if (!Number.isInteger(maxMessagesPerHour) || maxMessagesPerHour < 1 || maxMessagesPerHour > 100) throw new Error('maxMessagesPerHour must be 1 to 100.');
  const language = value.language ?? 'en';
  if (!TEXT[language]) throw new Error('language must be "en" or "ko".');
  return { ...value, pollSeconds, maxMessagesPerHour, language };
}

export function readToken(file) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || (stat.mode & 0o077) !== 0 || (typeof process.getuid === 'function' && stat.uid !== process.getuid())) {
      throw new Error('The Slack token file must be a regular file owned by you with mode 600.');
    }
    const token = fs.readFileSync(fd, 'utf8').trim();
    if (!token.startsWith('xoxb-')) throw new Error('The Slack token must be a bot token (xoxb-).');
    return token;
  } finally {
    fs.closeSync(fd);
  }
}

export function slackClient(token, fetchImpl = globalThis.fetch) {
  return {
    async call(method, params = {}) {
      const body = new URLSearchParams(Object.entries(params).map(([key, value]) => [key, String(value)]));
      const response = await fetchImpl(`https://slack.com/api/${method}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
        signal: AbortSignal.timeout(15_000)
      });
      const data = await response.json().catch(() => ({}));
      if (data.ok !== true) throw new Error(`Slack ${method} failed: ${String(data.error || response.status).slice(0, 60)}`);
      return data;
    }
  };
}

const escapeSlack = (text) => String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function readState(file) {
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  } catch (error) {
    if (error.code === 'ENOENT') return { messages: {}, sent: [] };
    throw error;
  }
  try {
    if (!fs.fstatSync(fd).isFile()) throw new Error('Slack approver state must be a regular file.');
    const data = JSON.parse(fs.readFileSync(fd, 'utf8'));
    return {
      messages: data.messages && typeof data.messages === 'object' ? data.messages : {},
      sent: Array.isArray(data.sent) ? data.sent : [],
      warned: Number(data.warned) || 0
    };
  } finally {
    fs.closeSync(fd);
  }
}

function writeState(file, state) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(state)}\n`, { mode: 0o600, flag: 'wx' });
  fs.renameSync(temporary, file);
}

export function terminalOnly(entry) {
  return (entry.summary || []).some((item) => (item.signals || []).some((signal) => TERMINAL_ONLY.has(signal)));
}

function scopeKind(entry) {
  const keys = Array.isArray(entry.itemKeys) ? entry.itemKeys : [];
  if (!keys.length) return 'exact';
  return keys.some((key) => !key.startsWith('signal:')) ? 'packages' : 'signal';
}

export function messageText(entry, language = 'en') {
  const t = TEXT[language];
  const lines = [`*${t.head(entry.code)}*`];
  for (const item of entry.summary || []) {
    const kinds = (item.signals || []).map((signal) => t.signals[signal] || signal).join(', ');
    lines.push(`• ${escapeSlack(item.name)} — ${escapeSlack(kinds)}: ${escapeSlack((item.reasons || []).join(' ')).slice(0, 300)}`);
  }
  lines.push(terminalOnly(entry) ? t.terminal : `${t.approve} ${t.scope[scopeKind(entry)]}`);
  return lines.join('\n');
}

export function createSlackApprover({ store, slack, config, stateDir, now = () => Date.now(), log = () => {} }) {
  const file = path.join(stateDir, STATE_FILE);
  const t = TEXT[config.language];
  let channel = null;

  async function finish(code, record, status, text) {
    record.status = status;
    try {
      await slack.call('chat.update', { channel: record.channel, ts: record.ts, text });
    } catch (error) {
      log(`update failed for ${code}: ${error.message}`);
    }
  }

  return {
    async start() {
      const auth = await slack.call('auth.test');
      if (auth.team_id !== config.teamId || auth.user_id !== config.botUserId) throw new Error('Slack workspace or bot does not match the configuration.');
      channel = (await slack.call('conversations.open', { users: config.ownerUserId })).channel?.id;
      if (!channel) throw new Error('Could not open a direct message with the owner.');
    },

    async tick() {
      if (!channel) throw new Error('start() first');
      const state = readState(file);
      const hourAgo = now() - 60 * 60 * 1000;
      state.sent = state.sent.filter((time) => time > hourAgo);
      const pending = new Map(store.listPending().map((entry) => [entry.code, store.findPending(entry.code) || entry]));

      // New stopped actions.
      for (const [code, entry] of pending) {
        if (state.messages[code]) continue;
        if (state.sent.length >= config.maxMessagesPerHour) {
          if (!state.warned || state.warned < hourAgo) {
            await slack.call('chat.postMessage', { channel, text: t.tooMany });
            state.warned = now();
          }
          break;
        }
        const posted = await slack.call('chat.postMessage', { channel, text: messageText(entry, config.language), unfurl_links: false });
        state.sent.push(now());
        state.messages[code] = { channel, ts: posted.ts, status: terminalOnly(entry) ? 'terminal' : 'waiting', digest: entry.digest, postedAt: now() };
        if (!terminalOnly(entry)) {
          for (const name of [APPROVE, REJECT]) {
            await slack.call('reactions.add', { channel, timestamp: posted.ts, name }).catch(() => {});
          }
        }
      }

      // Answers to waiting messages.
      for (const [code, record] of Object.entries(state.messages)) {
        if (record.status !== 'waiting') continue;
        const entry = pending.get(code);
        if (!entry || entry.digest !== record.digest) {
          await finish(code, record, 'closed', t.closed);
          continue;
        }
        const reply = await slack.call('reactions.get', { channel: record.channel, timestamp: record.ts, full: true });
        const reactions = reply.message?.reactions || [];
        const by = (name) => (reactions.find((reaction) => reaction.name === name)?.users || []).includes(config.ownerUserId);
        if (by(REJECT)) {
          await finish(code, record, 'rejected', t.rejected);
        } else if (by(APPROVE)) {
          if (store.approve(code)) {
            log(`approved ${code} from Slack`);
            await finish(code, record, 'approved', t.approved);
          } else {
            await finish(code, record, 'closed', t.closed);
          }
        }
      }

      // Forget finished messages after a day.
      for (const [code, record] of Object.entries(state.messages)) {
        if (record.status !== 'waiting' && now() - record.postedAt > 24 * 60 * 60 * 1000) delete state.messages[code];
      }
      writeState(file, state);
    }
  };
}
