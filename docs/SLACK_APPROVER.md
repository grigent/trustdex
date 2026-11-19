# Approving from Slack

<p align="right">
  <strong>English</strong> | <a href="./SLACK_APPROVER.ko.md">한국어</a>
</p>

When the [Claude Code hook](CLAUDE_HOOK.md) stops an action, a person normally allows it with `trustdex allow-once <code>` in their own terminal. `trustdex slack-approver` lets the same person do that from Slack when they are away from the computer.

## How it works

1. The hook stops an action and records it with a code, as usual.
2. `slack-approver`, running on the same computer, sends the owner a direct message: the code, what was stopped and why, and how long an approval would last. It adds ✅ and ❌ reactions to tap.
3. When the owner reacts with ✅, it records the same one-time approval `allow-once` would, and edits the message to say so. ❌ refuses. The agent then runs the identical action again.

It checks the Slack reactions every few seconds. It never runs anything itself.

## What it will not do

- Approve changes to agent settings, MCP configuration or TrustDex itself (`guard-tamper`), or unparsed commands near protected files. The message says these can only be allowed in the terminal.
- Accept a reaction from anyone but the configured owner, by Slack user id. That includes its own bot.
- Send more than `maxMessagesPerHour` messages an hour (20 by default). Beyond that, it sends a single warning.

Its record of which message belongs to which code lives in the approval state directory, which the hook protects from agent writes. An agent therefore cannot point it at an older message the owner already approved.

## Setup

1. Create a Slack app with a bot token (`xoxb-…`) and the scopes `chat:write`, `im:write`, `reactions:read` and `reactions:write`. Install it to your workspace.
2. Save the token to a file only you can read (`chmod 600`). Add that path to `secretPaths` in the install policy, so agents cannot read it.
3. Write `slack-approver.json` **next to your install policy** (for example `~/.config/trustdex/slack-approver.json`). The hook protects that file automatically:

```json
{
  "tokenFile": "/Users/you/.config/trustdex/slack-bot-token",
  "teamId": "T0123456789",
  "botUserId": "U0BOT000001",
  "ownerUserId": "U0YOU000001",
  "language": "en"
}
```

4. Run it, for example as a launch agent:

```bash
node /opt/trustdex/bin/trustdex.mjs slack-approver --config ~/.config/trustdex/slack-approver.json
```

`--once` checks one time and exits, which is useful for testing.

## Limits

- Anyone who can react as you in Slack can approve. Keep Slack behind two-factor sign-in, lock your phone, and do not give agents a Slack connection that acts as you (a user token or a connector signed in as you). The hook cannot tell your tap from such a connection.
- The message shows the same summary as `allow-once`: item names, the kind of risk and the reason, never the command text. If that is not enough to decide, refuse and check on the computer.
- A tap is easier than typing a code. Approve only what you asked for yourself.
