# Claude Code hook

<p align="right">
  <strong>English</strong> | <a href="./CLAUDE_HOOK.ko.md">한국어</a>
</p>

`trustdex claude-hook` checks each Claude Code tool call before it runs. It never approves anything itself. When it finds nothing risky it stays silent and Claude Code's normal permission flow continues.

## Why a dialog is not enough

A permission dialog is one click away from "allow". People click it without reading, especially people who do not read code. Many also turn prompts off entirely (`bypassPermissions`) because the dialogs are tiring.

Recent incidents show what an unread approval can cost:
- npm releases hijacked through a phished maintainer (`chalk`/`debug`, September 2025)
- self-spreading install-script worms that steal tokens (Shai-Hulud, 2025)
- malware that ran local AI coding CLIs with their safety flags off to search the disk for secrets (Nx "s1ngularity", August 2025)
- packages registered under names that models invent ("slopsquatting")

So by default the hook does not turn a risky action into a dialog. It denies the action and explains why in plain words. A person can then allow that exact action once, deliberately, in their own terminal.

## What it stops

| Signal | Level | Examples |
|---|---|---|
| `guard-tamper` | BLOCK | changing `~/.claude/settings.json`, project `.claude/settings*.json`, `.mcp.json`, `~/.claude.json`, Codex/Gemini/Cursor agent config, the TrustDex installation, its policy or approval state; agent commands that mention `trustdex allow-once` |
| `secret-access` | BLOCK | reading or copying SSH private keys, cloud/registry/GitHub tokens (`~/.aws`, `~/.npmrc`, `~/.config/gh/hosts.yml`, `~/.docker/config.json`, `~/.kube/config`, ...), agent login files, keychains (`security find-generic-password -w`, `dump-keychain`), browser cookies and saved logins, `gh auth token`, plus any paths in `secretPaths` |
| `agent-permission-bypass` | BLOCK | `claude --dangerously-skip-permissions`, `--permission-mode bypassPermissions`, `codex --dangerously-bypass-approvals-and-sandbox` / `--yolo` / `-s danger-full-access` / `approval_policy=never`, `gemini --yolo` / `-y`, `cursor-agent --force`, `aider --yes-always`, `q chat --trust-all-tools`, `amp --dangerously-allow-all` |
| package install signals | BLOCK / ASK | see [Pre-install package checks](INSTALL_CHECK.md) |
| `persistence-change` | ASK | launch agents and daemons, `launchctl load/bootstrap`, `crontab`, login items, shell startup files such as `~/.zshrc` |

The following stay allowed:
- reading settings (`cat`, `jq`, `grep`, `Read`)
- checking that a key exists (`ls ~/.ssh`, `test -f`)
- SSH tools that use a key without revealing it (`ssh -i`, `scp -i`)
- ordinary project edits

The hook covers `Bash`, `Read`, `Grep`, `Glob`, `Write`, `Edit`, `MultiEdit`, and `NotebookEdit`.

For Bash commands, the hook also looks inside some content that is not written on the command line itself:
- Nested `sh -c '...'`, `eval`, and `$(...)` are followed.
- Here-documents are treated as data when they go to programs such as `git` or `cat`, and checked when a shell or interpreter runs them.
- Local script files run directly (`bash x.sh`, `python3 x.py`, `source x`, `./x.sh`) are read, up to 1 MiB and two levels of nesting, and checked the same way.

## Allowing a stopped action once

When the hook stops something, the reason it gives to the agent ends like this:

```text
If the user understands it and still wants it, they type this in their own terminal app (not in this chat): trustdex allow-once K7M2QX9P
```

Running `trustdex allow-once K7M2QX9P` works like this:

1. It shows what was stopped and why.
2. It asks the person to type `yes`.
3. It records a one-time approval.

The approval is bound to the SHA-256 digest of that exact tool call (the same command text, or the same file and content). It expires after 30 minutes and is used up by the first matching call. Codes expire after an hour. `trustdex allow-once --list` shows what is waiting.

The agent cannot approve its own action in three ways:

- `allow-once` refuses to run without an interactive terminal, and agent shells are not interactive terminals.
- The hook blocks agent commands that mention `trustdex allow-once`.
- The hook blocks writes to the approval state directory (`~/.config/trustdex/state`, mode 700).

## Ask mode

`--on-risk ask` keeps Claude Code's own dialog for ASK-level findings (for example a package with install scripts) for people who prefer it. BLOCK-level findings are still denied.

## Setup

1. Put a reviewed copy of TrustDex somewhere stable. Do not use `npx trustdex`, which would download the gate itself at run time.
2. Optionally add a small `trustdex` wrapper on your `PATH` so that `trustdex allow-once` is easy to type.
3. Register the hook for every tool it guards:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Read|Grep|Glob|Write|Edit|MultiEdit|NotebookEdit",
        "hooks": [
          {
            "type": "command",
            "command": "node /opt/trustdex/bin/trustdex.mjs claude-hook --install-policy ~/.config/trustdex/install-policy.json --protect ~/.local/bin/trustdex",
            "timeout": 60
          }
        ]
      }
    ]
  }
}
```

The running TrustDex copy, the policy file, and the state directory are protected automatically. `--protect` adds more files, such as the wrapper. The install policy accepts `secretPaths`: absolute or `~/` paths of extra credential files to protect.

If the hook cannot read its input or configuration, it denies file tools and Bash commands that could be risky rather than failing open. Unrelated tools keep working.

## Limits

These are static checks of what a tool call says it will do:

- They do not follow code that builds paths or commands at run time, for example a Python script that decodes a hidden path. They do not stop a program that the user has already allowed from misbehaving later.
- An agent with unrestricted shell access can, in principle, find a way around any check that runs in the same account.

Use the hook as one layer next to:
- an OS sandbox for the agent
- tokens with the least scope you can give
- `ignore-scripts` and lockfiles
- not running agents in bypass mode on machines that hold production credentials
