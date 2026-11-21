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
| `persistence-change` | ASK | launch agents and daemons, `launchctl load/bootstrap`, `crontab`, login items, shell startup files such as `~/.zshrc`, git hooks (`.git/hooks/*`, `git config core.hooksPath`) |
| `obfuscated-execution` | BLOCK | decoding hidden content and running it: `base64 -d \| sh`, `xxd -r \| python3`, `gunzip \| sh`, `eval "$(... base64 -d)"` |
| `remote-secret-access` | ASK | over SSH: reading files that usually hold secrets (`.env`, `*.env`, `*.pem`, `*.key`, `id_*`, `credentials`, `*token*`, `*secret*`, `*password*`, `*api_key*`), printing environment variables (`env`, `docker exec ... printenv`), `kubectl get secret`, or copying such files off a server with `scp`/`rsync` |
| `remote-config-change` | ASK | over SSH: changing or overwriting those files, server settings under `/etc`, `~/.ssh/authorized_keys`, shell startup files, or scheduled jobs (`crontab`) |

Some cases deserve a note:
- `secret-access` also covers sending environment dumps (`env`, `printenv`) or `.env` files over the network with `curl`, `nc`, `scp` and similar tools.
- `guard-tamper` also covers `claude mcp add`, `codex mcp add`, and similar commands that register MCP servers.
- Paths written inside one-line code (`python3 -c`, `node -e`) are checked.
- Relative paths after a `cd` within the same command resolve against the new directory.
- Stopping a job (`launchctl unload`, `bootout`, `disable`, `remove`) is not a startup-item change.
- Commands run on another computer (`ssh host 'cmd'`, `ssh host <<EOF`, `scp`/`rsync host:path`) are checked by generic file names, because this computer's paths mean nothing there. Everyday server work (`uptime`, `docker ps`, logs, `systemctl restart`, reading `/etc/nginx/nginx.conf`, `ls`/`chmod` on a `.env`) stays quiet. `ssh` to this same computer (`localhost`, its own host name) is checked like a local command.

The following stay allowed:
- reading settings (`cat`, `jq`, `grep`, `Read`, and one-line Python or Node code that only reads, such as `python3 -c "print(json.load(open(p)))"`; code that may write, run another program, or hide what it calls is still treated as a change)
- listing waiting approvals (`trustdex allow-once --list`)
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

The approval is bound to the SHA-256 digest of that exact tool call: for Bash, the directory the command effectively starts in plus the command after any leading `cd` (Claude Code may drop a leading `cd` to the current directory), plus a SHA-256 of every local script file the command runs that the hook reads (`bash x.sh`, `python3 x.py`, `source x`, `./x.sh`, of any size), so changing the script after approval makes it a different action; for file tools, the same file and content. It expires after an hour and is used up by the first matching call. Codes also expire after an hour.

Package findings work differently, to keep everyday work smooth.
- Covered findings: a release that is too recent, install scripts, a new package, a deprecated or yanked version, a first-time publisher, or a look-alike name.
- Safer alternative first: a too-recent release names the newest older version that is outside the waiting window (for example `Use wrangler@4.160.1 instead`). The agent is told to use such an alternative, or `--ignore-scripts`, without asking you.
- Approval by version: if you approve, the approval covers those exact package versions and findings for 24 hours, in any command. Deploys and migrations that call the same tool do not need a new code each time.
- Limits: a package approval never covers BLOCK findings or anything outside those packages.
- Startup items: approving a `persistence-change` finding covers startup-item and scheduled-job changes for 1 hour in any command, so one maintenance session needs one approval. It never covers other findings.
- Servers: approving a `remote-secret-access` or `remote-config-change` finding covers that kind of work on that host for 1 hour. Another host, the other kind, and local findings still stop.
- Installed tools pass: tools already installed in the project's `node_modules/.bin` are used as installed, also after a `cd` inside the command and from parent folders. They do not trigger a registry check. `trustdex allow-once --list` shows what is waiting.

Away from the computer, the same person can approve from Slack instead: see [Approving from Slack](SLACK_APPROVER.md). Changes to agent settings or TrustDex itself stay terminal-only.

The agent cannot approve its own action in three ways:

- `allow-once` refuses to run without an interactive terminal, and agent shells are not interactive terminals.
- The hook blocks agent commands that mention `trustdex allow-once`.
- The hook blocks writes to the approval state directory (`~/.config/trustdex/state`, mode 700).

## Ask mode

`--on-risk ask` keeps Claude Code's own dialog for ASK-level findings (for example a package with install scripts, a startup item, or reading a secret file on a server) for people who prefer it, for example when working from a phone. BLOCK-level findings are still denied and never become a dialog: changing agent settings or TrustDex itself, reading local credentials, starting an agent without its guardrails, and running decoded content.

The trade-off: a dialog is one tap, and dialogs that appear often get tapped out of habit. Typing a code in a terminal is a deliberate second step. Use ask mode if the friction would otherwise make you switch the hook off, and keep the default where you can.

## Setup

On macOS and Linux, `npx trustdex@<version> init` does the steps below for you: it copies that version to `~/.local/share/trustdex/<version>`, adds the wrapper, creates a policy if none exists, and registers the fail-closed hook after backing up your settings. It shows the plan and asks for `yes` first. To set it up by hand:

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
            "command": "node /opt/trustdex/bin/trustdex.mjs claude-hook --install-policy ~/.config/trustdex/install-policy.json --protect ~/.local/bin/trustdex || { echo 'TrustDex could not run, so this action was stopped.' >&2; exit 2; }",
            "timeout": 60
          }
        ]
      }
    ]
  }
}
```

Keep the `|| { ...; exit 2; }` part. Claude Code treats a hook that exits with any code other than 0 or 2 as a non-blocking error and runs the tool anyway. Without it, a missing `node`, a moved TrustDex copy, or a crash at start-up would let every action through silently. With it, those cases stop the action (exit 2) and tell the agent why. TrustDex itself always exits 0 and reports its decision as JSON, including when it cannot read its input or policy.

The running TrustDex copy, the policy file, and the state directory are protected automatically. `--protect` adds more files, such as the wrapper. The install policy also accepts:

- `secretPaths`: absolute or `~/` paths of extra credential files to protect.
- `allowStartupItems`: launchd labels of your own jobs that agents may start without approval, such as `"com.example.backup"` or `"com.example.*"`. It covers `launchctl enable gui/<uid>/<label>` and `launchctl load|bootstrap` of plists in `~/Library/LaunchAgents` whose file name is an allowed label. Writing or copying a plist into `~/Library/LaunchAgents` still needs approval, so an agent cannot plant a new job under an allowed name. A wildcard needs at least two segments before it (`com.*` and `*` are rejected).

```json
{
  "version": 1,
  "allowStartupItems": ["com.example.*"]
}
```

If the hook cannot read its input or configuration, it denies file tools and Bash commands that could be risky rather than failing open. Unrelated tools keep working.

## Settings that switch hooks off

Any settings file, including a project's `.claude/settings.json` that arrives with a cloned repository, can contain `disableAllHooks`. When hooks are disabled, this hook does not run at all, so it cannot protect that session.

The hook stops agents from writing such a setting. A repository can still ship one, though. Before opening an untrusted repository, check it:

```bash
trustdex inspect-claude-settings path/to/repo/.claude/settings.json
```

The check reports `claude-hooks-disabled` as BLOCK. Organisations can also deliver the hook through Claude Code's managed settings, which project files cannot override.

## Limits

These are static checks of what a tool call says it will do:

- They do not follow code that builds paths or commands at run time, for example a Python script that decodes a hidden path. They do not stop a program that the user has already allowed from misbehaving later.
- An agent with unrestricted shell access can, in principle, find a way around any check that runs in the same account.
- Programs that run other files the hook does not recognise as scripts (an executable without a script extension, `make`, `npm run`) are not read, and approvals are not bound to those files.
- Server checks see only the command text sent over SSH. A script already on the server, a secret file with an unusual name, or a program that reads secrets by itself are not seen. Give agents server accounts with the least access they need.

Use the hook as one layer next to:
- an OS sandbox for the agent
- tokens with the least scope you can give
- `ignore-scripts` and lockfiles
- not running agents in bypass mode on machines that hold production credentials
