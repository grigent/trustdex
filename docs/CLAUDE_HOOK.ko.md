# Claude Code 훅

<p align="right">
  <a href="./CLAUDE_HOOK.md">English</a> | <strong>한국어</strong>
</p>

`trustdex claude-hook`은 Claude Code의 도구 호출을 실행 전에 하나씩 검사합니다. 스스로 무언가를 승인하는 일은 없습니다. 위험한 것이 없으면 아무 말도 하지 않고, Claude Code의 원래 권한 흐름이 그대로 이어집니다.

## 확인 창만으로는 부족한 이유

권한 확인 창은 클릭 한 번이면 "허용"입니다. 사람들은 읽지 않고 누르곤 하고, 코드를 모르는 사람은 더 그렇습니다. 확인 창이 귀찮아서 아예 끄는(`bypassPermissions`) 사람도 많습니다.

최근 사건들은 읽지 않은 허용 한 번이 얼마나 큰 피해가 되는지 보여 줍니다.
- 관리자 계정이 피싱으로 털려 npm 릴리스가 탈취된 사건(`chalk`/`debug`, 2025년 9월)
- 설치 스크립트로 토큰을 훔치며 스스로 퍼지는 웜(Shai-Hulud, 2025년)
- 컴퓨터에 깔린 AI 코딩 도구를 안전장치를 끈 채 실행시켜 디스크에서 비밀값을 찾게 한 악성코드(Nx "s1ngularity", 2025년 8월)
- 모델이 지어내는 패키지 이름으로 미리 올려 둔 패키지("slopsquatting")

그래서 이 훅은 기본값에서 위험한 행동을 확인 창으로 바꾸지 않습니다. 대신 거부하고 이유를 쉬운 말로 알려 줍니다. 그 뒤 사람이 자기 터미널에서, 일부러, 그 행동 하나만 한 번 허용할 수 있습니다.

## 막는 것

| 신호 | 수준 | 예 |
|---|---|---|
| `guard-tamper` | BLOCK | `~/.claude/settings.json`, 프로젝트의 `.claude/settings*.json`, `.mcp.json`, `~/.claude.json`, Codex·Gemini·Cursor 에이전트 설정, TrustDex 설치본·정책·승인 상태 변경. `trustdex allow-once`를 언급하는 에이전트 명령 |
| `secret-access` | BLOCK | SSH 개인 키, 클라우드·저장소·깃허브 토큰(`~/.aws`, `~/.npmrc`, `~/.config/gh/hosts.yml`, `~/.docker/config.json`, `~/.kube/config` 등), 에이전트 로그인 파일, 키체인(`security find-generic-password -w`, `dump-keychain`), 브라우저 쿠키·저장된 로그인(윈도우 `AppData` 아래 Chrome, Edge, Brave, Firefox 프로필 포함), 윈도우 자격 증명 관리자·Vault 파일, `gh auth token` 읽기·복사. `secretPaths`에 넣은 경로도 포함 |
| `agent-permission-bypass` | BLOCK | `claude --dangerously-skip-permissions`, `--permission-mode bypassPermissions`, `codex --dangerously-bypass-approvals-and-sandbox` / `--yolo` / `-s danger-full-access` / `approval_policy=never`, `gemini --yolo` / `-y`, `cursor-agent --force`, `aider --yes-always`, `q chat --trust-all-tools`, `amp --dangerously-allow-all` |
| 패키지 설치 신호 | BLOCK / ASK | [설치 전 패키지 검사](INSTALL_CHECK.ko.md) 참고 |
| `persistence-change` | ASK | 런치 에이전트·데몬, `launchctl load/bootstrap`, `crontab`, 로그인 항목, `~/.zshrc` 같은 셸 시작 파일, git 훅(`.git/hooks/*`, `git config core.hooksPath`). 윈도우에서는 `Run`/`RunOnce` 레지스트리 키, 예약 작업(`schtasks /create`, `Register-ScheduledTask`), 새 서비스, 시작프로그램 폴더, PowerShell 프로필(`$PROFILE`) |
| `obfuscated-execution` | BLOCK | 숨긴 내용을 풀어서 실행: `base64 -d \| sh`, `xxd -r \| python3`, `gunzip \| sh`, `eval "$(... base64 -d)"` |
| `remote-secret-access` | ASK | SSH로 서버에서: 보통 비밀값이 든 파일 읽기(`.env`, `*.env`, `*.pem`, `*.key`, `id_*`, `credentials`, `*token*`, `*secret*`, `*password*`, `*api_key*`), 환경변수 출력(`env`, `docker exec ... printenv`), `kubectl get secret`, `scp`/`rsync`로 그런 파일을 서버에서 가져오기 |
| `remote-config-change` | ASK | SSH로 서버에서: 그런 파일 바꾸기·덮어쓰기, `/etc` 아래 서버 설정, `~/.ssh/authorized_keys`, 셸 시작 파일, 예약 작업(`crontab`) 바꾸기 |

몇 가지는 따로 적어 둡니다.
- `secret-access`는 환경변수 목록(`env`, `printenv`)이나 `.env` 파일을 `curl`, `nc`, `scp` 같은 도구로 네트워크에 보내는 것도 포함합니다.
- `guard-tamper`는 MCP 서버를 등록하는 `claude mcp add`, `codex mcp add` 같은 명령도 포함합니다.
- 한 줄 코드(`python3 -c`, `node -e`) 안에 적힌 경로도 검사합니다.
- 같은 명령 안에서 `cd`로 옮긴 뒤의 상대 경로는 새 폴더 기준으로 봅니다.
- 작업을 멈추는 것(`launchctl unload`, `bootout`, `disable`, `remove`)은 시작 항목 변경으로 보지 않습니다.
- 다른 컴퓨터에서 실행되는 명령(`ssh host 'cmd'`, `ssh host <<EOF`, `scp`/`rsync host:경로`)은 일반적인 파일 이름으로 검사합니다. 이 컴퓨터의 경로는 그곳에서 뜻이 다르기 때문입니다. 평소 서버 작업(`uptime`, `docker ps`, 로그 보기, `systemctl restart`, `/etc/nginx/nginx.conf` 읽기, `.env`에 `ls`·`chmod`)은 조용히 지나갑니다. 같은 컴퓨터로 가는 `ssh`(`localhost`, 자기 호스트 이름)는 로컬 명령처럼 검사합니다.

다음은 계속 허용됩니다.
- 설정 읽기(`cat`, `jq`, `grep`, `Read`, 그리고 `python3 -c "print(json.load(open(p)))"`처럼 읽기만 하는 파이썬·노드 한 줄 코드. 쓰거나, 다른 프로그램을 실행하거나, 무엇을 부르는지 숨길 수 있는 코드는 여전히 변경으로 봅니다)
- 기다리는 승인 목록 보기(`trustdex allow-once --list`)
- 키가 있는지 확인하기(`ls ~/.ssh`, `test -f`)
- 키를 드러내지 않고 쓰는 SSH 도구(`ssh -i`, `scp -i`)
- 평범한 프로젝트 수정

검사하는 도구는 `Bash`, `PowerShell`, `Read`, `Grep`, `Glob`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit`입니다.

윈도우의 Claude Code는 Bash 대신 `PowerShell` 도구로 명령을 실행하기도 합니다. 훅은 이 명령도 읽습니다.
- cmdlet과 그 별칭(`Get-Content`/`gc`/`cat`, `Copy-Item`, `Set-Content`, `Out-File`, 리디렉션, `[IO.File]::ReadAllText` 같은 .NET 호출), 그리고 `$HOME`, `$env:USERPROFILE`, `$env:APPDATA`, `$env:LOCALAPPDATA`, `Join-Path`, 같은 명령 안에서 앞서 넣은 변수로 만든 경로를 Bash와 같은 방식으로 검사합니다. 경로가 있는지만 보는 것(`Test-Path`, `Get-Item`)은 조용히 지나갑니다.
- 코드를 내려받아 바로 실행하는 것(`iwr ... | iex`, `Invoke-Expression (... DownloadString(...))`, `[scriptblock]::Create`)은 `pipe-to-shell`, 숨긴 내용을 풀어서 실행하는 것(`-EncodedCommand`, `iex`와 함께 쓴 `FromBase64String`)은 `obfuscated-execution`입니다.
- 명령이 실행하는 프로그램(`git`, `npm`, `node -e`, `cmd /c`, `claude ...`)은 패키지 설치를 포함해 Bash와 같은 방식으로 검사합니다.
- 해석할 수 없는 명령은 보호하는 경로, 패키지 도구, 시작 항목이나 내려받기 관련 단어가 들어 있으면 거부합니다.

Git Bash식 윈도우 경로(`/c/Users/...`, `/cygdrive/c/...`)는 `C:\Users\...`와 같은 경로로 봅니다.

Bash 명령은 명령줄에 직접 적히지 않은 내용도 일부 들여다봅니다.
- 중첩된 `sh -c '...'`, `eval`, `$(...)`를 따라갑니다.
- 히어독은 `git`·`cat` 같은 프로그램으로 가면 데이터로 보고, 셸이나 해석기가 실행하면 검사합니다.
- 바로 실행하는 로컬 스크립트 파일(`bash x.sh`, `python3 x.py`, `source x`, `./x.sh`)은 1MiB, 두 단계 중첩까지 읽어서 같은 방식으로 검사합니다.

## 멈춘 행동을 한 번만 허용하기

훅이 무언가를 멈추면, 에이전트에게 주는 이유는 이렇게 끝납니다.

```text
If the user understands it and still wants it, they type this in their own terminal app (not in this chat): trustdex allow-once K7M2QX9P
```

`trustdex allow-once K7M2QX9P`는 다음 순서로 동작합니다.

1. 무엇을 왜 멈췄는지 보여 줍니다.
2. `yes`를 입력하라고 합니다.
3. 한 번짜리 승인을 기록합니다.

승인은 그 도구 호출의 SHA-256 다이제스트에 묶입니다. Bash는 명령이 실제로 시작되는 폴더와 앞쪽 `cd`를 뺀 나머지 명령에 묶이고(Claude Code가 현재 폴더로 가는 앞쪽 `cd`를 지우기도 하므로), 그 명령이 실행하고 훅이 읽는 로컬 스크립트 파일(`bash x.sh`, `python3 x.py`, `source x`, `./x.sh`, 크기와 상관없이)의 SHA-256에도 묶입니다. 그래서 승인 뒤 스크립트를 바꾸면 다른 행동이 됩니다. 파일 도구는 같은 파일과 내용에 묶입니다. 1시간 뒤 만료되고, 처음 일치하는 호출에 한 번 쓰이면 사라집니다. 코드도 1시간 뒤 만료됩니다.

패키지 경고는 평소 작업이 막히지 않도록 다르게 다룹니다.
- 대상: 너무 최근 릴리스, 설치 스크립트, 새 패키지, 사용 중단·철회 버전, 처음 보는 게시자, 유명 이름 흉내
- 더 안전한 방법 먼저: 너무 최근 릴리스면 대기 기간이 지난 가장 새로운 이전 버전을 알려 줍니다(예: `Use wrangler@4.160.1 instead`). 에이전트에게는 사용자에게 묻지 말고 그런 대안이나 `--ignore-scripts`를 쓰라고 안내합니다.
- 버전 단위 승인: 사용자가 승인하면 그 정확한 패키지 버전과 경고에 대해 어떤 명령이든 24시간 동안 통과합니다. 같은 도구를 부르는 배포나 마이그레이션마다 코드를 새로 받을 필요가 없습니다.
- 한계: 패키지 승인은 BLOCK 경고나 그 패키지 밖의 다른 경고는 덮지 않습니다.
- 시작 항목: `persistence-change` 경고를 승인하면 시작 항목·예약 작업 변경을 어떤 명령이든 1시간 동안 허용합니다. 한 번의 정비 작업에 승인은 한 번이면 됩니다. 다른 경고는 덮지 않습니다.
- 서버: `remote-secret-access`나 `remote-config-change` 경고를 승인하면 그 서버에서 그 종류의 작업을 1시간 동안 허용합니다. 다른 서버, 다른 종류, 이 컴퓨터의 경고는 그대로 멈춥니다.
- 설치된 도구 통과: 프로젝트의 `node_modules/.bin`에 이미 깔린 도구는 설치된 그대로 씁니다. 명령 안에서 `cd`로 옮긴 뒤나 상위 폴더에 있어도 마찬가지이며, 저장소 조회를 하지 않습니다. `trustdex allow-once --list`로 기다리는 항목을 볼 수 있습니다.

컴퓨터 앞에 없을 때는 같은 사람이 슬랙에서 허용할 수도 있습니다. [슬랙으로 허용하기](SLACK_APPROVER.ko.md)를 보세요. 에이전트 설정이나 TrustDex 자체 변경은 여전히 터미널에서만 허용됩니다.

에이전트는 세 가지 이유로 자기 행동을 스스로 승인할 수 없습니다.

- `allow-once`는 대화형 터미널이 아니면 실행을 거부합니다. 에이전트의 셸은 대화형 터미널이 아닙니다.
- 훅이 `trustdex allow-once`를 언급하는 에이전트 명령을 막습니다.
- 훅이 승인 상태 폴더(`~/.config/trustdex/state`, 권한 700)에 쓰는 것을 막습니다.

## 확인 창 모드

확인 창을 더 좋아한다면, 예를 들어 휴대폰으로 원격 작업을 한다면 `--on-risk ask`를 쓰세요. ASK 수준(예: 설치 스크립트가 있는 패키지, 시작 항목, 서버의 비밀값 파일 읽기)은 Claude Code의 확인 창으로 묻습니다. BLOCK 수준은 그래도 거부하고 확인 창으로 바꾸지 않습니다. 에이전트 설정이나 TrustDex 자체 바꾸기, 이 컴퓨터의 자격 증명 읽기, 안전장치를 끈 에이전트 실행, 숨긴 내용을 풀어서 실행하기가 여기에 해당합니다.

대가도 있습니다. 확인 창은 한 번 누르면 끝이고, 자주 뜨면 습관처럼 누르게 됩니다. 터미널에 코드를 치는 것은 일부러 하는 두 번째 단계입니다. 번거로워서 훅을 아예 끌 것 같을 때 확인 창 모드를 쓰고, 가능하면 기본값을 유지하세요.

## 설정

macOS, Linux, 윈도우에서는 `npx trustdex@<버전> init`이 아래 단계를 대신 해 줍니다. 그 버전을 `~/.local/share/trustdex/<버전>`에 복사하고, 실행 파일을 만들고, 정책이 없으면 만들고, 설정을 백업한 뒤 고장 나면 멈추는 훅을 등록합니다. 먼저 계획을 보여 주고 `yes`를 받습니다. 직접 설정하려면 다음과 같이 합니다.

1. 검토한 TrustDex 사본을 고정된 곳에 둡니다. `npx trustdex`는 검사 도구 자체를 실행할 때마다 내려받으므로 쓰지 마세요.
2. `trustdex allow-once`를 쉽게 칠 수 있도록, 원하면 `PATH`에 작은 `trustdex` 실행 파일을 둡니다.
3. 검사할 모든 도구에 훅을 등록합니다.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell|Read|Grep|Glob|Write|Edit|MultiEdit|NotebookEdit",
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

뒤의 `|| { ...; exit 2; }`는 지우지 마세요. Claude Code는 0이나 2가 아닌 코드로 끝난 훅을 막지 않는 오류로 보고 도구를 그대로 실행합니다. 이 부분이 없으면 `node`가 없거나, TrustDex 사본이 옮겨졌거나, 시작하다 죽었을 때 모든 행동이 조용히 통과합니다. 이 부분이 있으면 그런 경우 행동을 멈추고(코드 2) 에이전트에게 이유를 알립니다. TrustDex 자체는 입력이나 정책을 읽지 못할 때도 항상 0으로 끝나고 판단을 JSON으로 알립니다.

실행 중인 TrustDex 사본, 정책 파일, 상태 폴더는 자동으로 보호됩니다. `--protect`로 실행 파일 같은 다른 파일을 더 보호할 수 있습니다. 설치 정책에는 다음도 넣을 수 있습니다.

- `secretPaths`: 더 보호할 자격 증명 파일의 절대 경로나 `~/` 경로.
- `allowStartupItems`: 에이전트가 승인 없이 켤 수 있는 내 예약 작업의 launchd 라벨(예: `"com.example.backup"`, `"com.example.*"`). `launchctl enable gui/<uid>/<라벨>`과, `~/Library/LaunchAgents` 안에서 파일 이름이 허용된 라벨인 plist의 `launchctl load|bootstrap`이 대상입니다. `~/Library/LaunchAgents`에 plist를 쓰거나 복사하는 것은 여전히 승인이 필요하므로, 에이전트가 허용된 이름으로 새 작업을 심을 수는 없습니다. 와일드카드 앞에는 두 마디 이상이 있어야 합니다(`com.*`, `*`는 거부).

```json
{
  "version": 1,
  "allowStartupItems": ["com.example.*"]
}
```

훅이 입력이나 설정을 읽지 못하면, 위험할 수 있는 파일 도구와 Bash·PowerShell 명령을 그냥 통과시키지 않고 거부합니다. 관계없는 도구는 계속 동작합니다.

### 윈도우

윈도우의 Claude Code는 훅 명령을 Git Bash로 실행하므로, `init`에는 [Git for Windows](https://git-scm.com/downloads/win)가 필요합니다. `CLAUDE_CODE_GIT_BASH_PATH`와 흔히 쓰는 Git 설치 폴더에서 `bash.exe`를 찾고, 없으면 아무것도 바꾸지 않고 멈춥니다. 윈도우에서 `init`은 다음을 합니다.

- `%USERPROFILE%\.local\share\trustdex\<버전>`에 설치하고, 실행 파일 두 개 `%USERPROFILE%\.local\bin\trustdex`(Git Bash용)와 `trustdex.cmd`(PowerShell·명령 프롬프트용)를 만들어 둘 다 보호합니다.
- 훅을 슬래시(`/`) 경로와 `"shell": "bash"`로 적어서, 고장 나면 멈추는 `|| { ...; exit 2; }` 부분이 Git Bash에서 돌게 합니다.
- matcher에 `PowerShell`을 넣습니다.

PowerShell에서 `trustdex allow-once`를 치려면 실행 파일 폴더를 사용자 `PATH`에 한 번 넣으세요. `init`이 그 명령을 알려 줍니다. 윈도우 훅을 직접 적으면 다음과 같습니다.

```json
{
  "matcher": "Bash|PowerShell|Read|Grep|Glob|Write|Edit|MultiEdit|NotebookEdit",
  "hooks": [
    {
      "type": "command",
      "shell": "bash",
      "command": "'C:/Program Files/nodejs/node.exe' 'C:/Users/you/.local/share/trustdex/<version>/bin/trustdex.mjs' claude-hook --install-policy 'C:/Users/you/.config/trustdex/install-policy.json' --protect 'C:/Users/you/.local/bin/trustdex' --protect 'C:/Users/you/.local/bin/trustdex.cmd' || { echo 'TrustDex could not run, so this action was stopped.' >&2; exit 2; }",
      "timeout": 60
    }
  ]
}
```

## 훅을 끄는 설정

어떤 설정 파일이든 `disableAllHooks`를 넣을 수 있습니다. 저장소를 받을 때 함께 오는 프로젝트의 `.claude/settings.json`도 마찬가지입니다. 훅이 꺼지면 이 훅은 아예 실행되지 않으므로, 그 세션은 보호받지 못합니다.

이 훅은 에이전트가 그런 설정을 쓰는 것은 막습니다. 하지만 저장소가 처음부터 그 설정을 담고 올 수는 있습니다. 믿을 수 없는 저장소는 열기 전에 확인하세요.

```bash
trustdex inspect-claude-settings 저장소경로/.claude/settings.json
```

이 검사는 `claude-hooks-disabled`를 BLOCK으로 보고합니다. 조직은 프로젝트 파일이 덮어쓸 수 없는 Claude Code 관리자 설정으로 훅을 배포할 수도 있습니다.

## 한계

이 검사는 도구 호출이 무엇을 하겠다고 적혀 있는지를 정적으로 보는 것입니다.

- 실행 중에 경로나 명령을 만들어 내는 코드는 따라가지 못합니다(예: 숨겨진 경로를 복호화하는 파이썬 스크립트). 사용자가 이미 허용한 프로그램이 나중에 엉뚱한 일을 하는 것도 막지 못합니다.
- 셸을 제한 없이 쓰는 에이전트라면, 같은 계정에서 도는 어떤 검사든 원리상 피해 갈 방법을 찾을 수 있습니다.
- 훅이 스크립트로 알아보지 못하는 파일을 실행하는 경우(스크립트 확장자가 없는 실행 파일, `make`, `npm run`)는 읽지 않고, 승인도 그 파일 내용에 묶이지 않습니다.
- PowerShell 검사는 명령 글자를 읽습니다. 명령이 실행하는 스크립트 파일(`& .\x.ps1`, `powershell -File x.ps1`), 실행 중에 계산되는 값, 스스로 비밀값을 읽는 모듈은 따라가지 않습니다.
- 서버 검사는 SSH로 보내는 명령 글자만 봅니다. 서버에 이미 있는 스크립트, 이름이 특이한 비밀값 파일, 스스로 비밀값을 읽는 프로그램은 보지 못합니다. 에이전트가 쓰는 서버 계정은 꼭 필요한 권한만 주세요.

이 훅은 다음과 함께 쓰는 한 겹의 보호로 쓰세요.
- 에이전트용 운영체제 샌드박스
- 가능한 한 좁은 권한의 토큰
- `ignore-scripts`와 잠금 파일
- 운영 자격 증명이 있는 컴퓨터에서는 에이전트를 확인 없는 모드로 돌리지 않기
