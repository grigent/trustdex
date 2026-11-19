# 슬랙으로 허용하기

<p align="right">
  <a href="./SLACK_APPROVER.md">English</a> | <strong>한국어</strong>
</p>

[Claude Code 훅](CLAUDE_HOOK.ko.md)이 행동을 멈추면 보통은 사람이 자기 터미널에서 `trustdex allow-once <코드>`로 허용합니다. `trustdex slack-approver`를 쓰면, 컴퓨터 앞에 없을 때도 같은 사람이 슬랙에서 허용할 수 있습니다.

## 동작 방식

1. 훅이 평소처럼 행동을 멈추고 코드와 함께 기록합니다.
2. 같은 컴퓨터에서 도는 `slack-approver`가 주인에게 DM을 보냅니다. 코드, 무엇을 왜 멈췄는지, 허용하면 얼마 동안 유효한지가 담깁니다. 누르기 쉽게 ✅와 ❌ 반응도 달아 둡니다.
3. 주인이 ✅를 누르면 `allow-once`와 똑같은 한 번짜리 승인을 기록하고, 메시지를 고쳐 허용됐다고 알립니다. ❌는 거절입니다. 그 뒤 에이전트가 똑같은 행동을 다시 실행합니다.

몇 초마다 슬랙 반응을 확인합니다. 스스로 무언가를 실행하지는 않습니다.

## 하지 않는 일

- 다음은 허용하지 않습니다. 메시지에 터미널에서만 허용할 수 있다고 적어 줍니다.
  - 에이전트 설정, MCP 설정, TrustDex 자체 변경(`guard-tamper`)
  - 보호 파일 근처에서 해석하지 못한 명령
- 설정한 주인이 아닌 사람의 반응은 받지 않습니다. 슬랙 사용자 ID로 확인하며, 자기 봇의 반응도 받지 않습니다.
- 한 시간에 `maxMessagesPerHour`(기본 20)개보다 많이 보내지 않습니다. 넘으면 경고를 한 번만 보냅니다.

어떤 메시지가 어떤 코드인지 기록한 파일은 승인 상태 폴더에 있습니다. 이 폴더는 훅이 에이전트의 쓰기를 막으므로, 에이전트가 주인이 예전에 허용한 메시지를 가리키게 바꿀 수 없습니다.

## 설정

1. 봇 토큰(`xoxb-…`)이 있는 슬랙 앱을 만들고 `chat:write`, `im:write`, `reactions:read`, `reactions:write` 권한을 줘서 워크스페이스에 설치합니다.
2. 토큰을 나만 읽을 수 있는 파일(`chmod 600`)에 저장합니다. 그 경로를 설치 정책의 `secretPaths`에 넣어 에이전트가 읽지 못하게 합니다.
3. `slack-approver.json`을 **설치 정책 파일과 같은 폴더**(예: `~/.config/trustdex/slack-approver.json`)에 씁니다. 훅이 이 파일을 자동으로 보호합니다.

```json
{
  "tokenFile": "/Users/you/.config/trustdex/slack-bot-token",
  "teamId": "T0123456789",
  "botUserId": "U0BOT000001",
  "ownerUserId": "U0YOU000001",
  "language": "ko"
}
```

4. 런치 에이전트 등으로 실행합니다.

```bash
node /opt/trustdex/bin/trustdex.mjs slack-approver --config ~/.config/trustdex/slack-approver.json
```

`--once`를 주면 한 번만 확인하고 끝나므로 시험할 때 편합니다.

## 한계

- 슬랙에서 나로서 반응할 수 있는 누구나 허용할 수 있습니다. 슬랙에 2단계 인증을 걸고 휴대폰을 잠가 두세요. 에이전트에게 나로서 동작하는 슬랙 연결(사용자 토큰, 내 계정으로 로그인한 커넥터)을 주지 마세요. 훅은 내가 누른 것과 그런 연결이 누른 것을 구별하지 못합니다.
- 메시지에는 `allow-once`와 같은 요약(항목 이름, 위험 종류, 이유)만 담기고 명령 원문은 담기지 않습니다. 그것만으로 판단이 안 되면 거절하고 컴퓨터에서 확인하세요.
- 누르기는 코드 입력보다 쉽습니다. 내가 직접 시킨 일만 허용하세요.
