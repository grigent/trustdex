# Devin에서 TrustDex 사용하기

<p align="right">
  <a href="./DEVIN.md">English</a> | <strong>한국어</strong>
</p>

TrustDex는 Devin CLI가 MCP 설정을 받기 전에 그 설정을 검사할 수 있습니다. 설정 증거를
로컬에서 평가하며, MCP 서버를 실행하거나 설정을 업로드하지 않습니다. ALLOW 결정은 증거가
정책과 일치했다는 뜻이지, 서버 코드가 안전하다는 증명이 아닙니다.

## 지원하는 설정

Devin CLI는 `.devin/mcp_config.json`(프로젝트), `.devin/mcp_config.local.json`(로컬),
사용자 수준 `mcp_config.json`의 `mcpServers` 객체에서 MCP 서버를 읽습니다. 그 파일 중
하나를 전달하세요.

```json
{
  "mcpServers": {
    "reviewed-tools": {
      "url": "https://your-reviewed-server.example/mcp",
      "transport": "http"
    }
  }
}
```

위 URL은 예시입니다. 직접 검토한 서버와 신뢰 정책을 설정하세요.

지원하는 서버 필드:

| 종류 | 필드 |
| --- | --- |
| 로컬 명령 (stdio) | `command`, `args`, `env`, `disabled`, `disabledTools` |
| 원격 서버 (기본 `http`, 또는 `sse`) | `url`, `transport`, `headers`, `disabled`, `disabledTools` |

서버에는 `command`와 `url` 중 정확히 하나만 있어야 합니다. 그 밖의 것은 모두 거부합니다.
알 수 없는 루트·서버 필드, 다른 전송 방식, 형식이 잘못된 항목, 자격 증명·쿼리
매개변수·프래그먼트가 들어 있는 URL이 해당됩니다. 문서화된 OAuth 클라이언트
필드(`oauthClientId`, `oauthClientSecret`, `oauthResource`, `oauthScopes`)도 명시적인 검사
구현이 생기기 전까지는 의도적으로 제외합니다. 일반적인 `devin mcp login` OAuth에는 이
필드가 필요 없으며, 그 부분은 Devin의 책임으로 남습니다.

변수 확장: `env`와 `headers` 값의 `${env:NAME}`은 허용하고 참조한 이름을 기록합니다. 로컬
파일 내용을 서버로 보내게 되는 `${file:/path}`와 그 밖의 `${...}` 형태는 거부하며,
`command`, `args`, `url`의 확장도 모두 거부합니다.

헤더가 있으면 `static-http-headers` 또는 `env-http-headers` 신호가 붙고, 기본 제공 팩은
이를 검토 대상으로 둡니다.

`"disabled": true`인 서버도 활성 서버와 같은 결정을 받습니다. 플래그 하나만 고치면
실행되기 때문입니다. 지문에는 전송 방식, 헤더 이름, 참조한 환경 변수 이름, `disabled`
플래그, `disabledTools`의 다이제스트가 들어갑니다. 따라서 서버를 켜거나 숨긴 도구를 다시
노출하면 서명된 검토가 무효가 됩니다. 헤더·환경 변수 값과 도구 이름은 넣지 않으므로,
자격 증명 값만 교체하면 검토는 유지됩니다. 명령 인자나 URL 경로에 자격 증명을 넣지
마세요. 게이트 출력 파일은 허용된 원본 항목을 그대로 보존하므로 입력에 있던 자격 증명이
들어 있을 수 있습니다. 로컬에만 두고 버전 관리에 넣지 마세요.

## 검사와 게이트

```bash
node ./bin/trustdex.mjs inspect-devin ./.devin/mcp_config.json \
  --pack strict --policy ./trustdex.policy.json

node ./bin/trustdex.mjs gate-devin ./.devin/mcp_config.json \
  --pack strict --policy ./trustdex.policy.json \
  --out ./.trustdex/devin-mcp_config.json
```

정책 파일은 사용자가 명시한 신뢰 정책이며, 벤더 이름에서 추론한 목록이 아닙니다.
기본적으로 게이트는 ALLOW 항목만 포함하고 ASK와 BLOCK 항목은 제외합니다. 게이트 종료
코드 `1`은 대기 중인 ASK 결정이 있다는 뜻이고 `2`는 실패입니다. TrustDex는 Devin 설정을
수정하지 않습니다. 게이트된 파일을 검토한 뒤, Devin이 읽는 파일의 `mcpServers` 부분을
직접 교체하세요.

Devin CLI는 프로젝트·로컬·사용자 파일을 병합합니다. 사용하는 파일을 각각 검사하세요.
TrustDex는 이 파일들을 찾아내거나 병합하지 않습니다. 이 워크플로는 웹 앱에서 Devin
조직에 설치한 MCP 서버, 플러그인, Devin 내장 도구, 엔터프라이즈 허용 목록을 다루지
않습니다. `permissions` 규칙은 따로 검사합니다. [권한 설정](#권한-설정)을 참고하세요.

## 권한 설정

`inspect-devin`은 MCP 서버를 다룹니다. 권한 규칙은 다른 파일인 `config.json`에 있으며
따로 검사합니다.

```bash
node ./bin/trustdex.mjs inspect-devin-settings ./.devin/config.json --pack strict --json
```

| 관찰된 설정 | 신호 | 기본 제공 팩 |
| --- | --- | --- |
| `permissions.allow`의 `Exec(...)` 규칙 또는 `exec` 도구 | `devin-auto-approved-exec` | `BLOCK` |
| 넓은 `permissions.allow` 규칙: `edit` 도구, 와일드카드·구분자·`~`·`.`로만 된 `Write(...)` 범위(`**`, `/**`, `~/**` 등), `.devin`·`.claude`·`.config` 디렉터리를 가리키는 `Write(...)` 범위, 호스트가 와일드카드뿐인 `Fetch(...)` 범위(`*`, `domain:*`, `https://*/*`) | `devin-broad-auto-approve` | `BLOCK` |
| 그 밖의 `permissions.allow` 규칙(`Read`, `Write`, `Fetch`, 도구 이름, `mcp__...`) | `devin-auto-approved-tools` | `ASK` |
| `permission_mode: "dangerous"` | `devin-permission-mode-bypass` | `BLOCK` |
| `permission_mode: "accept-edits"` 또는 `"smart"` | `devin-permission-mode-auto` | `ASK` |
| 비어 있지 않은 `hooks` 이벤트 | `devin-hooks` | `BLOCK` |
| 비어 있지 않은 `sandbox.excluded.allow`(일치하는 명령이 확인 없이 샌드박스 밖에서 실행됨) | `devin-sandbox-excluded-exec` | `BLOCK` |
| `local_tools_bypass_permissions: true`(로컬 도구 연결의 Bypass 모드) | `devin-local-tools-bypass` | `BLOCK` |
| `mcpServers` 키(예전 Devin CLI 버전이 읽음) | `devin-mcp-servers` | `ASK` |
| 켜진 가져오기 제공자: 문서화된 `read_config_from` 옵션이 없거나 `true` 또는 `null`임(`read_config_from` 자체가 없는 경우 포함, 그 도구나 Devin Cloud에서 규칙, 스킬, MCP 서버, 플러그인을 가져올 수 있음) | `devin-external-config` | `ASK` |
| `proxy`나 알 수 없는 `sandbox`·`sandbox.excluded`·`read_config_from` 키처럼 TrustDex가 검사하지 않는 설정 | `uninspected-devin-settings` | `ASK` |

설정 파일은 정책과 관계없이 ALLOW가 되지 않습니다. `ask`와 `deny` 규칙은 제한하는
규칙이라 신호를 추가하지 않습니다. 에이전트에 자율성을 주지 않는 문서화된 설정(`agent`,
표시 옵션, `keymap` 등과 `sandbox.allowed_domains`, `sandbox.denied_domains`,
`sandbox.network_mode`)은 값을 읽지 않고 건너뜁니다. `sandbox.excluded` 목록은 `Exec(...)`
규칙만 받으며 개수만 보고합니다. Devin CLI는 값이 없거나 `null`인 `read_config_from` 제공자를
켜므로, 파일이 문서화된 제공자 10개(`agents_standard`, `cursor`, `windsurf`, `claude`,
`copilot`, `codex`, `kiro`, `opencode`, `zed`, `cloud`)를 모두 `false`로 둘 때만
`devin-external-config`가 없습니다. 다른 설정 파일이 실행 시 이를 바꿀 수 있습니다. 켜진
제공자의 개수(`metadata.externalConfigProviderCount`)만 보고하며, 제공자 이름과 가져오는
파일은 읽지도 보고하지도 않습니다. 불리언이나 `null`로 된 객체가 아닌 값은 거부합니다. 넓은
규칙은 개수(`metadata.broadAllowRuleCount`)만 보고하고 범위는 보고하지 않습니다.

규칙은 문서화된 형식이어야 합니다: `Read(...)`, `Write(...)`, `Exec(...)`, `Fetch(...)`,
도구 이름 `read`, `edit`, `grep`, `glob`, `exec`, 또는 `mcp__*`, `mcp__server__*`,
`mcp__server__tool`. 그 밖의 규칙, 알 수 없는 `permission_mode`, 형식이 잘못된 섹션,
주석이 있는 파일은 거부합니다. Devin CLI는 `config.json`의 주석을 허용하므로, 검사할
사본에서는 주석을 지우세요.

보고서에는 권한 모드, 불리언, 개수만 들어갑니다. 규칙 범위, MCP 서버·도구 이름, 훅
내용, 검사하지 않는 설정의 이름은 들어가지 않습니다.

한계: 한 번에 파일 하나만 검사하며 사용자·프로젝트·로컬 파일을 병합하지 않습니다.
다루지 않는 것: `.devin/hooks.v1.json`, `read_config_from`으로 다른 도구에서 가져오는
훅과 규칙, 조직·팀 설정, 시스템 정책 파일, 세션 중에 부여한 승인, `--permission-mode`
플래그와 `DEVIN_PERMISSION_MODE`. `mcpServers` 항목 자체는 `inspect-devin`으로 검사하세요.

문서화된 설정 형식의 픽스처로 테스트했으며, Devin CLI 릴리스에서 실행해 본 것은
아닙니다. 출처:
[Devin CLI permissions](https://docs.devin.ai/cli/reference/permissions),
[configuration file](https://docs.devin.ai/cli/reference/configuration/config-file).

## 서명된 검토와 변경 감지

```bash
node ./bin/trustdex.mjs keygen --private .trustdex/private.pem --public .trustdex/public.pem
node ./bin/trustdex.mjs approve-devin ./.devin/mcp_config.json --private .trustdex/private.pem --dir .trustdex/devin-review --pack strict --policy ./trustdex.policy.json
node ./bin/trustdex.mjs recheck-devin ./.devin/mcp_config.json --review-dir .trustdex/devin-review --public .trustdex/public.pem
node ./bin/trustdex.mjs snapshot-devin ./.devin/mcp_config.json --out .trustdex/devin-snapshot.json --pack strict --policy ./trustdex.policy.json
```

승인은 BLOCK 결정을 거부합니다. 재검사는 APPROVED, NEEDS_REVIEW, INVALID 중 하나를
돌려줍니다. 개인 키는 절대 커밋하지 마세요.

## 비활성 예제

`examples/devin.mcp_config.json`은 예약된 `.invalid` 도메인, 자리 표시용 환경 변수 참조,
실행되지 않는 비활성 로컬 명령을 사용합니다. 정적 검사 전용입니다.

```bash
node ./bin/trustdex.mjs inspect-devin ./examples/devin.mcp_config.json --pack strict --policy ./examples/claude.policy.json
```

검사는 의도적으로 `2`로 끝납니다. 예상 결정은 ALLOW 1개, ASK 2개, BLOCK 1개입니다.

문서화된 설정 형식의 픽스처로 테스트하며 Devin CLI 릴리스로 테스트하지는 않습니다. 출처:
[Devin CLI MCP 설정](https://docs.devin.ai/cli/extensibility/mcp/configuration).
