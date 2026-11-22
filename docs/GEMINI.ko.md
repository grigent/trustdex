# Gemini CLI에서 TrustDex 사용하기

<p align="right">
  <a href="./GEMINI.md">English</a> | <strong>한국어</strong>
</p>

TrustDex는 Gemini CLI가 MCP 서버 정의를 받기 전에 그 정의를 검사할 수 있습니다. 설정
증거를 로컬에서 평가하며, MCP 서버를 실행하거나 설정을 업로드하지 않습니다. ALLOW 결정은
증거가 정책과 일치했다는 뜻이지, 서버 코드가 안전하다는 증명이 아닙니다.

## 지원하는 설정

Gemini CLI는 `settings.json`의 `mcpServers` 객체에서 MCP 서버를 읽습니다. 그 객체만 별도
JSON 파일로 복사하세요. `settings.json` 전체는 거부합니다. 다른 설정이 검사 없이
통과하게 되기 때문입니다.

```json
{
  "mcpServers": {
    "reviewed-tools": {
      "httpUrl": "https://your-reviewed-server.example/mcp"
    }
  }
}
```

위 URL은 예시입니다. 직접 검토한 서버와 신뢰 정책을 설정하세요.

지원하는 서버 필드:

| 종류 | 필드 |
| --- | --- |
| 로컬 명령 (stdio) | `command`, `args`, `env`, `cwd`, `timeout`, `trust`, `includeTools`, `excludeTools` |
| SSE 엔드포인트 | `url`, `headers`, `timeout`, `trust`, `includeTools`, `excludeTools` |
| HTTP 스트리밍 엔드포인트 | `httpUrl`, `headers`, `timeout`, `trust`, `includeTools`, `excludeTools` |

서버에는 `command`, `url`, `httpUrl` 중 정확히 하나만 있어야 합니다. 그 밖의 것은 모두
거부합니다. 알 수 없는 루트·서버 필드, 형식이 잘못된 항목, `command`·`args`·`cwd`·
엔드포인트의 `${...}`, 자격 증명·쿼리 매개변수·프래그먼트가 들어 있는 URL이
해당됩니다. 문서화된 `oauth`, `authProviderType`, `targetAudience`,
`targetServiceAccount` 필드도 명시적인 검사 구현이 생기기 전까지는 의도적으로
제외합니다. 자동 OAuth 탐색에는 이 필드가 필요 없으며, 그 부분은 Gemini CLI의 책임으로
남습니다.

신호:

- `trust: true`는 Gemini CLI가 해당 서버의 모든 도구 호출 확인을 건너뛰게 합니다.
  `auto-approve-tools` 신호가 붙고 기본 제공 팩은 이를 검토 대상으로 두므로, 이런 서버는
  명시적인 정책 결정 없이는 ALLOW가 되지 않습니다.
- 헤더가 하나라도 있으면 `static-http-headers`가 붙습니다. Gemini CLI는 변수 확장을
  `env`에 대해서만 문서화하므로, 헤더 값은 리터럴 자격 증명으로 취급합니다.

지문에는 전송 방식, 헤더 이름, `env`에서 참조한 환경 변수 이름(`$NAME`, `${NAME}`,
`%NAME%`), `trust` 플래그, `includeTools`·`excludeTools`·`cwd`의 다이제스트가 들어갑니다.
따라서 `trust`를 켜거나, 도구 필터를 넓히거나, 작업 디렉터리를 바꾸면 서명된 검토가
무효가 됩니다. 헤더·환경 변수 값, 도구 이름, 디렉터리 경로는 넣지 않으므로, 자격 증명
값만 교체하면 검토는 유지됩니다. `timeout`은 형식만 검증하고 지문에는 넣지 않습니다.
명령 인자나 URL 경로에 자격 증명을 넣지 마세요. 게이트 출력 파일은 허용된 원본 항목을
그대로 보존하므로 입력에 있던 자격 증명이 들어 있을 수 있습니다. 로컬에만 두고 버전
관리에 넣지 마세요.

## 검사와 게이트

```bash
node ./bin/trustdex.mjs inspect-gemini ./gemini-mcpServers.json \
  --pack strict --policy ./trustdex.policy.json

node ./bin/trustdex.mjs gate-gemini ./gemini-mcpServers.json \
  --pack strict --policy ./trustdex.policy.json \
  --out ./.trustdex/gemini-mcpServers.json
```

정책 파일은 사용자가 명시한 신뢰 정책이며, 벤더 이름에서 추론한 목록이 아닙니다.
기본적으로 게이트는 ALLOW 항목만 포함하고 ASK와 BLOCK 항목은 제외합니다. 게이트 종료
코드 `1`은 대기 중인 ASK 결정이 있다는 뜻이고 `2`는 실패입니다. TrustDex는 Gemini 설정을
수정하지 않습니다. 게이트된 파일을 검토한 뒤, `settings.json`의 `mcpServers` 부분을 직접
교체하고 Gemini CLI를 다시 시작하세요.

Gemini CLI는 사용자·프로젝트·시스템 설정을 병합하고, 확장 프로그램이 자체 MCP 서버를
추가할 수도 있습니다. 사용하는 `mcpServers` 객체를 각각 검사하세요. TrustDex는 이를
찾아내거나 병합하지 않습니다. 이 워크플로는 전역 `mcp` 설정(`mcp.allowed`,
`mcp.excluded`, `mcp.serverCommand`), 확장 프로그램, Gemini CLI 내장 도구, 샌드박스를
다루지 않습니다. 이 중 일부 설정은 아래 `inspect-gemini-settings`가 분류합니다.

## Gemini CLI 권한 설정

MCP 게이트는 어떤 외부 서버가 노출되는지를 다룹니다. 어떤 동작이 확인 없이 실행되는지는
Gemini CLI 자체 설정이 따로 정합니다. 사용자·프로젝트·시스템 `settings.json`을 별도
단계로 검사하세요.

```bash
node ./bin/trustdex.mjs inspect-gemini-settings ./.gemini/settings.json --pack strict --json
```

설정 값은 그대로 출력하지 않고 기능별로 분류합니다.

| 관찰된 설정 | 신호 | 기본 제공 팩 |
| --- | --- | --- |
| `tools.allowed`에 셸 도구 또는 와일드카드가 있음 | `gemini-auto-approved-shell` | `BLOCK` |
| `tools.discoveryCommand`, `tools.callCommand`, `mcp.serverCommand` | `gemini-tool-commands` | `BLOCK` |
| `hooks` 항목이 있음 (이 파일에서 `hooksConfig.enabled`가 `false`여도) | `gemini-hooks` | `BLOCK` |
| 그 밖의 `tools.allowed` 항목 | `gemini-auto-approved-tools` | 최소 `ASK` |
| `general.defaultApprovalMode`가 `auto_edit` | `gemini-auto-edit` | 최소 `ASK` |
| `tools.sandboxAllowedPaths` 또는 `tools.sandboxNetworkAccess` | `gemini-sandbox-relaxed` | 최소 `ASK` |
| `tools.sandbox`가 `false`, `"false"`, `"0"`(이 파일이 샌드박스를 끔) | `gemini-sandbox-disabled` | 최소 `ASK` |
| `tools.sandbox`에 환경 변수 참조(`$VAR`, `${VAR}`, `${VAR:-DEFAULT}`)가 있음 | `gemini-sandbox-unresolved` | 최소 `ASK` |
| `security.enablePermanentToolApproval` 또는 `security.autoAddToPolicyByDefault` | `gemini-persistent-approvals` | 최소 `ASK` |
| `security.folderTrust.enabled`가 `false` | `gemini-folder-trust-disabled` | 최소 `ASK` |
| `security.environmentVariableRedaction.allowed` | `gemini-env-redaction-bypass` | 최소 `ASK` |
| `policyPaths` 또는 `adminPolicyPaths` | `gemini-policy-paths` | 최소 `ASK` |
| `mcpServers`, `admin.mcp.config`, `admin.mcp.requiredConfig` 항목 | `gemini-mcp-servers` | 최소 `ASK` |
| TrustDex가 검사하지 않는 설정 | `uninspected-gemini-settings` | 최소 `ASK` |

설정 파일은 정책과 관계없이 ALLOW가 되지 않습니다. 제한하는 설정(`tools.exclude`,
`tools.core`, `tools.confirmationRequired`, `security.disableYoloMode`,
`security.disableAlwaysAllow`)은 신호를 추가하지 않습니다. 검사 대상 설정의 타입이
틀리거나, 지원하지 않는 승인 모드이거나, 순수 JSON이 아닌 파일(주석 포함)은 거부합니다.

`metadata.sandboxSetting`은 `omitted`(생략), `disabled`(Gemini CLI가 끔으로 처리하는 `false`,
`"false"`, `"0"`), `enabled`(`true`, `"true"`, `"1"`, 또는 Gemini CLI가 지원하는 샌드박스 명령
`docker`, `podman`, `sandbox-exec`, `runsc`, `lxc`, `windows-native`. 명령은 보고하지 않음),
`unresolved` 중 하나여서 생략된 샌드박스와 꺼진 샌드박스를 구분합니다. `metadata.sandboxConfigured`는
`enabled`일 때만 `true`입니다. 두 값은 검사한 파일에 기록된 설정을 나타냅니다. 실제 실행 시
적용되는 샌드박스는 상위 설정 계층, `GEMINI_SANDBOX` 환경 변수, `--sandbox` CLI 옵션에 따라
달라질 수 있습니다.

Gemini CLI는 설정을 검증하기 전에 `$VAR`, `${VAR}`, `${VAR:-DEFAULT}` 참조를 환경 변수 값으로
치환합니다. TrustDex는 환경 변수를 읽지 않으므로, 이런 참조가 들어 있는 `tools.sandbox` 문자열은
`unresolved`로 보고하고 `gemini-sandbox-unresolved` 신호를 추가합니다(최소 `ASK`. 파일의 다른
신호에는 각각의 정책이 그대로 적용됨). 변수 이름, 기본값, 입력 문자열은 보고하지 않습니다.
Gemini CLI가 설정 오류로 처리하는 그 밖의 `tools.sandbox` 문자열은 거부하며(`BLOCK`, 종료 코드 2),
오류나 보고서에 값이 나타나지 않습니다. 빈 문자열도 거부합니다. Gemini CLI의 샌드박스 파서는 빈
문자열을 꺼짐으로 처리하지만, TrustDex는 이를 명시적 설정으로 받아들이지 않습니다.
보고서에는 승인 모드, 불리언, 개수만 들어갑니다. 도구 이름, 명령, 경로, 훅 내용, 확장
패턴, 변수 이름, 검사하지 않는 설정의 이름은 들어가지 않습니다. 그래서 내용 지문이나
서명된 검토 기록이 없고, 같은 분류 안에서 개수가 같은 변경은 감지하지 못합니다.

이 명령은 파일 하나만 읽습니다. 사용자·프로젝트·시스템 계층을 병합하지 않고,
`policyPaths`가 가리키는 정책 파일을 읽지 않으며, `--yolo` 같은 명령줄 플래그나 확장
프로그램이 제공하는 설정은 보지 못합니다. `mcpServers`는 `inspect-gemini`로 검사하세요.
공식 문서:
[Gemini CLI configuration](https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md).

## 서명된 검토와 변경 감지

```bash
node ./bin/trustdex.mjs keygen --private .trustdex/private.pem --public .trustdex/public.pem
node ./bin/trustdex.mjs approve-gemini ./gemini-mcpServers.json --private .trustdex/private.pem --dir .trustdex/gemini-review --pack strict --policy ./trustdex.policy.json
node ./bin/trustdex.mjs recheck-gemini ./gemini-mcpServers.json --review-dir .trustdex/gemini-review --public .trustdex/public.pem
node ./bin/trustdex.mjs snapshot-gemini ./gemini-mcpServers.json --out .trustdex/gemini-snapshot.json --pack strict --policy ./trustdex.policy.json
```

승인은 BLOCK 결정을 거부합니다. 재검사는 APPROVED, NEEDS_REVIEW, INVALID 중 하나를
돌려줍니다. 개인 키는 절대 커밋하지 마세요.

## 비활성 예제

`examples/gemini.mcpServers.json`은 예약된 `.invalid` 도메인과 실제 값이 아닌 자리 표시용
헤더를 사용합니다. 정적 검사 전용입니다.

```bash
node ./bin/trustdex.mjs inspect-gemini ./examples/gemini.mcpServers.json --pack strict --policy ./examples/claude.policy.json
```

검사는 의도적으로 `2`로 끝납니다. 예상 결정은 ALLOW 1개, ASK 2개(헤더와 `trust: true`),
BLOCK 1개입니다.

문서화된 설정 형식의 픽스처로 테스트하며 Gemini CLI 릴리스로 테스트하지는 않습니다. 출처:
[MCP servers with Gemini CLI](https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md).
