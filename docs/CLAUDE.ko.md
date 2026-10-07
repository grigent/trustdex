# Claude에서 TrustDex 사용하기

<p align="right">
  <a href="./CLAUDE.md">English</a> | <strong>한국어</strong>
</p>

TrustDex는 Claude Code 또는 Claude Desktop이 MCP JSON을 받기 전에 이를 검사할 수 있습니다. 설정 증거를 로컬에서 평가하고, MCP 서버를 시작하지 않으며, 설정을 업로드하지 않습니다. ALLOW 결정은 증거가 정책과 일치한다는 뜻이며 서버 코드가 안전하다는 것을 증명하지 않습니다.

Claude 전용 명령은 TrustDex 0.5.0 이상에서 사용할 수 있습니다. 게시된 CLI를 실행하려면 아래 예제의 `node ./bin/trustdex.mjs` 대신 `npx trustdex@0.5.0`을 사용하거나, 소스 체크아웃에서 명령을 직접 사용하세요.

## 지원되는 설정

최상위 `mcpServers` 객체가 있는 전용 JSON 파일을 사용하세요.

```json
{
  "mcpServers": {
    "reviewed-tools": {
      "type": "http",
      "url": "https://your-reviewed-server.example/mcp"
    }
  }
}
```

위 URL은 설명용입니다. 직접 검토한 서버와 신뢰 정책을 설정하세요.

지원되는 서버 필드:

| 전송 방식 | 필드 |
| --- | --- |
| `stdio`(`type`을 생략한 경우의 기본값이기도 함) | `type`, `command`, `args`, `env` |
| `http` 또는 `sse` | `type`, `url`, `headers`, `headersHelper` |

원격 항목에는 명시적인 `type`이 필요합니다. 명령 인수와 환경/헤더 값은 문자열이어야 합니다. 알 수 없는 루트/서버 필드, 다른 전송 방식, 잘못된 항목, 해석되지 않은 명령/인수/엔드포인트 변수, 자격 증명·쿼리 매개변수·프래그먼트가 포함된 URL은 안전하게 실패합니다. 이는 명시적인 검사 구현이 마련될 때까지 사용자 지정 `oauth`, `alwaysLoad`, WebSocket 설정 및 향후 제어 기능을 의도적으로 제외합니다. 일반적인 서버 관리형 OAuth에는 `oauth` 필드가 필요 없으며 Claude가 계속 책임집니다.

인증 헤더는 `static-http-headers` 및/또는 `env-http-headers` 신호를 추가합니다. 기본 제공 팩에서는 이에 대한 검토를 요구합니다. `headersHelper`는 `header-helper-command`를 추가하며, Claude가 셸에서 실행하므로 기본 제공 팩에서는 이를 차단합니다. TrustDex는 도우미를 절대 실행하지 않습니다.

지문에는 전송 방식, 헤더 이름, 참조된 환경 변수 이름 및 도우미 존재 여부가 포함됩니다. 헤더/변수 값, 기본값 및 도우미 명령 텍스트는 제외됩니다. 자격 증명 값만 교체해도 검토는 무효화되지 않지만 헤더 이름이나 환경 변수 참조를 변경하면 무효화됩니다. 자격 증명을 명령 인수나 URL 경로에 넣지 마세요. 게이트된 파일은 허용된 원본 항목을 보존하며 입력에 제공된 자격 증명을 포함할 수 있습니다. 로컬에 보관하고 버전 관리에서 제외하세요.

## Claude Code

Claude Code는 `.mcp.json`에서 프로젝트 MCP 설정을 읽습니다. Claude 어댑터로 검사한 뒤 해당 세션에는 생성된 설정만 제공하세요.

소스 체크아웃의 PowerShell에서:

```powershell
node ./bin/trustdex.mjs inspect-claude ./.mcp.json --pack strict --policy ./trustdex.policy.json

node ./bin/trustdex.mjs gate-claude ./.mcp.json --pack strict --policy ./trustdex.policy.json --out ./.trustdex/claude-mcp.json
if ($LASTEXITCODE -ne 0) { throw "Resolve the gate error or pending reviews before starting Claude." }

claude --strict-mcp-config --mcp-config ./.trustdex/claude-mcp.json
```

정책 파일은 공급업체 이름에서 추론한 목록이 아니라 사용자의 명시적인 신뢰 정책입니다. 엄격한 기본값을 사용하려면 `--policy`를 생략하세요. 엄격한 기본값은 알 수 없는 소스를 차단하고 로컬 프로그램에 대해 묻습니다. 기본적으로 게이트에는 ALLOW 항목만 포함됩니다. ASK와 BLOCK 항목은 제외됩니다. 게이트 종료 코드 `1`은 처리되지 않은 ASK 결정, `2`는 실패를 나타냅니다. 게이트가 실패한 뒤 이전 출력 파일로 실행하지 마세요.

`--strict-mcp-config` 플래그가 중요합니다. `--mcp-config`만 사용하면 다른 MCP 소스와 함께 설정이 추가됩니다. 관리형 MCP 설정을 사용하는 조직은 관리 정책의 실제 서버도 확인해야 합니다. 이 워크플로는 Claude의 기본 제공 도구를 게이트하거나 모든 스킬/플러그인을 자동으로 검사하지 않습니다.

생성된 Claude Code 세션 안에서 `/mcp`를 사용해 실제로 로드된 서버를 확인하세요. 설정/단위 테스트가 이 런타임 확인을 대신할 수는 없습니다.

공식 참고 자료: [Claude Code MCP](https://code.claude.com/docs/en/mcp) 및 [CLI 플래그](https://code.claude.com/docs/en/cli-reference).

## 서명된 검토 및 드리프트

검토 워크플로 전체에서 Claude 어댑터를 유지하세요. 일반 MCP 명령은 Claude 전용 제어를 검사하지 않습니다.

```bash
node ./bin/trustdex.mjs keygen --private .trustdex/private.pem --public .trustdex/public.pem
node ./bin/trustdex.mjs approve-claude ./.mcp.json --private .trustdex/private.pem --dir .trustdex/claude-review --pack strict --policy ./trustdex.policy.json
node ./bin/trustdex.mjs recheck-claude ./.mcp.json --review-dir .trustdex/claude-review --public .trustdex/public.pem
node ./bin/trustdex.mjs snapshot-claude ./.mcp.json --out .trustdex/claude-snapshot.json --pack strict --policy ./trustdex.policy.json
```

승인은 BLOCK 결정을 거부합니다. ASK 결정에는 명시적인 사람의 검토가 필요합니다. `approve-claude`를 실행하면 해당 검토가 기록되지만 게이트 정책이 자동으로 변경되지는 않습니다. 재검사는 APPROVED, NEEDS_REVIEW 또는 INVALID를 반환합니다. 기존 일반 검토는 지문이 다르므로 Claude 어댑터로 다시 검토해야 합니다. 비공개 키는 절대 커밋하면 안 됩니다.

## Claude Desktop

로컬 stdio MCP 설정에서는 `claude_desktop_config.json`의 `mcpServers` 객체만 전용 입력 파일로 내보내세요. 관련 없는 Desktop 환경설정을 MCP 어댑터에 입력하지 마세요. 해당 파일에 `inspect-claude`와 `gate-claude`를 사용하고 결과를 검토한 뒤, Desktop 설정의 `mcpServers` 섹션만 게이트된 섹션으로 교체하고 Claude Desktop을 다시 시작하세요. 원본 설정의 백업을 보관하세요.

TrustDex는 활성 Desktop 설정을 수정하거나 커넥터를 설치하지 않습니다. Desktop 확장과 계정 수준 원격 커넥터에는 별도 검토가 필요합니다. 이 JSON 게이트가 이를 자동으로 관리하지는 않습니다.

## 비활성 예제

`examples/claude.mcp.json`은 예약된 `.invalid` 도메인, 자리표시자 환경 변수 참조 및 비활성 도우미 문자열을 사용합니다. Claude에서 실행하지 마세요. 정적 검사 전용입니다.

```bash
node ./bin/trustdex.mjs inspect-claude ./examples/claude.mcp.json --pack strict --policy ./examples/claude.policy.json
node ./bin/trustdex.mjs gate-claude ./examples/claude.mcp.json --pack strict --policy ./examples/claude.policy.json --out .trustdex/example-claude.json
```

검사는 의도적으로 `2`로 종료됩니다. 예상 결정은 ALLOW 1개, ASK 1개, BLOCK 2개입니다. 게이트는 `reviewed`만 기록하고 검토가 남아 있으므로 `1`로 종료됩니다.
