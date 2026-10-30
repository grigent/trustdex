# TrustDex

<p align="right">
  <a href="./README.md">English</a> | <strong>한국어</strong>
</p>

[![CI](https://github.com/grigent/trustdex/actions/workflows/ci.yml/badge.svg)](https://github.com/grigent/trustdex/actions/workflows/ci.yml)
[![CodeQL](https://github.com/grigent/trustdex/actions/workflows/codeql.yml/badge.svg)](https://github.com/grigent/trustdex/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/grigent/trustdex)](https://github.com/grigent/trustdex/releases)
[![npm](https://img.shields.io/npm/v/trustdex)](https://www.npmjs.com/package/trustdex)
[![License](https://img.shields.io/github/license/grigent/trustdex)](LICENSE)

**AI 에이전트 도구를 위한 로컬 우선 신뢰 및 출처 검증 게이트입니다.**

TrustDex는 AI 에이전트가 어떤 MCP 서버, 스킬, 플러그인을 사용하도록 허용할지 판단하는 데 도움을 줍니다. 발견된 모든 확장을 신뢰하는 대신, TrustDex는 관찰 가능한 증거를 평가하여 다음 세 가지 결과 중 하나를 반환합니다.

- **ALLOW** - 명시적인 신뢰 정책과 일치
- **ASK** - 사람의 검토가 필요
- **BLOCK** - 현재 정책에서 신뢰되지 않음

> TrustDex는 보안 관련 인프라이며, 악성 코드 스캐너, 샌드박스 또는 인증 서비스가 아닙니다. ALLOW 결과는 검사된 증거가 사용자의 정책과 일치한다는 의미일 뿐입니다.

> **프로젝트 상태:** TrustDex는 초기 단계이며 파일럿 사용자를 찾고 있습니다. 보안 경계가 문서화되어 있고, 지원되는 Node.js 버전에서 변경 사항을 테스트하지만, 1.0 이전에는 호환성이 계속 변경될 수 있습니다. [로드맵](docs/ROADMAP.ko.md), [거버넌스](GOVERNANCE.ko.md), [지원 가이드](SUPPORT.ko.md)를 참고하세요.

## TrustDex가 필요한 이유

AI 에이전트는 자격 증명을 받거나, 파일에 접근하거나, 원격 서비스에 연결하거나, 로컬 프로그램을 실행할 수 있는 서드파티 MCP 서버, 스킬, 플러그인에 점점 더 의존하고 있습니다. 패키지를 설치할 수 있다는 사실만으로 해당 패키지를 에이전트가 자동으로 사용할 수 있어서는 안 됩니다.

TrustDex는 **도구가 노출되기 전**에 의사 결정 계층을 추가합니다.

```text
사용자 요청
    |
    v
AI 에이전트 / Codex
    |
    v
TrustDex 정책 + 출처 검증 게이트
    |-- ALLOW -> 도구 노출 가능
    |-- ASK   -> 사람의 검토 필요
    `-- BLOCK -> 도구를 사용할 수 없도록 유지
```

TrustDex는 이름, 스타 수 또는 브랜딩만으로 "공식" 여부를 추론하지 않습니다. 출처는 명시적이고 검토 가능한 증거로 확인해야 합니다.

## 현재 코드에서 지원하는 기능

- 설정을 업로드하지 않고 로컬에서 MCP 서버 항목 검사
- 패키지, 원격, 로컬 및 알 수 없는 소스 구분
- 유동 버전, 실행 시 설치하는 런처, 셸 실행, 파일 시스템 경로로 보이는 인수, 비밀 정보로 보이는 환경 변수 이름, 원격 엔드포인트 등 신뢰 관련 신호 감지
- `SKILL.md` 파일 및 플러그인 매니페스트에서 신뢰 관련 메타데이터와 지침 검사
- 기본 제공 `strict`, `official-first`, `development` 정책 팩 적용
- 로컬 신뢰 저장소에서 명시적인 게시자/출처 주장 연결
- **ALLOW / ASK / BLOCK** 결정 출력
- 정책에서 승인된 도구만 포함하는 필터링된 MCP 설정 생성
- 스냅샷 생성 및 소스, 출처, 결정, 기능 드리프트 감지
- 검토된 스냅샷에 대한 Ed25519 서명 신뢰 기록 생성
- CI에서 GitHub Action으로 실행
- 비밀 값을 저장하지 않고 MCP 항목, 스킬 및 플러그인 매니페스트의 지문 생성
- Codex `config.toml`의 MCP 섹션 검사 및 필터링
- 경로 값을 보관하지 않고 Codex 승인, 샌드박스, 네트워크, 쓰기 가능 루트, 웹 검색 및 서브에이전트 설정 검사
- 명시적인 전송 방식 검증과 헤더 실행 제어를 포함해 Claude Code MCP JSON 검사 및 필터링
- 규칙 값을 보관하지 않고 자동 셸, 파일 시스템, 네트워크, MCP 및 서브에이전트 권한에 대해 Claude Code 권한 설정 검사
- GitHub, npm 및 공식 MCP Registry를 대상으로 명시적인 출처 조회 수행
- 최신 GitHub 릴리스 태그/커밋에 GitHub 검증 서명이 있는지 확인
- 서명된 검토 번들을 생성하고 신뢰 관련 상태가 변경되면 자동으로 재검토 요구
- 보고서의 원격 엔드포인트 세부 정보에서 자격 증명, 경로 및 쿼리 값 제거
- 엄격한 정책에서 URL에 포함된 자격 증명과 안전하지 않은 원격 전송 차단
- 여러 호스트에서 Windows 실행 파일 경로와 명령 래퍼를 일관되게 인식
- 지원하지 않는 Codex MCP 키와 하위 섹션을 발견하면 안전하게 실패
- 사용자가 제공한 패키지 바이트를 npm SRI 또는 MCP Registry SHA-256 메타데이터와 대조해 검증
- 무결성 기반 신뢰 증거를 설정된 패키지 버전에 연결하고 불일치 차단
- 각 Claude/Codex MCP 소스의 결정·출처 상태를 도구 이름이나 규칙 값 없이 자동 도구 권한과 연결
- 명시적으로 제공된 값 없는 런타임 MCP 인벤토리를 검토된 연결과 대조해 차단되거나 예상 밖으로 로드된 서버 감지
- 수명이 짧은 런타임 인벤토리를 Ed25519 생성자 증명, 만료 및 선택적 캡처 나이 제한으로 인증
- VS Code 호환 에디터 확장(VS Code, Cursor)을 정확한 버전과 설치 파일 다이제스트로 검사하고, 확장이 추가·업데이트·변경되면 재검토 요구
- 에이전트와 자동화를 위한 버전 있는 실패 시 차단 JSON 판정 계약을 출력하고, 공개 스키마에 맞춰 정책 파일을 엄격하게 검증

## 호환성

TrustDex에는 Node.js 20 이상이 필요합니다. CI는 Ubuntu에서 Node.js 20과 22로 전체 테스트 및 게이트 워크플로를 실행하고, 최신 Windows 및 macOS 러너에서는 Node.js 22로 실행합니다. 체크아웃된 복합 GitHub Action에는 전용 엔드투엔드 스모크 테스트가 있습니다.

## 빠른 시작

Node.js 20 이상이 필요합니다.

npm에서 직접 실행:

```bash
npx trustdex@0.11.0 --help
npx trustdex@0.11.0 inspect ./mcp.json --pack strict --policy ./trustdex.policy.json
```

또는 소스 체크아웃에서 작업:

```bash
git clone https://github.com/grigent/trustdex.git
cd trustdex
npm test
npm run check

node ./bin/trustdex.mjs inspect ./examples/mcp.json \
  --pack strict \
  --policy ./examples/trustdex.policy.json
```

예제에는 의도적으로 알 수 없는 서버가 포함되어 있으므로 엄격한 검사는 0이 아닌 종료 코드를 반환합니다.

검사의 종료 코드:

- `0` - 모든 항목 허용
- `1` - 하나 이상의 항목에 검토 필요
- `2` - 하나 이상의 항목이 차단되었거나 명령 실패

## 재현 가능한 방어적 연구

TrustDex에는 서드파티 서비스에 연결하거나 실행하지 않고 정책 경계를 테스트할 수 있는 비활성 적대적 벤치마크가 포함되어 있습니다. 픽스처는 예약된 `.invalid` 도메인, 자리표시자 자격 증명 및 설정 데이터만 사용합니다. TrustDex는 이를 정적으로 검사하며 나열된 서버를 실행하지 않습니다.

```bash
npm run test:research

node ./bin/trustdex.mjs inspect \
  ./examples/adversarial/mcp-config.json \
  --pack strict \
  --policy ./examples/adversarial/policy.json
```

직접 검사는 의도적으로 종료 코드 `2`를 반환합니다. 체크인된 기대 결과는 `ALLOW` 1개, `ASK` 1개, `BLOCK` 5개입니다. 자동화된 테스트는 자리표시자 비밀 값이 결과에 나타나지 않는지, 비밀 정보를 포함하는 새 환경 변수가 이전 검토 상태를 무효화하는지도 확인합니다.

[방어적 AI 에이전트 보안 사용 사례](docs/DEFENSIVE_USE_CASE.ko.md), [방어적 보안 연구 정책](docs/SECURITY_RESEARCH.ko.md), [평가 기록](docs/EVALUATION.ko.md), [적대적 픽스처 가이드](examples/adversarial/README.ko.md)를 참고하세요.

## 기본 제공 정책 팩

```bash
node ./bin/trustdex.mjs policy strict
node ./bin/trustdex.mjs policy official-first
node ./bin/trustdex.mjs policy development
```

`official-first`는 소위 공식 공급업체의 하드코딩된 목록을 유지하지 **않습니다**. 신뢰 저장소에 명시적인 출처 증거가 있는 소스(또는 사용자가 명시적으로 허용 목록에 추가한 소스)만 허용하며, 알 수 없는 서드파티 소스는 기본적으로 차단합니다.

[신뢰 저장소와 출처](docs/TRUST_STORE.ko.md)를 참고하세요.

## 에이전트가 사용하기 전에 도구 필터링

```bash
node ./bin/trustdex.mjs gate ./examples/mcp.json \
  --pack official-first \
  --out .trustdex/gated-mcp.json
```

기본적으로 `ALLOW` 항목만 게이트된 설정에 기록됩니다. `ASK` 항목은 검토될 때까지 제외됩니다.

이것이 TrustDex의 핵심 경계입니다. 에이전트는 검토되지 않은 원본 설정 대신 필터링된 설정을 받습니다.

## 스킬 및 플러그인 검사

```bash
node ./bin/trustdex.mjs inspect-skill ./path/to/SKILL.md --pack strict
node ./bin/trustdex.mjs inspect-plugin ./path/to/plugin.json --pack strict
```

이 검사는 관찰 가능한 신뢰 신호를 드러냅니다. 확장이 안전하다는 것을 증명하지는 않습니다.

## IDE 확장 검사

VS Code와 Cursor용 Claude Code 확장 같은 에디터 확장은 사용자의 로컬 권한으로 실행되고 자동으로 업데이트됩니다. TrustDex는 사용자가 지정한 확장 디렉터리의 목록을 만들고, 설치된 모든 파일의 다이제스트를 계산하며, 정확한 버전으로 고정한 확장만 허용합니다.

```bash
node ./bin/trustdex.mjs inspect-ide-extensions ~/.cursor/extensions \
  --pack strict --policy ./ide-policy.json
node ./bin/trustdex.mjs approve-ide-extensions ~/.cursor/extensions \
  --private trustdex-private.pem --dir .trustdex/ide-review --policy ./ide-policy.json
node ./bin/trustdex.mjs recheck-ide-extensions ~/.cursor/extensions \
  --review-dir .trustdex/ide-review --public trustdex-public.pem
```

고정한 `2.1.312`가 `2.1.313`으로 바뀌는 것처럼 검토하지 않은 업데이트는 절대 ALLOW가 되지 않고(`strict`, `official-first`는 BLOCK, `development`는 ASK), `recheck-ide-extensions`에서 `NEEDS_REVIEW`로 보고됩니다. 아무것도 실행하지 않으며 네트워크 요청도 하지 않습니다. 신호, 정책 필드, 한계는 [IDE 확장](docs/IDE_EXTENSIONS.ko.md)을 참고하세요.

## 에이전트와 자동화에서 사용

검사 명령은 `--decisions`로 버전이 있고 값이 없는 JSON 판정 보고서(`schemas/trustdex-decisions-v1.schema.json`)를 출력합니다. 종료 코드는 항상 판정과 일치하고, 검사가 실패해도 BLOCK 보고서를 출력하므로 하네스가 실패 시 허용될 수 없습니다. 정책 파일은 엄격하게 검증하여 알 수 없는 필드와 잘못된 판정 값을 거부합니다. 보고서를 안전하게 읽는 법과 정책·신뢰 저장소·서명 키를 에이전트 손이 닿지 않게 두는 법은 [에이전트 연동](docs/AGENT_INTEGRATION.ko.md)을 참고하세요.

## Codex config.toml

현재 Codex 클라이언트는 `config.toml`의 `[mcp_servers.<name>]` 테이블 아래에 MCP 설정을 저장합니다. TrustDex는 해당 MCP 섹션을 위한 전용 어댑터를 제공합니다.

```bash
node ./bin/trustdex.mjs inspect-codex ./examples/codex.config.toml --pack strict

node ./bin/trustdex.mjs gate-codex ./examples/codex.config.toml \
  --pack strict \
  --out .trustdex/gated-codex.toml
```

게이트는 승인되지 않은 MCP 섹션을 제거하면서 관련 없는 TOML 섹션은 유지합니다. TrustDex는 필요한 MCP 관련 TOML 구성만 의도적으로 파싱합니다. 지원하지 않는 MCP 구문은 조용히 신뢰하지 않고 실패합니다.

MCP 도구와 별도로 에이전트의 실행 경계를 검사하세요.

```bash
node ./bin/trustdex.mjs inspect-codex-settings \
  ./examples/codex.permissions.toml \
  --pack strict
```

이 명령은 승인 정책, 샌드박스 종류, 네트워크 접근, 추가 쓰기 가능 루트 개수, 웹 검색 모드 및 명시적인 서브에이전트 활성화를 보고합니다. 쓰기 가능 경로나 관련 없는 설정의 값은 보관하지 않습니다. 문서화된 병합 우선순위를 검사하려면 활성 소스를 명시적으로 제공하세요. `--project`는 저장소 루트에서 현재 디렉터리 방향으로 반복합니다.

```bash
node ./bin/trustdex.mjs inspect-codex-settings-stack \
  --system ./review/system.toml \
  --user ./review/user.toml \
  --project ./review/root-project.toml \
  --project ./review/closest-project.toml \
  --cli ./review/cli-overrides.toml \
  --pack strict
```

단계별 게이트 워크플로와 이 프로젝트가 자체 검토 과정에서 Codex를 사용하는 방법은 [Codex에서 TrustDex 사용하기](docs/CODEX.ko.md)를 참고하세요.

## Claude Code MCP 설정

Claude Code는 `mcpServers` JSON 형식을 사용합니다. 전송 방식 변경, 인증 헤더 메타데이터 및 헤더 도우미 명령이 검사와 서명된 검토에 포함되도록 Claude 전용 명령을 사용하세요.

```bash
node ./bin/trustdex.mjs inspect-claude ./.mcp.json --pack strict
node ./bin/trustdex.mjs gate-claude ./.mcp.json --pack strict --out .trustdex/claude-mcp.json
claude --strict-mcp-config --mcp-config .trustdex/claude-mcp.json
```

Claude를 시작하기 전에 게이트의 결과를 확인하세요. 기본적으로 `ALLOW` 항목만 노출되며, `ASK` 항목에는 검토가 필요합니다. 어댑터는 검사할 수 없는 설정을 조용히 신뢰하지 않고 거부합니다. 이 명령은 npm 0.5.0 이상과 소스 체크아웃에서 사용할 수 있습니다. 게시된 CLI를 실행하려면 `node ./bin/trustdex.mjs` 대신 `npx trustdex@0.11.0`을 사용하세요.

지원되는 설정, PowerShell 오류 처리, 서명된 검토 및 Claude Desktop 워크플로는 [Claude에서 TrustDex 사용하기](docs/CLAUDE.ko.md)를 참고하세요.

Claude Code 프로젝트 및 사용자 설정은 별도 확인 없이 실행되는 작업을 허용할 수도 있습니다. 문서화된 `permissions` 객체와 인접한 자동 실행 설정을 별도로 검사하세요.

```bash
node ./bin/trustdex.mjs inspect-claude-settings \
  ./.claude/settings.json \
  --pack strict
```

이 명령은 구조적인 기능 증거만 보고합니다. 권한 지정자, 디렉터리 값, 훅 명령, 도메인, 자격 증명 도우미 값 또는 환경 값을 출력하거나 지문에 포함하지 않습니다. 문서화된 파일 우선순위와 목록 병합을 계산하려면 소스를 명시적으로 제공하세요.

```bash
node ./bin/trustdex.mjs inspect-claude-settings-stack \
  --user ./review/user.settings.json \
  --project ./.claude/settings.json \
  --local ./.claude/settings.local.json \
  --session ./review/session.settings.json \
  --managed ./review/managed-settings.json \
  --pack strict
```

스택 검사는 여전히 정적 검토 도구이며 런타임 샌드박스가 아닙니다. 파일, 환경 변수 재정의 또는 조직 정책을 자동으로 찾지 않으며, 전달된 소스만 평가합니다.

## 권한 상태 드리프트

각 런타임에 대해 값이 제거된 구조적 기준 상태를 기록한 뒤 에이전트 또는 정책
변경 후 상태와 비교할 수 있습니다.

```bash
node ./bin/trustdex.mjs snapshot-claude-settings \
  ./.claude/settings.json \
  --pack strict \
  --out .trustdex/claude-posture.json

node ./bin/trustdex.mjs snapshot-codex-settings \
  ~/.codex/config.toml \
  --pack strict \
  --out .trustdex/codex-posture.json

node ./bin/trustdex.mjs snapshot-claude-settings-stack \
  --user ./review/user.settings.json \
  --project ./.claude/settings.json \
  --managed ./review/managed-settings.json \
  --pack strict \
  --out .trustdex/claude-stack-posture.json

node ./bin/trustdex.mjs diff-permissions \
  .trustdex/approved-posture.json \
  .trustdex/current-posture.json \
  --json
```

자동 허용, 쓰기 범위, 네트워크 접근, 서브에이전트, 정책 의미 또는 분류되지 않은
설정이 확대되면 `diff-permissions`는 종료 코드 `1`을 반환합니다. 더 제한적으로만
변한 경우에는 종료 코드 `0`과 `restricted` 상태를 반환합니다. 스냅샷에는 개수,
문서화된 열거 값, 기능 범주, 위험 신호 및 정책 의미 다이제스트만 포함됩니다.
입력 경로, 규칙 지정자, 쓰기 가능 경로, 도메인, 명령, 환경 변수 이름과 값 및
관련 없는 설정 값은 제외합니다. 값이 제거된 규칙 내용이 같은 개수 안에서 바뀌면
감지할 수 없으므로 이는 런타임 강제가 아니라 권고형 CI 검토 게이트입니다.

기계 소비자는 `--json` 출력을
[`schemas/permission-posture-v1.schema.json`](schemas/permission-posture-v1.schema.json)과
[`schemas/permission-posture-diff-v1.schema.json`](schemas/permission-posture-diff-v1.schema.json)으로
검증할 수 있습니다. 병합 소스 스냅샷과 차이는
[`schemas/permission-posture-v2.schema.json`](schemas/permission-posture-v2.schema.json)과
[`schemas/permission-posture-diff-v2.schema.json`](schemas/permission-posture-diff-v2.schema.json)을
사용합니다. 스키마가 바뀌면 새로운 정수 `schemaVersion`을 사용하며 기존
필드의 의미를 조용히 바꾸지 않습니다.

## 도구 출처와 자동 권한 연결

MCP 소스와 해당 소스에 부여된 자동 권한을 하나의 값 없는 기록으로 검토합니다.

```bash
node ./bin/trustdex.mjs snapshot-claude-bindings ./.mcp.json \
  --settings ./.claude/settings.json \
  --trust-store ./trust-store.json \
  --out .trustdex/claude-bindings.json

node ./bin/trustdex.mjs snapshot-codex-bindings ~/.codex/config.toml \
  --trust-store ./trust-store.json \
  --out .trustdex/codex-bindings.json

node ./bin/trustdex.mjs diff-bindings \
  .trustdex/approved-bindings.json \
  .trustdex/current-bindings.json \
  --json
```

Claude에서는 `--settings` 대신 스택 소스 플래그를 사용할 수 있습니다. 범위가
제한된 권한은 MCP 소스가 `ALLOW`일 때만 `bound`가 될 수 있습니다. 와일드카드/전체
도구 권한, ASK 소스, 출처 변경, 일치하지 않는 규칙 및 모호한 서버 이름 일치는
재검토 또는 차단 대상입니다. Codex의 `default_tools_approval_mode = "approve"`는
전체 도구 권한으로 취급합니다. 보고서는 서버 이름과 구조적 개수만 보관하고
엔드포인트 경로, 권한 지정자 및 도구 이름은 제외합니다.
[`schemas/tool-permission-bindings-v1.schema.json`](schemas/tool-permission-bindings-v1.schema.json)과
[`schemas/tool-permission-bindings-diff-v1.schema.json`](schemas/tool-permission-bindings-diff-v1.schema.json)으로
검증할 수 있습니다. 이는 검토 증거이며 런타임 권한 강제 기능이 아닙니다.

## 실제 런타임 도구 증거

권한이 있는 런타임 어댑터는 런타임, 캡처 방식, 서버 이름 및 도구 개수만 포함한
최소 인벤토리를 생성할 수 있습니다. TrustDex는 비공개 파일을 찾거나 도구 호출을
가로채지 않고 이 명시적 입력을 결합 스냅샷과 대조합니다.

```bash
node ./bin/trustdex.mjs keygen \
  --private .trustdex/runtime-producer-private.pem \
  --public .trustdex/runtime-producer-public.pem

node ./bin/trustdex.mjs sign-runtime-inventory \
  ./runtime-tool-inventory.json \
  --private .trustdex/runtime-producer-private.pem \
  --out .trustdex/runtime-attestation.json \
  --ttl-seconds 300

node ./bin/trustdex.mjs snapshot-runtime-tools \
  .trustdex/claude-bindings.json \
  ./runtime-tool-inventory.json \
  --attestation .trustdex/runtime-attestation.json \
  --public .trustdex/runtime-producer-public.pem \
  --max-age-seconds 120 \
  --require-authenticated \
  --out .trustdex/runtime-tools.json

node ./bin/trustdex.mjs diff-runtime-tools \
  .trustdex/approved-runtime-tools.json \
  .trustdex/current-runtime-tools.json \
  --json
```

관찰된 BLOCK 소스와 예상 밖 서버는 `block`, 관찰된 ASK 또는 광범위한 자동 권한
연결은 `needs-review`가 됩니다. 인벤토리에 없는 설정 서버는 제한적으로만 변한
상태입니다. 도구 개수 증가와 새로 관찰된 서버는 재검토를 요구합니다. 인증하지 않은
스키마 v2 인벤토리는 항상 최소 `needs-review`가 됩니다. 인증은 정확한 인벤토리,
고정된 생성자 키, 만료 및 선택적 캡처 나이 제한을 검증하지만 완전성이나 어댑터
안전성을 증명하지는 않습니다. 스키마는
[`schemas/runtime-tool-inventory-v1.schema.json`](schemas/runtime-tool-inventory-v1.schema.json),
[`schemas/runtime-tool-inventory-attestation-v1.schema.json`](schemas/runtime-tool-inventory-attestation-v1.schema.json),
[`schemas/effective-runtime-tools-v2.schema.json`](schemas/effective-runtime-tools-v2.schema.json),
[`schemas/effective-runtime-tools-diff-v2.schema.json`](schemas/effective-runtime-tools-diff-v2.schema.json)입니다.
기존 v1 실제 보고서도 계속 읽을 수 있습니다. 도구 이름 대신 개수만 보관하므로 개수는
같고 도구 집합만 바뀌는 대체는 비교 범위 밖입니다. 검증, 키 교체 및 위협 경계는
[인증된 런타임 증거](docs/RUNTIME_EVIDENCE.ko.md)를 참고하세요.

## 온라인 출처 관찰

일반 검사는 계속 로컬에서만 수행됩니다. 다음 명령은 명시적으로 실행할 때만 네트워크 조회를 수행합니다.

```bash
node ./bin/trustdex.mjs provenance github modelcontextprotocol/servers
node ./bin/trustdex.mjs provenance github-release owner/repository
node ./bin/trustdex.mjs provenance npm @scope/package
node ./bin/trustdex.mjs provenance mcp io.github.user/server
```

조회 결과는 **증거이지 신뢰가 아닙니다**. 증거를 로컬 신뢰 저장소의 주장으로 전환하려면 사용자가 게시자를 명시적으로 지정해야 합니다.

```bash
node ./bin/trustdex.mjs trust-source mcp io.github.user/server \
  --publisher "Example Publisher" \
  --out ./trust-store.json
```

`github-release`의 경우 GitHub가 릴리스 태그 또는 대상 커밋 서명을 검증된 것으로 보고하지 않으면 TrustDex는 신뢰 주장을 생성하지 않습니다.

### 정확한 패키지 바이트 검증

레지스트리 메타데이터는 예상 다이제스트를 식별할 수 있지만, 메타데이터만으로 다운로드한 파일이 해당 값과 일치한다는 것을 증명할 수는 없습니다. 검토한 정확한 패키지 아카이브 또는 아티팩트를 제공하세요.

```bash
node ./bin/trustdex.mjs trust-source npm @scope/package \
  --publisher "Example Publisher" \
  --artifact ./scope-package-1.2.3.tgz \
  --out ./trust-store.json

node ./bin/trustdex.mjs trust-source mcp io.github.user/server \
  --publisher "Example Publisher" \
  --artifact ./downloaded-package \
  --out ./trust-store.json
```

TrustDex는 파일을 로컬에서 읽고 해당 바이트를 npm SRI 메타데이터 또는 MCP Registry SHA-256 다이제스트와 비교합니다. 아티팩트를 다운로드하거나 실행하지 않습니다. 무결성 기반 증거는 특정 버전에 연결됩니다. 설정된 패키지 버전이 다르면 `artifact-version-mismatch`가 발생하며 차단됩니다.

## 출처 신뢰 저장소

예시:

```json
{
  "version": 1,
  "claims": [
    {
      "type": "package",
      "subject": "example-mcp-server",
      "publisher": "Example Publisher",
      "status": "verified",
      "evidence": {
        "kind": "manual-review",
        "reference": "https://example.invalid/security-review"
      }
    }
  ]
}
```

그런 다음:

```bash
node ./bin/trustdex.mjs inspect ./mcp.json \
  --pack official-first \
  --trust-store ./trust-store.json
```

여기서 `verified`는 해당 신뢰 저장소에서 관리하는 증거에 따라 검증되었다는 뜻입니다. OpenAI, TrustDex, GitHub, npm 또는 다른 플랫폼이 확장을 인증했다는 의미가 아닙니다.

## 기능 및 출처 드리프트

기준선 저장:

```bash
node ./bin/trustdex.mjs snapshot ./examples/mcp.json \
  --pack strict \
  --out .trustdex/baseline.json
```

업데이트 후 다른 스냅샷을 저장하고 비교:

```bash
node ./bin/trustdex.mjs diff .trustdex/baseline.json .trustdex/current.json
```

TrustDex는 새로 추가된 신호, 소스 변경, 출처 변경, 결정 변경, 콘텐츠/설정 지문 변경을 보고합니다.

검토 워크플로에서는 서명 키를 한 번 생성하고 차단되지 않은 설정을 승인합니다.

```bash
node ./bin/trustdex.mjs keygen \
  --private .trustdex/private.pem \
  --public .trustdex/public.pem

node ./bin/trustdex.mjs approve ./examples/mcp.json \
  --private .trustdex/private.pem \
  --dir .trustdex/review \
  --pack development
```

나중에 해당 서명된 검토를 기준으로 현재 설정을 다시 평가합니다.

```bash
node ./bin/trustdex.mjs recheck ./examples/mcp.json \
  --review-dir .trustdex/review \
  --public .trustdex/public.pem
```

결과는 `APPROVED`, `NEEDS_REVIEW` 또는 `INVALID`입니다. 지문, 소스, 출처, 신호 또는 정책 관련 변경이 발생하면 이전 상태의 일치가 무효화됩니다.

## 서명된 신뢰 기록

로컬 서명 키 생성:

```bash
node ./bin/trustdex.mjs keygen \
  --private .trustdex/trustdex-private.pem \
  --public .trustdex/trustdex-public.pem
```

검토된 스냅샷 서명:

```bash
node ./bin/trustdex.mjs sign .trustdex/baseline.json \
  --private .trustdex/trustdex-private.pem \
  --out .trustdex/trust-record.json
```

나중에 검증:

```bash
node ./bin/trustdex.mjs verify .trustdex/trust-record.json \
  --public .trustdex/trustdex-public.pem \
  --snapshot .trustdex/baseline.json
```

비공개 키는 절대 커밋하면 안 됩니다.

## GitHub Action

```yaml
- uses: actions/checkout@v4

- uses: grigent/trustdex@v0.11.0
  with:
    config: ./mcp.json
    pack: official-first
    trust-store: ./trust-store.json
    output: .trustdex/gated-mcp.json
```

프로덕션 CI에서는 이동하는 브랜치 대신 검토된 커밋 SHA에 Action을 고정하세요.

## 원칙

1. **로컬 우선.** 비공개 에이전트 설정이 컴퓨터 밖으로 나갈 필요가 없어야 합니다.
2. **맹목적으로 신뢰하지 않기.** 출처가 없으면 추측으로 ALLOW하지 않고 검토하거나 거부해야 합니다.
3. **출력에 비밀 값 포함 금지.** 환경 변수 이름은 보고할 수 있지만 값은 보고하지 않습니다.
4. **드리프트는 중요합니다.** 신뢰 관련 변경이 발생해도 승인이 조용히 유지되어서는 안 됩니다.
5. **단순한 결과.** 불투명한 위험 점수 대신 ALLOW / ASK / BLOCK을 사용합니다.
6. **브랜딩보다 증거.** 익숙한 이름만으로 "공식"이라고 추론하지 않습니다.
7. **런타임 중립.** 도구 출처와 에이전트 행동 권한은 Codex와 Claude 모두에서 검토할 수 있어야 하며, 추가 런타임으로 확장할 수 있어야 합니다.

## 로드맵

공개 로드맵은 [docs/ROADMAP.ko.md](docs/ROADMAP.ko.md)에서 관리합니다. 단기 작업은 안정적인 옵트인 런타임 어댑터, 호환성 테스트, 재현 가능한 통제 및 실제 파일럿 피드백에 중점을 둡니다. 로드맵 항목은 계획이며 약속이 아닙니다.

## 보안

TrustDex는 서드파티 코드가 안전하다는 것을 **증명하지 않으며**, 샌드박싱, 의존성 검사, 코드 검토 또는 최소 권한 자격 증명을 대체하지 않습니다.

[SECURITY.ko.md](SECURITY.ko.md), [docs/THREAT_MODEL.ko.md](docs/THREAT_MODEL.ko.md), [docs/DEFENSIVE_USE_CASE.ko.md](docs/DEFENSIVE_USE_CASE.ko.md), [docs/SECURITY_RESEARCH.ko.md](docs/SECURITY_RESEARCH.ko.md), [docs/EVALUATION.ko.md](docs/EVALUATION.ko.md), [docs/TRUST_STORE.ko.md](docs/TRUST_STORE.ko.md)를 참고하세요.

## 기여

기여를 환영합니다. [CONTRIBUTING.ko.md](CONTRIBUTING.ko.md), [GOVERNANCE.ko.md](GOVERNANCE.ko.md), [CODE_OF_CONDUCT.ko.md](CODE_OF_CONDUCT.ko.md), [AGENTS.ko.md](AGENTS.ko.md)를 참고하세요.

## 라이선스

MIT
