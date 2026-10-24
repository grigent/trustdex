# Codex에서 TrustDex 사용하기

<p align="right">
  <a href="./CODEX.md">English</a> | <strong>한국어</strong>
</p>

이 가이드는 Codex 클라이언트가 시작할 수 있는 MCP 서버를 게이트하는 방법과 TrustDex 자체를 Codex로 유지관리하는 방법을 설명합니다.

TrustDex는 독립 프로젝트입니다. OpenAI와 제휴하거나 OpenAI의 보증 또는 인증을 받지 않았으며, ALLOW 결정은 OpenAI 또는 TrustDex의 안전 인증이 아닙니다.

## Codex MCP 서버 게이트

Codex 클라이언트는 `config.toml`(기본적으로 `~/.codex/` 아래)의 `[mcp_servers.<name>]` 테이블에서 MCP 서버 정의를 읽습니다. 각 항목은 로컬 프로세스를 시작하거나 제공된 자격 증명으로 원격 엔드포인트에 연결할 수 있습니다.

### 1. 현재 설정 검사

```bash
npx trustdex@0.11.0 inspect-codex ~/.codex/config.toml --pack strict
```

이 명령은 파일을 로컬에서 읽으며 네트워크 요청을 하지 않습니다. 출력에는 각 MCP 서버, 소스 유형, 신뢰 신호 및 ALLOW / ASK / BLOCK 결정이 표시됩니다. 환경 변수 이름은 표시될 수 있지만 값은 절대 표시되지 않습니다.

기계가 읽을 수 있는 출력에는 `--json`을 사용하고, 명시적인 게시자 증거를 연결하려면 `--trust-store ./trust-store.json`을 사용하세요([TRUST_STORE.ko.md](TRUST_STORE.ko.md) 참고).

### 2. 게이트된 사본 작성

```bash
npx trustdex@0.11.0 gate-codex ~/.codex/config.toml \
  --pack official-first \
  --trust-store ./trust-store.json \
  --out ./gated-config.toml
```

게이트된 파일은 관련 없는 TOML 섹션(모델, 기능, 프로필)을 그대로 유지하며 ALLOW가 아닌 모든 MCP 섹션을 제거합니다. 다른 승인 계층이 있을 때만 사용해야 하는 `--include-ask`를 전달하지 않는 한 `ASK` 항목도 제외됩니다.

사용하기 전에 차이를 검토하세요.

```bash
diff ~/.codex/config.toml ./gated-config.toml
```

TrustDex는 `config.toml`을 직접 수정하지 않습니다. 원본 파일을 교체하거나 Codex 설치가 게이트된 사본을 가리키도록 하는 작업은 검토 후 사용자가 명시적으로 수행합니다.

### 3. 변경할 때마다 다시 실행

패키지 버전이 올라가거나, 런처가 바뀌거나, 새 환경 변수가 전달되면 MCP 항목이 변경됩니다. `config.toml`이 변경될 때마다 `inspect-codex`와 `gate-codex`를 다시 실행하세요. dotfiles 저장소의 CI 작업 또는 pre-commit 훅이 적합합니다.

[README](../README.ko.md#기능-및-출처-드리프트)의 서명된 `snapshot`, `approve`, `recheck` 드리프트 워크플로는 현재 MCP JSON만 받습니다. Codex `config.toml`로 확장하는 작업은 [로드맵](ROADMAP.ko.md)에 기록되어 있습니다.

### 안전하게 실패하는 파싱

TrustDex는 Codex MCP 섹션에 사용되는 TOML 구성만 파싱합니다. 지원하지 않는 MCP 키, 중첩 하위 섹션 또는 구문은 건너뛰지 않고 오류로 보고되므로 TrustDex가 완전히 읽을 수 없는 설정이 조용히 ALLOW가 되지 않습니다.

## Codex 실행 권한 검사

MCP 게이트는 외부 도구를 제어하고 Codex 승인·샌드박스 설정은 에이전트가 로컬에서 할 수 있는 일을 제어합니다. 이 설정을 별도로 검사하세요.

```bash
node ./bin/trustdex.mjs inspect-codex-settings \
  ./examples/codex.permissions.toml \
  --pack strict \
  --json
```

어댑터는 `approval_policy`, `approvals_reviewer`, `sandbox_mode`, `default_permissions`, `web_search` 및 문서화된 `sandbox_workspace_write` 키를 검증합니다. 다음을 보고합니다.

- `danger-full-access`는 `BLOCK`
- `workspace-write`, 외부 네트워크 접근, 추가 쓰기 가능 루트, 실시간 웹 검색, 자동 검토 및 `approval_policy = "never"`는 최소 `ASK`
- 명시적인 멀티 에이전트 활성화, 사용자 정의 권한 프로필, 앱/플러그인 섹션 및 완전히 검사하지 않는 설정은 `ASK`

보안 관련 값의 타입이나 열거 값이 지원되지 않으면 안전하게 실패합니다. 공식 설정 레퍼런스가 함께 사용하지 말라고 명시하므로 `default_permissions`와 기존 샌드박스 설정을 같이 사용해도 실패합니다. 쓰기 가능 루트 경로와 관련 없는 설정의 값은 보관·출력·지문화하지 않습니다.

문서화된 설정 우선순위를 적용하려면 스택 명령을 사용하세요. `--project`는 저장소 루트에서 현재 디렉터리 방향으로 반복하며 가장 가까운 프로젝트 파일이 우선합니다.

```bash
node ./bin/trustdex.mjs inspect-codex-settings-stack \
  --system ./review/system.toml \
  --managed ./review/managed.toml \
  --user ./review/user.toml \
  --profile ./review/profile.toml \
  --project ./review/root-project.toml \
  --project ./review/closest-project.toml \
  --cli ./review/cli-overrides.toml \
  --pack strict --json
```

스택은 시스템부터 CLI 우선순위까지 지원되는 보안 필드별로 병합됩니다. 높은 소스가 재정의하더라도 어떤 소스에 지원하지 않는 구문이 있으면 안전하게 실패합니다. 보고서에는 고정된 소스 범위 개수만 남고 설정 경로나 관련 없는 값은 남지 않습니다. 소스는 명시적 입력이며 신뢰된 프로젝트, 활성 프로필, 클라우드 관리 기본값, 요구사항 또는 CLI 플래그를 자동으로 찾지 않습니다. 이는 정적 증거이며 Codex 샌드박스 자체가 아닙니다. 클라이언트에서 활성 권한 프로필을 확인하세요. 공식 OpenAI 문서는 샌드박스 경계와 승인 처리를 구분합니다. [설정 레퍼런스](https://developers.openai.com/codex/config-reference)와 [설정 우선순위](https://developers.openai.com/codex/config-basic)를 참고하세요.

### 권한 상태 드리프트

검토한 구조적 기준 상태를 생성해 커밋한 뒤 CI에서 현재 스냅샷을 만들고
비교하세요.

```bash
node ./bin/trustdex.mjs snapshot-codex-settings \
  ~/.codex/config.toml \
  --pack strict \
  --out .trustdex/codex-posture.json

node ./bin/trustdex.mjs snapshot-codex-settings-stack \
  --system ./review/system.toml \
  --user ./review/user.toml \
  --project ./review/project.toml \
  --pack strict \
  --out .trustdex/codex-stack-posture.json

node ./bin/trustdex.mjs diff-permissions \
  .trustdex/approved-codex-posture.json \
  .trustdex/current-codex-posture.json \
  --json
```

네트워크 활성화, 더 넓은 쓰기 범위, 더 약한 샌드박스나 승인 상태, 실시간 검색,
서브에이전트 활성화, 새 위험 신호 및 정책 의미 변경은 검토를 요구하고 종료 코드
`1`을 반환합니다. 제한적으로만 변한 경우 종료 코드 `0`을 반환합니다. 스냅샷은
구조적 개수와 문서화된 열거 값만 저장하며 설정 파일 경로, 쓰기 가능 루트 경로,
사용자 정의 프로필 값 또는 관련 없는 설정은 저장하지 않습니다. 다이제스트는
우발적이거나 조정되지 않은 편집을 감지하지만 누구나 서명되지 않은 다이제스트를
다시 계산할 수 있습니다. 인증이 아니며 Codex 런타임 샌드박스를 대체하지 않습니다.
병합 소스 스냅샷은 스키마 v2를 사용합니다. 최종 구조 설정이 같더라도 소스 범위 개수가
바뀌면 분류되지 않은 변경으로 처리되어 `NEEDS_REVIEW`를 반환합니다.

### MCP 출처와 자동 권한 연결

Codex는 한 MCP 서버가 노출한 모든 도구를 자동 승인할 수 있습니다. 이 권한을
서버의 정책 및 출처 결과와 함께 검토합니다.

```bash
node ./bin/trustdex.mjs snapshot-codex-bindings ~/.codex/config.toml \
  --trust-store ./trust-store.json \
  --pack strict \
  --out .trustdex/codex-bindings.json

node ./bin/trustdex.mjs diff-bindings \
  .trustdex/approved-codex-bindings.json \
  .trustdex/current-codex-bindings.json
```

`default_tools_approval_mode = "approve"`는 전체 도구 자동 권한이므로 ALLOW
소스에서도 검토가 필요합니다. 와일드카드 도구 범위는 불리언으로 기록하며 도구
이름, 엔드포인트 경로 및 관련 없는 값은 제외합니다. 이 정적 연결은 설정이 실제로
로드되었음을 증명하거나 Codex 런타임 샌드박스를 강제하지 않습니다.

### 명시적 런타임 인벤토리 비교

권한이 있는 Codex 통합은 해당 세션에 보이는 MCP 서버 이름과 서버별 도구 개수를
담은 `agent-runtime-tool-inventory` JSON을 제공할 수 있습니다.
`snapshot-runtime-tools <bindings> <inventory> --out <evidence>`로 검토된 Codex
결합 스냅샷과 대조하고, `diff-runtime-tools`로 노출 확대를 게이트합니다. 이는 옵트인
증거 어댑터 계약이며 자동 설정 탐색, 공식 Codex 내보내기 형식 또는 런타임 강제가
아닙니다. 캡처 경로와 샌드박스는 클라이언트에서 별도로 확인하세요. 운영 증거에는
[인증된 런타임 증거](RUNTIME_EVIDENCE.ko.md)에 나온 `sign-runtime-inventory`, 고정된
생성자 공개 키, 제한된 `--max-age-seconds` 및 `--require-authenticated`를 사용하세요.

### 스킬 및 플러그인

에이전트 스킬과 플러그인 매니페스트도 같은 방법으로 검사할 수 있습니다.

```bash
npx trustdex@0.11.0 inspect-skill ./path/to/SKILL.md --pack strict
npx trustdex@0.11.0 inspect-plugin ./path/to/plugin.json --pack strict
```

이 명령은 파이프로 연결된 셸 설치 프로그램, 민감한 경로 참조, 네트워크 URL 및 와일드카드 도구 범위와 같은 관찰 가능한 신호를 보고합니다. 스킬이나 플러그인이 안전하다는 것을 증명하지는 않습니다.

## CI에서 MCP 설정 게이트

에이전트용 MCP 설정을 제공하는 저장소는 모든 풀 리퀘스트에서 [TrustDex GitHub Action](../README.ko.md#github-action)으로 게이트할 수 있습니다. Action을 검토된 커밋 SHA에 고정하세요.

## Codex를 사용한 TrustDex 유지관리

TrustDex는 사용자에게 적용하도록 요청하는 것과 동일한 신뢰 경계를 사용해 Codex를 검토자 및 유지관리 도우미로 사용합니다.

- [AGENTS.ko.md](../AGENTS.ko.md)에는 개발 규칙과 Codex 코드 검토가 TrustDex 풀 리퀘스트에 적용하는 **검토 지침** 섹션이 있습니다. 지침은 프로젝트의 보안 불변 조건(조용한 ALLOW 금지, 출력에 비밀 값 금지, 출처가 차단 신호를 무시하지 못함, 안전하게 실패하는 파싱, Action 고정)을 명시적인 검토 발견 사항으로 전환합니다.
- Codex 제안은 다른 기여와 동일하게 취급됩니다. 풀 리퀘스트를 거치고, 크로스 플랫폼 CI 매트릭스와 CodeQL을 통과해야 하며, 유지관리자 검토 후에만 병합됩니다.
- Codex는 릴리스 자격 증명을 보유하지 않습니다. npm 게시는 유지관리자가 트리거하는 `.github/workflows/publish.yml`에서 Sigstore 출처가 포함된 Trusted Publisher OIDC를 사용합니다.

Codex 또는 다른 코딩 에이전트로 기여하는 경우 변경 사항에도 동일한 AGENTS.md 규칙이 적용됩니다.
