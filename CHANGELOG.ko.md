# 변경 기록

<p align="right">
  <a href="./CHANGELOG.md">English</a> | <strong>한국어</strong>
</p>

## 미출시

- 러너 옵션으로 실제 설치되는 패키지를 판단: `uvx --from`과 `npx -p/--package`가 패키지를 지정하며, `uvx --python 3.12` 같은 옵션 값을 더 이상 패키지로 오인하지 않음. 레지스트리 재지정(`--registry`, `--userconfig`, `--index-url`, `--extra-index-url`, `--find-links` 등)은 `package-source-override`(BLOCK), 추가 패키지(`uvx --with`, 반복된 `-p`)는 `additional-packages`(BLOCK, `development`에서는 ASK), `npx -c/--call`과 `--node-options`는 `shell-execution`, 인식하지 못한 러너 옵션이나 `=값`을 붙인 플래그(npm은 `-y=x`를 `--yes x`로 펼침)는 `ambiguous-runner-arguments`(BLOCK)를 추가
- 패키지·설정·설치된 실행 파일의 출처를 바꾸는 러너 옵션을 `package-source-override`(BLOCK)로 처리: npm `--cache`, `--prefix`, `--workspace`, uv `--config-file`, `--env-file`, `--constraint`, `--override`, `--build-constraint`, `--cache-dir`, `--keyring-provider`, 그리고 버전이 아닌 경로나 프로그램 이름을 준 `--python`
- `npx -p`/`uvx --from`이 패키지 자신의 이름이 아닌 명령(`sh`, `python` 등, 검토한 패키지가 아니라 PATH에서 찾음)을 실행하면 `runner-command-mismatch`(BLOCK, `development`에서는 ASK) 추가
- 러너 서버의 `env`가 러너·인터프리터·로더 설정(`npm_config_*`, `UV_*`, `BUN_CONFIG_*`, `NODE_OPTIONS`, `PYTHONPATH`, `LD_PRELOAD`, `DYLD_*`, `PATH`, `HOME` 등)을 지정하면 `runner-environment-override`(BLOCK) 추가
- 정확한 버전만 고정으로 인정: `@` 뒤의 완전한 시맨틱 버전, 또는 `==` 뒤의 와일드카드 없는 PEP 440 버전(이전에는 `name@^1.0.0`, `name@1.2`, `name@1.x`, `name==1.*`도 고정으로 보고됨)
- `trustedPackages`와 신뢰 저장소 패키지 주장은 레지스트리 지정에서만 이름으로 일치시키고, 신뢰한 이름으로 시작하는 URL·원격·경로(예: `trusted@https://...`)는 전체가 같을 때만 일치

- **보안:** 줄 단위 Codex TOML 처리를 TOML 렉서로 교체. 이전에는 공백이나 따옴표가 들어간 헤더(`[mcp_servers . x]`, `["mcp_servers".x]`)나 루트 수준 점 키로 작성한 MCP 서버를 `inspect-codex`가 건너뛰었고, 이 서버가 검사 없이 `gate-codex`를 통과했음. 백슬래시로 끝나는 리터럴 문자열이 뒤따르는 테이블을 숨길 수 있었고, 따옴표가 들어간 설정 헤더가 `inspect-codex-settings`에서 샌드박스·승인 설정을 숨길 수 있었음. 이제 이 경우들은 모두 검사하거나 거부함
- Codex MCP 환경 변수마다 정적 값인지, 호스트에서 전달되는지(`source` 포함), 베어러 토큰인지, 그리고 `env_http_headers` 헤더마다 어떤 호스트 변수를 읽는지 기록. 잘못된 `env_vars`, 중복 키, 반복된 서버 테이블, 테이블 배열, 제어 문자, 잘못된 맨 값을 거부(**호환성:** 모든 Codex MCP 지문이 한 번 바뀌므로 기존 Codex 스냅샷과 결합은 지문 변경을 보고하며 한 번 재검토가 필요함)
- 패키지 지정(URL, `name@url`, scp 형식 원격, uvx `--from`)에 포함된 자격 증명, 쿼리 값, `;params`를 출력·스냅샷에 남기지 않도록 수정. 단순한 레지스트리 지정, `npm:` 별칭, 로컬 경로는 그대로 보여 주고, 그 밖의 지정은 WHATWG URL 파서(알려진 스킴만)나 scp 형식 원격으로 해석해 스킴, 호스트, 경로, git ref만 보여 주며, 해석할 수 없는 지정은 `<unparseable-package-spec>`으로 표시하고 모든 팩에서 BLOCK(`unparseable-package-spec`). 단순한 지정만 고정 버전으로 인정하고, 쿼리 값이나 `;params`가 있는 패키지 URL은 보여 줄 수도 추적할 수도 없으므로 모든 팩에서 BLOCK(`package-url-query`)
- `--flag=URL` 값을 포함한 모든 명령줄 인수의 URL·scp 형식 자격 증명에 `embedded-credentials`를 표시하고, 그 인수는 자격 증명을 뺀 형태로 지문에 넣음. 쿼리 값을 비롯한 다른 인수 값의 변경은 계속 지문을 바꿈
- IDE 확장의 설치 출처와 대상 플랫폼은 알려진 값만 보고하고, 신뢰할 수 없는 `displayName`은 결과에서 제외
- 지원하는 모든 입력 형식에 고유한 값을 심고 어떤 명령이든 그 값을 출력하거나 저장하면 실패하는 카나리 회귀 테스트를 추가하고, 출력 비식별 규칙(이름은 보고 가능, 값은 금지) 문서화
- 모든 검사 명령에 `--decisions` 추가: 종료 코드가 판정과 일치하고 검사 실패 시 BLOCK을 보고하는, 버전이 있고 값이 없는 `trustdex-decisions` JSON 보고서
- `--policy` 파일을 엄격하게 검증하여 알 수 없는 필드, 지원하지 않는 버전, 잘못된 판정 값을 조용히 대체하지 않고 거부(**호환성:** 필드 이름에 오타가 있는 정책은 이제 오류가 남)
- `--decisions` 모드에서 빈 인벤토리를 ASK로 보고하고, 이를 구현하지 않은 명령에서는 `--decisions`를 거부하며, 객체가 아닌 MCP 항목을 버리지 않고 실패 시 차단
- 정책 파일을 불러올 때 `signalActions`의 알 수 없는 신호 이름과 정확한 버전이 없는 IDE 확장 항목을 거부
- 판정 보고서, 정책 파일, v3 신뢰 스냅샷의 JSON 스키마를 공개하고 에이전트 연동 및 운영 규칙 문서화
- 검토한 Codex `config.toml`에 서명하고 Codex 고유의 도구·승인 모드 변경까지 드리프트를 재확인할 수 있도록 `snapshot-codex`, `approve-codex`, `recheck-codex` 추가
- 오류 메시지가 입력 내용을 인용하지 않도록 수정: 잘못된 JSON은 파일 이름만 보고하고, Codex TOML 인라인 테이블 오류는 자격 증명이 들어 있을 수 있는 항목을 더 이상 출력하지 않음
- 따옴표 없는 TOML 값(맨 단어, 날짜)을 문자열로 읽지 않고 거부
- VS Code 호환 에디터 확장 디렉터리(VS Code, Cursor)를 위한 `inspect-ide-extensions`, `snapshot-ide-extensions`, `approve-ide-extensions`, `recheck-ide-extensions` 추가
- IDE 확장은 정확한 버전의 `trustedIdeExtensions` 고정(선택적으로 설치 파일 다이제스트 포함)으로만 허용하고, 정책 오버레이가 줄일 수 없는 `blockedIdeExtensions` 차단 목록 추가
- 심볼릭 링크를 따라가지 않고 설치된 모든 확장 파일(내용과 실행 권한)의 다이제스트를 계산하고, `.obsolete`가 등록된 확장을 숨기지 못하게 하며, 잘못되었거나 일반 파일이 아닌 설치 기록, 누락된 매니페스트, 설치 기록과 매니페스트 불일치, 버전 범위, 지정 디렉터리 밖이나 심볼릭 링크를 거치는 위치에 대해 실패 시 차단
- 정책 오버레이와 관계없이 고정되지 않은 IDE 확장은 ASK 이상, IDE 무결성 신호는 BLOCK으로 유지
- 릴리스 및 배포 워크플로가 사용하는 npm CLI를 정확한 버전으로 고정

## 0.11.0 - 2026-10-24

- 정확한 값 없는 Claude/Codex 런타임 인벤토리를 위한 수명이 짧은 Ed25519 생성자 증명 추가
- 다른 키, 변조, 만료, 오래된 캡처, 과도한 수명 및 미래 시각 런타임 증거 거부
- 안전하게 실패하는 인증 상태와 생성자 키 드리프트를 포함한 스키마 v2 실제 증거, CLI 워크플로, 테스트 및 운영 가이드 추가

## 0.10.0 - 2026-10-24

- 명시적인 값 없는 Claude/Codex 런타임 MCP 인벤토리 계약과 실제 경계 대조 추가
- 관찰된 BLOCK 또는 미설정 서버를 차단하고 ASK/광범위 권한 노출에 재검토 요구
- 자체 검증 런타임 증거 스냅샷, 드리프트 분류, 버전 지정 스키마 및 비활성 픽스처 추가

## 0.9.0 - 2026-10-24

- 권한 지정자나 도구 이름을 보관하지 않고 Claude Code 및 Codex MCP 정책/출처 결과를 자동 도구 권한과 연결
- 자체 검증 결합 스냅샷, 드리프트 분류, 버전 지정 JSON 스키마 및 비활성 적대적 픽스처 추가
- 일치하지 않거나 모호한 Claude MCP 권한 규칙과 차단/출처 불일치 소스의 자동 권한을 안전하게 실패하도록 처리

## 0.8.0 - 2026-10-24

- 문서화된 소스 우선순위를 사용하는 명시적 Claude Code 및 Codex 설정 스택 검사 추가
- 소스 경로를 제외하고 소스 구성 드리프트에 재검토를 요구하는 스키마 v2 병합 권한 상태 스냅샷 추가
- 높은 우선순위 소스가 재정의하더라도 잘못된 낮은 우선순위 소스를 안전하게 실패하도록 처리

## 0.7.0 - 2026-10-24

- 자체 일관성을 검증하는 Claude 및 Codex 권한 상태 스냅샷과 자율성 확대 검토 게이트 추가
- 값이 제거된 검사, 스냅샷 및 차이 출력을 검증하는 비활성 적대적 권한 픽스처 추가

## 0.6.0 - 2026-10-24

- 자동 셸, 파일 시스템, 네트워크, MCP 및 서브에이전트 권한을 위한 Claude Code 권한 정적 검사 추가
- Codex 승인, 샌드박스, 네트워크, 쓰기 가능 루트, 웹 검색 및 서브에이전트 설정 정적 검사 추가
- 명령, 경로, 도메인, 훅, 자격 증명 도우미 또는 관련 없는 설정 값을 보관하지 않고 지원하지 않는 보안 관련 설정을 안전하게 거부
- 프로젝트의 방어적 AI 에이전트 보안 사용 사례, 허가 경계, CVP 증거 경계 및 재현 가능한 평가 문서화
- 문서화된 로컬 평가를 npm 아티팩트에서도 재현할 수 있도록 게시 패키지에 비활성 예제 포함

## 0.5.1 - 2026-10-24

- 신뢰 관련 엔드포인트 구조는 유지하면서 URL 자격 증명, 쿼리 값, 민감한 명령 인수를 설정 지문에서 제외

## 0.5.0 - 2026-10-07

- stdio, HTTP 및 SSE 설정에 대한 Claude MCP JSON 검사 및 게이트 추가
- 지원하지 않는 Claude 설정과 해석되지 않은 명령/엔드포인트 확장을 안전하게 실패하도록 처리
- 인증 헤더 메타데이터를 검토하고 비밀 값을 보관하지 않으면서 셸 기반 헤더 도우미를 기본적으로 차단
- Claude 전용 스냅샷과 서명된 승인/재검사 명령 추가
- Claude Code 및 Claude Desktop 게이트 워크플로 문서화

## 0.4.4 - 2026-10-06

- 문서화된 방어적 보안 연구 정책과 재현 가능한 평가 기록 추가
- ALLOW / ASK / BLOCK 기대 결과와 드리프트 테스트가 적용된 비활성 적대적 MCP 픽스처 추가
- 향후 GitHub 릴리스용 체크섬과 CycloneDX SBOM 생성
- 향후 릴리스 패키지용 GitHub 빌드 출처 및 SBOM 증명 생성

## 0.4.3 - 2026-09-30

CLI 정확성 및 Codex 유지관리 준비:

- 0.4.2 패키지에서 `trustdex --version`과 도움말 배너가 0.4.0을 보고하던 문제 수정. 이제 CLI는 `package.json`에서 버전을 읽음
- TrustDex의 보안 불변 조건을 검토 발견 사항으로 정의하는 Codex 검토 지침을 AGENTS.md에 추가
- Codex 통합 가이드(`docs/CODEX.md`) 추가
- 파일럿 피드백 이슈 양식 추가
- CodeQL 초기화와 분석을 함께 업데이트하고 관련 Dependabot 업데이트를 그룹화

## 0.4.2 - 2026-09-19

신뢰할 수 있는 npm 게시 방식으로 마이그레이션:

- npm Trusted Publisher OIDC를 통해 `grigent/trustdex`와 `.github/workflows/publish.yml`만 승인
- 게시 워크플로에서 장기 `NPM_TOKEN` 대체 경로 제거
- 모든 npm 릴리스에 Sigstore 출처 유지
- npm 및 GitHub Action 예제를 검증 릴리스에 맞게 조정

## 0.4.1 - 2026-09-19

npm 패키징 수정:

- 정규화된 `bin` 경로를 사용해 게시된 npm 매니페스트의 `trustdex` 명령 유지
- npm 및 출처 도구용 저장소 메타데이터 정규화
- 직접적인 `npx trustdex` 사용법을 문서화하고 npm 버전 배지 노출

## 0.4.0 - 2026-09-19

보안 강화, 아티팩트 무결성 및 공개 유지관리 준비:

- Ubuntu, Windows 및 macOS에서 전체 크로스 플랫폼 CI 실행
- CI에서 복합 GitHub Action을 엔드투엔드로 실행
- 사용자가 제공한 아티팩트 바이트를 npm SRI 또는 MCP Registry SHA-256 메타데이터와 대조해 검증
- 무결성 증거를 패키지 버전에 연결하고 설정 불일치 차단
- 검사 출력에서 원격 URL 자격 증명, 경로 및 쿼리 값 제거
- URL에 포함된 자격 증명, 안전하지 않은 전송 및 URL 쿼리 매개변수 표시
- 플랫폼 전반에서 Windows 실행 파일 경로와 명령 래퍼 정규화
- 지원하지 않는 Codex MCP 키와 하위 섹션을 안전하게 실패하도록 처리
- 지원되는 Codex 실행 제어의 지문 생성
- CodeQL, 변경 불가능한 GitHub Action 고정값, 의존성 업데이트 및 소유권 규칙 추가
- 거버넌스, 지원, 아키텍처, 로드맵 및 기여 템플릿 추가

## 0.3.0 - 2026-09-19

검토 가능한 출처 및 Codex 통합:

- MCP 설정, 스킬 및 플러그인 매니페스트에 대한 신뢰 관련 지문
- 자동 `APPROVED` / `NEEDS_REVIEW` 재검사를 포함한 서명된 승인 번들
- 명시적인 GitHub 저장소 및 npm 레지스트리 출처 조회
- 공식 MCP Registry v0.1 출처 조회
- GitHub 최신 릴리스 서명 검증
- Codex `config.toml` MCP 전용 파서 및 섹션 게이트
- `mcpServers`와 `servers` JSON 컨테이너 형식 모두 지원
- 신원 불일치, 서명 상태, 지문 드리프트 및 Codex 게이트에 대한 추가 테스트

## 0.2.0

신뢰 및 출처 게이트:

- 기본 제공 `strict`, `official-first`, `development` 정책 팩
- 증거 메타데이터가 포함된 명시적 출처 신뢰 저장소
- 정책 승인 서버만 출력하는 런타임 MCP 게이트
- 에이전트 스킬 및 플러그인 매니페스트 검사
- 출처 드리프트 감지를 포함한 스냅샷 스키마 v2
- Ed25519 서명 신뢰 기록
- GitHub Action 지원
- 확장된 보안 테스트 및 문서

## 0.1.0

최초 작동 프로토타입:

- MCP JSON 설정을 로컬에서 검사
- 패키지, 원격, 로컬 및 알 수 없는 소스 분류
- 비밀 값을 출력하지 않고 신뢰 관련 신호 감지
- ALLOW / ASK / BLOCK 정책 결정 적용
- 결정론적 스냅샷 생성
- 소스 및 신호 드리프트를 확인하는 스냅샷 비교
- Node.js 테스트 스위트 및 GitHub Actions CI
