# 변경 기록

<p align="right">
  <a href="./CHANGELOG.md">English</a> | <strong>한국어</strong>
</p>

## 미출시

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
