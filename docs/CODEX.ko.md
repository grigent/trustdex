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
npx trustdex@0.4.4 inspect-codex ~/.codex/config.toml --pack strict
```

이 명령은 파일을 로컬에서 읽으며 네트워크 요청을 하지 않습니다. 출력에는 각 MCP 서버, 소스 유형, 신뢰 신호 및 ALLOW / ASK / BLOCK 결정이 표시됩니다. 환경 변수 이름은 표시될 수 있지만 값은 절대 표시되지 않습니다.

기계가 읽을 수 있는 출력에는 `--json`을 사용하고, 명시적인 게시자 증거를 연결하려면 `--trust-store ./trust-store.json`을 사용하세요([TRUST_STORE.ko.md](TRUST_STORE.ko.md) 참고).

### 2. 게이트된 사본 작성

```bash
npx trustdex@0.4.4 gate-codex ~/.codex/config.toml \
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

### 스킬 및 플러그인

에이전트 스킬과 플러그인 매니페스트도 같은 방법으로 검사할 수 있습니다.

```bash
npx trustdex@0.4.4 inspect-skill ./path/to/SKILL.md --pack strict
npx trustdex@0.4.4 inspect-plugin ./path/to/plugin.json --pack strict
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
