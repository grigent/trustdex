# 설계 노트: Sigstore 검증, 런타임 어댑터, 레지스트리, 조직 신뢰 저장소

<p align="right">
  <a href="./DESIGN_NOTES.md">English</a> | <strong>한국어</strong>
</p>

이 문서는 논의를 위한 제안입니다. 상태 줄에 따로 적지 않은 한 여기 적힌 내용은 구현되어 있지 않으며, 각 항목은 `AGENTS.md`의 규칙(설계 논의 없이 새 의존성, 네트워크 호출, `child_process` 사용 금지)에 닿기 때문에 코드를 쓰기 전에 명시적인 결정이 필요합니다.

## 1. npm provenance의 Sigstore 서명 검증

> 상태: 아래 선택지 A를 `src/sigstore.mjs`에 구현했습니다. 확인하는 것과 확인하지 않는 것은 [TRUST_STORE.ko.md](TRUST_STORE.ko.md)에 있습니다. 이제 `matched` 결과에는 검증된 서명이 필요합니다. 머클 포함 증명과 내장 SCT도 검증하며, 신뢰 루트 갱신 검토 절차는 [TRUST_ROOT.ko.md](TRUST_ROOT.ko.md)에 있습니다. 이 절의 나머지는 설계 기록으로 남겨 둡니다.

### 현재

`provenance npm`과 `trust-source npm`은 `registry.npmjs.org`가 해당 버전에 대해 제공하는 증명을 받아, 그 증명이 버전의 sha512를 가리키는지 확인하고, 증명 안의 소스 저장소를 패키지가 선언한 저장소와 비교합니다. 증명의 서명은 확인하지 않으며 증거에 `signatureVerified: false`로 기록합니다. 따라서 레지스트리가 정직한 증명을 제공한다고 신뢰하는 상태입니다.

### 검증이 추가하는 것

증명이 Sigstore CA가 해당 저장소의 GitHub Actions 워크플로에 발급한 인증서로 서명되었고, 그 서명이 투명성 로그에 기록되었는지 확인합니다. 그러면 레지스트리나 네트워크 공격자가 지어낸 증명을 제시할 수 없게 됩니다.

### 선택지

| 선택지 | 의존성 | 네트워크 | 주된 비용 |
| --- | --- | --- | --- |
| A. 저장소에 고정한 신뢰 루트로 `node:crypto`만 써서 검증 | 없음 | 이미 하는 증명 요청 외에 없음 | 인증서 체인, DSSE, 로그 항목 검사 코드를 TrustDex가 직접 관리해야 하고, Sigstore가 키를 교체하면 고정한 루트를 갱신해야 함 |
| B. `sigstore` npm 패키지 사용 | 지금은 의존성이 없는 도구에 의존성 트리 추가 | TUF로 신뢰 루트를 받아옴 | TrustDex 자체의 공급망 노출 |
| C. `npm audit signatures` 실행 | 없음 | npm이 하는 만큼 | `bin/`과 `src/`에서 쓰지 않는 `child_process` 필요 |
| D. 현재 동작 유지 | 없음 | 없음 | 레지스트리를 계속 신뢰 |

### 권장

선택지 A를 다음 검사로 한정합니다. 리프 인증서에 대한 DSSE 봉투 서명, 고정한 Fulcio 루트까지의 인증서 체인, 인증서의 발급자·저장소 필드와 비교 대상 저장소의 일치, 고정한 로그 키에 대한 투명성 로그 서명 항목, 로그 시각이 인증서 유효 기간 안에 있는지.

닫힌 실패 규칙: 검사가 실패하거나 지원하지 않는 형식이면 `signatureVerified: false`와 `unverifiable` 결과를 유지하며, `trust-source`는 이미 이 결과를 거부합니다. 만료되었거나 모르는 신뢰 루트는 건너뛰지 않고 실패로 처리합니다. `check-install`과 `claude-hook`은 바뀌지 않습니다.

남은 결정: 고정한 루트를 누가 갱신하고 그 갱신을 어떻게 검토할지, 서명이 검증되지 않은 `matched`를 `trust-source`가 계속 받아들일지, PyPI 증명에도 같은 처리를 할지.

## 2. 런타임 어댑터

> 상태: 변환기 두 개가 있습니다. `inventory-claude-init`은 사용자가 Claude Code의 문서화된 스트림 출력에서 캡처한 `system/init` 이벤트를 인벤토리로 바꾸고, `inventory-codex-mcp-status`는 문서화된 `codex app-server` 프로토콜의 `mcpServerStatus/list` 요청·응답을 같은 방식으로 바꿉니다([RUNTIME_EVIDENCE.ko.md](RUNTIME_EVIDENCE.ko.md) 참고). 둘 다 파일만 읽고 스스로 아무것도 관찰하지 않으므로 아래 제약은 그대로입니다. Gemini CLI(`init` 스트림 이벤트에는 세션 ID와 모델만 있고, `gemini mcp list`는 사람이 읽는 텍스트)와 Devin은 기계 판독형 세션 인벤토리를 문서화하지 않으므로 제공하지 않습니다.

### 현재

런타임 증거는 사용자가 제공합니다. TrustDex는 `claude`, `codex` 런타임에 대해 값이 없는 인벤토리(`agent-runtime-tool-inventory`, 서버 이름과 도구 수)를 받고, 생성자 키로 서명되어 있으면 그것을 확인한 뒤, 검토된 설정과 대조합니다. TrustDex는 MCP 서버를 시작하지 않고, 에이전트를 호출하지 않으며, 세션 파일을 읽지 않습니다.

### 제약

인벤토리를 만드는 어댑터는 실행 중인 에이전트를 관찰해야 합니다. CLI 안에서 그렇게 하려면 에이전트 명령을 실행하거나(`child_process`), 문서화되지 않은 세션 상태를 읽거나, MCP 서버에 연결해야 하며, 어느 쪽이든 신뢰 경계가 넓어집니다.

### 제안

- 어댑터는 `bin/`과 `src/` 밖에 둡니다. 어댑터는 인벤토리를 출력하고 `sign-runtime-inventory`로 서명하는 별도의 옵트인 프로그램입니다. CLI는 계속 서명된 값 없는 문서만 받습니다.
- 런타임 개발사가 안정적이라고 문서화했고 사용자가 허가한 인터페이스에 대해서만 어댑터를 제공하며, 테스트한 런타임 버전을 [호환성 매트릭스](COMPATIBILITY.ko.md)에 적습니다.
- 어댑터는 도구 이름, 인자, 경로, 환경 값을 내보내지 않습니다. 스키마가 이미 요구하는 대로 서버 이름과 개수만 내보냅니다.
- 각 어댑터에는 문서화된 인터페이스에서 기록한 픽스처, 서버 누락·서버 추가·도구 수 변경 테스트, 비밀 값 카나리 테스트가 함께 들어갑니다.

남은 결정: 어느 런타임 인터페이스를 먼저 대상으로 할지, 어댑터를 이 저장소의 `examples/` 아래에 둘지 별도 릴리스를 가진 패키지로 둘지, 개발자 기기에서 생성자 키를 누가 보관할지(에이전트가 읽을 수 있는 키는 아무것도 인증하지 못합니다).

## 3. 다른 패키지 레지스트리의 출처 증명

> 상태: 보류. 관리자가 2026-11-22에 이 항목을 미루기로 결정했으며 구현된 것은 없습니다.

### 현재

`check-install`과 `claude-hook`은 `registry.npmjs.org`와 `pypi.org`의 공개 메타데이터를 읽습니다. 빌드 출처 증명(`provenance npm`, `trust-source npm`)은 npm에만 있습니다. PyPI 패키지는 수동 검토나 `--artifact` 무결성 증거로만 신뢰 저장소에 기록할 수 있습니다.

### PyPI가 문서화한 내용

PyPI는 PEP 740을 구현하며, 릴리스 파일마다 `GET https://pypi.org/integrity/<project>/<version>/<filename>/provenance`로 provenance 객체를 제공합니다([Integrity API](https://docs.pypi.org/api/integrity/)). simple JSON 인덱스는 각 파일의 `provenance` 필드에 이 URL을 적습니다. 각 객체는 증명을 만든 Trusted Publisher별로 묶여 있습니다(GitHub의 경우 `repository`, `workflow`, `environment`). 각 증명은 Fulcio 인증서와 포함 증명이 있는 Rekor 항목을 가진 DSSE 봉투이며, 기본 predicate는 `https://docs.pypi.org/attestations/publish/v1`입니다. PyPI [보안 모델](https://docs.pypi.org/attestations/security-model/) 문서는 증명이 파일의 출처를 보여 줄 뿐 신뢰 여부를 알려 주지 않으며, 릴리스 사이에 Trusted Publisher가 바뀌면 탈취 신호일 수 있다고 적고 있습니다.

### 선택지

| 선택지 | 네트워크 | 주요 비용 |
| --- | --- | --- |
| A. `src/sigstore.mjs`를 재사용하는 `provenance pypi`, `trust-source pypi` | 이 두 명시적 명령에서 `pypi.org`만 | PEP 740 봉투 형태용 어댑터. 로그 항목 종류 `dsse` 0.0.1은 npm용으로 이미 지원함 |
| B. `check-install`에서도 PyPI 출처 증명 확인 | 설치 검사마다 파일당 요청 1건 추가 | 일상 경로의 지연과 새 실패 원인. `check-install`을 가볍게 유지한다는 이전 결정과 충돌 |
| C. RubyGems, crates.io, Go 모듈 | 새 호스트 | RubyGems는 gem 푸시용 Trusted Publishing은 문서화했지만 TrustDex가 검증할 파일별 증명 API는 문서화하지 않음. crates.io와 Go는 여기서 평가하지 않음. 각각 문서화된 인터페이스가 먼저 필요함 |

### 권장안

선택지 A만 진행합니다. 규칙:

- 모든 증명을 고정된 신뢰 루트에 대해 기존 DSSE, Fulcio, CT, Rekor 포함 증명, 체크포인트 검사로 검증합니다. subject 다이제스트는 JSON API의 파일 SHA-256과 같아야 하고, 인증서의 저장소는 묶음의 `publisher.repository`와 같아야 합니다.
- GitHub Trusted Publisher는 저장소만이 아니라 두 신원 필드를 모두 인증서와 대조합니다. 인증서의 Build Config URI([Fulcio OID 1.3.6.1.4.1.57264.1.18](https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264118--build-config-uri))가 그 저장소와 `publisher.workflow`의 워크플로 파일을 가리켜야 합니다: `https://github.com/<publisher.repository>/.github/workflows/<publisher.workflow>@<ref>`. 저장소는 대소문자를 구분하지 않고, 워크플로 파일 이름은 정확히 같아야 합니다. 같은 저장소의 다른 워크플로가 받은 인증서나 Build Config URI가 없는 인증서는 실패로 처리합니다. `publisher.environment`가 있으면 기록하지만, Fulcio 인증서에 환경이 들어 있지 않으므로 아직 대조하지 않습니다.
- npm처럼 그 저장소를 프로젝트가 선언한 소스 URL과 비교합니다. 없음, 불일치, 확인 불가 결과는 npm과 마찬가지로 `trust-source`가 거부합니다.
- 이전 릴리스와 다른 publisher는 새 신호(`pypi-publisher-changed`)가 되고, 증명이 있던 프로젝트의 새 릴리스에 증명이 없으면 `provenance-dropped`입니다. 둘 다 등록을 막습니다.
- 처음에는 `GitHub` publisher만 받습니다. 다른 publisher 종류는 인증서 신원을 테스트하기 전까지 실패로 처리합니다.
- sdist와 wheel은 각각 별도의 파일과 provenance를 가집니다. 명령은 정확한 버전을 받아 그 릴리스의 모든 파일을 검증하고, 하나라도 실패하면 실패합니다.

남은 결정: PyPI만 먼저 할지, 릴리스의 모든 파일을 검증할지 설치 도구가 고를 파일만 검증할지, GitLab·Google Cloud publisher가 필요한지.

## 4. 조직 단위 신뢰 저장소

> 상태: 보류. 관리자가 2026-11-22에 이 항목을 미루기로 결정했으며 구현된 것은 없습니다.

### 현재

신뢰 저장소는 클레임을 담은 로컬 JSON 파일입니다. 팀이 저장소에 커밋할 수는 있지만, 누가 클레임을 썼는지 증명하지 못하고, 오래된 사본으로 바꿔치기할 수 있으며, 개발자는 검토된 저장소와 수정된 저장소를 구별할 수 없습니다. 검토 키는 이미 있습니다. 신뢰 기록은 Ed25519로 서명되고, 키셋([RUNTIME_EVIDENCE.ko.md](RUNTIME_EVIDENCE.ko.md))이 허용 키를 용도, 유효 기간, 폐기와 함께 나열합니다.

### 목표

조직이 저장소 하나를 게시하면 모든 개발자 기기와 CI 작업이 오프라인으로 검증할 수 있고, 노트북 한 대의 침해, 악성 PR, 오래된 사본으로는 신뢰 범위를 넓힐 수 없어야 합니다.

### 제안

- **서명된 문서.** 새 종류 `trustdex-org-trust-store`가 기존 클레임을 `organization`, `sequence`(증가만 하는 정수), `issuedAt`, `expiresAt`와 함께 감싸고, TrustDex가 신뢰 기록에 이미 쓰는 정규화 JSON에 Ed25519로 서명합니다.
- **키 정책.** 검증에는 `review`, `runtime-producer`와 구별되는 새 용도 `trust-store`를 가진 키셋을 씁니다. 선택적으로 임계값(예: 키 3개 중 2개)을 두어 키 하나를 도난당해도 저장소를 게시할 수 없게 합니다.
- **롤백과 동결 방지.** TrustDex는 받아들인 가장 높은 `sequence`를 상태 디렉터리에 저장하고 더 낮은 값을 거부합니다. 만료된 저장소는 건너뛰지 않고 거부해, 오래된 저장소가 옛 신뢰를 유지하지 못하게 합니다.
- **로컬 계층.** 개발자의 로컬 저장소는 같은 대상에 대한 조직 클레임을 대체할 수 없습니다. 조직이 다루지 않는 대상의 로컬 클레임은 쓸 수 있지만 로컬로 표시되어, 정책으로 조직 클레임만 요구할 수 있습니다. 어느 저장소도 기능 BLOCK을 뒤집지 못합니다.
- **배포.** 새 네트워크 코드는 없습니다. 조직이 자체 도구(저장소, MDM, CI 산출물)로 서명된 파일을 전달하고, TrustDex는 `--org-trust-store <file> --keyset <file>`로 읽습니다.
- **출력.** 판정에는 저장소의 조직, sequence, 키 ID만 기록하고 클레임 증거 URL은 남기지 않습니다.

### 채택하지 않은 대안

- 검사 시점에 URL에서 저장소 가져오기: 네트워크 접근과 침해 대상 서버가 늘어납니다.
- 저장소에 커밋된 신뢰 저장소를 서명 없이 신뢰하기: 병합된 PR 하나로 신뢰 범위를 넓힐 수 있게 됩니다.
- `review` 키 재사용: 설정 검토에 서명하는 키가 조직 신뢰까지 다시 쓸 수 있게 됩니다.

남은 결정: 조직 거부 항목을 추가할지(지금 클레임에는 `verified` 상태만 있음), 처음부터 임계값 서명을 요구할지, 요구할 기본 유효 기간(`expiresAt`), 깨끗한 기기에서 시작하는 CI 러너에서 받아들인 `sequence`를 어디에 저장할지.

