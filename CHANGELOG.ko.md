# 변경 기록

<p align="right">
  <a href="./CHANGELOG.md">English</a> | <strong>한국어</strong>
</p>

## 미출시

- 출력(`provenance`, `trust-source`): GitHub, npm, MCP Registry 메타데이터에서 가져온 저장소·원격 URL에서 사용자 정보, 쿼리 값, 프래그먼트를 지웁니다. GitHub 참조는 응답의 `html_url` 대신 확인한 저장소 이름으로 만듭니다. 이전에는 메타데이터에 든 자격 증명이 출력되고 신뢰 저장소에 기록됐습니다.
- 시험: 출력 카나리 검사가 모든 CLI 명령을 실행하고(네트워크 명령은 대역 `fetch`로), 검사에서 빠진 명령이 있으면 실패합니다.
- 파서(MCP JSON, Codex TOML, `SKILL.md`, 플러그인 매니페스트): 같은 키가 두 번 나오는(이스케이프로 쓴 경우 포함) JSON, `__proto__` 키, 128단계를 넘는 중첩, 64단계를 넘게 중첩된 TOML 배열·인라인 테이블, 16 MiB를 넘는 입력, 잘못된 UTF-8, NUL 문자가 든(UTF-16) `SKILL.md`는 이제 실패로 닫힙니다. 이전에는 `JSON.parse`가 마지막 중복 값을 조용히 남겼고, 깊은 입력은 스택 넘침으로 멈췄고, 잘못된 바이트는 U+FFFD로 읽혔습니다.
- 스킬: 큰따옴표 YAML 이스케이프(`"\x2a"`, `"Bash\u0028*)"`)를 풀어서 도구 범위를 분류하고, 단독 CR도 줄바꿈으로 보며, 범위에 별칭·앵커·태그가 있으면 `uninspected-tool-scope`로 표시합니다. 이전에는 이스케이프로 쓴 와일드카드나 셸 허용을 놓쳤습니다.
- 파서: 키셋과 IDE 확장의 `package.json`·`extensions.json`·`.obsolete`도 같은 엄격 JSON 파서를 써서 중복 키나 `__proto__` 키가 실패로 닫힙니다. 16 MiB 한도는 파이프 입력에도 적용되고, 빈 TOML 컨테이너도 깊이 한도에 들어가며, 제어 문자나 `#`·따옴표·괄호·쉼표로 풀리는 YAML 이스케이프는 셸 허용을 숨기거나 터미널에 닿지 않고 `uninspected-tool-scope`로 남습니다. 이렇게 읽지 못한 범위에서는 어느 단어로든 `Bash`·`PowerShell`이 나오면 셸 허용으로 보고 그런 이스케이프 옆의 와일드카드도 잡습니다. 따옴표 안의 `#`는 글자로 읽고, 여러 줄 플로 목록의 주석은 그 줄에서 끝나 뒤 항목을 숨기지 못합니다.

## 0.20.5 - 2026-11-22

- 공급망(`check-install`, npm 빌드 출처): npm-pick-manifest, npm-install-checks, pacote와 대조했습니다. 패키지 이름만 쓰거나 범위를 쓰면 npm이 건너뛰는 deprecated 또는 `engines` 불일치 `latest`를 더 이상 고르지 않습니다. npm `--tag`는 기본 태그로 반영합니다. 정확한 버전 없는 `--before`, 프리릴리스 비교식, 선택을 바꿀 수 있는 `engines.npm`이나 해석하지 못한 `engines`는 ASK `unresolved-version`입니다. 빌드 출처는 이제 인증서의 Build Config URI(Fulcio OID 1.3.6.1.4.1.57264.1.18)가 증명이 주장하는 워크플로 파일을 가리켜야 합니다. 이전에는 서명된 statement의 워크플로 경로만 사용했습니다.
- 스킬(`inspect-skill`): Claude Code 스킬 문서와 대조했습니다. frontmatter의 `hooks`는 `skill-hooks`(키로 읽을 수 없는 frontmatter나 그 밖의 `hooks` 언급은 검토가 필요한 `skill-frontmatter-uninspected`), `` !`command` ``와 ` ```! ` 블록은 `skill-shell-injection`을 추가하며, Claude Code가 확인 없이 실행하므로 둘 다 `BLOCK`입니다. `allowed-tools` 권한 부여는 모두 `skill-auto-approved-tools`(최소 `ASK`), `Bash`나 `PowerShell` 부여는 `skill-shell-auto-approve`(`BLOCK`)를 추가합니다. 이전에는 와일드카드만 보고했습니다.
- 플러그인(`inspect-plugin`): Claude Code는 매니페스트에 없어도 플러그인 루트의 `hooks/hooks.json`, `.mcp.json`, `.lsp.json`, `monitors/monitors.json`, `bin/`을 불러오므로 모든 매니페스트에 `plugin-components-uninspected`(최소 `ASK`)가 붙습니다. `monitors`, `experimental.monitors`, `channels`도 `plugin-executable-components`로 봅니다.
- 일반 MCP(`inspect`): TrustDex가 읽지 않는 서버 필드(예: `headers`, `envFile`, `cwd`, `stdio`/`http`/`sse`/`streamable-http` 외의 `type`)는 무시하지 않고 `uninspected-server-fields`(최소 `ASK`)를 추가합니다.
- Codex MCP(`inspect-codex`): Codex 자체 검증에 맞춰 `default_tools_approval_mode`는 `auto`, `prompt`, `writes`, `approve`만, `env_vars`의 `source`는 `local`, `remote`만 허용합니다. `command` 서버의 HTTP 전용 키, `url` 서버의 `args`/`env`/`env_vars`/`cwd`, `command`와 `url`이 모두 없는 서버, 빈 `http_headers_helper`는 실패 처리(fail closed)합니다.
- Claude Code 설정 검사는 실행형 도우미와 보호 훅을 끌 수 있는 설정을 차단하고, 알 수 없는 설정 이름은 출력하지 않습니다. 환경 변수 키, 관리형 전용 권한 규칙, 작업 디렉터리 외부 접근 제한에는 공식 병합 규칙을 적용합니다. Claude 권한 스냅샷 v1/v2에는 쓰기 차단, 확인 대신 거부, 관리형 전용 규칙 여부를 선택 필드로 기록합니다. 이 정보가 없는 스냅샷과 비교하면 다시 검토해야 합니다.
- Gemini MCP 검사에서 실행 대상이나 도구 필터의 미확인 참조를 거부하고, 헤더와 `env`의 단순 자격 증명 참조를 값 없이 추적합니다. 영향을 받는 설정은 다시 검토하고 서명해야 할 수 있습니다.
- Gemini 권한 검사에서 `tools.core`의 자동 승인과 MCP 자동 승인 설정을 보고하고, 기본 제공 팩에서 미확인 도구 승인을 차단합니다. 관리자 보안 모드는 YOLO 및 항상 허용 표시에도 반영됩니다.
- `inspect-devin-settings`가 Devin CLI 문서의 동작을 더 정확히 따릅니다. 모든 변경은 신호를 더하거나 조치를 높이기만 하며, 설정 파일은 여전히 ALLOW가 되지 않습니다.
  - 일치하는 명령을 확인 없이 샌드박스 밖에서 실행하는 `sandbox.excluded.allow`는 `devin-sandbox-excluded-exec`(`BLOCK`)를 추가합니다. 이전에는 `sandbox`를 건너뛰었습니다. `sandbox.excluded` 목록은 `Exec(...)` 규칙만 받으며 그 밖의 값은 거부합니다. 알 수 없는 `sandbox` 키는 검사하지 않는 설정으로 셉니다.
  - 넓은 허용 규칙(`edit` 도구, `**` 같은 모든 경로 `Write(...)` 범위, `.devin`·`.claude`·`.config`를 가리키는 `Write(...)` 범위, 모든 호스트 `Fetch(...)` 범위)은 `devin-broad-auto-approve`(`BLOCK`)를 추가합니다. 에이전트가 자기 규칙과 훅을 고치거나 읽은 내용을 아무 곳에나 보낼 수 있기 때문입니다.
  - `local_tools_bypass_permissions: true`는 `permission_mode: "dangerous"`처럼 `ASK` 대신 `BLOCK`입니다.
  - 값이 없거나 `null`인 `read_config_from` 제공자는 Devin CLI처럼 켜진 것으로 셉니다. 따라서 문서화된 제공자 10개가 모두 `false`일 때만 `devin-external-config`가 없으며, `null`은 더 이상 거부되지 않습니다. 알 수 없는 제공자 키는 검사하지 않는 설정으로 셉니다.
  - 새 메타데이터: `broadAllowRuleCount`, `sandboxExcludedAllowCount`/`AskCount`/`DenyCount`.

## 0.20.4 - 2026-11-22

- `inspect-gemini-settings`: Gemini CLI가 검증 전에 치환하는 환경 변수 참조(`$VAR`, `${VAR}`, `${VAR:-DEFAULT}`)가 들어 있는 `tools.sandbox` 문자열은 이제 거부하지 않고 `sandboxSetting: "unresolved"`와 `gemini-sandbox-unresolved` 신호(최소 `ASK`)로 보고합니다. 변수 이름, 기본값, 입력 문자열은 보고하지 않습니다. 지원하지 않는 명령 문자열과 빈 문자열은 기존대로 거부하며, Gemini CLI는 빈 문자열을 꺼짐으로 처리한다는 차이를 문서에 적었습니다.

## 0.20.3 - 2026-11-22

- `inspect-gemini-settings`: `tools.sandbox`는 `true`, `"true"`, `"1"`, 또는 Gemini CLI가 지원하는 샌드박스 명령(`docker`, `podman`, `sandbox-exec`, `runsc`, `lxc`, `windows-native`)일 때만 `enabled`입니다. Gemini CLI가 설정 오류로 처리하는 그 밖의 문자열은 이제 `enabled`로 보고하지 않고 거부합니다(종료 코드 2). 입력 값은 출력하지 않습니다.

## 0.20.2 - 2026-11-22

- `inspect-gemini-settings`: Gemini CLI가 끔으로 처리하는 문자열 `"false"`, `"0"`인 `tools.sandbox`를 이제 `disabled`로 분류하고 `gemini-sandbox-disabled`(최소 `ASK`)와 `sandboxConfigured: false`를 보고합니다. 이전에는 `enabled`로 보고했습니다. 파일의 `false`가 다른 계층보다 우선한다는 설명을 바로잡았습니다. `sandboxSetting`은 검사한 파일의 설정이며, 실제 값은 상위 설정 계층, `GEMINI_SANDBOX`, `--sandbox`에 따라 달라질 수 있습니다.

## 0.20.1 - 2026-11-22

- `provenance npm`, `trust-source npm`: Rekor 포함 증명이 없다는 것만이 실패 원인인 Sigstore 번들은 이제 `signature-not-verified` 대신 `inclusion-proof-missing` 이유와 함께 `unverifiable`입니다. 검증 정책과 형식 0.1 번들의 2024년 기준은 그대로입니다. 호환성: 0.19.0에서 `matched`였고 0.20.0이 거부하는 번들(예: 2024-02-08에 기록된 `sigstore@2.2.1`, `@sigstore/sign@2.2.2`의 provenance)은 계속 거부됩니다. [docs/TRUST_STORE.ko.md](docs/TRUST_STORE.ko.md) 참고.
- `inspect-gemini-settings`: `tools.sandbox: false`를 명시하면 `gemini-sandbox-disabled`(최소 `ASK`)를 추가하고, `metadata.sandboxSetting`으로 생략(`omitted`), 꺼짐(`disabled`), 켜짐(`enabled`)을 구분합니다.
- `inspect-devin-settings`: `read_config_from`에 `true`인 제공자가 있으면 Devin CLI가 그 도구의 파일에서 규칙, 스킬, 훅, MCP 서버를 가져올 수 있으므로 `devin-external-config`(`ASK`)를 추가합니다. 켜진 제공자 개수만 보고하고 가져오는 파일은 읽지 않습니다. 불리언 객체가 아닌 `read_config_from`은 이제 거부합니다.
- 설계 노트: 보류된 PyPI provenance 설계에서 GitHub Trusted Publisher는 Fulcio Build Config URI도 `publisher.workflow`와 일치해야 합니다. 문서만 바뀝니다.

## 0.20.0 - 2026-11-22

- `inspect-devin-settings`: Devin CLI `config.json`의 권한 설정을 기능별로 분류합니다. `Exec` 자동 승인 규칙, `permission_mode: "dangerous"`, 훅은 `BLOCK`이고, 그 밖의 `allow` 규칙, `accept-edits`·`smart` 모드, `local_tools_bypass_permissions`, 예전 `mcpServers` 키, 검사하지 않는 설정은 `ASK`입니다. 설정 파일은 어떤 정책에서도 ALLOW가 되지 않고, 문서화된 형식이 아닌 규칙은 거부하며, 보고서에는 권한 모드, 불리언, 개수만 들어갑니다. [docs/DEVIN.ko.md](docs/DEVIN.ko.md)를 참고하세요.
- `inspect-gemini-settings`: Gemini CLI `settings.json`의 권한 설정을 기능별로 분류합니다. 셸 도구 자동 승인, 도구·MCP 명령 설정, 훅은 `BLOCK`이고, 그 밖의 자동 승인, 완화된 샌드박스, 폴더 신뢰 해제, 추가 정책 경로, 검사하지 않는 설정은 최소 `ASK`입니다. 설정 파일은 어떤 정책에서도 ALLOW가 되지 않으며, 보고서에는 승인 모드, 불리언, 개수만 들어갑니다. [docs/GEMINI.ko.md](docs/GEMINI.ko.md) 참고.
- 동작 변경: Claude Code·Codex·Gemini CLI 권한 설정 파일(또는 설정 스택)은 ALLOW가 되지 않습니다. 이전에는 `localAction: "allow"`를 둔 사용자 정책이 신호가 없는 설정 파일을 승인했지만, 이제는 `permission settings always require review` 사유와 함께 ASK입니다. 기본 제공 팩은 이미 ASK였습니다.
- `provenance npm`과 `trust-source npm`은 서명 인증서에 고정된 인증서 투명성 로그의 서명된 인증서 타임스탬프(SCT)가 내장되어 있어야 통과시킵니다. 없으면 `unverifiable`입니다. 네트워크 요청은 추가되지 않습니다.
- 고정된 Sigstore 신뢰 루트를 그 출처인 업스트림 `trusted_root.json`과 대조하는 테스트를 추가했고, 갱신 방법은 [docs/TRUST_ROOT.ko.md](docs/TRUST_ROOT.ko.md)에 있습니다.
- `provenance npm`과 `trust-source npm`이 Sigstore 로그 항목의 머클 포함 증명도 고정된 로그 키가 서명한 트리 헤드까지 검증합니다. 증명이 없거나 검증되지 않는 번들은 `unverifiable`이며 기록되지 않습니다. 2023년 형식 0.1 번들만 로그의 서명된 약속만 담을 수 있습니다. 네트워크 요청은 추가되지 않습니다.

## 0.19.0 - 2026-11-22

- `inspect-gemini`, `gate-gemini`, `snapshot-gemini`, `approve-gemini`, `recheck-gemini`: Gemini CLI가 읽기 전에 `mcpServers`를 검사하고 게이트합니다. 모든 도구 호출 확인을 건너뛰는 `trust: true`에는 `auto-approve-tools` 신호가 붙고, 기본 제공 팩에서는 ALLOW가 되지 않습니다. 알 수 없는 필드, OAuth·Google 자격 증명 필드, `settings.json`의 다른 설정, URL의 자격 증명·쿼리 값은 거부합니다. `trust`, 도구 필터, 작업 디렉터리를 바꾸면 서명된 검토가 무효가 됩니다. [docs/GEMINI.ko.md](docs/GEMINI.ko.md)를 참고하세요.
- `inspect-devin`, `gate-devin`, `snapshot-devin`, `approve-devin`, `recheck-devin`: Devin CLI가 읽기 전에 `mcp_config.json`을 검사하고 게이트합니다. 알 수 없는 필드, OAuth 클라이언트 필드, `${file:...}` 확장, URL의 자격 증명·쿼리 값은 거부합니다. `disabled` 서버도 활성 서버와 같은 결정을 받고, 서버를 켜거나 숨긴 도구를 다시 노출하면 서명된 검토가 무효가 됩니다. [docs/DEVIN.ko.md](docs/DEVIN.ko.md)를 참고하세요.
- `inventory-codex-mcp-status`: 문서화된 `codex app-server` 프로토콜에서 캡처한 `mcpServerStatus/list` 요청·응답 쌍을 값 없는 런타임 도구 인벤토리(서버 이름과 도구 개수만)로 변환합니다. TrustDex는 전달받은 파일만 읽고, Codex를 실행하거나 MCP 서버에 접속하지 않습니다. 페이지가 빠졌거나(첫 요청은 목록의 처음부터, 이후 요청은 직전 응답의 커서에서 이어져야 함), 요청에 스레드가 없거나 서버 하나만 골랐거나, 서버의 스레드 상태가 확정되지 않았거나, 연결된 서버의 도구 탐색이 실패했거나, 같은 서버 이름이 두 번 나오면 캡처를 거부합니다.

## 0.18.0 - 2026-11-22

- `inventory-claude-init`: Claude Code의 문서화된 `--output-format stream-json`에서 캡처한 `system/init` 이벤트를 값 없는 런타임 도구 인벤토리(서버 이름과 도구 개수만)로 변환합니다. TrustDex는 파일만 읽으며 Claude를 실행하거나 MCP 서버에 접속하지 않습니다. 연결 대기 중인 서버, 알 수 없는 상태, 나열된 서버 중 정확히 하나에 속하지 않는 MCP 도구는 거부합니다
- `provenance npm`과 `trust-source npm`이 npm 빌드 출처 증명의 Sigstore 번들을 Node 내장 crypto와 고정된 신뢰 루트로 오프라인 검증합니다(새 의존성·요청 없음). 이제 일치로 판정하려면 DSSE 서명이 유효하고, 인증서가 고정된 Fulcio 루트로 이어지며 같은 GitHub 저장소를 가리키고, 해당 봉투에 대한 Rekor 항목의 서명된 타임스탬프가 유효해야 합니다. 그렇지 않으면 `unverifiable`이며 `trust-source`가 거부합니다. 확인하지 않는 것: SCT, 머클 포함 증명, RFC 3161 타임스탬프, 신뢰 루트 교체
- 스킬 파일: 와일드카드 도구 범위가 YAML 블록 목록, 여러 줄 플로 목록, BOM이나 빈 줄 뒤, 다른 대소문자, 뒤따르는 주석, 반복된 키, `Bash(*)` 같은 제한 없는 지정자로 쓰여도 보고합니다. TrustDex가 해석하지 못하는 문법의 도구 범위는 좁다고 읽지 않고 `uninspected-tool-scope`(ASK)를 추가합니다
- 스킬 파일: 더 많은 내려받아 실행 형태(`| zsh`, `| python`, `| iex`, `bash <(...)`, `bash -c "$(...)"`), 패키지 러너, 자격 증명 위치(`$HOME/.ssh`, `~/.gnupg`, `~/.kube`, `~/.npmrc` 등)가 기존 지시문 신호를 올립니다. 여전히 텍스트 휴리스틱입니다
- 플러그인 매니페스트: 훅, MCP 서버, LSP 서버, 스크립트를 선언하면 `plugin-executable-components`(ASK)를 추가합니다. `permissions.allow: ["Bash(*)"]` 같은 중첩 와일드카드 권한을 보고하고, 64단계보다 깊게 중첩된 매니페스트는 거부합니다
- MCP JSON: `command`, `args`, `env`, `url`, `endpoint`의 타입이 잘못되면 `malformed-server-fields`(BLOCK), `env`·`sudo`·`busybox` 같은 래퍼가 셸을 실행하거나 명령이 `dash`·`ksh`이면 `shell-execution`을 추가합니다
- `examples/adversarial/extensions/`와 `examples/adversarial/mcp-evasion.json`에 비활성 픽스처를 추가했습니다
- `slack-approver`: 토큰 파일에는 봇 토큰 형태의 값 하나만 있어야 합니다. `tokenFile`이 다른 파일을 가리켜도 그 내용이 Slack으로 전송되지 않으며, `slack.com` 요청은 더 이상 리디렉션을 따르지 않습니다
- 문서: `test/compatibility.test.mjs`로 확인하는 [호환성 매트릭스](docs/COMPATIBILITY.ko.md)와 [스키마 안정성 규칙](docs/SCHEMAS.ko.md), Sigstore 검증과 런타임 어댑터 [설계 노트](docs/DESIGN_NOTES.ko.md)(제안이며 구현되지 않음), 0.17.3 로드맵 진행 현황

## 0.17.3 - 2026-11-22

- `provenance npm`과 `trust-source npm`이 최신 버전의 npm 빌드 provenance를 패키지가 지금 선언한 저장소, 이전에 선언했던 저장소와 비교합니다. `trust-source`는 다른 저장소에서 빌드된 릴리스(`mismatch`), 이전 버전에 있던 provenance가 빠진 릴리스(`dropped`), 버전의 sha512와 맞출 수 없는 provenance(`unverifiable`)를 거부하고, 일치하면 소스 저장소와 워크플로를 주장에 기록합니다. Sigstore 서명은 검증하지 않으며, `check-install`은 새 요청을 하지 않습니다

## 0.17.2 - 2026-11-22

- `provenance-dropped`(ASK) 추가: 이전 버전은 provenance와 함께 게시됐는데 최근 npm 릴리스에는 없을 때. 프로젝트 CI가 아닌 탈취한 토큰으로 올린 릴리스에서 흔한 모습입니다. 레지스트리가 provenance를 알려주는지만 비교하며 증명 자체는 검증하지 않습니다. 설치 정책 허용 목록으로 끌 수 없습니다
- 탈취된 npm 릴리스를 `known-malicious-release`로 차단: `vant` 2.13.3–2.13.5, 3.6.13–3.6.15, 4.9.11–4.9.14 ([메인테이너 공지](https://github.com/youzan/vant/discussions/13273)), `@wppconnect-team/wppconnect` 2.4.1 ([GHSA-cxc9-87g6-qrj9](https://github.com/advisories/GHSA-cxc9-87g6-qrj9)), `@wppconnect/server` 2.10.82 ([메인테이너가 확인한 보고](https://github.com/wppconnect-team/wppconnect-server/issues/2734)), `qrcode-reader-vue3` 3.1.4 ([GHSA-9q69-8j7m-ppmh](https://github.com/advisories/GHSA-9q69-8j7m-ppmh)). 정확히 고정한 버전은 오프라인으로 검사하고, 해석된 버전도 차단하며, 대체 버전으로 추천하지 않습니다

## 0.17.1 - 2026-11-21

- PyPI `agent-framework`의 `1.26.1`, `1.26.2`를 차단합니다. 버전을 정확히 지정한 명령은 오프라인으로 검사하고, 이전에 승인된 명령도 Claude Code 훅이 거부합니다. [GHSA-764m-3ppc-5m73](https://github.com/advisories/GHSA-764m-3ppc-5m73)

## 0.17.0 - 2026-11-21

- `trustdex init` 추가: macOS와 Linux에서 Claude Code 훅을 한 번에 설정함. 계획을 보여 주고 `yes`(또는 `--yes`)를 받아야 진행하며, `--dry-run`은 계획만 보여 줌. 실행 중인 TrustDex를 `~/.local/share/trustdex/<버전>`에 복사하고, `~/.local/bin`에 `trustdex` 명령을 만들고, 설치 정책이 없을 때만 새로 만들고, `~/.claude/settings.json`을 백업한 뒤 고장 나면 멈추는 PreToolUse 훅 하나를 추가함. 다른 설정과 훅은 그대로 두고, 다시 실행하면 TrustDex 훅만 바꿈. `--strict`는 묻지 않고 거부, `--uninstall`은 TrustDex 훅만 뺌
- README: Claude Code 1분 시작 안내

## 0.16.1 - 2026-11-20

- 자격 증명 파일을 입력 리디렉션으로 프로그램에 넘기는 것(`cmd < ~/.ssh/id_rsa`, 붙여 쓴 `<file`, `0<`)을 `secret-access`로 막음. 전에는 받는 프로그램이 SSH 도구일 때(`ssh host 'cmd' < 비밀파일`)나 `<`에 파일 이름을 붙여 쓸 때 통과했음. `<`로 읽는 파일은 읽기로만 보므로 `while read …; done < ~/.zshrc`는 더 이상 시작 항목 변경으로 보지 않음

## 0.16.0 - 2026-11-19

- `slack-approver` 추가: 훅이 멈춘 행동을 설정한 주인에게 슬랙 DM으로 보내고, 주인(슬랙 사용자 ID로 확인, 봇은 안 됨)이 ✅를 누르면 한 번짜리 승인을 기록함. ❌는 거절. 에이전트 설정·TrustDex 자체 변경과 보호 파일 근처의 해석 못 한 명령은 터미널에서만 허용. 기본 한 시간에 20개까지만 보냄. 메시지 기록은 보호되는 승인 상태 폴더에 두고, 훅이 설치 정책 옆의 `slack-approver.json`을 보호함. [docs/SLACK_APPROVER.ko.md](docs/SLACK_APPROVER.ko.md) 참고
- 훅이 멈출 때 주는 안내에 `allow-once` 대신 슬랙 메시지로 허용하는 방법도 적음

## 0.15.1 - 2026-11-19

- 로컬 스크립트를 실행하는 Bash 명령(`bash x.sh`, `python3 x.py`, `source x`, `./x.sh`)의 한 번짜리 승인을 그 스크립트의 SHA-256에도 묶음(크기와 상관없이). 승인 뒤 스크립트를 바꾸거나, 승인 때 없던 스크립트를 새로 만들면 다른 행동이 되어 따로 승인이 필요함

## 0.15.0 - 2026-11-19

- SSH로 다른 컴퓨터에 보내는 명령(`ssh host 'cmd'`, `ssh host <<EOF`, `scp`/`rsync host:경로`)을 일반적인 이름으로 검사함. 보통 비밀값이 든 파일 읽기, 환경변수·`kubectl` 비밀값 출력은 `remote-secret-access`(ASK), 그런 파일·`/etc`·`authorized_keys`·셸 시작 파일·`crontab` 바꾸기는 `remote-config-change`(ASK). 승인하면 그 서버에서 그 종류의 작업을 1시간 허용함. 평소 서버 작업은 조용히 지나가고, 같은 컴퓨터로 가는 `ssh`는 로컬 명령처럼 검사함
- 안내하는 훅 명령 끝에 `|| { ...; exit 2; }`를 붙임. `node`가 없거나 TrustDex 사본이 옮겨졌거나 시작하다 죽어도, 막지 않는 훅 오류로 통과하지 않고 행동을 멈춤
- 확인 창 모드에서도 계속 막는 것과 그 대가를 문서에 적음
- 하루 실제로 써 본 결과를 반영해 Claude Code 훅을 덜 번거롭게 함
  - 읽기만 하는 파이썬·노드 한 줄 코드(`python3 -c "print(json.load(open(p)))"`, `node -e "...readFileSync(p)..."`)는 에이전트 설정이나 시작 항목을 바꾸는 것으로 보지 않음. 쓰거나, 다른 프로그램을 실행하거나, 무엇을 부르는지 숨길 수 있는 코드는 그대로 막음
  - `trustdex allow-once --list` 허용. 승인 자체는 여전히 사람만 할 수 있음
  - launchd 작업을 멈추는 것(`launchctl unload`, `bootout`, `disable`, `remove`)은 시작 항목 변경으로 보지 않음
  - 설치 정책에 `allowStartupItems` 추가: 내 예약 작업의 launchd 라벨(`"com.example.*"`)을 넣으면, 에이전트가 `launchctl enable`이나 `~/Library/LaunchAgents`에서 `load`/`bootstrap`으로 승인 없이 켤 수 있음. 그 폴더에 plist를 쓰는 것은 여전히 승인 필요
  - 정확히 그 행동 하나에 대한 한 번짜리 승인을 30분에서 1시간으로 늘려, 코드·시작 항목 승인과 같은 기준으로 맞춤

## 0.14.2 - 2026-11-19

- 에이전트 보호의 오탐 줄임
  - 명령 하나하나를 따로 판정함(읽기만 하는 명령은 다른 명령과 묶여도 허용)
  - `/dev/null`이나 다른 출력으로 보내는 리디렉션은 쓰기로 보지 않음
  - 읽기 전용으로 보는 명령: `bash -n`, `plutil -lint`/`-p`, `launchctl print`/`list`, `defaults read`, 읽기 전용 `git`, 제자리 수정 없는 `sed`/`awk`, `-delete`/`-exec` 없는 `find`
- 시작 항목 경고(`persistence-change`)를 승인하면 정확한 명령 하나가 아니라 시작 항목·예약 작업 변경을 어떤 명령이든 1시간 동안 허용

## 0.14.1 - 2026-11-18

- Bash 1회 승인을 실제 시작 폴더와 앞쪽 `cd`를 뺀 명령에 묶음. Claude Code가 현재 폴더로 가는 앞쪽 `cd`를 지워도 승인이 맞고, 다른 폴더의 같은 명령에는 적용되지 않음

## 0.14.0 - 2026-11-18

- `check-install` 추가
  - npm, pnpm, yarn, bun, npx, pip, uv, uvx, pipx, poetry, pdm 설치 명령을 오프라인으로 해석하고, 내려받아 바로 실행하는 파이프라인(`curl ... | sh`, `bash <(curl ...)`)을 차단
  - 레지스트리 패키지마다 공개 npm 저장소나 PyPI를 조회(패키지 이름만 전송)
  - BLOCK: 없는 패키지, 잘못된 무결성 메타데이터
  - ASK: 최근 릴리스(48시간), 새 패키지(30일), 설치 스크립트·소스 빌드, 최근 릴리스의 처음 보는 게시자, 사용 중단·철회 버전, 유명 이름 흉내, git/URL 출처, 별도 레지스트리, 풀지 못한 범위, 매니페스트 설치, 조회 실패
- `claude-hook` 추가: Bash, Read, Grep, Glob, Write, Edit, MultiEdit, NotebookEdit용 Claude Code `PreToolUse` 훅. 스스로 승인하지 않고, 위험할 수 있는 도구는 실패 시 막음. 막는 것:
  - 위험한 패키지 설치
  - 에이전트 설정·MCP 설정·TrustDex 자체 변경(`guard-tamper`)
  - 키체인·브라우저 로그인·`gh auth token`을 포함한 자격 증명 읽기(`secret-access`)
  - 권한·샌드박스 검사를 끈 AI 코딩 CLI 실행(`agent-permission-bypass`)
  - 자동 실행 항목(`persistence-change`)
- 기본값에서는 위험한 행동을 클릭 한 번짜리 확인 창으로 바꾸지 않고 거부함. `trustdex allow-once <코드>`를 추가해, 대화형 터미널 앞의 사람이 그 행동 하나만 30분 안에 한 번 허용하게 함(에이전트가 실행하거나 위조할 수 없음). `--on-risk ask`로 ASK 수준은 확인 창을 유지할 수 있음
- 훅이 다음도 검사함
  - 셸·해석기가 실행하는 히어독 본문, 바로 실행하는 로컬 스크립트 파일, 같은 명령 안의 변수와 `cd`, 한 줄 코드(`python3 -c`, `node -e`) 속 경로
  - 환경변수 목록과 `.env` 파일을 네트워크로 보내는 것
  - `claude`/`codex`/`gemini`의 `mcp add` 명령
  - git 훅(`.git/hooks`, `core.hooksPath`)
- 숨긴 내용을 풀어서 실행하는 것(`base64 -d | sh`, `eval "$(... base64 -d)"`, `xxd -r | python3`, `gunzip | sh`)을 `obfuscated-execution`으로 차단
- Claude 설정의 `disableAllHooks`를 `claude-hooks-disabled`로 보고(모든 정책 팩에서 BLOCK)
- 평소 패키지 사용의 불편 줄임
  - 프로젝트에 이미 깔린 실행 파일을 `cd` 뒤와 상위 폴더에서도 찾음
  - 너무 최근 릴리스면 가장 새로운 이전 버전을 안전한 대안으로 알려 줌
  - 패키지 경고를 승인하면 정확한 명령 하나에 30분이 아니라, 그 정확한 버전에 대해 어떤 명령이든 24시간 통과
- 엄격한 설치 정책 파일(`--install-policy`) 추가: 릴리스·패키지 나이 기준, 매니페스트 설치 처리, 좁은 범위의 허용 목록. 허용 목록은 BLOCK 신호, `recent-release`, `publisher-changed`를 끌 수 없음
- Codex `approvals_reviewer = "guardian_subagent"`를 설정 검사와 권한 상태에서 자동 검토자(`codex-auto-review`)로 인정

## 0.13.1 - 2026-11-08

- **보안:** 설치된 IDE 확장 폴더 검사에 최대 5만 파일, 10만 항목, 파일 총량 2GiB, 디렉터리 깊이 64단계 제한 적용. 한도 초과 시 부분 지문을 승인에 사용하지 않고 차단하며 디렉터리 목록을 순차적으로 읽음
- Windows 홈 상대경로(`~\\`) 인식 및 Claude 권한 도구명 대소문자 변형에 대한 보수적인 셸·파일·네트워크·서브에이전트·MCP 위험 분류 강화
- MCP 게이트에서 평가 결과의 누락·중복·유효하지 않은 판정을 거부하고 위험한 프로토타입 이름도 안전하게 구성
- CLI 값 플래그 누락·중복·연속 플래그를 오류로 처리하고 종료 코드 및 도움말 회귀 테스트 확장
- 서명된 런타임 인벤토리 캡처의 기본 최대 경과 시간 3600초 검증(명시적 검증 값은 허용), 서명 만료와 캡처 최신성 구분 문서화
- TOML 유한 지수 표기 지원 및 여러 줄 문자열의 반복적인 나머지 문자열 복사 제거
- 릴리스 워크플로를 읽기 전용 검증 작업과 필요한 쓰기 권한을 가진 배포 작업으로 분리하고 러너·레지스트리 대응 및 Codex 배열 교체 규칙 문서화

## 0.13.0 - 2026-11-08

- **보안:** 출력 파일을 독점 생성 임시 파일과 원자적 교체로 저장하고, 심볼릭 링크/일반 파일이 아닌 출력 경로 및 저장소 내부 심볼릭 링크 상위 디렉터리를 거부하며 개인키 0600 권한 유지
- 온라인 출처 조회에 10초 제한과 리다이렉트 차단을 적용하고 HTTP 오류에서 민감한 URL 값을 노출하지 않음
- npm 철회 또는 버전/SRI 무결성 메타데이터 오류와 MCP Registry 아티팩트 누락에 실패 시 차단 원칙을 적용하고 신뢰 저장소의 중복 대상 클레임 거부
- 검증된 패키지의 버전 불일치 및 npm/PyPI 생태계 간 무결성 근거 교차 대체를 차단하고 다운그레이드·교차 대체·메타데이터 누락 회귀 테스트 추가
- Windows 드라이브 및 UNC 경로와 혼합 구분자 탐지, 이중 MCP 설정 컨테이너와 누락된 source 근거 거부
- 소스 및 출처 스냅샷을 정규 JSON으로 비교하여 키 순서 변화에 따른 오탐 방지
- 기존 JSON·종료 코드·변경 라벨을 유지하면서 NO_COLOR/TTY를 지원하는 비밀값 없는 ANSI 컬러 Diff 제공
- GitHub 정책 검사 복붙 워크플로와 정확한 상태 뱃지 안내, Node.js 24 CI 지원
- GitHub Release 검증 완료 시 명시적인 workflow_dispatch를 통해 npm Trusted Publishing 연결

## 0.12.0 - 2026-10-30

- 러너 옵션으로 실제 설치되는 패키지를 판단: `uvx --from`과 `npx -p/--package`가 패키지를 지정하며, `uvx --python 3.12` 같은 옵션 값을 더 이상 패키지로 오인하지 않음. 레지스트리 재지정(`--registry`, `--userconfig`, `--index-url`, `--extra-index-url`, `--find-links` 등)은 `package-source-override`(BLOCK), 추가 패키지(`uvx --with`, 반복된 `-p`)는 `additional-packages`(BLOCK, `development`에서는 ASK), `npx -c/--call`과 `--node-options`는 `shell-execution`, 인식하지 못한 러너 옵션이나 `=값`을 붙인 플래그(npm은 `-y=x`를 `--yes x`로 펼침)는 `ambiguous-runner-arguments`(BLOCK)를 추가
- 패키지·설정·설치된 실행 파일의 출처를 바꾸는 러너 옵션을 `package-source-override`(BLOCK)로 처리: npm `--cache`, `--prefix`, `--workspace`, uv `--config-file`, `--env-file`, `--constraint`, `--override`, `--build-constraint`, `--cache-dir`, `--keyring-provider`, 그리고 버전이 아닌 경로나 프로그램 이름을 준 `--python`
- `npx -p`/`uvx --from`이 패키지 자신의 이름이 아닌 명령(`sh`, `python` 등, 검토한 패키지가 아니라 PATH에서 찾음)을 실행하면 `runner-command-mismatch`(BLOCK, `development`에서는 ASK) 추가
- 러너 서버의 `env`가 러너·인터프리터·로더 설정(`npm_config_*`, `UV_*`, `BUN_OPTIONS`를 포함한 `BUN_*`, `NODE_OPTIONS`, `PYTHONPATH`, `LD_PRELOAD`, `DYLD_*`, `PATH`, `HOME`, `NODE_TLS_REJECT_UNAUTHORIZED`, CA 번들 변수 등)을 지정하면 `runner-environment-override`(BLOCK) 추가
- `npx --no`는 더 이상 플래그로 허용하지 않음(npx가 패키지 뒤의 모든 옵션을 읽게 됨)
- `command`와 `url`/`endpoint`를 모두 가진 서버에 `ambiguous-server-transport`(BLOCK) 추가(이전에는 원격으로만 판단)
- 정확한 버전만 고정으로 인정: `@` 뒤의 완전한 시맨틱 버전, 또는 PEP 508 이름의 `==` 뒤에 오는 와일드카드 없는 PEP 440 버전(이전에는 `name@^1.0.0`, `name@1.2`, `name@1.x`, `name==1.*`도 고정으로 보고됨)
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
- `verify`, 모든 `recheck*` 명령, `verify-runtime-inventory`, `snapshot-runtime-tools`에 `--public` 대신 쓸 수 있는 `--keyset keyset.json` 추가: SHA-256 SPKI 키 ID, 필수 `purposes`(`review`, `runtime-producer` 또는 둘 다, 기본값 없음), 서명된 `createdAt` 시점에 검사하는 `notBefore`/`notAfter` 유효 기간, 교체를 위한 여러 활성 키, 같은 파일 안의 폐기 목록을 갖추고 엄격하게 검증되는 `trustdex-keyset` v1 허용 목록(스키마 공개). 두 플래그를 함께 주거나, 한 플래그를 두 번 주거나, `--flag=값` 형식을 쓰면 오류이며, 필드 이름이 반복된 키셋 JSON은 거부
- 위조 서명을 받아들이는 소차수·비정규 Ed25519 공개 키와 신뢰 기록의 비정규 base64 서명을 거부(`--public` 사용 시 포함)
- `revokedAt`이 없는 폐기는 전면 폐기(그 키의 모든 서명이 INVALID)로 처리하고, `revokedAt`이 있으면 그보다 엄격히 이전에 서명된 증거만 유지하며, 이 시각은 키 보유자가 주장하는 값임을 문서화
- 키셋 모드에서 유효한 서명된 `createdAt`이 없거나 5분보다 먼 미래인 신뢰 기록을 거부하고 서명 키 ID만 출력. 공개 키의 ID를 출력하는 `key-id` 추가

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
