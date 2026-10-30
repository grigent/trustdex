# IDE 확장

<p align="right">
  <a href="./IDE_EXTENSIONS.md">English</a> | <strong>한국어</strong>
</p>

AI 코딩 에이전트는 점점 더 에디터 확장 형태로 배포됩니다(예: VS Code와 Cursor용 Claude Code 확장). 에디터 확장은 사용자의 로컬 권한을 그대로 가지고 실행되며, 마켓플레이스가 자동으로 업데이트합니다. 2026년 10월 Cursor는 변조된 `Anthropic.claude-code` 빌드(버전 `2.1.313`)가 몇 시간 동안 Cursor 확장 마켓플레이스에 올라가 있었고, 공격자 SSH 키를 추가하고 역방향 터널을 열려고 시도했다고 공지했습니다. 사용자는 평범한 업데이트로 이 빌드를 받았습니다.

TrustDex는 설치된 확장을 MCP 서버와 같은 방식으로 다룹니다. 이름, 게시자 표시, 마켓플레이스만으로는 아무것도 신뢰하지 않습니다. 확장은 사용자가 고정한 정확한 버전과 일치할 때만 ALLOW이며, 서명된 검토 기록으로 설치된 파일이 이후 바뀌었는지 감지할 수 있습니다.

## 검사 대상

`inspect-ide-extensions`는 사용자가 지정한 VS Code 호환 확장 디렉터리 하나를 읽습니다. 예:

| 에디터 | 일반적인 디렉터리 |
|---|---|
| VS Code | `~/.vscode/extensions` |
| Cursor | `~/.cursor/extensions` |
| VS Code Remote / Codespaces | `~/.vscode-server/extensions` |

해당 디렉터리에서 TrustDex는 다음을 수행합니다.

- 에디터 설치 기록인 `extensions.json`과 `.obsolete`를 읽고, 형식이 잘못되었거나 너무 크거나 일반 파일이 아니면 실패 시 차단(fail closed)합니다.
- 설치 기록의 모든 항목을 항상 검사합니다. `<id>-<version>[-<platform>]` 키가 `.obsolete`에도 있는 항목은 버리지 않고 `ide-extension-marked-obsolete`로 보고합니다.
- 설치 기록에 없는 폴더는 그 폴더 자신의 매니페스트 키가 삭제 예정으로 표시된 경우에만 건너뜁니다.
- 각 확장의 `package.json`을 읽고 게시자, 이름, 버전을 설치 기록과 비교합니다.
- `package.json`이 있지만 설치 기록에 없는 확장 폴더를 보고합니다. 숨김 폴더도 포함합니다.
- 설치된 확장의 모든 파일(상대 경로, 크기, 실행 권한, 내용)에 대해 SHA-256 다이제스트를 계산합니다. 심볼릭 링크는 대상 문자열만 기록하고 따라가지 않습니다.
- 설치 기록의 위치 중 경로 구성 요소 하나라도 심볼릭 링크이면 디렉터리 밖으로 간주하고 읽지 않습니다. 매니페스트와 제어 파일은 심볼릭 링크를 따라가지 않고 엽니다.
- 확장 코드를 실행하지 않고, 네트워크 요청을 하지 않습니다.

결과에는 확장 ID, 버전, 기록된 설치 출처(`gallery`, `vsix` 등), 대상 플랫폼, 다이제스트, 신호가 들어갑니다. 결과와 스냅샷에는 절대 경로가 포함되지 않습니다.

## 신호

| 신호 | strict | 의미 |
|---|---|---|
| `ide-extension-missing-manifest` | BLOCK | 등록된 폴더가 없거나 심볼릭 링크이거나, `package.json`이 없거나 파싱할 수 없음 |
| `ide-extension-manifest-mismatch` | BLOCK | `package.json`의 게시자/이름/버전이 설치 기록과 다르거나 유효하지 않음 |
| `ide-extension-digest-mismatch` | BLOCK | 설치된 파일이 정책에 고정한 `#sha256:` 다이제스트와 다름 |
| `ide-extension-external-location` | BLOCK | 설치 기록이 지정한 디렉터리 밖이나 심볼릭 링크를 거치는 경로를 가리킴(읽지 않음) |
| `ide-extension-unregistered` | ASK | 설치 기록에 없는 확장 폴더가 존재함 |
| `ide-extension-marked-obsolete` | ASK | 설치 기록에 있지만 `.obsolete`에 삭제 예정으로 표시됨 |
| `ide-extension-non-gallery-source` | ASK | 설치 기록에 마켓플레이스(`gallery`) 설치로 남아 있지 않음(예: `.vsix`) |
| `ide-extension-prerelease` | ASK | 프리릴리스 빌드가 설치됨 |
| `ide-extension-startup-activation` | ASK | 사용자 동작 없이 시작 시 활성화됨(`*` 또는 `onStartupFinished`) |
| `ide-extension-untrusted-workspaces` | ASK | 신뢰하지 않는 작업 공간을 완전히 지원한다고 선언함 |
| `ide-extension-native-code` | ASK | 네이티브 실행 파일이나 모듈이 있음(ELF, Mach-O, PE, `.node`, `.dll`, `.so`, `.dylib`, `.exe`) |
| `ide-extension-bundles-extensions` | ASK | `extensionPack` 또는 `extensionDependencies`를 선언함 |
| `ide-extension-non-regular-files` | ASK | 확장 트리에 심볼릭 링크나 특수 파일이 있음 |

설치 출처가 `gallery`라는 것은 에디터가 마켓플레이스 설치로 기록했다는 뜻일 뿐, 안전하다는 증거가 아닙니다. 2026년 10월의 변조 빌드도 마켓플레이스를 통해 배포되었습니다.

## 정책

```json
{
  "trustedIdeExtensions": [
    "anthropic.claude-code@2.1.314",
    "example.formatter@3.2.0#sha256:<inspect 출력의 다이제스트>"
  ],
  "blockedIdeExtensions": [
    "example.abandoned@*"
  ]
}
```

- `trustedIdeExtensions` 항목은 정확한 semver 버전을 지정해야 합니다. 버전이 없거나 `1.*`, `^1.0.0`, `latest` 같은 범위를 쓴 항목은 거부되므로, 게시자를 신뢰해도 다음 업데이트가 자동으로 신뢰되지 않습니다. 잘못된 IDE 항목은 IDE 검사뿐 아니라 모든 평가를 실패시킵니다.
- 선택적인 `#sha256:<digest>` 고정을 쓰면 설치된 파일이 바이트 단위로 일치해야 합니다. 다르면 차단됩니다.
- `blockedIdeExtensions` 항목은 정확한 버전 또는 모든 버전을 뜻하는 `@*`와 일치하며, 항상 허용 고정보다 우선합니다. 정책 오버레이는 차단 목록에 항목을 추가만 할 수 있고, 기본 항목을 제거할 수 없습니다.
- 고정되지 않은 확장은 정책 팩의 `unknownAction`을 따르지만(`strict`, `official-first`는 BLOCK, `development`는 ASK), ASK보다 완화되지는 않습니다. ALLOW는 정확한 고정으로만 나옵니다.
- 고정된 확장도 신호에 따라 ASK 또는 BLOCK으로 올라갈 수 있습니다. 네 가지 BLOCK 무결성 신호(매니페스트 누락, 매니페스트 불일치, 다이제스트 불일치, 외부 위치)는 정책 오버레이가 `signalActions`를 낮춰도 BLOCK으로 유지됩니다.

에디터가 알려진 악성 빌드를 배포한 마켓플레이스에서 확장을 설치한다면 그 정확한 버전을 `blockedIdeExtensions`에 추가하세요. 예를 들어 Cursor 확장 마켓플레이스를 쓰는 에디터라면 `"anthropic.claude-code@2.1.313"`입니다. 영향받는 버전과 마켓플레이스는 공급사의 공식 공지를 기준으로 판단하세요.

## 검토와 재확인

```bash
node ./bin/trustdex.mjs inspect-ide-extensions ~/.cursor/extensions \
  --pack strict --policy ./ide-policy.json

node ./bin/trustdex.mjs approve-ide-extensions ~/.cursor/extensions \
  --private trustdex-private.pem --dir .trustdex/ide-review \
  --pack strict --policy ./ide-policy.json

node ./bin/trustdex.mjs recheck-ide-extensions ~/.cursor/extensions \
  --review-dir .trustdex/ide-review --public trustdex-public.pem
```

`approve-ide-extensions`는 BLOCK 결정이 포함된 목록에는 서명하지 않습니다. `recheck-ide-extensions`는 설치된 확장이 서명된 검토와 일치하면 `0`, 확장이 추가·제거·업데이트·변경되면 `NEEDS_REVIEW`와 함께 `1`, 검토 기록이 유효하지 않으면 `2`로 종료합니다. 무해한 예제로 확인해 볼 수 있습니다.

```bash
node ./bin/trustdex.mjs inspect-ide-extensions ./examples/ide-extensions \
  --pack strict --policy ./examples/ide-extensions.policy.json
```

예제는 `example.updated-ext@2.0.0`을 고정했지만 `2.0.1`이 설치되어 있으므로 차단됩니다. `example.sideloaded-ext`는 차단 목록에 있습니다.

## 권장 에디터 설정

TrustDex는 설치된 상태를 검사할 뿐, 에디터가 업데이트를 설치하는 것을 막을 수는 없습니다. 검토가 의미 있도록 다음을 권장합니다.

- 확장 자동 업데이트를 끄고(`"extensions.autoUpdate": false`) 의도적으로 업데이트하세요.
- 에디터를 열기 전, 로그인 스크립트, 또는 정기 작업으로 `recheck-ide-extensions`를 실행하고 `NEEDS_REVIEW`가 나오면 확인하세요.
- 가능하면 서명용 개인 키는 검사 대상 컴퓨터 밖에 보관하세요.

## 한계

- 정적 검사는 확장이 안전하다는 것을 증명하지 않습니다. 버전과 다이제스트가 고정된 확장도 악성일 수 있으며, 고정은 사용자가 검토한 빌드와 같다는 것만 증명합니다.
- TrustDex는 확장이 이미 호스트의 다른 곳에 만든 변경(예: SSH 키, 서비스)을 감지하거나 제거하지 않습니다. 알려진 악성 빌드가 설치되었다면 공급사의 조치 안내를 따르세요.
- TrustDex는 확장 디렉터리를 읽을 수 있을 만큼 로컬 호스트를 신뢰합니다. 완전히 장악된 호스트는 TrustDex가 읽는 내용을 위조할 수 있습니다.
- 지정한 디렉터리만 검사합니다. 에디터는 다른 위치(예: 내장 확장, `--extensions-dir` 폴더)에서도 확장을 불러올 수 있습니다.
