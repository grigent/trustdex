# 호환성 매트릭스

<p align="right">
  <a href="./COMPATIBILITY.md">English</a> | <strong>한국어</strong>
</p>

이 문서는 TrustDex가 무엇을 대상으로 테스트되는지 나열합니다. 모든 행은 이 저장소의 테스트 파일로 뒷받침됩니다. 행에 적힌 명령, 테스트, 예제가 존재하지 않거나 플랫폼 표가 CI 매트릭스와 다르면 `test/compatibility.test.mjs`가 실패합니다.

## 플랫폼

| OS | Node.js |
| --- | --- |
| Linux (`ubuntu-latest`) | 20, 22, 24 |
| Windows (`windows-latest`) | 22 |
| macOS (`macos-latest`) | 22 |

지원하는 최소 버전은 Node.js 20입니다. `trustdex init`은 macOS와 Linux만 지원합니다.

## 입력

| 입력 | 명령 | 테스트 | ID |
| --- | --- | --- | --- |
| 일반 MCP JSON (`mcpServers` / `servers`) | `inspect`, `gate`, `snapshot`, `diff`, `approve`, `recheck` | `test/policy.test.mjs`, `test/hardening.test.mjs`, `test/research-fixtures.test.mjs` | `mcp-json` |
| Claude Code `.mcp.json` 및 Claude Desktop `mcpServers` | `inspect-claude`, `gate-claude`, `snapshot-claude`, `approve-claude`, `recheck-claude` | `test/claude.test.mjs` | `claude-mcp` |
| Claude Code 설정 파일 및 병합 스택 | `inspect-claude-settings`, `inspect-claude-settings-stack`, `snapshot-claude-settings`, `snapshot-claude-settings-stack`, `diff-permissions` | `test/claude-settings.test.mjs`, `test/settings-stack.test.mjs`, `test/posture.test.mjs` | `claude-settings` |
| Claude Code `PreToolUse` 훅 | `claude-hook`, `init`, `allow-once` | `test/claude-hook.test.mjs`, `test/init.test.mjs` | `claude-hook` |
| Codex `config.toml` MCP 서버 | `inspect-codex`, `gate-codex`, `snapshot-codex`, `approve-codex`, `recheck-codex` | `test/codex-toml.test.mjs`, `test/codex-review.test.mjs` | `codex-toml` |
| Codex 승인·샌드박스 설정 및 병합 스택 | `inspect-codex-settings`, `inspect-codex-settings-stack`, `snapshot-codex-settings`, `snapshot-codex-settings-stack` | `test/codex-settings.test.mjs`, `test/settings-stack.test.mjs` | `codex-settings` |
| 자동 승인에 연결한 MCP 출처 (Claude, Codex) | `snapshot-claude-bindings`, `snapshot-codex-bindings`, `diff-bindings` | `test/bindings.test.mjs` | `bindings` |
| 명시적 런타임 도구 인벤토리 (`claude`, `codex`) | `inventory-claude-init`, `snapshot-runtime-tools`, `diff-runtime-tools`, `sign-runtime-inventory`, `verify-runtime-inventory` | `test/claude-runtime-inventory.test.mjs`, `test/runtime-evidence.test.mjs`, `test/runtime-attestation.test.mjs`, `test/keyset.test.mjs` | `runtime-evidence` |
| `SKILL.md` 스킬 파일 | `inspect-skill` | `test/v02.test.mjs`, `test/research-fixtures.test.mjs` | `skill` |
| 플러그인 매니페스트 (`plugin.json`) | `inspect-plugin` | `test/v02.test.mjs`, `test/research-fixtures.test.mjs` | `plugin` |
| VS Code 호환 확장 디렉터리 (VS Code, Cursor, Remote) | `inspect-ide-extensions`, `snapshot-ide-extensions`, `approve-ide-extensions`, `recheck-ide-extensions` | `test/ide-extensions.test.mjs` | `ide-extensions` |
| npm 및 PyPI 설치 명령 (`registry.npmjs.org`, `pypi.org`) | `check-install` | `test/install-check.test.mjs` | `install-npm-pypi` |
| 온라인 출처 확인: GitHub, npm, MCP Registry | `provenance`, `trust-source` | `test/integrity.test.mjs`, `test/v03.test.mjs` | `provenance` |

## 여기서 "호환"의 의미

- TrustDex는 이 저장소의 픽스처로 **설정 형식**을 테스트합니다. Claude Code, Claude Desktop, Codex, VS Code, Cursor의 릴리스를 대상으로 실행하지 않으므로, 특정 런타임 버전을 인증하지 않습니다.
- 각 어댑터는 해당 문서에 나열된 필드만 받습니다. 그 밖의 필드, 전송 방식, 문법은 닫힌 쪽으로 실패합니다(오류 또는 ASK/BLOCK 신호). 런타임이 설정을 추가하면, 어댑터 릴리스가 이를 다룰 때까지 TrustDex는 거부하거나 표시합니다.
- 런타임 증거는 권한 있는 통합이 제공한 인벤토리에서 런타임 이름 `claude`와 `codex`를 받습니다. TrustDex는 실행 중인 에이전트를 직접 읽는 어댑터를 제공하지 않습니다. `inventory-claude-init`은 Claude Code의 문서화된 `--output-format stream-json`에서 사용자가 직접 캡처한 `system/init` 이벤트를 변환합니다. 문서화된 이벤트 형태로 테스트하며 Claude Code 릴리스로 테스트하지는 않습니다.
- 온라인 어댑터는 `api.github.com`, `registry.npmjs.org`, `pypi.org`, MCP Registry의 공개 응답 형식에 의존합니다. 실제 요청이 아니라 응답 형태를 본뜬 픽스처로 테스트합니다.

## 불일치 제보

현재 런타임이 쓴 설정을 TrustDex가 거부하면, 필드 이름과 런타임 버전을 적어 이슈를 열어 주세요. 비밀 값이나 비공개 엔드포인트는 포함하지 마세요.
