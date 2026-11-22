# 스키마 안정성 규칙

<p align="right">
  <a href="./SCHEMAS.md">English</a> | <strong>한국어</strong>
</p>

TrustDex는 버전이 붙은 JSON 문서를 읽고 씁니다. 정책 파일, 서명된 스냅샷, 결정 보고서, 권한 상태, 바인딩, 런타임 증거, 키셋이 여기에 해당합니다. 이 문서는 그 형식들이 따르는 규칙을 적어, 연동 코드나 저장된 승인이 작성 당시의 의미를 그대로 유지하게 합니다.

## 공개된 스키마

| 스키마 | `kind` | 버전 |
| --- | --- | --- |
| [`schemas/effective-runtime-tools-diff-v1.schema.json`](../schemas/effective-runtime-tools-diff-v1.schema.json) | — | 1 |
| [`schemas/effective-runtime-tools-diff-v2.schema.json`](../schemas/effective-runtime-tools-diff-v2.schema.json) | — | 2 |
| [`schemas/effective-runtime-tools-v1.schema.json`](../schemas/effective-runtime-tools-v1.schema.json) | `agent-effective-tool-boundary` | 1 |
| [`schemas/effective-runtime-tools-v2.schema.json`](../schemas/effective-runtime-tools-v2.schema.json) | `agent-effective-tool-boundary` | 2 |
| [`schemas/permission-posture-diff-v1.schema.json`](../schemas/permission-posture-diff-v1.schema.json) | — | 1 |
| [`schemas/permission-posture-diff-v2.schema.json`](../schemas/permission-posture-diff-v2.schema.json) | — | 2 |
| [`schemas/permission-posture-v1.schema.json`](../schemas/permission-posture-v1.schema.json) | `agent-permission-posture` | 1 |
| [`schemas/permission-posture-v2.schema.json`](../schemas/permission-posture-v2.schema.json) | `agent-permission-posture` | 2 |
| [`schemas/runtime-tool-inventory-attestation-v1.schema.json`](../schemas/runtime-tool-inventory-attestation-v1.schema.json) | `agent-runtime-tool-inventory-attestation` | 1 |
| [`schemas/runtime-tool-inventory-v1.schema.json`](../schemas/runtime-tool-inventory-v1.schema.json) | `agent-runtime-tool-inventory` | 1 |
| [`schemas/tool-permission-bindings-diff-v1.schema.json`](../schemas/tool-permission-bindings-diff-v1.schema.json) | — | 1 |
| [`schemas/tool-permission-bindings-v1.schema.json`](../schemas/tool-permission-bindings-v1.schema.json) | `agent-tool-permission-bindings` | 1 |
| [`schemas/trust-snapshot-v3.schema.json`](../schemas/trust-snapshot-v3.schema.json) | — | 3 |
| [`schemas/trustdex-decisions-v1.schema.json`](../schemas/trustdex-decisions-v1.schema.json) | `trustdex-decisions` | 1 |
| [`schemas/trustdex-keyset-v1.schema.json`](../schemas/trustdex-keyset-v1.schema.json) | `trustdex-keyset` | 1 |
| [`schemas/trustdex-policy-v1.schema.json`](../schemas/trustdex-policy-v1.schema.json) | — | 1 |

`schemas/`에 있는 파일이 이 표에 없으면 `test/compatibility.test.mjs`가 실패합니다.

## 읽는 쪽의 규칙

- 모르는 `schemaVersion`(정책은 `version`)이나 `kind`를 가진 문서는 거부합니다. 이전 버전 방식으로 대신 읽지 않습니다.
- 모르는 필드는 거부합니다. 공개된 모든 스키마는 `additionalProperties: false`이며, 모르는 필드·모르는 신호 이름·잘못된 동작이 있는 정책 파일은 일부만 적용하지 않고 거부합니다.
- 문서가 없거나 비어 있거나 해석할 수 없으면 "문제 없음"이 아니라 BLOCK으로 처리합니다.
- `ask`는 사람이 검토해야 한다는 뜻이며 허용이 아닙니다.

## 변경 규칙

- 필드는 해당 스키마 버전이 유지되는 동안 같은 의미를 가집니다. 필드를 다른 용도로 재사용하지 않습니다.
- 필드의 의미가 바뀌거나, 결정·동작 값이 추가되거나, 필드가 제거되거나, 지문·서명이 포함하는 범위가 바뀌면 새 정수 버전과 새 스키마 파일을 만듭니다.
- 같은 버전 안에서 필드를 추가할 수 있는 경우는 그 필드를 모르는 쪽이 안전하게 유지될 때뿐입니다. 즉 그 필드가 ASK나 BLOCK을 ALLOW로 바꿀 수 없어야 합니다. 읽는 쪽이 모르는 필드를 거부하므로, 대부분의 추가는 새 버전으로 나갑니다.
- 이전 스키마 파일은 저장된 문서를 계속 검증할 수 있도록 `schemas/`에 남깁니다. 버전이 다른 권한 상태 스냅샷을 비교하면 검토가 필요한 변경으로 보고합니다.
- 지문이나 스냅샷이 바뀌어도, 변경 전에 기록된 승인이 검토한 것과 다른 설정을 통과시켜서는 안 됩니다. 지문 입력이 바뀌면 기존 승인은 재확인에서 실패하고 다시 검토받아야 합니다.
- 스냅샷과 보고서에는 비밀 값, 소스 경로, 권한 지정자가 들어가지 않습니다. 새 출력 필드는 `test/secret-canary.test.mjs`의 카나리 검사에 추가합니다.
- 모든 스키마 변경에는 테스트와 새 버전을 적은 변경 기록이 함께 들어갑니다.

## 이 규칙이 약속하지 않는 것

TrustDex는 1.0 이전입니다. 명령 이름, 사람이 읽는 출력, 신호 이름은 마이너 버전 사이에 바뀔 수 있으며 변경 기록에 남깁니다. 위 규칙은 버전이 붙은 JSON 문서에만 적용됩니다.
