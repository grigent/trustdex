# 인증된 런타임 증거

<p align="right">
  <a href="./RUNTIME_EVIDENCE.md">English</a> | <strong>한국어</strong>
</p>

TrustDex는 권한이 있는 Claude 또는 Codex 통합이 생성한 값 없는 런타임 인벤토리를
인증할 수 있습니다. 인증은 고정된 어떤 Ed25519 키가 정확한 인벤토리에 서명했는지와
수명이 짧은 증명이 신선한지를 확인합니다. 어댑터가 침해되지 않았거나 인벤토리가
완전하거나 런타임이 검토된 정책을 강제했다는 사실까지 증명하지는 않습니다.

## 종단 간 워크플로

전용 생성자 키 쌍을 한 번 만드세요. 비공개 키는 어댑터에 보관하고, 공개 키는
신뢰할 수 있는 채널을 통해 각 검증자에게 배포합니다.

```bash
node ./bin/trustdex.mjs keygen \
  --private .trustdex/runtime-producer-private.pem \
  --public .trustdex/runtime-producer-public.pem
```

권한 있는 어댑터는 런타임, 캡처 시각/방식, 서버 이름 및 서버별 도구 개수만 담은
`agent-runtime-tool-inventory` JSON을 작성합니다. 그 파일에 즉시 서명하세요. 기본
수명은 5분이고 최대 수명은 24시간입니다.

```bash
node ./bin/trustdex.mjs sign-runtime-inventory \
  ./runtime-tool-inventory.json \
  --private .trustdex/runtime-producer-private.pem \
  --out .trustdex/runtime-attestation.json \
  --ttl-seconds 300
```

대조 전에 생성자 신원, 서명, 만료 및 캡처 신선도를 검증합니다.

```bash
node ./bin/trustdex.mjs verify-runtime-inventory \
  ./runtime-tool-inventory.json \
  --attestation .trustdex/runtime-attestation.json \
  --public .trustdex/runtime-producer-public.pem \
  --max-age-seconds 120 \
  --json

node ./bin/trustdex.mjs snapshot-runtime-tools \
  .trustdex/claude-bindings.json \
  ./runtime-tool-inventory.json \
  --attestation .trustdex/runtime-attestation.json \
  --public .trustdex/runtime-producer-public.pem \
  --max-age-seconds 120 \
  --require-authenticated \
  --out .trustdex/runtime-tools.json
```

잘못되거나 만료되거나 오래되거나 미래 시각이거나 다른 키를 사용하거나 인벤토리와
불일치하는 증명은 종료 코드 `2`를 반환합니다. 인증하지 않은 스키마 v2 실제 증거는
항상 최소 `needs-review`가 되며, 관찰된 차단/미설정 서버는 계속 `block`이 됩니다.

## 서명 범위

Ed25519 서명은 스키마/알고리즘 식별자, 정규 인벤토리 다이제스트, 런타임, 캡처
시각과 방식, 생성자 공개 키 ID, 생성 시각 및 만료 시각을 포함합니다. 키 ID는 공개
SPKI 바이트의 SHA-256 다이제스트입니다. 별도 인벤토리 스키마가 원시 도구 목록과
임의 필드를 거부하므로 증명과 실제 보고서에는 도구 이름, 엔드포인트, 자격 증명 또는
비공개 키 자료가 포함되지 않습니다.

선택적인 `--max-age-seconds`는 증명 만료와 별개입니다. 만료는 서명 사용 가능 시간을,
최대 나이는 원본 캡처의 허용 나이를 제한합니다. TrustDex는 제한된 시계 오차만
허용하기 위해 5분보다 먼 미래의 캡처와 증명도 거부합니다.

## 운영 및 키 교체

- 생성자 전용 키를 사용하고 비공개 파일을 최소 권한으로 보호하며 커밋하지 마세요.
  일반 검토 기록 키도 암호학적으로 작동하지만 운영 역할은 분리해야 합니다.
- 예상 공개 키는 인벤토리/증명 채널 밖에서 고정하세요. 공격자가 증거와 공개 키를
  모두 바꿀 수 있다면 서명은 신원 주장이 아닙니다.
- 감사 보존이 필요하면 인벤토리, 증명, 고정 키 ID, 결합 스냅샷 및 실제 보고서를
  함께 보관하세요. 실제 보고서는 자체 일관성을 확인하지만 독립적으로 서명되지는 않습니다.
- 키 교체 시 새 공개 키를 먼저 배포하고, 제한된 중첩 기간 동안 오케스트레이션에서
  이전 또는 새 고정 키를 허용한 뒤 생성자를 전환하고 이전 키를 폐기하세요. TrustDex는
  호출당 전달된 키 하나를 검증하며 키 허용 목록과 폐기는 배포 환경의 책임입니다.
- `producer-key-changed`와 `inventory-authentication-changed` 차이를 검토 이벤트로
  취급하세요. 비공개 키 탈취가 의심되면 검증자에서 키를 제거하고 새 키로 증거를 다시 발급하세요.

계약은
[`runtime-tool-inventory-v1.schema.json`](../schemas/runtime-tool-inventory-v1.schema.json),
[`runtime-tool-inventory-attestation-v1.schema.json`](../schemas/runtime-tool-inventory-attestation-v1.schema.json),
[`effective-runtime-tools-v2.schema.json`](../schemas/effective-runtime-tools-v2.schema.json),
[`effective-runtime-tools-diff-v2.schema.json`](../schemas/effective-runtime-tools-diff-v2.schema.json)에 정의되어 있습니다.
