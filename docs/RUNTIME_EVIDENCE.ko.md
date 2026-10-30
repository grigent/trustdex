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
- `--public`은 호출당 정확히 하나의 키를 고정합니다. 허용 목록, 교체 중첩 기간, 폐기에는
  아래에 설명한 `--keyset` 파일을 사용하세요.
- `producer-key-changed`와 `inventory-authentication-changed` 차이를 검토 이벤트로
  취급하세요. 비공개 키 탈취가 의심되면 키셋에서 그 키를 `revokedAt` 없이 폐기하고 새 키로
  증거를 다시 발급하세요.

## 키셋: 허용 목록, 교체, 폐기

검증하는 모든 명령은 `--public key.pem` 대신 `--keyset keyset.json`을 받습니다.
대상은 `verify`, `recheck`, `recheck-claude`, `recheck-codex`, `recheck-ide-extensions`,
`verify-runtime-inventory`, `snapshot-runtime-tools`입니다. 두 플래그를 함께 주거나
`--keyset`을 두 번 주면 오류입니다. `--public`의 동작은 이전과 같습니다.

키셋은 운영자가 작성하는 버전 있는 허용 목록입니다
([`trustdex-keyset-v1.schema.json`](../schemas/trustdex-keyset-v1.schema.json),
[예시](../examples/trustdex-keyset.example.json)).

```json
{
  "schemaVersion": 1,
  "kind": "trustdex-keyset",
  "keys": [
    {
      "id": "<SPKI DER 바이트의 sha256>",
      "publicKey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
      "purposes": ["runtime-producer"],
      "notBefore": "2026-11-01T00:00:00.000Z",
      "notAfter": "2027-11-01T00:00:00.000Z",
      "note": "producer key 2026-11"
    }
  ],
  "revoked": [
    { "id": "<키 ID>", "note": "suspected compromise" },
    { "id": "<키 ID>", "revokedAt": "2026-11-01T00:00:00.000Z", "note": "retired" }
  ]
}
```

- **키 ID.** `id`는 키의 SPKI DER 바이트에 대한 SHA-256이며, 증명의 `producerKeyId`와
  같은 값입니다. `node ./bin/trustdex.mjs key-id key.pem`으로 출력할 수 있습니다.
- **엄격한 파싱.** 알 수 없는 필드, 잘못된 `schemaVersion` 또는 `kind`, 빈 `keys` 목록,
  중복된 키 또는 폐기 ID, 키와 맞지 않는 `id`, 정규 형식의 단일 `PUBLIC KEY` PEM 블록이
  아닌 값(비공개 키와 인증서는 거부), Ed25519가 아닌 키, 알 수 없는 용도,
  `YYYY-MM-DDTHH:mm:ss.sssZ` 형식이 아닌 시각, `notBefore` 이후가 아닌 `notAfter`는 모두
  즉시 오류(종료 코드 `2`)입니다. `--public`이나 일부만 유효한 키셋으로 대신 진행하지 않습니다.
- **용도.** 모든 키는 `purposes`를 반드시 나열해야 합니다. `review` 키는 신뢰 기록(`verify`,
  `recheck*`)을, `runtime-producer` 키는 런타임 인벤토리 증명을 검증합니다. 기본값이 없으므로
  둘 다 나열한 키만 둘 다 검증합니다. 검토 키가 런타임 증거를 인증하거나 그 반대가 되지
  않도록 키를 분리하는 것을 권장합니다.
- **서명된 시각.** 유효 기간과 폐기 기준 시각은 서명된 내용에 기록된 시각, 즉 신뢰 기록이나
  증명의 `createdAt`으로 평가합니다. `notBefore`는 포함하고 `notAfter`는 제외합니다.
  따라서 유효 기간 안에 서명된 검토는 기간이 끝난 뒤에도 유효합니다. 증명 만료와
  `--max-age-seconds`는 계속 검증 시점에 적용됩니다.
- **신뢰 기록.** 신뢰 기록에는 키 ID가 없으므로 TrustDex는 나열된 모든 키로 서명을
  확인해 서명자를 찾은 뒤 그 키에 폐기, 용도, 유효 기간 검사를 적용합니다. `--keyset`을
  쓰면 유효한 `createdAt`이 없는 기록과 `createdAt`이 5분보다 먼 미래인 기록은 `INVALID`입니다.
  이는 서명자가 미리 배포된 키의 유효 기간으로 시각을 앞당겨 기록하는 것을 막습니다.
  `--public` 검증에는 이전처럼 이 시각 검사가 적용되지 않습니다.
- **출력.** 키셋 검증이 성공하면 서명 키 ID를 출력합니다(`verify`와 `recheck`는
  `Signing key:`, `recheck --json`은 `keyId`). 오류는 `keys[1].id` 같은 필드 위치만 말하고
  파일 내용, 키 자료, 메모는 출력하지 않습니다.

### 폐기 시점 의미

- **`revokedAt`이 없는 폐기는 전면적**입니다. 그 키의 모든 서명이 `INVALID`이며, 폐기보다
  훨씬 전에 서명된 검토도 마찬가지입니다. 이것이 기본값이며 탈취가 의심될 때 맞는
  선택입니다. 영향받은 검토는 새 키로 다시 승인하세요.
- **`revokedAt`이 있는 폐기**는 서명된 시각이 `revokedAt`보다 엄격히 이른 증거만 유지하고,
  같거나 이후에 서명된 증거는 `INVALID`로 만듭니다. 서명된 시각은 키 보유자가 주장하는
  값이므로 탈취한 비공개 키를 가진 사람은 시각을 과거로 기록할 수 있습니다. `revokedAt`은
  탈취가 의심되지 않는 키를 은퇴시킬 때만 쓰거나, 이전 증거를 계속 신뢰하겠다는 명시적
  결정으로 취급하세요.
- 폐기 항목은 더 이상 나열되지 않은 키를 가리킬 수 있습니다. 키를 제거한 뒤에도 항목을
  남겨 두면 실수로 다시 추가해도 계속 거부됩니다.

### 교체 절차

1. 새 키 쌍을 만들고 `key-id`로 ID를 출력합니다.
2. 새 키를 계획된 전환 시각 이하의 `notBefore`와 함께 키셋에 추가하고 모든 검증자에
   배포합니다. 이제 두 키가 모두 허용됩니다.
3. 서명자(`approve`, `sign`) 또는 런타임 생성자(`sign-runtime-inventory`)를 새 비공개
   키로 전환합니다.
4. 이전 키를 닫습니다. 기존 검토가 계속 검증되도록 `notAfter`를 전환 시각으로
   설정하거나, 모든 검토를 다시 승인한 뒤 키를 제거합니다. 런타임 증명의 수명은 최대
   24시간이므로 이전 생성자 키는 전환 후 최대 증명 수명이 지나면 제거할 수 있습니다.
5. 이전 키가 탈취되었을 수 있다면 대신 키를 제거하거나 `revokedAt` 없이 `revoked`에
   추가합니다.

`notAfter`와 `revokedAt`은 정직한 서명자만 막습니다. 서명된 시각은 비공개 키를 가진 쪽이
정하므로, 이전 키를 가진 사람은 기준 시각 이전 날짜로 새 검토에 서명할 수 있고 신뢰 기록은
만료되지 않습니다. 키 보유자를 막으려면 키를 제거하거나 `revokedAt` 없이 폐기하세요. 런타임
생성자 키의 경우 날짜를 거슬러 올리는 범위는 최대 증명 수명인 24시간으로 제한됩니다.

### 폐기 훅

키셋 파일 자체가 폐기 훅입니다. TrustDex는 검증할 때마다 파일을 읽으며 네트워크 조회,
CRL 또는 OCSP 조회, 캐싱, 프로세스 실행을 하지 않습니다. 배포 환경은 검토된 저장소 커밋,
구성 관리, CI 산출물 같은 자체 채널로 파일을 갱신해 폐기를 전달합니다. 키셋은 고정된 공개
키처럼 보호하세요. 키셋을 쓸 수 있는 사람은 키를 추가하거나 폐기를 제거할 수 있습니다.
TrustDex는 키셋 자체에 서명하지 않습니다.

계약은
[`runtime-tool-inventory-v1.schema.json`](../schemas/runtime-tool-inventory-v1.schema.json),
[`runtime-tool-inventory-attestation-v1.schema.json`](../schemas/runtime-tool-inventory-attestation-v1.schema.json),
[`effective-runtime-tools-v2.schema.json`](../schemas/effective-runtime-tools-v2.schema.json),
[`effective-runtime-tools-diff-v2.schema.json`](../schemas/effective-runtime-tools-diff-v2.schema.json)에 정의되어 있습니다.
